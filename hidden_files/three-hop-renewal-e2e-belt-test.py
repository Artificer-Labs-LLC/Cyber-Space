"""Belt: THREE-HOP gossip chain + SAME-KEY RENEWAL e2e
(primitives 1 naming + 4 identity).

Every renewal panel so far carried the renewal at most TWO gossip
hops (A->B->far). Never proven: a renewal surviving a THIRD hop --
the legit owner re-signs fresher under the same key, and the far
node three hops away, which never talks to the owner, must still
move forward hop by hop, while a stale pre-renewal binding must
never drag any hop backward.

Four INDEPENDENT nodes (separate DBs, separate node keys):
A owner, B and C intermediaries in series, D far node.

  1. A claims the label under K1 via the real claim route (v1);
     gossip A->B, B->C, C->D in series; every hop serves v1
     byte-identical; belt re-verifies v1 against K1 at D
  2. A renews via the real claim route: same K1, LATER issued_at,
     later expires_at (v2); A serves v2
  3. A gossips v2 to B; B REPLACES live v1 with v2; C and D still
     serve v1 (the renewal has only crossed one hop)
  4. Negative control: stale v1 fed to D's real merge half
     (core.ingest_gossiped_binding) returns "kept"; D still v1
  5. B gossips onward; C REPLACES v1 with v2; D still serves v1
  6. C gossips onward; D REPLACES v1 with v2 byte-identical and
     the belt re-verifies v2 against K1 at the third hop
  7. Re-gossip of v2 along the tail is idempotent (D still v2);
     an unclaimed label is silence (404) on D

Test-only allowances, twin of the parent belts: helper/belt
processes patch core._reject_nonpublic_node_url to admit the
loopback node URLs only. The genesis name is never touched.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/three-hop-renewal-e2e-belt-test.py
"""

import json
import os
import secrets
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from fed.ed25519 import checkvalid, publickey, sign  # noqa: E402
from core import _name_claim_payload  # noqa: E402

CASES = {"passed": 0, "failed": 0}
PORT_A, PORT_B, PORT_C, PORT_D = 18991, 18992, 18993, 18994
URL_A = f"http://127.0.0.1:{PORT_A}"
URL_B = f"http://127.0.0.1:{PORT_B}"
URL_C = f"http://127.0.0.1:{PORT_C}"
URL_D = f"http://127.0.0.1:{PORT_D}"
URLS = (URL_A, URL_B, URL_C, URL_D)
LABEL = "threehoprenew"


def check(name, cond, extra=""):
    if cond:
        CASES["passed"] += 1
        print(f"  ok  {name}")
    else:
        CASES["failed"] += 1
        print(f"  FAIL {name} {extra}")


def ts(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S+00:00")


def get(port, path):
    try:
        with urllib.request.urlopen(
                f"http://127.0.0.1:{port}{path}", timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read())
        except Exception:
            return e.code, {}
    except Exception:
        return 0, {}


def boot(tmp, priv, port):
    env = dict(os.environ, CYBERNET_DB_DIR=tmp,
               CYBERNET_NODE_PRIVKEY=priv)
    proc = subprocess.Popen(
        [os.path.join(REPO, "venv/bin/python"), "-m", "uvicorn",
         "app:app", "--host", "127.0.0.1", "--port", str(port)],
        cwd=REPO, env=env, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL)
    for _ in range(60):
        code, _ = get(port, "/api/v1/node")
        if code == 200:
            return proc, True
        time.sleep(0.5)
    return proc, False


def seed_peer(tmp, pub, url, name):
    conn = sqlite3.connect(os.path.join(tmp, "cybernet.db"))
    conn.execute(
        "INSERT INTO peers (node_pub, name, network, version, genesis,"
        " capabilities, announced_at, first_seen, retired_at, node_url)"
        " VALUES (?,?,?,?,?,?,?,?,?,?)",
        (pub, name, "cybernet", "0.1.0", 0, "[]",
         ts(datetime.now(timezone.utc)),
         ts(datetime.now(timezone.utc)), "", url))
    conn.commit()
    conn.close()


def run_helper(tmp, priv, call):
    urls = ", ".join(repr(u) for u in URLS)
    helper = (
        "import time, core\n"
        "_real = core._reject_nonpublic_node_url\n"
        "def _gate(url):\n"
        f"    return None if url.startswith(({urls})) else _real(url)\n"
        "core._reject_nonpublic_node_url = _gate\n"
        f"n = {call}\n"
        "print('sent:', n)\n"
        "time.sleep(4)\n")
    env = dict(os.environ, CYBERNET_DB_DIR=tmp,
               CYBERNET_NODE_PRIVKEY=priv)
    return subprocess.run(
        [os.path.join(REPO, "venv/bin/python"), "-c", helper],
        cwd=REPO, env=env, capture_output=True, text=True, timeout=60)


def ingest_on(tmp, priv, binding):
    helper = (
        "import core\n"
        f"print(core.ingest_gossiped_binding({binding!r}))\n")
    env = dict(os.environ, CYBERNET_DB_DIR=tmp,
               CYBERNET_NODE_PRIVKEY=priv)
    return subprocess.run(
        [os.path.join(REPO, "venv/bin/python"), "-c", helper],
        cwd=REPO, env=env, capture_output=True, text=True, timeout=60)


def claim(port, label, name_priv, name_pub, issued_dt, expires_dt):
    issued, expires = ts(issued_dt), ts(expires_dt)
    sig = sign(_name_claim_payload(label, name_pub, issued, expires),
               name_priv, bytes.fromhex(name_pub)).hex()
    body = urllib.parse.urlencode(
        {"name": label, "node_pubkey": name_pub,
         "issued_at": issued, "expires_at": expires,
         "signature": sig}).encode()
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/api/v1/names/claim",
        data=body, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, sig, issued, expires
    except urllib.error.HTTPError as e:
        return e.code, sig, issued, expires


def wait_served(port, label, sig):
    served, code = {}, 0
    for _ in range(20):
        code, served = get(port, f"/api/v1/names/{label}")
        if code == 200 and served.get("signature") == sig:
            return code, served
        time.sleep(0.5)
    return code, served


def verify(pub_hex, sig_hex, label, issued, expires):
    try:
        return checkvalid(
            bytes.fromhex(sig_hex),
            _name_claim_payload(label, pub_hex, issued, expires),
            bytes.fromhex(pub_hex)) is True
    except Exception:
        return False


def main():
    tmp_a = tempfile.mkdtemp(prefix="3hop-renew-a-")
    tmp_b = tempfile.mkdtemp(prefix="3hop-renew-b-")
    tmp_c = tempfile.mkdtemp(prefix="3hop-renew-c-")
    tmp_d = tempfile.mkdtemp(prefix="3hop-renew-d-")
    a_priv = secrets.token_hex(32)
    a_pub = publickey(bytes.fromhex(a_priv)).hex()
    b_priv = secrets.token_hex(32)
    b_pub = publickey(bytes.fromhex(b_priv)).hex()
    c_priv = secrets.token_hex(32)
    c_pub = publickey(bytes.fromhex(c_priv)).hex()
    d_priv = secrets.token_hex(32)
    d_pub = publickey(bytes.fromhex(d_priv)).hex()
    k1_priv = bytes.fromhex(secrets.token_hex(32))
    k1_pub = publickey(k1_priv).hex()

    proc_a, up_a = boot(tmp_a, a_priv, PORT_A)
    proc_b, up_b = boot(tmp_b, b_priv, PORT_B)
    proc_c, up_c = boot(tmp_c, c_priv, PORT_C)
    proc_d, up_d = boot(tmp_d, d_priv, PORT_D)
    try:
        check("four independent nodes boot",
              up_a and up_b and up_c and up_d)
        if not (up_a and up_b and up_c and up_d):
            return
        # Binding topology: A -> B -> C -> D only, a strict chain.
        seed_peer(tmp_a, b_pub, URL_B, "belt-node-b")
        seed_peer(tmp_b, a_pub, URL_A, "belt-node-a")
        seed_peer(tmp_b, c_pub, URL_C, "belt-node-c")
        seed_peer(tmp_c, b_pub, URL_B, "belt-node-b")
        seed_peer(tmp_c, d_pub, URL_D, "belt-node-d")
        seed_peer(tmp_d, c_pub, URL_C, "belt-node-c")

        now = datetime.now(timezone.utc)
        code, sig1, issued1, expires1 = claim(
            PORT_A, LABEL, k1_priv, k1_pub,
            now - timedelta(minutes=10), now + timedelta(days=30))
        check("A claims kept-key name under K1 via real route (v1)",
              code == 200, f"got {code}")

        out = run_helper(tmp_a, a_priv, "core._names_gossip_out()")
        check("A gossip v1 ran to 1 recipient", "sent: 1" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, served_b1 = wait_served(PORT_B, LABEL, sig1)
        check("B serves v1 byte-identical",
              code == 200 and served_b1.get("node_pubkey") == k1_pub,
              f"got {code} {served_b1}")
        out = run_helper(tmp_b, b_priv, "core._names_gossip_out()")
        check("B gossip v1 onward ran to 2 recipients",
              "sent: 2" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, served_c1 = wait_served(PORT_C, LABEL, sig1)
        check("C serves v1 byte-identical (learned via B)",
              code == 200 and served_c1.get("node_pubkey") == k1_pub,
              f"got {code} {served_c1}")
        out = run_helper(tmp_c, c_priv, "core._names_gossip_out()")
        check("C gossip v1 onward ran to 2 recipients",
              "sent: 2" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, served_d1 = wait_served(PORT_D, LABEL, sig1)
        check("D serves v1 byte-identical (learned via C, third hop)",
              code == 200 and served_d1.get("node_pubkey") == k1_pub
              and served_d1.get("issued_at") == issued1
              and served_d1.get("expires_at") == expires1,
              f"got {code} {served_d1}")
        check("belt re-verifies D's v1 binding against K1",
              verify(k1_pub, served_d1.get("signature", ""), LABEL,
                     issued1, expires1))

        code, sig2, issued2, expires2 = claim(
            PORT_A, LABEL, k1_priv, k1_pub,
            now - timedelta(minutes=5), now + timedelta(days=60))
        check("A renews same-key v2 via real route (fresher, same K1)",
              code == 200 and sig2 != sig1, f"got {code}")
        code, served_a2 = get(PORT_A, f"/api/v1/names/{LABEL}")
        check("A serves v2 locally after renewal",
              code == 200 and served_a2.get("signature") == sig2
              and served_a2.get("issued_at") == issued2
              and served_a2.get("expires_at") == expires2,
              f"got {code} {served_a2}")

        out = run_helper(tmp_a, a_priv, "core._names_gossip_out()")
        check("A gossip v2 ran to 1 recipient", "sent: 1" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, served_b2 = wait_served(PORT_B, LABEL, sig2)
        check("B REPLACED live v1 with renewed v2",
              code == 200 and served_b2.get("node_pubkey") == k1_pub
              and served_b2.get("issued_at") == issued2
              and served_b2.get("expires_at") == expires2,
              f"got {code} {served_b2}")
        code, served_cx = get(PORT_C, f"/api/v1/names/{LABEL}")
        check("C still serves v1 (renewal crossed one hop only)",
              code == 200 and served_cx.get("signature") == sig1,
              f"got {code} {served_cx}")
        code, served_dx = get(PORT_D, f"/api/v1/names/{LABEL}")
        check("D still serves v1 (renewal crossed one hop only)",
              code == 200 and served_dx.get("signature") == sig1,
              f"got {code} {served_dx}")

        stale = {"name": LABEL, "node_pubkey": k1_pub,
                 "issued_at": issued1, "expires_at": expires1,
                 "signature": sig1}
        res = ingest_on(tmp_d, d_priv, stale)
        check("stale v1 merge on D returns kept (forward only)",
              res.stdout.strip().endswith("kept"),
              f"stdout={res.stdout!r} stderr={res.stderr[-400:]!r}")
        code, served_dx = get(PORT_D, f"/api/v1/names/{LABEL}")
        check("D still serves v1 after stale attempt",
              code == 200 and served_dx.get("signature") == sig1,
              f"got {code} {served_dx}")

        out = run_helper(tmp_b, b_priv, "core._names_gossip_out()")
        check("B gossip v2 onward ran to 2 recipients",
              "sent: 2" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, served_c2 = wait_served(PORT_C, LABEL, sig2)
        check("C REPLACED live v1 with v2 learned onward from B",
              code == 200 and served_c2.get("node_pubkey") == k1_pub
              and served_c2.get("issued_at") == issued2
              and served_c2.get("expires_at") == expires2,
              f"got {code} {served_c2}")
        code, served_dx = get(PORT_D, f"/api/v1/names/{LABEL}")
        check("D still serves v1 before C's leg runs",
              code == 200 and served_dx.get("signature") == sig1,
              f"got {code} {served_dx}")

        out = run_helper(tmp_c, c_priv, "core._names_gossip_out()")
        check("C gossip v2 onward ran to 2 recipients",
              "sent: 2" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, served_d2 = wait_served(PORT_D, LABEL, sig2)
        check("D REPLACED live v1 with v2 (renewal survived third hop)",
              code == 200 and served_d2.get("node_pubkey") == k1_pub
              and served_d2.get("issued_at") == issued2
              and served_d2.get("expires_at") == expires2,
              f"got {code} {served_d2}")
        check("belt re-verifies D's v2 binding against K1",
              verify(k1_pub, served_d2.get("signature", ""), LABEL,
                     issued2, expires2))

        out = run_helper(tmp_c, c_priv, "core._names_gossip_out()")
        time.sleep(1)
        code, served_d3 = get(PORT_D, f"/api/v1/names/{LABEL}")
        check("re-gossip of v2 is idempotent (D still serves v2)",
              "sent: 2" in out.stdout and code == 200
              and served_d3.get("signature") == sig2,
              f"got {code} {served_d3} out={out.stdout!r}")
        code, _ = get(PORT_D, "/api/v1/names/neverclaimedlabel")
        check("unclaimed label is silence (404) on D", code == 404,
              f"got {code}")
    finally:
        for p in (proc_a, proc_b, proc_c, proc_d):
            p.terminate()
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()

    print(f"\n{CASES['passed']} passed, {CASES['failed']} failed")
    sys.exit(1 if CASES["failed"] else 0)


if __name__ == "__main__":
    main()
