"""Belt: THREE-HOP gossip chain + KEY ROTATION e2e
(primitives 1 naming + 4 identity).

Every rotation panel so far carried the rotation at most TWO
gossip hops (A->B->far, including the multi-hop K1->K2->K3 chain).
Never proven: a rotation surviving a THIRD hop -- the owner
designates a successor key, and the far node three hops away,
which never talks to the owner, must still accept the successor
hop by hop on the recorded designation, while a proof-less
successor binding must be refused at the far node.

Four INDEPENDENT nodes (separate DBs, separate node keys):
A owner, B and C intermediaries in series, D far node.

  1. A claims the label under K1 via the real claim route;
     gossip A->B, B->C, C->D in series; every hop serves K1
     byte-identical; belt re-verifies K1 at D
  2. A rotates K1 -> K2 via the real rotate route; A serves K2
  3. A gossips to B; B REPLACES live K1 with designated K2 and
     records the hop; C and D still serve K1
  4. Negative control: bare K2 binding (no designation proof)
     fed to D's real merge half returns "conflict"; D still K1
  5. B gossips onward; C REPLACES live K1 with K2 on B's recorded
     designation; D still serves K1
  6. C gossips onward; D REPLACES live K1 with K2 byte-identical,
     belt re-verifies K2 at D, D records the rotation hop
  7. Re-gossip along the tail is idempotent (D still K2);
     an unclaimed label is silence (404) on D

Test-only allowances, twin of the parent belts: helper/belt
processes patch core._reject_nonpublic_node_url to admit the
loopback node URLs only. The genesis name is never touched.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/three-hop-rotation-e2e-belt-test.py
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
from rotate_name import mint_rotation  # noqa: E402

CASES = {"passed": 0, "failed": 0}
PORT_A, PORT_B, PORT_C, PORT_D = 19011, 19012, 19013, 19014
URL_A = f"http://127.0.0.1:{PORT_A}"
URL_B = f"http://127.0.0.1:{PORT_B}"
URL_C = f"http://127.0.0.1:{PORT_C}"
URL_D = f"http://127.0.0.1:{PORT_D}"
URLS = (URL_A, URL_B, URL_C, URL_D)
LABEL = "threehoprotate"


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


def rotate(port, label, old_priv, old_pub, new_priv, new_pub,
           rot_dt, bind_dt, bind_exp_dt):
    rec = mint_rotation(label, old_priv, new_pub, issued_at=ts(rot_dt))
    b_issued, b_expires = ts(bind_dt), ts(bind_exp_dt)
    b_sig = sign(_name_claim_payload(label, new_pub, b_issued, b_expires),
                 new_priv, bytes.fromhex(new_pub)).hex()
    body = urllib.parse.urlencode(
        {"name": label, "old_pubkey": old_pub, "new_pubkey": new_pub,
         "rotation_issued_at": rec["issued_at"],
         "rotation_signature": rec["signature"],
         "binding_issued_at": b_issued, "binding_expires_at": b_expires,
         "binding_signature": b_sig}).encode()
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/api/v1/names/rotate",
        data=body, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read()), rec, b_sig, b_issued, b_expires
    except urllib.error.HTTPError as e:
        return e.code, {}, rec, b_sig, b_issued, b_expires


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
    tmp_a = tempfile.mkdtemp(prefix="3hop-rot-a-")
    tmp_b = tempfile.mkdtemp(prefix="3hop-rot-b-")
    tmp_c = tempfile.mkdtemp(prefix="3hop-rot-c-")
    tmp_d = tempfile.mkdtemp(prefix="3hop-rot-d-")
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
    k2_priv = bytes.fromhex(secrets.token_hex(32))
    k2_pub = publickey(k2_priv).hex()

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
        check("A claims kept-key name under K1 via real route",
              code == 200, f"got {code}")

        out = run_helper(tmp_a, a_priv, "core._names_gossip_out()")
        check("A gossip K1 ran to 1 recipient", "sent: 1" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, served_b1 = wait_served(PORT_B, LABEL, sig1)
        check("B serves K1 byte-identical",
              code == 200 and served_b1.get("node_pubkey") == k1_pub,
              f"got {code} {served_b1}")
        out = run_helper(tmp_b, b_priv, "core._names_gossip_out()")
        check("B gossip K1 onward ran to 2 recipients",
              "sent: 2" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, served_c1 = wait_served(PORT_C, LABEL, sig1)
        check("C serves K1 byte-identical (learned via B)",
              code == 200 and served_c1.get("node_pubkey") == k1_pub,
              f"got {code} {served_c1}")
        out = run_helper(tmp_c, c_priv, "core._names_gossip_out()")
        check("C gossip K1 onward ran to 2 recipients",
              "sent: 2" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, served_d1 = wait_served(PORT_D, LABEL, sig1)
        check("D serves K1 byte-identical (learned via C, third hop)",
              code == 200 and served_d1.get("node_pubkey") == k1_pub
              and served_d1.get("issued_at") == issued1
              and served_d1.get("expires_at") == expires1,
              f"got {code} {served_d1}")
        check("belt re-verifies D's K1 binding against K1",
              verify(k1_pub, served_d1.get("signature", ""), LABEL,
                     issued1, expires1))

        code, resp, rec1, sig2, issued2, expires2 = rotate(
            PORT_A, LABEL, k1_priv, k1_pub, k2_priv, k2_pub,
            now - timedelta(minutes=6), now - timedelta(minutes=5),
            now + timedelta(days=60))
        check("A rotates K1 -> K2 via real rotate route",
              code == 200 and resp.get("status") == "rotated",
              f"got {code} {resp}")
        code, served_a2 = get(PORT_A, f"/api/v1/names/{LABEL}")
        check("A serves K2 locally after rotation",
              code == 200 and served_a2.get("node_pubkey") == k2_pub
              and served_a2.get("signature") == sig2,
              f"got {code} {served_a2}")

        out = run_helper(tmp_a, a_priv, "core._names_gossip_out()")
        check("A gossip K2 ran to 1 recipient", "sent: 1" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, served_b2 = wait_served(PORT_B, LABEL, sig2)
        check("B REPLACED live K1 with designated K2",
              code == 200 and served_b2.get("node_pubkey") == k2_pub
              and served_b2.get("issued_at") == issued2
              and served_b2.get("expires_at") == expires2,
              f"got {code} {served_b2}")
        code, rots_b = get(PORT_B, f"/api/v1/names/{LABEL}/rotations")
        hops_b = rots_b.get("rotations", []) if code == 200 else []
        check("B recorded the K1 -> K2 hop",
              code == 200 and len(hops_b) == 1
              and hops_b[0].get("old_pubkey") == k1_pub
              and hops_b[0].get("new_pubkey") == k2_pub,
              f"got {code} {rots_b}")
        code, served_cx = get(PORT_C, f"/api/v1/names/{LABEL}")
        check("C still serves K1 (rotation crossed one hop only)",
              code == 200 and served_cx.get("signature") == sig1,
              f"got {code} {served_cx}")
        code, served_dx = get(PORT_D, f"/api/v1/names/{LABEL}")
        check("D still serves K1 (rotation crossed one hop only)",
              code == 200 and served_dx.get("signature") == sig1,
              f"got {code} {served_dx}")

        bare = {"name": LABEL, "node_pubkey": k2_pub,
                "issued_at": issued2, "expires_at": expires2,
                "signature": sig2}
        res = ingest_on(tmp_d, d_priv, bare)
        check("proof-less K2 binding merge on D returns conflict",
              res.stdout.strip().endswith("conflict"),
              f"stdout={res.stdout!r} stderr={res.stderr[-400:]!r}")
        code, served_dx = get(PORT_D, f"/api/v1/names/{LABEL}")
        check("D still serves K1 after proof-less attempt",
              code == 200 and served_dx.get("signature") == sig1,
              f"got {code} {served_dx}")

        out = run_helper(tmp_b, b_priv, "core._names_gossip_out()")
        check("B gossip K2 onward ran to 2 recipients",
              "sent: 2" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, served_c2 = wait_served(PORT_C, LABEL, sig2)
        check("C REPLACED live K1 with K2 on B's recorded designation",
              code == 200 and served_c2.get("node_pubkey") == k2_pub
              and served_c2.get("issued_at") == issued2
              and served_c2.get("expires_at") == expires2,
              f"got {code} {served_c2}")
        code, served_dx = get(PORT_D, f"/api/v1/names/{LABEL}")
        check("D still serves K1 before C's leg runs",
              code == 200 and served_dx.get("signature") == sig1,
              f"got {code} {served_dx}")

        out = run_helper(tmp_c, c_priv, "core._names_gossip_out()")
        check("C gossip K2 onward ran to 2 recipients",
              "sent: 2" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, served_d2 = wait_served(PORT_D, LABEL, sig2)
        check("D REPLACED live K1 with K2 (rotation survived third hop)",
              code == 200 and served_d2.get("node_pubkey") == k2_pub
              and served_d2.get("issued_at") == issued2
              and served_d2.get("expires_at") == expires2,
              f"got {code} {served_d2}")
        check("belt re-verifies D's K2 binding against K2",
              verify(k2_pub, served_d2.get("signature", ""), LABEL,
                     issued2, expires2))
        code, rots_d = get(PORT_D, f"/api/v1/names/{LABEL}/rotations")
        hops_d = rots_d.get("rotations", []) if code == 200 else []
        check("D recorded the K1 -> K2 hop (proof can travel onward)",
              code == 200 and len(hops_d) == 1
              and hops_d[0].get("old_pubkey") == k1_pub
              and hops_d[0].get("new_pubkey") == k2_pub,
              f"got {code} {rots_d}")

        out = run_helper(tmp_c, c_priv, "core._names_gossip_out()")
        time.sleep(1)
        code, served_d3 = get(PORT_D, f"/api/v1/names/{LABEL}")
        check("re-gossip of K2 is idempotent (D still serves K2)",
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
