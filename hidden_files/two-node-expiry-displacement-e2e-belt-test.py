"""Belt: two-node expiry displacement e2e (primitives 1+4).

The third panel of the displacement triptych: a different key can
never displace a LIVE binding (name-theft belt), the same key
re-signing fresher always can (renewal belt) — and an EXPIRED
incumbent yields to a different key. Expiry is the only garbage
collection in the registry; if a dead row kept its seat forever,
every lapsed name would be squatted by its own corpse.

Three INDEPENDENT nodes (separate DB dirs, separate node keys)
boot as separate processes on loopback. The belt holds name
keys K1 (first owner) and K2 (successor).

  1. A claims the label under K1 via the real claim route with a
     SHORT life (~110s); A's real _names_gossip_out federates it
     to B; B serves K1 byte-identical
  2. C claims the SAME label under K2 via its real claim route
     (valid, self-signed, long-lived) and gossips to B while K1
     is still live; B keeps K1 byte-identical (live incumbent)
  3. The belt waits until K1's expires_at passes
  4. K2's binding fed to B's real merge half
     (core.ingest_gossiped_binding loaded with B's DB dir)
     returns "replaced"; B now serves K2 byte-identical and the
     belt re-verifies it against K2
  5. C gossips again through the real send/receive halves; B
     still serves K2 (idempotent after displacement)

Test-only allowance: helpers patch core._reject_nonpublic_node_url
to admit the loopback peer URL only (twin of the theft/renewal
belts) — production's SSRF gate refuses loopback peer URLs, by
design. The genesis name is never touched.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/two-node-expiry-displacement-e2e-belt-test.py
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
PORT_A, PORT_B, PORT_C = 18821, 18822, 18823
URL_A = f"http://127.0.0.1:{PORT_A}"
URL_B = f"http://127.0.0.1:{PORT_B}"
URL_C = f"http://127.0.0.1:{PORT_C}"
LABEL = "twonodeexpiry"


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
            return r.status, json.loads(r.read()), sig, issued, expires
    except urllib.error.HTTPError as e:
        return e.code, {}, sig, issued, expires


def gossip_out(tmp, priv, peer_url):
    helper = (
        "import time, core\n"
        "_real = core._reject_nonpublic_node_url\n"
        "def _gate(url):\n"
        f"    return None if url.startswith({peer_url!r}) else _real(url)\n"
        "core._reject_nonpublic_node_url = _gate\n"
        "n = core._names_gossip_out()\n"
        "print('recipients:', n)\n"
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


def wait_served(port, label, sig):
    served = {}
    code = 0
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
    tmp_a = tempfile.mkdtemp(prefix="expiry-a-")
    tmp_b = tempfile.mkdtemp(prefix="expiry-b-")
    tmp_c = tempfile.mkdtemp(prefix="expiry-c-")
    a_priv = secrets.token_hex(32)
    a_pub = publickey(bytes.fromhex(a_priv)).hex()
    b_priv = secrets.token_hex(32)
    b_pub = publickey(bytes.fromhex(b_priv)).hex()
    c_priv = secrets.token_hex(32)
    c_pub = publickey(bytes.fromhex(c_priv)).hex()
    k1_priv = bytes.fromhex(secrets.token_hex(32))
    k1_pub = publickey(k1_priv).hex()
    k2_priv = bytes.fromhex(secrets.token_hex(32))
    k2_pub = publickey(k2_priv).hex()

    proc_a, up_a = boot(tmp_a, a_priv, PORT_A)
    proc_b, up_b = boot(tmp_b, b_priv, PORT_B)
    proc_c, up_c = boot(tmp_c, c_priv, PORT_C)
    try:
        check("three independent nodes boot", up_a and up_b and up_c)
        if not (up_a and up_b and up_c):
            return
        check("node keys and name keys are distinct",
              len({a_pub, b_pub, c_pub, k1_pub, k2_pub}) == 5)
        seed_peer(tmp_a, b_pub, URL_B, "belt-node-b")
        seed_peer(tmp_c, b_pub, URL_B, "belt-node-b")
        # The receive route only accepts gossip from known, unretired
        # peers (federation.fed_names_gossip) — B must know A and C.
        seed_peer(tmp_b, a_pub, URL_A, "belt-node-a")
        seed_peer(tmp_b, c_pub, URL_C, "belt-node-c")

        now = datetime.now(timezone.utc)
        expires1_dt = now + timedelta(seconds=110)
        code, claim1, sig1, issued1, expires1 = claim(
            PORT_A, LABEL, k1_priv, k1_pub,
            now - timedelta(seconds=10), expires1_dt)
        check("A claims kept-key name under K1 (short life) via real route",
              code == 200 and claim1.get("node_pubkey") == k1_pub,
              f"got {code} {claim1}")

        out = gossip_out(tmp_a, a_priv, URL_B)
        check("A gossip ran to 1 recipient",
              "recipients: 1" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, served_b1 = wait_served(PORT_B, LABEL, sig1)
        check("B serves K1 byte-identical while live",
              code == 200 and served_b1.get("node_pubkey") == k1_pub
              and served_b1.get("expires_at") == expires1,
              f"got {code} {served_b1}")

        code, claim2, sig2, issued2, expires2 = claim(
            PORT_C, LABEL, k2_priv, k2_pub,
            datetime.now(timezone.utc) - timedelta(seconds=5),
            datetime.now(timezone.utc) + timedelta(days=30))
        check("C claims same label under K2 via real route",
              code == 200 and claim2.get("node_pubkey") == k2_pub,
              f"got {code} {claim2}")

        out = gossip_out(tmp_c, c_priv, URL_B)
        check("C gossip (pre-expiry) ran to 1 recipient",
              "recipients: 1" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        time.sleep(1)
        code, served_b2 = get(PORT_B, f"/api/v1/names/{LABEL}")
        check("B keeps live K1 against K2 challenger (no early handover)",
              code == 200 and served_b2.get("signature") == sig1,
              f"got {code} {served_b2}")

        # Wait for K1's expiry to pass (chronological, belt clock).
        deadline = expires1_dt + timedelta(seconds=3)
        while datetime.now(timezone.utc) < deadline:
            time.sleep(2)
        check("K1 expiry has passed on the belt clock",
              datetime.now(timezone.utc) > expires1_dt)

        k2_binding = {"name": LABEL, "node_pubkey": k2_pub,
                      "issued_at": issued2, "expires_at": expires2,
                      "signature": sig2}
        res = ingest_on(tmp_b, b_priv, k2_binding)
        check("B merge of K2 against EXPIRED K1 returns replaced",
              res.stdout.strip().endswith("replaced"),
              f"stdout={res.stdout!r} stderr={res.stderr[-400:]!r}")
        code, served_b3 = get(PORT_B, f"/api/v1/names/{LABEL}")
        check("B now serves K2 byte-identical after expiry",
              code == 200 and served_b3.get("node_pubkey") == k2_pub
              and served_b3.get("issued_at") == issued2
              and served_b3.get("expires_at") == expires2
              and served_b3.get("signature") == sig2,
              f"got {code} {served_b3}")
        check("belt re-verifies B's K2 binding against K2",
              verify(k2_pub, served_b3.get("signature", ""), LABEL,
                     issued2, expires2))

        out = gossip_out(tmp_c, c_priv, URL_B)
        check("C gossip (post-expiry) ran to 1 recipient",
              "recipients: 1" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        time.sleep(1)
        code, served_b4 = get(PORT_B, f"/api/v1/names/{LABEL}")
        check("re-gossip after displacement is idempotent (B still K2)",
              code == 200 and served_b4.get("signature") == sig2,
              f"got {code} {served_b4}")
    finally:
        for p in (proc_a, proc_b, proc_c):
            p.terminate()
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()

    print(f"\n{CASES['passed']} passed, {CASES['failed']} failed")
    sys.exit(1 if CASES["failed"] else 0)


if __name__ == "__main__":
    main()
