"""Belt: two-node same-key renewal displacement e2e (primitives 1+4).

The legit-owner twin of two-node-name-theft-e2e: a different key can
never displace a live binding, but the SAME key re-signing fresher
must — otherwise a name could never be renewed across the federation.

Two INDEPENDENT nodes (separate DB dirs, separate node keys) boot
as separate processes on loopback. The belt holds name key K1.

  1. A claims a fresh name via the real POST /api/v1/names/claim (v1)
  2. A's REAL send half (core._names_gossip_out) gossips to B's real
     /fed/names/gossip receive route; B serves v1 byte-identical
  3. A renews via the real claim route: same K1, LATER issued_at,
     later expires_at (v2); A serves v2
  4. A gossips again; B must now serve v2 byte-identical (replaced,
     not kept) and the belt re-verifies v2 against K1
  5. Re-gossip of v2 is idempotent: B still serves v2
  6. Stale same-key v1 fed to B's real merge half
     (core.ingest_gossiped_binding in a helper loaded with B's DB
     dir) returns "kept" and B still serves v2 — renewal moves
     forward only

Test-only allowance: helpers patch core._reject_nonpublic_node_url
to admit the loopback peer URL only (twin of the theft belt) —
production's SSRF gate refuses loopback peer URLs, by design.
The genesis name is never touched.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/two-node-renewal-e2e-belt-test.py
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
PORT_A, PORT_B = 18811, 18812
URL_A = f"http://127.0.0.1:{PORT_A}"
URL_B = f"http://127.0.0.1:{PORT_B}"
LABEL = "twonoderenew"


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
    tmp_a = tempfile.mkdtemp(prefix="renew-a-")
    tmp_b = tempfile.mkdtemp(prefix="renew-b-")
    a_priv = secrets.token_hex(32)
    a_pub = publickey(bytes.fromhex(a_priv)).hex()
    b_priv = secrets.token_hex(32)
    b_pub = publickey(bytes.fromhex(b_priv)).hex()
    k1_priv = bytes.fromhex(secrets.token_hex(32))
    k1_pub = publickey(k1_priv).hex()

    proc_a, up_a = boot(tmp_a, a_priv, PORT_A)
    proc_b, up_b = boot(tmp_b, b_priv, PORT_B)
    try:
        check("two independent nodes boot", up_a and up_b)
        if not (up_a and up_b):
            return
        check("node keys and name key are distinct",
              len({a_pub, b_pub, k1_pub}) == 3)
        seed_peer(tmp_a, b_pub, URL_B, "belt-node-b")
        seed_peer(tmp_b, a_pub, URL_A, "belt-node-a")

        now = datetime.now(timezone.utc)
        code, claim1, sig1, issued1, expires1 = claim(
            PORT_A, LABEL, k1_priv, k1_pub,
            now - timedelta(minutes=3), now + timedelta(days=30))
        check("A claims kept-key name v1 via real route",
              code == 200 and claim1.get("node_pubkey") == k1_pub,
              f"got {code} {claim1}")

        out = gossip_out(tmp_a, a_priv, URL_B)
        check("A gossip v1 ran to 1 recipient",
              "recipients: 1" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, served_b1 = wait_served(PORT_B, LABEL, sig1)
        check("B serves v1 byte-identical before renewal",
              code == 200 and served_b1.get("issued_at") == issued1
              and served_b1.get("expires_at") == expires1,
              f"got {code} {served_b1}")

        # Renewal: SAME key, later issued, later expiry.
        code, claim2, sig2, issued2, expires2 = claim(
            PORT_A, LABEL, k1_priv, k1_pub,
            now - timedelta(minutes=1), now + timedelta(days=60))
        check("A renews same-key v2 via real route (fresher wins locally)",
              code == 200 and claim2.get("signature") == sig2
              and sig2 != sig1,
              f"got {code} {claim2}")
        code, served_a2 = get(PORT_A, f"/api/v1/names/{LABEL}")
        check("A serves v2 locally",
              code == 200 and served_a2.get("signature") == sig2,
              f"got {code} {served_a2}")

        out = gossip_out(tmp_a, a_priv, URL_B)
        check("A gossip v2 ran to 1 recipient",
              "recipients: 1" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, served_b2 = wait_served(PORT_B, LABEL, sig2)
        check("B REPLACED v1 with v2 after renewal gossip",
              code == 200 and served_b2.get("node_pubkey") == k1_pub
              and served_b2.get("issued_at") == issued2
              and served_b2.get("expires_at") == expires2,
              f"got {code} {served_b2}")
        check("belt re-verifies B's v2 binding against K1",
              verify(k1_pub, served_b2.get("signature", ""), LABEL,
                     issued2, expires2))

        out = gossip_out(tmp_a, a_priv, URL_B)
        time.sleep(1)
        code, served_b3 = get(PORT_B, f"/api/v1/names/{LABEL}")
        check("re-gossip of v2 is idempotent (B still serves v2)",
              "recipients: 1" in out.stdout and code == 200
              and served_b3.get("signature") == sig2,
              f"got {code} {served_b3} out={out.stdout!r}")

        v1 = {"name": LABEL, "node_pubkey": k1_pub,
              "issued_at": issued1, "expires_at": expires1,
              "signature": sig1}
        res = ingest_on(tmp_b, b_priv, v1)
        check("stale same-key v1 merge on B returns kept",
              res.stdout.strip().endswith("kept"),
              f"stdout={res.stdout!r} stderr={res.stderr[-400:]!r}")
        code, served_b4 = get(PORT_B, f"/api/v1/names/{LABEL}")
        check("B still serves v2 after stale v1 merge attempt",
              code == 200 and served_b4.get("signature") == sig2,
              f"got {code} {served_b4}")
    finally:
        for p in (proc_a, proc_b):
            p.terminate()
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()

    print(f"\n{CASES['passed']} passed, {CASES['failed']} failed")
    sys.exit(1 if CASES["failed"] else 0)


if __name__ == "__main__":
    main()
