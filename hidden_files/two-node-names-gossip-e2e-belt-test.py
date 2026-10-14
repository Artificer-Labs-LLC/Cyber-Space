"""Belt: two-node name depth e2e (primitives 1 naming + 2 resolution).

The Depth Test shape in miniature, on loopback: two INDEPENDENT nodes
(separate DB dirs, separate node keys) boot as separate processes.

  1. node A claims a fresh kept-key name through the real
     POST /api/v1/names/claim route (the belt holds the name privkey)
  2. A serves it; B has never heard of it (404)
  3. A's REAL send half (core._names_gossip_out, run in a helper
     process loaded with A's DB dir + node privkey) gossips the
     binding to B's real /fed/names/gossip receive route
  4. B serves the binding from its OWN registry, byte-identical
  5. the belt re-verifies B's served binding signature itself
     against the kept name key -- B is trusted only after proof

The one test-only allowance: the helper patches
core._reject_nonpublic_node_url to admit B's loopback URL only
(twin of depth-chain-e2e-test.py) -- production's SSRF gate refuses
loopback peer URLs, by design. The genesis name is never touched.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/two-node-names-gossip-e2e-belt-test.py
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
PORT_A, PORT_B = 18791, 18792
URL_A = f"http://127.0.0.1:{PORT_A}"
URL_B = f"http://127.0.0.1:{PORT_B}"
LABEL = "twonodee2e"


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


def main():
    tmp_a = tempfile.mkdtemp(prefix="twonode-a-")
    tmp_b = tempfile.mkdtemp(prefix="twonode-b-")
    a_priv = secrets.token_hex(32)
    a_pub = publickey(bytes.fromhex(a_priv)).hex()
    b_priv = secrets.token_hex(32)
    b_pub = publickey(bytes.fromhex(b_priv)).hex()
    name_priv = bytes.fromhex(secrets.token_hex(32))
    name_pub = publickey(name_priv).hex()

    proc_a, up_a = boot(tmp_a, a_priv, PORT_A)
    proc_b, up_b = boot(tmp_b, b_priv, PORT_B)
    try:
        check("both independent nodes boot", up_a and up_b)
        if not (up_a and up_b):
            return
        check("nodes carry distinct identities", a_pub != b_pub)

        # Peer knowledge both ways: A must know where B lives (send
        # half selects on node_url); B must know A as a peer (receive
        # gate refuses strangers).
        seed_peer(tmp_a, b_pub, URL_B, "belt-node-b")
        seed_peer(tmp_b, a_pub, URL_A, "belt-node-a")

        now = datetime.now(timezone.utc)
        issued = ts(now - timedelta(minutes=1))
        expires = ts(now + timedelta(days=30))
        sig = sign(_name_claim_payload(LABEL, name_pub, issued, expires),
                   name_priv, bytes.fromhex(name_pub)).hex()
        body = urllib.parse.urlencode(
            {"name": LABEL, "node_pubkey": name_pub,
             "issued_at": issued, "expires_at": expires,
             "signature": sig}).encode()
        req = urllib.request.Request(
            URL_A + "/api/v1/names/claim", data=body, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                claim_code, claim = r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            claim_code, claim = e.code, {}
        check("A claims kept-key name via real route",
              claim_code == 200 and claim.get("node_pubkey") == name_pub,
              f"got {claim_code} {claim}")

        code, served_a = get(PORT_A, f"/api/v1/names/{LABEL}")
        check("A serves its own binding",
              code == 200 and served_a.get("node_pubkey") == name_pub,
              f"got {code} {served_a}")
        code, _ = get(PORT_B, f"/api/v1/names/{LABEL}")
        check("B has never heard of it before gossip", code == 404,
              f"got {code}")

        # A's real send half, in a helper process holding A's state.
        helper = (
            "import time, core\n"
            f"_real = core._reject_nonpublic_node_url\n"
            "def _gate(url):\n"
            f"    return None if url.startswith({URL_B!r}) else _real(url)\n"
            "core._reject_nonpublic_node_url = _gate\n"
            "n = core._names_gossip_out()\n"
            "print('recipients:', n)\n"
            "time.sleep(4)\n")
        env = dict(os.environ, CYBERNET_DB_DIR=tmp_a,
                   CYBERNET_NODE_PRIVKEY=a_priv)
        out = subprocess.run(
            [os.path.join(REPO, "venv/bin/python"), "-c", helper],
            cwd=REPO, env=env, capture_output=True, text=True,
            timeout=60)
        check("A gossip send half ran to 1 recipient",
              "recipients: 1" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")

        served_b = {}
        for _ in range(20):
            code, served_b = get(PORT_B, f"/api/v1/names/{LABEL}")
            if code == 200:
                break
            time.sleep(0.5)
        check("B serves the gossiped binding from its own registry",
              code == 200 and served_b.get("node_pubkey") == name_pub,
              f"got {code} {served_b}")
        check("B's copy is byte-identical to A's claim",
              served_b.get("signature") == sig
              and served_b.get("issued_at") == issued
              and served_b.get("expires_at") == expires,
              f"got {served_b}")
        try:
            verified = checkvalid(
                bytes.fromhex(served_b.get("signature", "")),
                _name_claim_payload(LABEL, name_pub, issued, expires),
                bytes.fromhex(name_pub))
        except Exception:
            verified = False
        check("belt re-verifies B's served binding against kept key",
              verified is True)
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
