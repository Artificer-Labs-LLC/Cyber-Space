"""Belt: two-node name-theft resistance e2e (primitives 1 naming + 4 identity).

The hostile twin of two-node-names-gossip-e2e: gossip convergence is
only worth having if a carrier can repeat a binding but never plant
or displace one. Three INDEPENDENT nodes (separate DB dirs, separate
node keys) boot as separate processes on loopback.

  1. node A claims a fresh kept-key name through the real
     POST /api/v1/names/claim route (the belt holds name key K1)
  2. A's REAL send half (core._names_gossip_out, helper process)
     gossips the binding to B's real /fed/names/gossip receive route;
     B serves A's binding from its own registry
  3. attacker node C claims the SAME label under its own name key K2
     through its own real claim route (a perfectly valid, self-signed,
     fresher binding -- on C) and serves it locally
  4. C's REAL send half gossips C's registry to B
  5. B must STILL serve A's K1 binding, byte-identical: a live
     foreign incumbent is never displaced by a different key, however
     fresh or well-signed the challenger is

The one test-only allowance: the helpers patch
core._reject_nonpublic_node_url to admit the loopback peer URL only
(twin of two-node-names-gossip-e2e) -- production's SSRF gate refuses
loopback peer URLs, by design. The genesis name is never touched.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/two-node-name-theft-e2e-belt-test.py
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
PORT_A, PORT_B, PORT_C = 18801, 18802, 18803
URL_A = f"http://127.0.0.1:{PORT_A}"
URL_B = f"http://127.0.0.1:{PORT_B}"
URL_C = f"http://127.0.0.1:{PORT_C}"
LABEL = "twonodetheft"


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


def wait_served(port, label, pub):
    served = {}
    for _ in range(20):
        code, served = get(port, f"/api/v1/names/{label}")
        if code == 200 and served.get("node_pubkey") == pub:
            return code, served
        time.sleep(0.5)
    return code, served


def main():
    tmp_a = tempfile.mkdtemp(prefix="theft-a-")
    tmp_b = tempfile.mkdtemp(prefix="theft-b-")
    tmp_c = tempfile.mkdtemp(prefix="theft-c-")
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
        check("nodes and name keys are all distinct",
              len({a_pub, b_pub, c_pub, k1_pub, k2_pub}) == 5)

        # Peer knowledge: A->B (legit gossip), C->B (attack gossip);
        # B must know both senders (receive gate refuses strangers --
        # the attacker is a KNOWN peer, the hard case).
        seed_peer(tmp_a, b_pub, URL_B, "belt-node-b")
        seed_peer(tmp_b, a_pub, URL_A, "belt-node-a")
        seed_peer(tmp_b, c_pub, URL_C, "belt-node-c")
        seed_peer(tmp_c, b_pub, URL_B, "belt-node-b")

        now = datetime.now(timezone.utc)
        code, claim_a, sig_a, issued_a, expires_a = claim(
            PORT_A, LABEL, k1_priv, k1_pub,
            now - timedelta(minutes=2), now + timedelta(days=30))
        check("A claims kept-key name via real route",
              code == 200 and claim_a.get("node_pubkey") == k1_pub,
              f"got {code} {claim_a}")

        out = gossip_out(tmp_a, a_priv, URL_B)
        check("A gossip send half ran to 1 recipient",
              "recipients: 1" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, served_b = wait_served(PORT_B, LABEL, k1_pub)
        check("B serves A's binding before the attack",
              code == 200 and served_b.get("signature") == sig_a,
              f"got {code} {served_b}")

        # The attack: C claims the same label under K2 -- valid,
        # self-signed, and FRESHER than A's binding.
        code, claim_c, sig_c, _, _ = claim(
            PORT_C, LABEL, k2_priv, k2_pub,
            now - timedelta(minutes=1), now + timedelta(days=30))
        check("C claims the same label under its own key on C",
              code == 200 and claim_c.get("node_pubkey") == k2_pub,
              f"got {code} {claim_c}")
        code, served_c = get(PORT_C, f"/api/v1/names/{LABEL}")
        check("C serves the challenger binding locally (attack is real)",
              code == 200 and served_c.get("node_pubkey") == k2_pub
              and served_c.get("signature") == sig_c,
              f"got {code} {served_c}")

        out = gossip_out(tmp_c, c_priv, URL_B)
        check("C gossip send half ran to 1 recipient",
              "recipients: 1" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        time.sleep(2)

        code, served_b2 = get(PORT_B, f"/api/v1/names/{LABEL}")
        check("B STILL serves A's K1 binding after hostile gossip",
              code == 200 and served_b2.get("node_pubkey") == k1_pub,
              f"got {code} {served_b2}")
        check("B's copy is still byte-identical to A's claim",
              served_b2.get("signature") == sig_a
              and served_b2.get("issued_at") == issued_a
              and served_b2.get("expires_at") == expires_a,
              f"got {served_b2}")
        try:
            verified = checkvalid(
                bytes.fromhex(served_b2.get("signature", "")),
                _name_claim_payload(LABEL, k1_pub, issued_a, expires_a),
                bytes.fromhex(k1_pub))
        except Exception:
            verified = False
        check("belt re-verifies B's surviving binding against K1",
              verified is True)
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
