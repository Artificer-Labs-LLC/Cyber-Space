"""Belt: two-node rotation displacement e2e (primitives 1+4).

The fourth panel of the displacement series: a different key can
never displace a LIVE binding (name-theft belt), the same key
re-signing fresher always can (renewal belt), an expired incumbent
yields to anyone (expiry belt) — and a different key DESIGNATED by
the incumbent's own signed rotation record displaces a live
incumbent immediately. That is the only legitimate key change.

Before this belt the panel was hollow: the designation helpers
(_gossiped_rotation_designates / _gossiped_rotation_chain_designates)
were belted in isolation but had NO caller — the merge half never
consulted them and the gossip-out half never attached the chain, so
a rotated name could never federate past a mirror holding the live
old binding. This belt proves the wiring end to end:

Two INDEPENDENT nodes (separate DB dirs, separate node keys) boot
as separate processes on loopback. The belt holds name keys K1
(original owner) and K2 (designated successor).

  1. A claims the label under K1 via the real claim route; A's
     real _names_gossip_out federates it to B; B serves K1
  2. Negative control: K2's rotated binding fed to B's real merge
     half WITHOUT any rotation proof returns "conflict"; B still
     serves K1 (the designation gate did not become a squat vector)
  3. A rotates via the real /api/v1/names/rotate route (record
     minted by rotate_name.mint_rotation, signed by K1; new
     binding signed by K2); A serves K2 and holds the hop in its
     name_rotations table
  4. A's real _names_gossip_out runs again — the payload now
     carries rotation_chain; B REPLACES K1 with K2 and serves it
     byte-identical; the belt re-verifies it against K2
  5. B's real /api/v1/names/{label}/rotations serves the hop —
     B recorded the designation, so the proof can travel onward
  6. Re-gossip is idempotent (B still serves K2)

Test-only allowance: helpers patch core._reject_nonpublic_node_url
to admit the loopback peer URL only (twin of the theft/renewal
belts) — production's SSRF gate refuses loopback peer URLs, by
design. The genesis name is never touched.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/two-node-rotation-e2e-belt-test.py
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
PORT_A, PORT_B = 18831, 18832
URL_A = f"http://127.0.0.1:{PORT_A}"
URL_B = f"http://127.0.0.1:{PORT_B}"
LABEL = "twonoderotate"


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


def rotate(port, label, k1_priv, k1_pub, k2_priv, k2_pub,
           rot_dt, bind_dt, bind_exp_dt):
    rec = mint_rotation(label, k1_priv, k2_pub, issued_at=ts(rot_dt))
    b_issued, b_expires = ts(bind_dt), ts(bind_exp_dt)
    b_sig = sign(_name_claim_payload(label, k2_pub, b_issued, b_expires),
                 k2_priv, bytes.fromhex(k2_pub)).hex()
    body = urllib.parse.urlencode(
        {"name": label, "old_pubkey": k1_pub, "new_pubkey": k2_pub,
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
    tmp_a = tempfile.mkdtemp(prefix="rotate-a-")
    tmp_b = tempfile.mkdtemp(prefix="rotate-b-")
    a_priv = secrets.token_hex(32)
    a_pub = publickey(bytes.fromhex(a_priv)).hex()
    b_priv = secrets.token_hex(32)
    b_pub = publickey(bytes.fromhex(b_priv)).hex()
    k1_priv = bytes.fromhex(secrets.token_hex(32))
    k1_pub = publickey(k1_priv).hex()
    k2_priv = bytes.fromhex(secrets.token_hex(32))
    k2_pub = publickey(k2_priv).hex()

    proc_a, up_a = boot(tmp_a, a_priv, PORT_A)
    proc_b, up_b = boot(tmp_b, b_priv, PORT_B)
    try:
        check("two independent nodes boot", up_a and up_b)
        if not (up_a and up_b):
            return
        check("node keys and both name keys are distinct",
              len({a_pub, b_pub, k1_pub, k2_pub}) == 4)
        seed_peer(tmp_a, b_pub, URL_B, "belt-node-b")
        seed_peer(tmp_b, a_pub, URL_A, "belt-node-a")

        now = datetime.now(timezone.utc)
        code, claim1, sig1, issued1, expires1 = claim(
            PORT_A, LABEL, k1_priv, k1_pub,
            now - timedelta(minutes=5), now + timedelta(days=30))
        check("A claims kept-key name under K1 via real route",
              code == 200 and claim1.get("node_pubkey") == k1_pub,
              f"got {code} {claim1}")

        out = gossip_out(tmp_a, a_priv, URL_B)
        check("A gossip K1 ran to 1 recipient",
              "recipients: 1" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, served_b1 = wait_served(PORT_B, LABEL, sig1)
        check("B serves K1 byte-identical before rotation",
              code == 200 and served_b1.get("node_pubkey") == k1_pub,
              f"got {code} {served_b1}")

        # The rotated binding, built exactly as the rotate route will
        # accept it — but first fed to B with NO proof attached.
        rot_dt = now - timedelta(minutes=2)
        bind_dt = now - timedelta(minutes=1)
        code, resp, rec, b_sig, b_issued, b_expires = rotate(
            PORT_A, LABEL, k1_priv, k1_pub, k2_priv, k2_pub,
            rot_dt, bind_dt, now + timedelta(days=60))
        check("A rotates K1 -> K2 via real rotate route",
              code == 200 and resp.get("status") == "rotated",
              f"got {code} {resp}")
        code, served_a2 = get(PORT_A, f"/api/v1/names/{LABEL}")
        check("A serves K2 locally after rotation",
              code == 200 and served_a2.get("node_pubkey") == k2_pub
              and served_a2.get("signature") == b_sig,
              f"got {code} {served_a2}")

        bare = {"name": LABEL, "node_pubkey": k2_pub,
                "issued_at": b_issued, "expires_at": b_expires,
                "signature": b_sig}
        res = ingest_on(tmp_b, b_priv, bare)
        check("proof-less K2 binding merge on B returns conflict",
              res.stdout.strip().endswith("conflict"),
              f"stdout={res.stdout!r} stderr={res.stderr[-400:]!r}")
        code, served_bx = get(PORT_B, f"/api/v1/names/{LABEL}")
        check("B still serves K1 after proof-less attempt",
              code == 200 and served_bx.get("signature") == sig1,
              f"got {code} {served_bx}")

        out = gossip_out(tmp_a, a_priv, URL_B)
        check("A gossip K2 (with rotation chain) ran to 1 recipient",
              "recipients: 1" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, served_b2 = wait_served(PORT_B, LABEL, b_sig)
        check("B REPLACED live K1 with designated K2 after gossip",
              code == 200 and served_b2.get("node_pubkey") == k2_pub
              and served_b2.get("issued_at") == b_issued
              and served_b2.get("expires_at") == b_expires,
              f"got {code} {served_b2}")
        check("belt re-verifies B's K2 binding against K2",
              verify(k2_pub, served_b2.get("signature", ""), LABEL,
                     b_issued, b_expires))

        code, rots_b = get(PORT_B, f"/api/v1/names/{LABEL}/rotations")
        hops = rots_b.get("rotations", []) if code == 200 else []
        check("B recorded the designation hop (proof can travel onward)",
              code == 200 and len(hops) == 1
              and hops[0].get("old_pubkey") == k1_pub
              and hops[0].get("new_pubkey") == k2_pub,
              f"got {code} {rots_b}")

        out = gossip_out(tmp_a, a_priv, URL_B)
        time.sleep(1)
        code, served_b3 = get(PORT_B, f"/api/v1/names/{LABEL}")
        check("re-gossip after rotation is idempotent (B still serves K2)",
              "recipients: 1" in out.stdout and code == 200
              and served_b3.get("signature") == b_sig,
              f"got {code} {served_b3} out={out.stdout!r}")
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
