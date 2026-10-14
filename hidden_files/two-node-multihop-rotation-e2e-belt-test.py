"""Belt: multi-hop rotation chain e2e (primitives 1 naming + 4 identity).

The fifth panel of the displacement series. A name rotates TWICE
(K1 -> K2 -> K3) and the designation chain must carry mirrors at
EVERY distance:

  - a mirror one hop behind (holds K2, chain head is K1) must yield
    to K3 on the suffix designation K2 -> K3;
  - a mirror two hops behind (still holds K1) that never saw K2 as
    its incumbent must skip straight to K3 on the full chain;
  - a proof-less K3 binding still returns conflict everywhere.

Three INDEPENDENT nodes (separate DB dirs, separate node keys) boot
as separate processes on loopback. The belt holds name keys K1, K2,
K3 (original owner, first successor, second successor).

  1. A claims the label under K1 via the real claim route; A's real
     _names_gossip_out federates it to B; B's real _names_gossip_out
     federates it onward to C; B and C both serve K1
  2. A rotates K1 -> K2 via the real rotate route; gossip A -> B;
     B replaces live K1 with K2 and records hop 1
  3. A rotates K2 -> K3 via the real rotate route; A serves K3;
     gossip A -> B; B (mid-chain: holds K2 while the attached chain
     starts at K1) REPLACES K2 with K3 and records both hops
  4. Negative control: the bare K3 binding fed to C's real merge
     half with NO proof returns "conflict"; C still serves K1
  5. B's real _names_gossip_out runs — B's payload carries the
     two-hop chain from B's OWN name_rotations table (B never held
     K1's or K2's private key; the proof is the recorded lineage);
     C REPLACES live K1 directly with K3, byte-identical, and C's
     /rotations serves both hops
  6. Re-gossip B -> C is idempotent (C still serves K3)

Test-only allowance: helpers patch core._reject_nonpublic_node_url
to admit loopback peer URLs only (twin of the rotation belt) —
production's SSRF gate refuses loopback peer URLs, by design. The
genesis name is never touched.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/two-node-multihop-rotation-e2e-belt-test.py
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
PORT_A, PORT_B, PORT_C = 18841, 18842, 18843
URL_A = f"http://127.0.0.1:{PORT_A}"
URL_B = f"http://127.0.0.1:{PORT_B}"
URL_C = f"http://127.0.0.1:{PORT_C}"
LABEL = "twonodemultihop"


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


def gossip_out(tmp, priv, peer_url, expect_recipients):
    helper = (
        "import time, core\n"
        "_real = core._reject_nonpublic_node_url\n"
        "def _gate(url):\n"
        f"    return None if url.startswith('http://127.0.0.1:') else _real(url)\n"
        "core._reject_nonpublic_node_url = _gate\n"
        "n = core._names_gossip_out()\n"
        "print('recipients:', n)\n"
        "time.sleep(4)\n")
    env = dict(os.environ, CYBERNET_DB_DIR=tmp,
               CYBERNET_NODE_PRIVKEY=priv)
    out = subprocess.run(
        [os.path.join(REPO, "venv/bin/python"), "-c", helper],
        cwd=REPO, env=env, capture_output=True, text=True, timeout=60)
    return out, f"recipients: {expect_recipients}" in out.stdout


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
    tmp_a = tempfile.mkdtemp(prefix="multihop-a-")
    tmp_b = tempfile.mkdtemp(prefix="multihop-b-")
    tmp_c = tempfile.mkdtemp(prefix="multihop-c-")
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
    k3_priv = bytes.fromhex(secrets.token_hex(32))
    k3_pub = publickey(k3_priv).hex()

    proc_a, up_a = boot(tmp_a, a_priv, PORT_A)
    proc_b, up_b = boot(tmp_b, b_priv, PORT_B)
    proc_c, up_c = boot(tmp_c, c_priv, PORT_C)
    try:
        check("three independent nodes boot", up_a and up_b and up_c)
        if not (up_a and up_b and up_c):
            return
        check("node keys and all three name keys are distinct",
              len({a_pub, b_pub, c_pub, k1_pub, k2_pub, k3_pub}) == 6)
        # A talks only to B (so C can only learn rotations onward
        # from B); B talks to A and C; C knows both as peers.
        seed_peer(tmp_a, b_pub, URL_B, "belt-node-b")
        seed_peer(tmp_b, a_pub, URL_A, "belt-node-a")
        seed_peer(tmp_b, c_pub, URL_C, "belt-node-c")
        seed_peer(tmp_c, a_pub, URL_A, "belt-node-a")
        seed_peer(tmp_c, b_pub, URL_B, "belt-node-b")

        now = datetime.now(timezone.utc)
        code, claim1, sig1, issued1, expires1 = claim(
            PORT_A, LABEL, k1_priv, k1_pub,
            now - timedelta(minutes=10), now + timedelta(days=30))
        check("A claims kept-key name under K1 via real route",
              code == 200 and claim1.get("node_pubkey") == k1_pub,
              f"got {code} {claim1}")

        out, ok_n = gossip_out(tmp_a, a_priv, URL_B, 1)
        check("A gossip K1 ran to 1 recipient", ok_n,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, served_b1 = wait_served(PORT_B, LABEL, sig1)
        check("B serves K1 byte-identical",
              code == 200 and served_b1.get("node_pubkey") == k1_pub,
              f"got {code} {served_b1}")
        out, ok_n = gossip_out(tmp_b, b_priv, URL_C, 2)
        check("B gossip K1 onward ran to 2 recipients", ok_n,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, served_c1 = wait_served(PORT_C, LABEL, sig1)
        check("C serves K1 byte-identical (learned via B)",
              code == 200 and served_c1.get("node_pubkey") == k1_pub,
              f"got {code} {served_c1}")

        code, resp, rec1, sig2, issued2, expires2 = rotate(
            PORT_A, LABEL, k1_priv, k1_pub, k2_priv, k2_pub,
            now - timedelta(minutes=6), now - timedelta(minutes=5),
            now + timedelta(days=60))
        check("A rotates K1 -> K2 via real rotate route",
              code == 200 and resp.get("status") == "rotated",
              f"got {code} {resp}")
        out, ok_n = gossip_out(tmp_a, a_priv, URL_B, 1)
        check("A gossip K2 ran to 1 recipient", ok_n,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, served_b2 = wait_served(PORT_B, LABEL, sig2)
        check("B REPLACED live K1 with designated K2",
              code == 200 and served_b2.get("node_pubkey") == k2_pub,
              f"got {code} {served_b2}")
        code, served_cx = get(PORT_C, f"/api/v1/names/{LABEL}")
        check("C still serves K1 (A never gossips to C directly)",
              code == 200 and served_cx.get("signature") == sig1,
              f"got {code} {served_cx}")

        code, resp, rec2, sig3, issued3, expires3 = rotate(
            PORT_A, LABEL, k2_priv, k2_pub, k3_priv, k3_pub,
            now - timedelta(minutes=3), now - timedelta(minutes=2),
            now + timedelta(days=90))
        check("A rotates K2 -> K3 via real rotate route",
              code == 200 and resp.get("status") == "rotated",
              f"got {code} {resp}")
        code, served_a3 = get(PORT_A, f"/api/v1/names/{LABEL}")
        check("A serves K3 locally after second rotation",
              code == 200 and served_a3.get("node_pubkey") == k3_pub
              and served_a3.get("signature") == sig3,
              f"got {code} {served_a3}")

        out, ok_n = gossip_out(tmp_a, a_priv, URL_B, 1)
        check("A gossip K3 (two-hop chain) ran to 1 recipient", ok_n,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, served_b3 = wait_served(PORT_B, LABEL, sig3)
        check("B (mid-chain, held K2) REPLACED K2 with K3 on suffix designation",
              code == 200 and served_b3.get("node_pubkey") == k3_pub
              and served_b3.get("issued_at") == issued3
              and served_b3.get("expires_at") == expires3,
              f"got {code} {served_b3}")
        check("belt re-verifies B's K3 binding against K3",
              verify(k3_pub, served_b3.get("signature", ""), LABEL,
                     issued3, expires3))
        code, rots_b = get(PORT_B, f"/api/v1/names/{LABEL}/rotations")
        hops_b = rots_b.get("rotations", []) if code == 200 else []
        check("B recorded both hops (lineage complete on the mirror)",
              code == 200 and len(hops_b) == 2
              and hops_b[0].get("old_pubkey") == k1_pub
              and hops_b[0].get("new_pubkey") == k2_pub
              and hops_b[1].get("old_pubkey") == k2_pub
              and hops_b[1].get("new_pubkey") == k3_pub,
              f"got {code} {rots_b}")

        bare = {"name": LABEL, "node_pubkey": k3_pub,
                "issued_at": issued3, "expires_at": expires3,
                "signature": sig3}
        res = ingest_on(tmp_c, c_priv, bare)
        check("proof-less K3 binding merge on C returns conflict",
              res.stdout.strip().endswith("conflict"),
              f"stdout={res.stdout!r} stderr={res.stderr[-400:]!r}")
        code, served_cx = get(PORT_C, f"/api/v1/names/{LABEL}")
        check("C still serves K1 after proof-less attempt",
              code == 200 and served_cx.get("signature") == sig1,
              f"got {code} {served_cx}")

        out, ok_n = gossip_out(tmp_b, b_priv, URL_C, 2)
        check("B gossip K3 onward (chain from B's own table) ran to 2 recipients",
              ok_n, f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, served_c3 = wait_served(PORT_C, LABEL, sig3)
        check("C REPLACED live K1 directly with K3 via the two-hop chain",
              code == 200 and served_c3.get("node_pubkey") == k3_pub
              and served_c3.get("issued_at") == issued3
              and served_c3.get("expires_at") == expires3,
              f"got {code} {served_c3}")
        check("belt re-verifies C's K3 binding against K3",
              verify(k3_pub, served_c3.get("signature", ""), LABEL,
                     issued3, expires3))
        code, rots_c = get(PORT_C, f"/api/v1/names/{LABEL}/rotations")
        hops_c = rots_c.get("rotations", []) if code == 200 else []
        check("C recorded both hops (proof can travel onward again)",
              code == 200 and len(hops_c) == 2
              and hops_c[0].get("old_pubkey") == k1_pub
              and hops_c[0].get("new_pubkey") == k2_pub
              and hops_c[1].get("old_pubkey") == k2_pub
              and hops_c[1].get("new_pubkey") == k3_pub,
              f"got {code} {rots_c}")

        out, ok_n = gossip_out(tmp_b, b_priv, URL_C, 2)
        time.sleep(1)
        code, served_c4 = get(PORT_C, f"/api/v1/names/{LABEL}")
        check("re-gossip after multi-hop is idempotent (C still serves K3)",
              ok_n and code == 200
              and served_c4.get("signature") == sig3,
              f"got {code} {served_c4} out={out.stdout!r}")
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
