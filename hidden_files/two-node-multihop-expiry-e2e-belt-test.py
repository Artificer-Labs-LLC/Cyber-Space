"""Belt: multi-hop expiry + displacement e2e (primitives 1 naming + 4 identity).

The expiry twin of two-node-multihop-renewal-e2e. Every expiry panel
so far was single-hop (A -> B). Expiry must also hold two hops away:
a mirror that learned a short-lived binding only onward through an
intermediary must go silent when the binding's own clock runs out,
a stale copy of the dead binding must not resurrect it at any hop,
and a post-expiry claim by a NEW key must displace the silence all
the way down the chain.

Three INDEPENDENT nodes (separate DB dirs, separate node keys) boot
as separate processes on loopback. The belt holds name keys K1, K2.

  1. A claims the label under K1 via the real claim route with a
     short (~80s) life; A gossips to B; B gossips onward to C;
     B and C serve the K1 binding byte-identical
  2. The belt waits until the binding's expires_at passes (real
     clock); B and C both serve silence (404) for the label
  3. Negative control: stale K1 binding fed to C's real merge half
     (core.ingest_gossiped_binding) does not resurrect it; a fresh
     B -> C gossip run (B serves 404 itself) restores nothing
  4. A claims the same label under K2 via the real claim route
     (post-expiry displacement); gossip A -> B serves K2; gossip
     B -> C REPLACES the silence with K2 byte-identical, and the
     belt re-verifies the K2 binding at both hops
  5. Re-gossip B -> C is idempotent; an unclaimed label is
     silence (404) on C

Test-only allowance: helpers patch core._reject_nonpublic_node_url
to admit loopback peer URLs only (twin of the multihop renewal
belt) — production's SSRF gate refuses loopback peer URLs, by
design. The genesis name is never touched.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/two-node-multihop-expiry-e2e-belt-test.py
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
PORT_A, PORT_B, PORT_C = 18961, 18962, 18963
URL_A = f"http://127.0.0.1:{PORT_A}"
URL_B = f"http://127.0.0.1:{PORT_B}"
URL_C = f"http://127.0.0.1:{PORT_C}"
LABEL = "twonodemultihopexpiry"


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


def gossip_out(tmp, priv, expect_recipients):
    helper = (
        "import time, core\n"
        "_real = core._reject_nonpublic_node_url\n"
        "def _gate(url):\n"
        "    return None if url.startswith('http://127.0.0.1:') else _real(url)\n"
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


def wait_silence(port, label, deadline_s=30):
    for _ in range(deadline_s * 2):
        code, _ = get(port, f"/api/v1/names/{label}")
        if code == 404:
            return True
        time.sleep(0.5)
    return False


def verify(pub_hex, sig_hex, label, issued, expires):
    try:
        return checkvalid(
            bytes.fromhex(sig_hex),
            _name_claim_payload(label, pub_hex, issued, expires),
            bytes.fromhex(pub_hex)) is True
    except Exception:
        return False


def main():
    tmp_a = tempfile.mkdtemp(prefix="multihopexpiry-a-")
    tmp_b = tempfile.mkdtemp(prefix="multihopexpiry-b-")
    tmp_c = tempfile.mkdtemp(prefix="multihopexpiry-c-")
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
        check("node keys and both name keys are distinct",
              len({a_pub, b_pub, c_pub, k1_pub, k2_pub}) == 5)
        seed_peer(tmp_a, b_pub, URL_B, "belt-node-b")
        seed_peer(tmp_b, a_pub, URL_A, "belt-node-a")
        seed_peer(tmp_b, c_pub, URL_C, "belt-node-c")
        seed_peer(tmp_c, a_pub, URL_A, "belt-node-a")
        seed_peer(tmp_c, b_pub, URL_B, "belt-node-b")

        now = datetime.now(timezone.utc)
        expires1_dt = now + timedelta(seconds=80)
        code, claim1, sig1, issued1, expires1 = claim(
            PORT_A, LABEL, k1_priv, k1_pub,
            now - timedelta(seconds=10), expires1_dt)
        check("A claims kept-key name under K1 via real route (short life)",
              code == 200 and claim1.get("node_pubkey") == k1_pub,
              f"got {code} {claim1}")

        out, ok_n = gossip_out(tmp_a, a_priv, 1)
        check("A gossip K1 ran to 1 recipient", ok_n,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, served_b1 = wait_served(PORT_B, LABEL, sig1)
        check("B serves K1 byte-identical",
              code == 200 and served_b1.get("node_pubkey") == k1_pub,
              f"got {code} {served_b1}")
        out, ok_n = gossip_out(tmp_b, b_priv, 2)
        check("B gossip K1 onward ran to 2 recipients", ok_n,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, served_c1 = wait_served(PORT_C, LABEL, sig1)
        check("C serves K1 byte-identical (learned via B)",
              code == 200 and served_c1.get("node_pubkey") == k1_pub,
              f"got {code} {served_c1}")

        # Wait for the real clock to pass K1's expires_at.
        while datetime.now(timezone.utc) < expires1_dt + timedelta(seconds=2):
            time.sleep(2)
        check("belt waited past K1 expiry on the real clock",
              datetime.now(timezone.utc) > expires1_dt)
        check("B serves silence (404) after expiry",
              wait_silence(PORT_B, LABEL))
        check("C serves silence (404) after expiry (two hops out)",
              wait_silence(PORT_C, LABEL))

        stale = {"name": LABEL, "node_pubkey": k1_pub,
                 "issued_at": issued1, "expires_at": expires1,
                 "signature": sig1}
        res = ingest_on(tmp_c, c_priv, stale)
        check("stale expired K1 merge on C does not resurrect (not stored)",
              not res.stdout.strip().endswith("stored"),
              f"stdout={res.stdout!r} stderr={res.stderr[-400:]!r}")
        code, _ = get(PORT_C, f"/api/v1/names/{LABEL}")
        check("C still silent after stale merge attempt", code == 404,
              f"got {code}")
        out, _ = gossip_out(tmp_b, b_priv, 0)
        time.sleep(1)
        code, _ = get(PORT_C, f"/api/v1/names/{LABEL}")
        check("fresh B -> C gossip after expiry sends nothing live (0 recipients) and restores nothing on C",
              "recipients: 0" in out.stdout and code == 404,
              f"got {code} out={out.stdout!r}")

        now2 = datetime.now(timezone.utc)
        code, claim2, sig2, issued2, expires2 = claim(
            PORT_A, LABEL, k2_priv, k2_pub,
            now2 - timedelta(seconds=5), now2 + timedelta(days=30))
        check("A claims same label under NEW key K2 via real route (displacement)",
              code == 200 and claim2.get("node_pubkey") == k2_pub,
              f"got {code} {claim2}")
        out, ok_n = gossip_out(tmp_a, a_priv, 1)
        check("A gossip K2 ran to 1 recipient", ok_n,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, served_b2 = wait_served(PORT_B, LABEL, sig2)
        check("B serves K2 after displacement",
              code == 200 and served_b2.get("node_pubkey") == k2_pub
              and served_b2.get("issued_at") == issued2
              and served_b2.get("expires_at") == expires2,
              f"got {code} {served_b2}")
        check("belt re-verifies B's K2 binding against K2",
              verify(k2_pub, served_b2.get("signature", ""), LABEL,
                     issued2, expires2))
        out, ok_n = gossip_out(tmp_b, b_priv, 2)
        check("B gossip K2 onward ran to 2 recipients", ok_n,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, served_c2 = wait_served(PORT_C, LABEL, sig2)
        check("C REPLACED post-expiry silence with K2 learned onward from B",
              code == 200 and served_c2.get("node_pubkey") == k2_pub
              and served_c2.get("issued_at") == issued2
              and served_c2.get("expires_at") == expires2,
              f"got {code} {served_c2}")
        check("belt re-verifies C's K2 binding against K2",
              verify(k2_pub, served_c2.get("signature", ""), LABEL,
                     issued2, expires2))

        out, ok_n = gossip_out(tmp_b, b_priv, 2)
        time.sleep(1)
        code, served_c3 = get(PORT_C, f"/api/v1/names/{LABEL}")
        check("re-gossip after multi-hop displacement is idempotent (C still serves K2)",
              ok_n and code == 200
              and served_c3.get("signature") == sig2,
              f"got {code} {served_c3} out={out.stdout!r}")
        code, _ = get(PORT_C, "/api/v1/names/neverclaimedlabel")
        check("unclaimed label is silence (404) on C", code == 404,
              f"got {code}")
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
