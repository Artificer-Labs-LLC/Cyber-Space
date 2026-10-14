"""Belt: expiry + reach-resolve e2e (primitives 1+2+3+4).

The expiry-displacement belt proved an expired incumbent yields
its registry seat to a different key; the renewal+resolve belt
proved renewal keeps resolution alive under the same key. Never
proven together: what happens to RESOLUTION across expiry and
succession? Expiry must be a clean death for the address half too
-- not a stale redirect to a dead owner's host:

  1. A claims the label under K1 with a SHORT life (~110s),
     gossips to independent mirror B, announces a K1-signed reach
     descriptor (TTL 1 day -- the descriptor itself outlives the
     binding); resolve via B returns A/K1
  2. C claims the same label under K2 (long-lived) pre-expiry and
     gossips to B; B keeps live K1, and C's K2 reach announce is
     dropped at B (key mismatch against the live K1 binding) --
     resolve via B still returns A/K1
  3. The belt waits until K1's expires_at passes
  4. B serves the binding as 404 and the reach descriptor as 404
     (expired binding reads as absent; a descriptor whose binding
     is dead reads as absent even though its own TTL has not run)
     and resolve via B is SILENCE
  5. A stale K1 reach re-announce from A changes nothing: B still
     serves no descriptor and resolve via B is still silence
  6. K2's binding fed to B's real ingest returns replaced; C
     announces reach under K2; B serves the K2 descriptor and
     resolve via B returns C under K2 (step-6 live-verified at C)

Test-only allowances, twin of the parent belts: helper/belt
processes patch core._reject_nonpublic_node_url to admit the
loopback node URLs only (production's SSRF gate refuses loopback
peer URLs by design), and the belt clears core._resolve_memo
between phases -- the memo is a per-client 60s verified-result
cache, and each phase here is a fresh client's question. The
genesis name is never touched.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/two-node-expiry-resolve-e2e-belt-test.py
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

from fed.ed25519 import publickey, sign  # noqa: E402
import core  # noqa: E402
from core import _name_claim_payload  # noqa: E402

CASES = {"passed": 0, "failed": 0}
PORT_A, PORT_B, PORT_C = 18881, 18882, 18883
URL_A = f"http://127.0.0.1:{PORT_A}"
URL_B = f"http://127.0.0.1:{PORT_B}"
URL_C = f"http://127.0.0.1:{PORT_C}"
LABEL = "twonodeexpiryresolve"

_real_gate = core._reject_nonpublic_node_url


def _gate(url):
    if isinstance(url, str) and url.startswith((URL_A, URL_B, URL_C)):
        return None
    return _real_gate(url)


core._reject_nonpublic_node_url = _gate


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


def run_helper(tmp, priv, extra_env, call):
    helper = (
        "import time, core\n"
        "_real = core._reject_nonpublic_node_url\n"
        "def _gate(url):\n"
        f"    return None if url.startswith(({URL_A!r}, {URL_B!r}, {URL_C!r})) else _real(url)\n"
        "core._reject_nonpublic_node_url = _gate\n"
        f"n = {call}\n"
        "print('sent:', n)\n"
        "time.sleep(4)\n")
    env = dict(os.environ, CYBERNET_DB_DIR=tmp,
               CYBERNET_NODE_PRIVKEY=priv, **extra_env)
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
    served, code = {}, 0
    for _ in range(20):
        code, served = get(port, f"/api/v1/names/{label}")
        if code == 200 and served.get("signature") == sig:
            return code, served
        time.sleep(0.5)
    return code, served


def wait_reach(port, label, pub):
    desc, code = {}, 0
    for _ in range(20):
        code, desc = get(port, f"/api/v1/names/{label}/reach")
        if code == 200 and desc.get("node_pubkey") == pub:
            return code, desc
        time.sleep(0.5)
    return code, desc


def resolve_fresh(label):
    core._resolve_memo.clear()
    return core.resolve_cyberspace(label + ".cyberspace", URL_B)


def reach_out(tmp, priv, name_priv_hex, public_url):
    return run_helper(
        tmp, priv,
        {"CYBERNET_HOSTED_NAME": LABEL,
         "CYBERNET_NAME_PRIVKEY": name_priv_hex,
         "CYBERNET_PUBLIC_URL": public_url},
        "core._reach_out()")


def main():
    tmp_a = tempfile.mkdtemp(prefix="expiry-resolve-a-")
    tmp_b = tempfile.mkdtemp(prefix="expiry-resolve-b-")
    tmp_c = tempfile.mkdtemp(prefix="expiry-resolve-c-")
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
        seed_peer(tmp_a, b_pub, URL_B, "belt-node-b")
        seed_peer(tmp_c, b_pub, URL_B, "belt-node-b")
        seed_peer(tmp_b, a_pub, URL_A, "belt-node-a")
        seed_peer(tmp_b, c_pub, URL_C, "belt-node-c")

        now = datetime.now(timezone.utc)
        expires1_dt = now + timedelta(seconds=110)
        code, sig1, issued1, expires1 = claim(
            PORT_A, LABEL, k1_priv, k1_pub,
            now - timedelta(seconds=10), expires1_dt)
        check("A claims kept-key name under K1 (short life) via real route",
              code == 200, f"got {code}")

        out = run_helper(tmp_a, a_priv, {}, "core._names_gossip_out()")
        check("A gossip K1 ran to 1 recipient", "sent: 1" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, served_b1 = wait_served(PORT_B, LABEL, sig1)
        check("B serves K1 byte-identical while live", code == 200
              and served_b1.get("node_pubkey") == k1_pub,
              f"got {code} {served_b1}")

        out = reach_out(tmp_a, a_priv, k1_priv.hex(), URL_A)
        check("A reach announce under K1 ran to 1 recipient",
              "sent: 1" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, desc = wait_reach(PORT_B, LABEL, k1_pub)
        check("B serves the K1 reach descriptor", code == 200
              and desc.get("node_pubkey") == k1_pub, f"got {code} {desc}")
        got = resolve_fresh(LABEL)
        check("resolve via B returns A under K1 pre-expiry",
              isinstance(got, dict) and got.get("node_pubkey") == k1_pub
              and got.get("node_url") == URL_A and "via_relay" not in got
              and got.get("expires_at") == expires1,
              f"got {got}")

        code, sig2, issued2, expires2 = claim(
            PORT_C, LABEL, k2_priv, k2_pub,
            datetime.now(timezone.utc) - timedelta(seconds=5),
            datetime.now(timezone.utc) + timedelta(days=30))
        check("C claims same label under K2 via real route",
              code == 200, f"got {code}")
        out = run_helper(tmp_c, c_priv, {}, "core._names_gossip_out()")
        check("C gossip (pre-expiry) ran to 1 recipient",
              "sent: 1" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        time.sleep(1)
        code, served_b2 = get(PORT_B, f"/api/v1/names/{LABEL}")
        check("B keeps live K1 against K2 challenger (no early handover)",
              code == 200 and served_b2.get("signature") == sig1,
              f"got {code} {served_b2}")
        out = reach_out(tmp_c, c_priv, k2_priv.hex(), URL_C)
        check("C reach announce under K2 ran to 1 recipient",
              "sent: 1" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        time.sleep(1)
        code, desc = get(PORT_B, f"/api/v1/names/{LABEL}/reach")
        check("B still serves only the K1 descriptor (K2 announce dropped)",
              code == 200 and desc.get("node_pubkey") == k1_pub,
              f"got {code} {desc}")
        got = resolve_fresh(LABEL)
        check("resolve via B still returns A/K1 pre-expiry",
              isinstance(got, dict) and got.get("node_pubkey") == k1_pub
              and got.get("node_url") == URL_A, f"got {got}")

        deadline = expires1_dt + timedelta(seconds=3)
        while datetime.now(timezone.utc) < deadline:
            time.sleep(2)
        check("K1 expiry has passed on the belt clock",
              datetime.now(timezone.utc) > expires1_dt)

        code, _ = get(PORT_B, f"/api/v1/names/{LABEL}")
        check("B serves the expired K1 binding as 404", code == 404,
              f"got {code}")
        code, _ = get(PORT_B, f"/api/v1/names/{LABEL}/reach")
        check("B serves the K1 descriptor as 404 after binding expiry "
              "(descriptor TTL itself unexpired)", code == 404,
              f"got {code}")
        check("resolve via B is silence after expiry",
              resolve_fresh(LABEL) is None)

        out = reach_out(tmp_a, a_priv, k1_priv.hex(), URL_A)
        check("stale K1 reach re-announce ran to 1 recipient",
              "sent: 1" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        time.sleep(1)
        code, _ = get(PORT_B, f"/api/v1/names/{LABEL}/reach")
        check("stale K1 re-announce restores no descriptor on B",
              code == 404, f"got {code}")
        check("resolve via B still silence after stale re-announce",
              resolve_fresh(LABEL) is None)

        k2_binding = {"name": LABEL, "node_pubkey": k2_pub,
                      "issued_at": issued2, "expires_at": expires2,
                      "signature": sig2}
        res = ingest_on(tmp_b, b_priv, k2_binding)
        check("B merge of K2 against EXPIRED K1 returns replaced",
              res.stdout.strip().endswith("replaced"),
              f"stdout={res.stdout!r} stderr={res.stderr[-400:]!r}")
        code, served_b3 = wait_served(PORT_B, LABEL, sig2)
        check("B now serves K2 byte-identical", code == 200
              and served_b3.get("node_pubkey") == k2_pub,
              f"got {code} {served_b3}")

        out = reach_out(tmp_c, c_priv, k2_priv.hex(), URL_C)
        check("C reach announce under K2 ran to 1 recipient",
              "sent: 1" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, desc = wait_reach(PORT_B, LABEL, k2_pub)
        check("B serves the K2 reach descriptor", code == 200
              and desc.get("node_pubkey") == k2_pub, f"got {code} {desc}")
        got = resolve_fresh(LABEL)
        check("resolve via B returns C under K2 after succession",
              isinstance(got, dict) and got.get("node_pubkey") == k2_pub
              and got.get("node_url") == URL_C and "via_relay" not in got
              and got.get("expires_at") == expires2,
              f"got {got}")
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
