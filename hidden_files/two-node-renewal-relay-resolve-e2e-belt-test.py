"""Belt: two-node renewal + RELAY-strategy resolve e2e (primitives 1+2+3+4).

The renewal+rendezvous belt proved renewal does not orphan a
rendezvous descriptor; the rotation+relay belt proved rotation
kills a relay path. Never proven together: what happens to plain
RELAY resolution when the owner simply RENEWS under the same key?
Renewal must be the opposite of rotation here too -- the descriptor
and the hold-open are keyed by the same name key, so resolution
should survive and track the renewed binding:

  1. NAT-hidden A claims the label under K1 (v1), gossips to
     independent B, holds at relay C under TOK1, announces a
     K1-signed relay-only descriptor (no direct, no rendezvous);
     resolve via B returns K1 via_relay TOK1 carrying v1 window
  2. A renews via the real claim route: SAME key, later issued,
     later expiry (v2); A gossips again and B replaces v1 with v2
  3. B still serves the K1 relay descriptor (renewal does not
     orphan the address half -- same key, unlike rotation)
  4. Resolve via B returns K1 via_relay TOK1 carrying V2 window
  5. A stale v1 binding fed to B's real ingest returns kept; B
     still serves v2 and resolve still returns v2 window
  6. An unclaimed label resolves via B to silence

Test-only allowances, twin of the parent belts: helper/belt
processes patch core._reject_nonpublic_node_url to admit the
loopback node URLs only, and the belt clears core._resolve_memo
between phases. The genesis name is never touched.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/two-node-renewal-relay-resolve-e2e-belt-test.py
"""

import json
import os
import secrets
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from fed.ed25519 import publickey, sign  # noqa: E402
import core  # noqa: E402
import hold_open  # noqa: E402
from core import _name_claim_payload  # noqa: E402

CASES = {"passed": 0, "failed": 0}
PORT_A, PORT_B, PORT_C = 18941, 18942, 18943
URL_A = f"http://127.0.0.1:{PORT_A}"
URL_B = f"http://127.0.0.1:{PORT_B}"
URL_C = f"http://127.0.0.1:{PORT_C}"
URLS = (URL_A, URL_B, URL_C)
LABEL = "twonoderenewrelay"
TOK1 = "tok1-" + secrets.token_hex(8)

_real_gate = core._reject_nonpublic_node_url


def _gate(url):
    if isinstance(url, str) and url.startswith(URLS):
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


def reach_out(tmp, priv, name_priv_hex, relay_pub, tok):
    return run_helper(
        tmp, priv,
        {"CYBERNET_HOSTED_NAME": LABEL,
         "CYBERNET_NAME_PRIVKEY": name_priv_hex,
         "CYBERNET_PUBLIC_URL": "",
         "CYBERNET_RELAY_URL": URL_C,
         "CYBERNET_RELAY_PUBKEY": relay_pub,
         "CYBERNET_RELAY_TOKEN": tok},
        "core._reach_out()")


_c_pub = ""


def check_descriptor(tag, desc, tok):
    strats = [s for s in (desc.get("reach") or [])
              if isinstance(s, dict)]
    check(f"{tag} descriptor carries ONLY the relay strategy (NAT-hidden)",
          len(strats) == 1 and strats[0].get("kind") == "relay"
          and strats[0].get("url") == URL_C
          and strats[0].get("relay") == _c_pub
          and strats[0].get("token") == tok,
          f"reach={desc.get('reach')}")


def check_relay_resolve(tag, pub, tok, issued, expires):
    got = resolve_fresh(LABEL)
    check(f"resolve via B returns {tag} via relay C",
          isinstance(got, dict) and got.get("node_pubkey") == pub
          and got.get("node_url") == URL_C
          and got.get("via_relay") == {"relay_pub": _c_pub, "token": tok}
          and got.get("issued_at") == issued
          and got.get("expires_at") == expires,
          f"got {got}")


def main():
    global _c_pub
    tmp_a = tempfile.mkdtemp(prefix="renew-relay-a-")
    tmp_b = tempfile.mkdtemp(prefix="renew-relay-b-")
    tmp_c = tempfile.mkdtemp(prefix="renew-relay-c-")
    a_priv = secrets.token_hex(32)
    a_pub = publickey(bytes.fromhex(a_priv)).hex()
    b_priv = secrets.token_hex(32)
    b_pub = publickey(bytes.fromhex(b_priv)).hex()
    c_priv = secrets.token_hex(32)
    c_pub = publickey(bytes.fromhex(c_priv)).hex()
    _c_pub = c_pub
    k1_priv = bytes.fromhex(secrets.token_hex(32))
    k1_pub = publickey(k1_priv).hex()

    proc_a, up_a = boot(tmp_a, a_priv, PORT_A)
    proc_b, up_b = boot(tmp_b, b_priv, PORT_B)
    proc_c, up_c = boot(tmp_c, c_priv, PORT_C)
    stop1 = threading.Event()
    try:
        check("three independent nodes boot", up_a and up_b and up_c)
        if not (up_a and up_b and up_c):
            return
        seed_peer(tmp_a, b_pub, URL_B, "belt-node-b")
        seed_peer(tmp_b, a_pub, URL_A, "belt-node-a")

        now = datetime.now(timezone.utc)
        code, sig1, issued1, expires1 = claim(
            PORT_A, LABEL, k1_priv, k1_pub,
            now - timedelta(minutes=5), now + timedelta(days=30))
        check("A claims kept-key name v1 under K1 via real route",
              code == 200, f"got {code}")
        out = run_helper(tmp_a, a_priv, {}, "core._names_gossip_out()")
        check("A gossip v1 ran to 1 recipient", "sent: 1" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, served_b1 = wait_served(PORT_B, LABEL, sig1)
        check("B serves v1 byte-identical", code == 200
              and served_b1.get("node_pubkey") == k1_pub,
              f"got {code} {served_b1}")

        daemon1 = threading.Thread(
            target=hold_open.hold_open_cycle,
            args=(URL_C, TOK1, k1_priv.hex(), stop1),
            kwargs={"keepalive_every": 60.0}, daemon=True)
        daemon1.start()
        time.sleep(1.0)
        out = reach_out(tmp_a, a_priv, k1_priv.hex(), c_pub, TOK1)
        check("A reach announce under K1 ran to 1 recipient",
              "sent: 1" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, desc = wait_reach(PORT_B, LABEL, k1_pub)
        check("B serves the K1 relay descriptor", code == 200
              and desc.get("node_pubkey") == k1_pub, f"got {code} {desc}")
        check_descriptor("K1", desc, TOK1)
        check_relay_resolve("K1 v1", k1_pub, TOK1, issued1, expires1)

        # Renewal: SAME key, later issued, later expiry.
        code, sig2, issued2, expires2 = claim(
            PORT_A, LABEL, k1_priv, k1_pub,
            now - timedelta(minutes=1), now + timedelta(days=60))
        check("A renews same-key v2 via real claim route",
              code == 200 and sig2 != sig1, f"got {code}")
        out = run_helper(tmp_a, a_priv, {}, "core._names_gossip_out()")
        check("A gossip v2 ran to 1 recipient", "sent: 1" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, served_b2 = wait_served(PORT_B, LABEL, sig2)
        check("B replaced v1 with v2 (same key, fresher window)",
              code == 200 and served_b2.get("node_pubkey") == k1_pub
              and served_b2.get("issued_at") == issued2
              and served_b2.get("expires_at") == expires2,
              f"got {code} {served_b2}")

        code, desc = get(PORT_B, f"/api/v1/names/{LABEL}/reach")
        check("B still serves the K1 relay descriptor after renewal",
              code == 200 and desc.get("node_pubkey") == k1_pub,
              f"got {code} {desc}")
        check_descriptor("K1 post-renewal", desc, TOK1)
        check_relay_resolve("K1 v2", k1_pub, TOK1, issued2, expires2)

        v1 = {"name": LABEL, "node_pubkey": k1_pub,
              "issued_at": issued1, "expires_at": expires1,
              "signature": sig1}
        res = ingest_on(tmp_b, b_priv, v1)
        check("stale v1 merge on B returns kept",
              res.stdout.strip().endswith("kept"),
              f"stdout={res.stdout!r} stderr={res.stderr[-400:]!r}")
        code, served_b3 = get(PORT_B, f"/api/v1/names/{LABEL}")
        check("B still serves v2 after stale v1 merge attempt",
              code == 200 and served_b3.get("signature") == sig2,
              f"got {code} {served_b3}")
        check_relay_resolve("K1 v2 post-stale", k1_pub, TOK1, issued2, expires2)
        check("unclaimed label resolves via B to silence",
              resolve_fresh("nobodyclaimedit") is None)
    finally:
        stop1.set()
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
