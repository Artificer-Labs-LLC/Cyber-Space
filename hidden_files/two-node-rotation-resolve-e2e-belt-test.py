"""Belt: two-node rotation + reach-resolve e2e (primitives 1+2+3+4).

The rotation belt proved a designated K2 binding federates past a
mirror holding live K1; the reach belt proved resolve via a mirror
through a name-key-signed descriptor. Never proven together: what
happens to RESOLUTION when the key rotates under a live descriptor?

  1. A claims the label under K1, gossips to independent B, announces
     a K1-signed reach descriptor to B; resolve via B returns A/K1
  2. A rotates K1 -> K2 via the real rotate route; A gossips again
     and B replaces the binding with K2 (rotation belt's panel)
  3. The stale K1 descriptor is now re-keyed on B: B's /reach reads
     404 and resolve via B is SILENCE -- the rotated name never
     resolves through the old key's address half, fail-closed
  4. A re-announcing the descriptor under the OLD K1 key changes
     nothing (B's merge returns dropped-key-mismatch in effect:
     /reach still 404, resolve still silence)
  5. A re-announces under K2 (real _reach_out, NAME_PRIVKEY=K2);
     B serves the K2 descriptor and resolve via B returns A under
     K2, no via_relay, step-6 live-verified against A's K2 binding
  6. An unclaimed label resolves via B to silence

Test-only allowances, twin of the parent belts: helper/belt
processes patch core._reject_nonpublic_node_url to admit the two
loopback node URLs only (production's SSRF gate refuses loopback
peer URLs by design), and the belt clears core._resolve_memo
between phases -- the memo is a per-client 60s verified-result
cache, and each phase here is a fresh client's question. The
genesis name is never touched.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/two-node-rotation-resolve-e2e-belt-test.py
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
from rotate_name import mint_rotation  # noqa: E402

CASES = {"passed": 0, "failed": 0}
PORT_A, PORT_B = 18841, 18842
URL_A = f"http://127.0.0.1:{PORT_A}"
URL_B = f"http://127.0.0.1:{PORT_B}"
LABEL = "twonoderotresolve"

_real_gate = core._reject_nonpublic_node_url


def _gate(url):
    if isinstance(url, str) and url.startswith((URL_A, URL_B)):
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


def run_helper(tmp_a, a_priv, extra_env, call):
    helper = (
        "import time, core\n"
        "_real = core._reject_nonpublic_node_url\n"
        "def _gate(url):\n"
        f"    return None if url.startswith(({URL_A!r}, {URL_B!r})) else _real(url)\n"
        "core._reject_nonpublic_node_url = _gate\n"
        f"n = {call}\n"
        "print('sent:', n)\n"
        "time.sleep(4)\n")
    env = dict(os.environ, CYBERNET_DB_DIR=tmp_a,
               CYBERNET_NODE_PRIVKEY=a_priv, **extra_env)
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
            return r.status, sig
    except urllib.error.HTTPError as e:
        return e.code, sig


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
            return r.status, json.loads(r.read()), b_sig
    except urllib.error.HTTPError as e:
        return e.code, {}, b_sig


def wait_served(port, label, sig):
    served, code = {}, 0
    for _ in range(20):
        code, served = get(port, f"/api/v1/names/{label}")
        if code == 200 and served.get("signature") == sig:
            return code, served
        time.sleep(0.5)
    return code, served


def resolve_fresh(label):
    core._resolve_memo.clear()
    return core.resolve_cyberspace(label + ".cyberspace", URL_B)


def reach_out(tmp_a, a_priv, name_priv_hex):
    return run_helper(
        tmp_a, a_priv,
        {"CYBERNET_HOSTED_NAME": LABEL,
         "CYBERNET_NAME_PRIVKEY": name_priv_hex,
         "CYBERNET_PUBLIC_URL": URL_A},
        "core._reach_out()")


def main():
    tmp_a = tempfile.mkdtemp(prefix="rot-resolve-a-")
    tmp_b = tempfile.mkdtemp(prefix="rot-resolve-b-")
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
        seed_peer(tmp_a, b_pub, URL_B, "belt-node-b")
        seed_peer(tmp_b, a_pub, URL_A, "belt-node-a")

        now = datetime.now(timezone.utc)
        code, sig1 = claim(PORT_A, LABEL, k1_priv, k1_pub,
                           now - timedelta(minutes=5),
                           now + timedelta(days=30))
        check("A claims kept-key name under K1 via real route", code == 200,
              f"got {code}")

        out = run_helper(tmp_a, a_priv, {}, "core._names_gossip_out()")
        check("A gossip K1 ran to 1 recipient", "sent: 1" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, served_b1 = wait_served(PORT_B, LABEL, sig1)
        check("B serves K1 byte-identical", code == 200
              and served_b1.get("node_pubkey") == k1_pub,
              f"got {code} {served_b1}")

        out = reach_out(tmp_a, a_priv, k1_priv.hex())
        check("A reach announce under K1 ran to 1 recipient",
              "sent: 1" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, desc = 0, {}
        for _ in range(20):
            code, desc = get(PORT_B, f"/api/v1/names/{LABEL}/reach")
            if code == 200:
                break
            time.sleep(0.5)
        check("B serves the K1 reach descriptor", code == 200
              and desc.get("node_pubkey") == k1_pub, f"got {code} {desc}")
        got = resolve_fresh(LABEL)
        check("resolve via B returns A under K1 via descriptor",
              isinstance(got, dict) and got.get("node_pubkey") == k1_pub
              and got.get("node_url") == URL_A and "via_relay" not in got,
              f"got {got}")

        code, resp, b_sig = rotate(
            PORT_A, LABEL, k1_priv, k1_pub, k2_priv, k2_pub,
            now - timedelta(minutes=2), now - timedelta(minutes=1),
            now + timedelta(days=60))
        check("A rotates K1 -> K2 via real rotate route",
              code == 200 and resp.get("status") == "rotated",
              f"got {code} {resp}")
        out = run_helper(tmp_a, a_priv, {}, "core._names_gossip_out()")
        check("A gossip K2 (with chain) ran to 1 recipient",
              "sent: 1" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, served_b2 = wait_served(PORT_B, LABEL, b_sig)
        check("B replaced live K1 with designated K2", code == 200
              and served_b2.get("node_pubkey") == k2_pub,
              f"got {code} {served_b2}")

        code, _ = get(PORT_B, f"/api/v1/names/{LABEL}/reach")
        check("B /reach for the stale K1 descriptor reads 404 after rotation",
              code == 404, f"got {code}")
        check("resolve via B after rotation is silence (no old-key redirect)",
              resolve_fresh(LABEL) is None)

        out = reach_out(tmp_a, a_priv, k1_priv.hex())
        check("stale K1 reach re-announce ran (send half only)",
              "sent: 1" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, _ = get(PORT_B, f"/api/v1/names/{LABEL}/reach")
        check("B still serves no descriptor after stale K1 re-announce",
              code == 404, f"got {code}")
        check("resolve via B still silence after stale K1 re-announce",
              resolve_fresh(LABEL) is None)

        out = reach_out(tmp_a, a_priv, k2_priv.hex())
        check("A reach announce under K2 ran to 1 recipient",
              "sent: 1" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, desc = 0, {}
        for _ in range(20):
            code, desc = get(PORT_B, f"/api/v1/names/{LABEL}/reach")
            if code == 200:
                break
            time.sleep(0.5)
        check("B serves the K2 reach descriptor", code == 200
              and desc.get("node_pubkey") == k2_pub, f"got {code} {desc}")
        got = resolve_fresh(LABEL)
        check("resolve via B returns A under K2 via descriptor",
              isinstance(got, dict) and got.get("node_pubkey") == k2_pub
              and got.get("node_url") == URL_A and "via_relay" not in got,
              f"got {got}")
        check("unclaimed label resolves via B to silence",
              resolve_fresh("nobodyclaimedit") is None)
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
