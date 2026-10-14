"""Belt: two-node rotation + RELAY-strategy resolve e2e (1+2+3+4).

The rotation+resolve belt proved rotation under a DIRECT descriptor;
the relay belt proved resolve for a NAT-hidden hoster. Never proven
together: what happens to RELAY resolution when the key rotates?

  1. A claims the label under K1, gossips to independent B; A's
     hold-open daemon holds at relay C under TOK1 (name key K1);
     A announces a K1-signed relay-only descriptor to B; resolve
     via B returns K1 terminating at C with via_relay TOK1
  2. A rotates K1 -> K2 via the real rotate route; gossip replaces
     B's binding with K2
  3. The stale K1 descriptor reads 404 on B and resolve via B is
     SILENCE -- even though C still holds TOK1 open under K1, the
     rotated name never resolves through the old key's relay path
  4. Re-announcing under the OLD K1 key changes nothing
  5. A holds at C under K2 with a fresh TOK2, re-announces under
     K2; B serves the K2 relay-only descriptor and resolve via B
     returns K2 terminating at C with via_relay TOK2 -- step 6
     live-proves K2 signing a fresh challenge through C's hold-open
     under TOK2 (the still-running K1 daemon on TOK1 cannot answer
     it, so a pass cannot be the old key in disguise)
  6. An unclaimed label resolves via B to silence

Test-only allowances, twin of the parent belts: helper/belt
processes patch core._reject_nonpublic_node_url to admit the three
loopback node URLs only, and the belt clears core._resolve_memo
between phases. The genesis name is never touched.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/two-node-rotation-relay-resolve-e2e-belt-test.py
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
from rotate_name import mint_rotation  # noqa: E402

CASES = {"passed": 0, "failed": 0}
PORT_A, PORT_B, PORT_C = 18851, 18852, 18853
URL_A = f"http://127.0.0.1:{PORT_A}"
URL_B = f"http://127.0.0.1:{PORT_B}"
URL_C = f"http://127.0.0.1:{PORT_C}"
LABEL = "twonoderotrelay"
TOK1 = "tok1-" + secrets.token_hex(8)
TOK2 = "tok2-" + secrets.token_hex(8)

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


def run_helper(tmp_a, a_priv, extra_env, call):
    helper = (
        "import time, core\n"
        "_real = core._reject_nonpublic_node_url\n"
        "def _gate(url):\n"
        f"    return None if url.startswith(({URL_A!r}, {URL_B!r}, {URL_C!r})) else _real(url)\n"
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


def reach_out(tmp_a, a_priv, name_priv_hex, c_pub, tok):
    return run_helper(
        tmp_a, a_priv,
        {"CYBERNET_HOSTED_NAME": LABEL,
         "CYBERNET_NAME_PRIVKEY": name_priv_hex,
         "CYBERNET_PUBLIC_URL": "",
         "CYBERNET_RELAY_URL": URL_C,
         "CYBERNET_RELAY_PUBKEY": c_pub,
         "CYBERNET_RELAY_TOKEN": tok},
        "core._reach_out()")


def check_relay_resolve(tag, pub, tok):
    got = resolve_fresh(LABEL)
    check(f"resolve via B returns {tag} via relay C",
          isinstance(got, dict) and got.get("node_pubkey") == pub
          and got.get("node_url") == URL_C
          and got.get("via_relay") == {"relay_pub": _c_pub, "token": tok},
          f"got {got}")


_c_pub = ""


def main():
    global _c_pub
    tmp_a = tempfile.mkdtemp(prefix="rot-relay-a-")
    tmp_b = tempfile.mkdtemp(prefix="rot-relay-b-")
    tmp_c = tempfile.mkdtemp(prefix="rot-relay-c-")
    a_priv = secrets.token_hex(32)
    a_pub = publickey(bytes.fromhex(a_priv)).hex()
    b_priv = secrets.token_hex(32)
    b_pub = publickey(bytes.fromhex(b_priv)).hex()
    c_priv = secrets.token_hex(32)
    c_pub = publickey(bytes.fromhex(c_priv)).hex()
    _c_pub = c_pub
    k1_priv = bytes.fromhex(secrets.token_hex(32))
    k1_pub = publickey(k1_priv).hex()
    k2_priv = bytes.fromhex(secrets.token_hex(32))
    k2_pub = publickey(k2_priv).hex()

    proc_a, up_a = boot(tmp_a, a_priv, PORT_A)
    proc_b, up_b = boot(tmp_b, b_priv, PORT_B)
    proc_c, up_c = boot(tmp_c, c_priv, PORT_C)
    stop1, stop2 = threading.Event(), threading.Event()
    try:
        check("three independent nodes boot", up_a and up_b and up_c)
        if not (up_a and up_b and up_c):
            return
        seed_peer(tmp_a, b_pub, URL_B, "belt-node-b")
        seed_peer(tmp_b, a_pub, URL_A, "belt-node-a")

        now = datetime.now(timezone.utc)
        code, sig1 = claim(PORT_A, LABEL, k1_priv, k1_pub,
                           now - timedelta(minutes=5),
                           now + timedelta(days=30))
        check("A claims kept-key name under K1 via real route",
              code == 200, f"got {code}")
        out = run_helper(tmp_a, a_priv, {}, "core._names_gossip_out()")
        check("A gossip K1 ran to 1 recipient", "sent: 1" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, served_b1 = wait_served(PORT_B, LABEL, sig1)
        check("B serves K1 byte-identical", code == 200
              and served_b1.get("node_pubkey") == k1_pub,
              f"got {code} {served_b1}")
        check("resolve via B with binding only is silence",
              resolve_fresh(LABEL) is None)

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
        check("B serves the K1 reach descriptor", code == 200,
              f"got {code} {desc}")
        strats = [s for s in (desc.get("reach") or [])
                  if isinstance(s, dict)]
        check("K1 descriptor carries ONLY the relay strategy",
              len(strats) == 1 and strats[0].get("kind") == "relay"
              and strats[0].get("url") == URL_C
              and strats[0].get("relay") == c_pub
              and strats[0].get("token") == TOK1,
              f"reach={desc.get('reach')}")
        check_relay_resolve("K1", k1_pub, TOK1)

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
        check("B /reach for the stale K1 descriptor reads 404",
              code == 404, f"got {code}")
        check("resolve via B after rotation is silence (K1 hold-open "
              "at C still live, no old-key relay path)",
              resolve_fresh(LABEL) is None)

        out = reach_out(tmp_a, a_priv, k1_priv.hex(), c_pub, TOK1)
        check("stale K1 reach re-announce ran (send half only)",
              "sent: 1" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, _ = get(PORT_B, f"/api/v1/names/{LABEL}/reach")
        check("B still serves no descriptor after stale K1 re-announce",
              code == 404, f"got {code}")
        check("resolve via B still silence after stale K1 re-announce",
              resolve_fresh(LABEL) is None)

        daemon2 = threading.Thread(
            target=hold_open.hold_open_cycle,
            args=(URL_C, TOK2, k2_priv.hex(), stop2),
            kwargs={"keepalive_every": 60.0}, daemon=True)
        daemon2.start()
        time.sleep(1.0)
        out = reach_out(tmp_a, a_priv, k2_priv.hex(), c_pub, TOK2)
        check("A reach announce under K2 ran to 1 recipient",
              "sent: 1" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, desc = wait_reach(PORT_B, LABEL, k2_pub)
        check("B serves the K2 reach descriptor", code == 200,
              f"got {code} {desc}")
        strats = [s for s in (desc.get("reach") or [])
                  if isinstance(s, dict)]
        check("K2 descriptor carries ONLY the relay strategy (TOK2)",
              len(strats) == 1 and strats[0].get("kind") == "relay"
              and strats[0].get("url") == URL_C
              and strats[0].get("relay") == c_pub
              and strats[0].get("token") == TOK2,
              f"reach={desc.get('reach')}")
        check_relay_resolve("K2", k2_pub, TOK2)
        check("unclaimed label resolves via B to silence",
              resolve_fresh("nobodyclaimedit") is None)
    finally:
        stop1.set()
        stop2.set()
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
