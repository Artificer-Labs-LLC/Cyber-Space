"""Belt: THREE-HOP gossip chain + RENDEZVOUS-strategy resolve e2e
(primitives 1+2+3+4).

Next panel after three-hop direct (28a3d45): same strict three-hop
binding chain, but the owner is NAT-hidden and resolves via a relay
hold -- never proven at three hops.

Five INDEPENDENT nodes: A owner (NAT-hidden), B and C intermediaries
in series, D far resolver, R relay.

  1. A claims under K1; gossip A->B->C->D in series, each hop serves
     byte-identical, D 404 until C leg, belt re-verifies K1 at D
  2. D serves no /reach yet; resolve via D with binding only is silence
  3. A holds at relay R under TOK1 and announces a K1 relay-only
     descriptor to peers B and D; D serves ONLY the relay strategy
  4. Resolve via third hop D returns K1 via_relay TOK1 at R
  5. An unclaimed label resolves via D to silence

Test-only allowances twin the parents: loopback gate patch, memo
clear between resolves. Genesis name never touched.
Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/three-hop-gossip-rendezvous-resolve-e2e-belt-test.py
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

from fed.ed25519 import checkvalid, publickey, sign  # noqa: E402
import core  # noqa: E402
import hold_open  # noqa: E402
import rendezvous as _rz  # noqa: E402
from core import _name_claim_payload  # noqa: E402

CASES = {"passed": 0, "failed": 0}
PORT_A, PORT_B, PORT_C, PORT_D, PORT_R = 19001, 19002, 19003, 19004, 19005
URL_A = f"http://127.0.0.1:{PORT_A}"
URL_B = f"http://127.0.0.1:{PORT_B}"
URL_C = f"http://127.0.0.1:{PORT_C}"
URL_D = f"http://127.0.0.1:{PORT_D}"
URL_R = f"http://127.0.0.1:{PORT_R}"
URLS = (URL_A, URL_B, URL_C, URL_D, URL_R)
LABEL = "threehoprz"
EPOCH_LEN = 600
os.environ["CYBERNET_RENDEZVOUS_EPOCH_LEN"] = str(EPOCH_LEN)
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


def verify(pub_hex, sig_hex, label, issued, expires):
    try:
        return checkvalid(
            bytes.fromhex(sig_hex),
            _name_claim_payload(label, pub_hex, issued, expires),
            bytes.fromhex(pub_hex)) is True
    except Exception:
        return False


def resolve_fresh(label, base):
    core._resolve_memo.clear()
    return core.resolve_cyberspace(label + ".cyberspace", base)


def reach_out(tmp, priv, name_priv_hex, relay_pub, tok):
    return run_helper(
        tmp, priv,
        {"CYBERNET_HOSTED_NAME": LABEL,
         "CYBERNET_NAME_PRIVKEY": name_priv_hex,
         "CYBERNET_PUBLIC_URL": "",
         "CYBERNET_RELAY_URL": URL_R,
         "CYBERNET_RELAY_PUBKEY": relay_pub,
         "CYBERNET_RELAY_TOKEN": tok,
         "CYBERNET_RENDEZVOUS": "1",
         "CYBERNET_RENDEZVOUS_EPOCH_LEN": str(EPOCH_LEN)},
        "core._reach_out()")


def main():
    tmp_a = tempfile.mkdtemp(prefix="3hop-rz-a-")
    tmp_b = tempfile.mkdtemp(prefix="3hop-rz-b-")
    tmp_c = tempfile.mkdtemp(prefix="3hop-rz-c-")
    tmp_d = tempfile.mkdtemp(prefix="3hop-rz-d-")
    tmp_r = tempfile.mkdtemp(prefix="3hop-rz-r-")
    a_priv = secrets.token_hex(32)
    a_pub = publickey(bytes.fromhex(a_priv)).hex()
    b_priv = secrets.token_hex(32)
    b_pub = publickey(bytes.fromhex(b_priv)).hex()
    c_priv = secrets.token_hex(32)
    c_pub = publickey(bytes.fromhex(c_priv)).hex()
    d_priv = secrets.token_hex(32)
    d_pub = publickey(bytes.fromhex(d_priv)).hex()
    r_priv = secrets.token_hex(32)
    r_pub = publickey(bytes.fromhex(r_priv)).hex()
    k1_priv = bytes.fromhex(secrets.token_hex(32))
    k1_pub = publickey(k1_priv).hex()

    proc_a, up_a = boot(tmp_a, a_priv, PORT_A)
    proc_b, up_b = boot(tmp_b, b_priv, PORT_B)
    proc_c, up_c = boot(tmp_c, c_priv, PORT_C)
    proc_d, up_d = boot(tmp_d, d_priv, PORT_D)
    proc_r, up_r = boot(tmp_r, r_priv, PORT_R)
    stop1 = threading.Event()
    try:
        check("five independent nodes boot",
              up_a and up_b and up_c and up_d and up_r)
        if not (up_a and up_b and up_c and up_d and up_r):
            return
        # Binding topology: A -> B -> C -> D only, a strict chain.
        # A never gossips to C or D; B never gossips to D.
        seed_peer(tmp_a, b_pub, URL_B, "belt-node-b")
        seed_peer(tmp_b, a_pub, URL_A, "belt-node-a")
        seed_peer(tmp_b, c_pub, URL_C, "belt-node-c")
        seed_peer(tmp_c, b_pub, URL_B, "belt-node-b")
        seed_peer(tmp_c, d_pub, URL_D, "belt-node-d")
        seed_peer(tmp_d, c_pub, URL_C, "belt-node-c")

        now = datetime.now(timezone.utc)
        code, sig1, issued1, expires1 = claim(
            PORT_A, LABEL, k1_priv, k1_pub,
            now - timedelta(minutes=5), now + timedelta(days=30))
        check("A claims kept-key name under K1 via real route",
              code == 200, f"got {code}")
        code, _ = get(PORT_D, f"/api/v1/names/{LABEL}")
        check("D has never heard of it before gossip", code == 404,
              f"got {code}")

        out = run_helper(tmp_a, a_priv, {}, "core._names_gossip_out()")
        check("A gossip ran to 1 recipient", "sent: 1" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, served_b = wait_served(PORT_B, LABEL, sig1)
        check("B serves the binding byte-identical", code == 200
              and served_b.get("node_pubkey") == k1_pub,
              f"got {code} {served_b}")
        out = run_helper(tmp_b, b_priv, {}, "core._names_gossip_out()")
        check("B gossip onward ran to 2 recipients",
              "sent: 2" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, served_c = wait_served(PORT_C, LABEL, sig1)
        check("C serves the binding byte-identical (learned via B)",
              code == 200 and served_c.get("node_pubkey") == k1_pub
              and served_c.get("issued_at") == issued1
              and served_c.get("expires_at") == expires1,
              f"got {code} {served_c}")
        code, _ = get(PORT_D, f"/api/v1/names/{LABEL}")
        check("D still has never heard of it before C's leg",
              code == 404, f"got {code}")
        out = run_helper(tmp_c, c_priv, {}, "core._names_gossip_out()")
        check("C gossip onward ran to 2 recipients",
              "sent: 2" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, served_d = wait_served(PORT_D, LABEL, sig1)
        check("D serves the binding byte-identical (learned via C, "
              "third hop)",
              code == 200 and served_d.get("node_pubkey") == k1_pub
              and served_d.get("issued_at") == issued1
              and served_d.get("expires_at") == expires1,
              f"got {code} {served_d}")
        check("belt re-verifies D's binding against K1",
              verify(k1_pub, served_d.get("signature", ""), LABEL,
                     issued1, expires1))

        code, _ = get(PORT_D, f"/api/v1/names/{LABEL}/reach")
        check("D serves no reach descriptor before announce",
              code == 404, f"got {code}")
        check("resolve via D with binding only is silence",
              resolve_fresh(LABEL, URL_D) is None)

        seed_peer(tmp_a, d_pub, URL_D, "belt-node-d")
        daemon1 = threading.Thread(
            target=hold_open.hold_open_cycle,
            args=(URL_R, TOK1, k1_priv.hex(), stop1),
            kwargs={"keepalive_every": 60.0}, daemon=True)
        daemon1.start()
        time.sleep(1.0)
        out = reach_out(tmp_a, a_priv, k1_priv.hex(), r_pub, TOK1)
        check("A reach announce under K1 ran to 2 recipients",
              "sent: 2" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, desc = wait_reach(PORT_D, LABEL, k1_pub)
        check("D serves the K1 rendezvous descriptor", code == 200
              and desc.get("node_pubkey") == k1_pub,
              f"got {code} {desc}")
        strats = [s for s in (desc.get("reach") or [])
                  if isinstance(s, dict)]
        relay_s = [s for s in strats if s.get("kind") == "relay"]
        rz_s = [s for s in strats if s.get("kind") == "rendezvous"]
        check("D descriptor carries relay + rendezvous, no direct",
              len(strats) == 2 and len(relay_s) == 1
              and relay_s[0].get("url") == URL_R
              and relay_s[0].get("relay") == r_pub
              and relay_s[0].get("token") == TOK1,
              f"reach={desc.get('reach')}")
        check("rendezvous strategy advertises epoch_len=600 + hold_query",
              len(rz_s) == 1 and rz_s[0].get("epoch_len") == EPOCH_LEN
              and rz_s[0].get("hold_query") == "/relay/hold_query",
              f"reach={desc.get('reach')}")
        pts = _rz.derive_points(time.time(), k1_pub, EPOCH_LEN) or []
        held = any(get(PORT_R, "/relay/hold_query?point_id=" + p)[1].get("held") is True for p in pts)
        check("relay R holds a derived point under advertised 600-math", held, f"points={pts}")
        pts3600 = _rz.derive_points(time.time(), k1_pub, 3600) or []
        held3600 = any(get(PORT_R, "/relay/hold_query?point_id=" + p)[1].get("held") is True for p in pts3600)
        check("no point held under frozen 3600-math (advertised only)", not held3600, f"points={pts3600}")

        got = resolve_fresh(LABEL, URL_D)
        check("resolve via third hop D returns K1 via relay R (rendezvous)",
              isinstance(got, dict) and got.get("node_pubkey") == k1_pub
              and got.get("node_url") == URL_R
              and got.get("via_relay") == {"relay_pub": r_pub,
                                           "token": TOK1}
              and got.get("issued_at") == issued1
              and got.get("expires_at") == expires1,
              f"got {got}")
        check("unclaimed label resolves via D to silence",
              resolve_fresh("nobodyclaimedit", URL_D) is None)
    finally:
        stop1.set()
        for p in (proc_a, proc_b, proc_c, proc_d, proc_r):
            p.terminate()
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()

    print(f"\n{CASES['passed']} passed, {CASES['failed']} failed")
    sys.exit(1 if CASES["failed"] else 0)


if __name__ == "__main__":
    main()
