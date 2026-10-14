"""Belt: THREE-HOP gossip chain + KEY ROTATION + RELAY resolve e2e
(primitives 1 naming + 2 resolution + 3 hosting + 4 identity).

Three-hop rotation panels carried a direct descriptor; three-hop
relay panels never rotated. Never proven together: a NAT-hidden
owner's binding rotated to a successor key, carried a THIRD hop to
a far resolver -- rotation orphans the relay path there (the K1
descriptor and its TOK1 hold answer for a retired key), a stale K1
re-announce restores nothing, and only a fresh K2 hold under TOK2
plus a K2 re-announce restores resolve via the relay.

Five INDEPENDENT nodes (separate DBs, separate node keys):
A owner (NAT-hidden), B and C intermediaries in series, D far
resolver, R relay.

  1. A claims the label under K1 via the real claim route;
     gossip A->B, B->C, C->D in series; every hop serves K1
     byte-identical; D still 404s until C's leg runs; belt
     re-verifies K1 at D
  2. D serves no /reach yet; resolve via D with the binding only
     is silence (a binding alone never guesses an address)
  3. A holds at relay R under TOK1 and announces a K1 relay-only
     descriptor (owner announce, not gossip); D serves ONLY the
     relay strategy; resolve via third hop D returns K1 via_relay
     TOK1 at R
  4. A rotates K1 -> K2 via the real rotate route; gossip replaces
     K1 hop by hop in series only as each leg runs; proof-less K2
     fed to D's real merge half returns conflict; D records the
     rotation hop and re-verifies K2
  5. D /reach for the stale K1 descriptor reads 404 and resolve
     via D is silence (rotation orphans the relay path); stale K1
     re-announce changes nothing; A holds at R under K2 with TOK2
     and re-announces; D serves the K2 relay descriptor and
     resolve via D returns K2 via_relay TOK2 at R
  6. An unclaimed label resolves via D to silence

Test-only allowances, twin of the parent belts: helper/belt
processes patch core._reject_nonpublic_node_url to admit the
loopback node URLs only, and the belt clears core._resolve_memo
between resolves. The genesis name is never touched.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/three-hop-rotation-relay-resolve-e2e-belt-test.py
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
from core import _name_claim_payload  # noqa: E402
from rotate_name import mint_rotation  # noqa: E402

CASES = {"passed": 0, "failed": 0}
PORT_A, PORT_B, PORT_C, PORT_D, PORT_R = 19021, 19022, 19023, 19024, 19025
URL_A = f"http://127.0.0.1:{PORT_A}"
URL_B = f"http://127.0.0.1:{PORT_B}"
URL_C = f"http://127.0.0.1:{PORT_C}"
URL_D = f"http://127.0.0.1:{PORT_D}"
URL_R = f"http://127.0.0.1:{PORT_R}"
URLS = (URL_A, URL_B, URL_C, URL_D, URL_R)
LABEL = "threehoprotarelay"
TOK1 = "tok1-" + secrets.token_hex(8)
TOK2 = "tok2-" + secrets.token_hex(8)

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


def unseed_peer(tmp, pub):
    conn = sqlite3.connect(os.path.join(tmp, "cybernet.db"))
    conn.execute("DELETE FROM peers WHERE node_pub=?", (pub,))
    conn.commit()
    conn.close()


def ingest_on(tmp, priv, binding):
    helper = (
        "import core\n"
        f"print(core.ingest_gossiped_binding({binding!r}))\n")
    env = dict(os.environ, CYBERNET_DB_DIR=tmp,
               CYBERNET_NODE_PRIVKEY=priv)
    return subprocess.run(
        [os.path.join(REPO, "venv/bin/python"), "-c", helper],
        cwd=REPO, env=env, capture_output=True, text=True, timeout=60)


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
         "CYBERNET_RELAY_TOKEN": tok},
        "core._reach_out()")


def main():
    tmp_a = tempfile.mkdtemp(prefix="3hop-rotarelay-a-")
    tmp_b = tempfile.mkdtemp(prefix="3hop-rotarelay-b-")
    tmp_c = tempfile.mkdtemp(prefix="3hop-rotarelay-c-")
    tmp_d = tempfile.mkdtemp(prefix="3hop-rotarelay-d-")
    tmp_r = tempfile.mkdtemp(prefix="3hop-rotarelay-r-")
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
    k2_priv = bytes.fromhex(secrets.token_hex(32))
    k2_pub = publickey(k2_priv).hex()

    proc_a, up_a = boot(tmp_a, a_priv, PORT_A)
    proc_b, up_b = boot(tmp_b, b_priv, PORT_B)
    proc_c, up_c = boot(tmp_c, c_priv, PORT_C)
    proc_d, up_d = boot(tmp_d, d_priv, PORT_D)
    proc_r, up_r = boot(tmp_r, r_priv, PORT_R)
    stop1, stop2 = threading.Event(), threading.Event()
    try:
        check("five independent nodes boot",
              up_a and up_b and up_c and up_d and up_r)
        if not (up_a and up_b and up_c and up_d and up_r):
            return
        seed_peer(tmp_a, b_pub, URL_B, "belt-node-b")
        seed_peer(tmp_b, a_pub, URL_A, "belt-node-a")
        seed_peer(tmp_b, c_pub, URL_C, "belt-node-c")
        seed_peer(tmp_c, b_pub, URL_B, "belt-node-b")
        seed_peer(tmp_c, d_pub, URL_D, "belt-node-d")
        seed_peer(tmp_d, c_pub, URL_C, "belt-node-c")

        now = datetime.now(timezone.utc)
        code, sig1, issued1, expires1 = claim(
            PORT_A, LABEL, k1_priv, k1_pub,
            now - timedelta(minutes=10), now + timedelta(days=30))
        check("A claims kept-key name under K1 via real route",
              code == 200, f"got {code}")
        code, _ = get(PORT_D, f"/api/v1/names/{LABEL}")
        check("D has never heard of it before gossip", code == 404,
              f"got {code}")

        out = run_helper(tmp_a, a_priv, {}, "core._names_gossip_out()")
        check("A gossip K1 ran to 1 recipient", "sent: 1" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, served_b1 = wait_served(PORT_B, LABEL, sig1)
        check("B serves K1 byte-identical",
              code == 200 and served_b1.get("node_pubkey") == k1_pub,
              f"got {code} {served_b1}")
        out = run_helper(tmp_b, b_priv, {}, "core._names_gossip_out()")
        check("B gossip K1 onward ran to 2 recipients",
              "sent: 2" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, served_c1 = wait_served(PORT_C, LABEL, sig1)
        check("C serves K1 byte-identical (learned via B)",
              code == 200 and served_c1.get("node_pubkey") == k1_pub
              and served_c1.get("issued_at") == issued1
              and served_c1.get("expires_at") == expires1,
              f"got {code} {served_c1}")
        code, _ = get(PORT_D, f"/api/v1/names/{LABEL}")
        check("D still 404 before C's leg runs", code == 404,
              f"got {code}")
        out = run_helper(tmp_c, c_priv, {}, "core._names_gossip_out()")
        check("C gossip K1 onward ran to 2 recipients",
              "sent: 2" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, served_d1 = wait_served(PORT_D, LABEL, sig1)
        check("D serves K1 byte-identical (learned via C, third hop)",
              code == 200 and served_d1.get("node_pubkey") == k1_pub
              and served_d1.get("issued_at") == issued1
              and served_d1.get("expires_at") == expires1,
              f"got {code} {served_d1}")
        check("belt re-verifies D's K1 binding against K1",
              verify(k1_pub, served_d1.get("signature", ""), LABEL,
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
        check("D serves the K1 relay descriptor", code == 200
              and desc.get("node_pubkey") == k1_pub,
              f"got {code} {desc}")
        strats = [s for s in (desc.get("reach") or [])
                  if isinstance(s, dict)]
        check("D descriptor carries ONLY the relay strategy (NAT-hidden)",
              len(strats) == 1 and strats[0].get("kind") == "relay"
              and strats[0].get("url") == URL_R
              and strats[0].get("relay") == r_pub
              and strats[0].get("token") == TOK1,
              f"reach={desc.get('reach')}")
        got = resolve_fresh(LABEL, URL_D)
        check("resolve via third hop D returns K1 via relay R",
              isinstance(got, dict) and got.get("node_pubkey") == k1_pub
              and got.get("node_url") == URL_R
              and got.get("via_relay") == {"relay_pub": r_pub,
                                           "token": TOK1}
              and got.get("issued_at") == issued1
              and got.get("expires_at") == expires1,
              f"got {got}")

        unseed_peer(tmp_a, d_pub)
        code, resp, rec1, sig2, issued2, expires2 = rotate(
            PORT_A, LABEL, k1_priv, k1_pub, k2_priv, k2_pub,
            now - timedelta(minutes=6), now - timedelta(minutes=5),
            now + timedelta(days=60))
        check("A rotates K1 -> K2 via real rotate route",
              code == 200 and resp.get("status") == "rotated",
              f"got {code} {resp}")

        out = run_helper(tmp_a, a_priv, {}, "core._names_gossip_out()")
        check("A gossip K2 ran to 1 recipient", "sent: 1" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, served_b2 = wait_served(PORT_B, LABEL, sig2)
        check("B REPLACED live K1 with designated K2",
              code == 200 and served_b2.get("node_pubkey") == k2_pub
              and served_b2.get("issued_at") == issued2
              and served_b2.get("expires_at") == expires2,
              f"got {code} {served_b2}")
        code, served_cx = get(PORT_C, f"/api/v1/names/{LABEL}")
        check("C still serves K1 (rotation crossed one hop only)",
              code == 200 and served_cx.get("signature") == sig1,
              f"got {code} {served_cx}")
        code, served_dx = get(PORT_D, f"/api/v1/names/{LABEL}")
        check("D still serves K1 (rotation crossed one hop only)",
              code == 200 and served_dx.get("signature") == sig1,
              f"got {code} {served_dx}")

        bare = {"name": LABEL, "node_pubkey": k2_pub,
                "issued_at": issued2, "expires_at": expires2,
                "signature": sig2}
        res = ingest_on(tmp_d, d_priv, bare)
        check("proof-less K2 binding merge on D returns conflict",
              res.stdout.strip().endswith("conflict"),
              f"stdout={res.stdout!r} stderr={res.stderr[-400:]!r}")
        code, served_dx = get(PORT_D, f"/api/v1/names/{LABEL}")
        check("D still serves K1 after proof-less attempt",
              code == 200 and served_dx.get("signature") == sig1,
              f"got {code} {served_dx}")

        out = run_helper(tmp_b, b_priv, {}, "core._names_gossip_out()")
        check("B gossip K2 onward ran to 2 recipients",
              "sent: 2" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, served_c2 = wait_served(PORT_C, LABEL, sig2)
        check("C REPLACED live K1 with K2 on B's recorded designation",
              code == 200 and served_c2.get("node_pubkey") == k2_pub
              and served_c2.get("issued_at") == issued2
              and served_c2.get("expires_at") == expires2,
              f"got {code} {served_c2}")
        code, served_dx = get(PORT_D, f"/api/v1/names/{LABEL}")
        check("D still serves K1 before C's leg runs",
              code == 200 and served_dx.get("signature") == sig1,
              f"got {code} {served_dx}")

        out = run_helper(tmp_c, c_priv, {}, "core._names_gossip_out()")
        check("C gossip K2 onward ran to 2 recipients",
              "sent: 2" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, served_d2 = wait_served(PORT_D, LABEL, sig2)
        check("D REPLACED live K1 with K2 (rotation survived third hop)",
              code == 200 and served_d2.get("node_pubkey") == k2_pub
              and served_d2.get("issued_at") == issued2
              and served_d2.get("expires_at") == expires2,
              f"got {code} {served_d2}")
        check("belt re-verifies D's K2 binding against K2",
              verify(k2_pub, served_d2.get("signature", ""), LABEL,
                     issued2, expires2))
        code, rots_d = get(PORT_D, f"/api/v1/names/{LABEL}/rotations")
        hops_d = rots_d.get("rotations", []) if code == 200 else []
        check("D recorded the K1 -> K2 hop",
              code == 200 and len(hops_d) == 1
              and hops_d[0].get("old_pubkey") == k1_pub
              and hops_d[0].get("new_pubkey") == k2_pub,
              f"got {code} {rots_d}")

        seed_peer(tmp_a, d_pub, URL_D, "belt-node-d")
        code, _ = get(PORT_D, f"/api/v1/names/{LABEL}/reach")
        check("D /reach for stale K1 descriptor reads 404 "
              "(rotation orphans the relay path at third hop)",
              code == 404, f"got {code}")
        check("resolve via third hop D after rotation is silence",
              resolve_fresh(LABEL, URL_D) is None)
        out = reach_out(tmp_a, a_priv, k1_priv.hex(), r_pub, TOK1)
        check("stale K1 reach re-announce ran to 2 recipients",
              "sent: 2" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, _ = get(PORT_D, f"/api/v1/names/{LABEL}/reach")
        check("D still serves no descriptor after stale K1 re-announce",
              code == 404, f"got {code}")
        check("resolve via D still silence after stale K1 re-announce",
              resolve_fresh(LABEL, URL_D) is None)

        daemon2 = threading.Thread(
            target=hold_open.hold_open_cycle,
            args=(URL_R, TOK2, k2_priv.hex(), stop2),
            kwargs={"keepalive_every": 60.0}, daemon=True)
        daemon2.start()
        time.sleep(1.0)
        out = reach_out(tmp_a, a_priv, k2_priv.hex(), r_pub, TOK2)
        check("A reach announce under K2 ran to 2 recipients",
              "sent: 2" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, desc = wait_reach(PORT_D, LABEL, k2_pub)
        check("D serves the K2 relay descriptor", code == 200
              and desc.get("node_pubkey") == k2_pub,
              f"got {code} {desc}")
        strats = [s for s in (desc.get("reach") or [])
                  if isinstance(s, dict)]
        check("D K2 descriptor carries ONLY the relay strategy (TOK2)",
              len(strats) == 1 and strats[0].get("kind") == "relay"
              and strats[0].get("url") == URL_R
              and strats[0].get("relay") == r_pub
              and strats[0].get("token") == TOK2,
              f"reach={desc.get('reach')}")
        got = resolve_fresh(LABEL, URL_D)
        check("resolve via third hop D returns K2 via relay R",
              isinstance(got, dict) and got.get("node_pubkey") == k2_pub
              and got.get("node_url") == URL_R
              and got.get("via_relay") == {"relay_pub": r_pub,
                                           "token": TOK2}
              and got.get("issued_at") == issued2
              and got.get("expires_at") == expires2,
              f"got {got}")
        check("unclaimed label resolves via D to silence",
              resolve_fresh("nobodyclaimedit", URL_D) is None)
    finally:
        stop1.set()
        stop2.set()
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
