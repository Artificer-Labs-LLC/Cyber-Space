"""Belt: FIVE-HOP gossip chain + KEY ROTATION + RENDEZVOUS resolve e2e
(primitives 1 naming + 2 resolution + 3 hosting + 4 identity).

The last five-hop rotation cell: rotation at five hops carried
direct (2655102) and relay (8128d43) only; a NAT-hidden owner whose
only path is a rendezvous hold was unproven. Rotation is the
dangerous lifecycle event here: the successor key must cross five
mirrors by recorded designation, rotation must ORPHAN the
rendezvous path at the far end (the relay still holds a derived
point under the dead key's advertised epoch math, yet no resolve
may use it), and only a fresh K2 hold + K2 rendezvous announce
may restore resolution.

Seven INDEPENDENT nodes (separate DBs, separate node keys):
A owner (NAT-hidden), B, C, D, E intermediaries in series, F far
resolver, R relay.

  1. A claims the label under K1 via the real claim route;
     gossip A->B, B->C, C->D, D->E, E->F strictly in series; every
     hop serves K1 byte-identical; the next node still 404s until
     its predecessor's leg runs; belt re-verifies K1 at F
  2. F serves no /reach yet; resolve via F with the binding only
     is silence (a binding alone never guesses an address)
  3. A holds at relay R under TOK1 and announces a K1
     relay+rendezvous descriptor (epoch_len 600, owner announce,
     not gossip); F serves relay+rendezvous and no direct; R holds
     a derived point under the advertised 600-math only; resolve
     via fifth hop F returns K1 via_relay TOK1 at R
  4. A rotates K1 -> K2 via the real rotate route; gossip replaces
     K1 hop by hop in series only as each leg runs; proof-less K2
     fed to F's real merge returns conflict; F records the
     rotation hop and re-verifies K2
  5. F /reach for the stale K1 descriptor reads 404 and resolve
     via F is silence -- even though R still holds the K1 derived
     point under the 600-math (rotation orphans the rendezvous
     path at the fifth hop); stale K1 re-announce changes
     nothing; A holds at R under fresh TOK2 and announces K2
     rendezvous, R holds a 600-derived point under K2, restoring
     resolve via F returning K2 via_relay TOK2 at R
  6. An unclaimed label resolves via F to silence

Test-only allowances, twin of the parent belts: helper/belt
processes patch core._reject_nonpublic_node_url to admit the
loopback node URLs only, and the belt clears core._resolve_memo
between resolves. The genesis name is never touched.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/five-hop-rotation-rendezvous-resolve-e2e-belt-test.py
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
from rotate_name import mint_rotation  # noqa: E402

CASES = {"passed": 0, "failed": 0}
NAMES = ("A", "B", "C", "D", "E", "F")
PORTS = {n: 19041 + i for i, n in enumerate(NAMES)}
URLS = {n: f"http://127.0.0.1:{PORTS[n]}" for n in NAMES}
LABEL = "fivehoprotarz"
PORT_R = 19047
URL_R = f"http://127.0.0.1:{PORT_R}"
EPOCH_LEN = 600
os.environ["CYBERNET_RENDEZVOUS_EPOCH_LEN"] = str(EPOCH_LEN)
TOK1 = "tok1-" + secrets.token_hex(8)
TOK2 = "tok2-" + secrets.token_hex(8)

_real_gate = core._reject_nonpublic_node_url


def _gate(url):
    if isinstance(url, str) and url.startswith(tuple(URLS.values()) + (URL_R,)):
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
    urls = ", ".join(repr(u) for u in list(URLS.values()) + [URL_R])
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


def check_descriptor(tag, desc, tok):
    strats = [s for s in (desc.get("reach") or []) if isinstance(s, dict)]
    relay_strats = [x for x in strats if x.get("kind") == "relay"]
    rz_strats = [x for x in strats if x.get("kind") == "rendezvous"]
    check(f"{tag} descriptor carries relay + rendezvous, no direct",
          len(strats) == 2 and len(relay_strats) == 1
          and relay_strats[0].get("url") == URL_R
          and relay_strats[0].get("relay") == _r_pub
          and relay_strats[0].get("token") == tok,
          f"reach={desc.get('reach')}")
    check(f"{tag} rendezvous strategy advertises epoch_len=600 + hold_query",
          len(rz_strats) == 1
          and rz_strats[0].get("epoch_len") == EPOCH_LEN
          and rz_strats[0].get("hold_query") == "/relay/hold_query",
          f"reach={desc.get('reach')}")


def check_held(tag, pub):
    pts600 = _rz.derive_points(time.time(), pub, EPOCH_LEN) or []
    held600 = any(
        get(PORT_R, "/relay/hold_query?point_id=" + p)[1].get("held") is True
        for p in pts600)
    check(f"relay holds a derived point under {tag} advertised 600-math",
          held600, f"points={pts600}")
    pts3600 = _rz.derive_points(time.time(), pub, 3600) or []
    held3600 = any(
        get(PORT_R, "/relay/hold_query?point_id=" + p)[1].get("held") is True
        for p in pts3600)
    check(f"no point held under {tag} frozen 3600-math (advertised only)",
          not held3600, f"points={pts3600}")


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


_r_pub = ""


def main():
    global _r_pub
    tmps, privs, pubs, procs = {}, {}, {}, {}
    for n in NAMES:
        tmps[n] = tempfile.mkdtemp(prefix=f"5hop-rotarz-{n.lower()}-")
        privs[n] = secrets.token_hex(32)
        pubs[n] = publickey(bytes.fromhex(privs[n])).hex()
    tmp_r = tempfile.mkdtemp(prefix="5hop-rotarz-r-")
    priv_r = secrets.token_hex(32)
    pub_r = publickey(bytes.fromhex(priv_r)).hex()
    _r_pub = pub_r
    k1_priv = bytes.fromhex(secrets.token_hex(32))
    k1_pub = publickey(k1_priv).hex()
    k2_priv = bytes.fromhex(secrets.token_hex(32))
    k2_pub = publickey(k2_priv).hex()

    ups = {}
    for n in NAMES:
        procs[n], ups[n] = boot(tmps[n], privs[n], PORTS[n])
    proc_r, up_r = boot(tmp_r, priv_r, PORT_R)
    stop1 = threading.Event()
    stop2 = threading.Event()
    try:
        check("seven independent nodes boot", all(ups.values()) and up_r)
        if not (all(ups.values()) and up_r):
            return
        # strict chain seeding: each node knows only its neighbours
        for i, n in enumerate(NAMES):
            if i > 0:
                seed_peer(tmps[n], pubs[NAMES[i - 1]],
                          URLS[NAMES[i - 1]],
                          f"belt-node-{NAMES[i - 1].lower()}")
            if i < len(NAMES) - 1:
                seed_peer(tmps[n], pubs[NAMES[i + 1]],
                          URLS[NAMES[i + 1]],
                          f"belt-node-{NAMES[i + 1].lower()}")

        now = datetime.now(timezone.utc)
        code, sig1, issued1, expires1 = claim(
            PORTS["A"], LABEL, k1_priv, k1_pub,
            now - timedelta(minutes=10), now + timedelta(days=30))
        check("A claims kept-key name under K1 via real route",
              code == 200, f"got {code}")
        code, _ = get(PORTS["F"], f"/api/v1/names/{LABEL}")
        check("F has never heard of it before gossip", code == 404,
              f"got {code}")

        legs = (("A", 1), ("B", 2), ("C", 2), ("D", 2), ("E", 2))
        for src, want in legs:
            dst = NAMES[NAMES.index(src) + 1]
            out = run_helper(tmps[src], privs[src], {},
                             "core._names_gossip_out()")
            check(f"{src} gossip K1 ran to {want} recipient(s)",
                  f"sent: {want}" in out.stdout,
                  f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
            code, served = wait_served(PORTS[dst], LABEL, sig1)
            check(f"{dst} serves K1 byte-identical (learned via {src})",
                  code == 200 and served.get("node_pubkey") == k1_pub
                  and served.get("issued_at") == issued1
                  and served.get("expires_at") == expires1,
                  f"got {code} {served}")
            nxt_i = NAMES.index(dst) + 1
            if nxt_i < len(NAMES):
                nxt = NAMES[nxt_i]
                code, _ = get(PORTS[nxt], f"/api/v1/names/{LABEL}")
                check(f"{nxt} still 404 before {dst}'s leg runs",
                      code == 404, f"got {code}")
        code, served_f1 = get(PORTS["F"], f"/api/v1/names/{LABEL}")
        check("belt re-verifies F's K1 binding against K1",
              verify(k1_pub, served_f1.get("signature", ""), LABEL,
                     issued1, expires1))

        code, _ = get(PORTS["F"], f"/api/v1/names/{LABEL}/reach")
        check("F serves no reach descriptor before announce",
              code == 404, f"got {code}")
        check("resolve via F with binding only is silence",
              resolve_fresh(LABEL, URLS["F"]) is None)

        seed_peer(tmps["A"], pubs["F"], URLS["F"], "belt-node-f")
        daemon1 = threading.Thread(
            target=hold_open.hold_open_cycle,
            args=(URL_R, TOK1, k1_priv.hex(), stop1),
            kwargs={"keepalive_every": 60.0}, daemon=True)
        daemon1.start()
        time.sleep(1.0)
        out = reach_out(tmps["A"], privs["A"], k1_priv.hex(), pub_r, TOK1)
        check("A rendezvous announce under K1 ran to 2 recipients",
              "sent: 2" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, desc = wait_reach(PORTS["F"], LABEL, k1_pub)
        check("F serves the K1 rendezvous descriptor", code == 200
              and desc.get("node_pubkey") == k1_pub,
              f"got {code} {desc}")
        check_descriptor("F K1", desc, TOK1)
        check_held("K1", k1_pub)
        got = resolve_fresh(LABEL, URLS["F"])
        check("resolve via fifth hop F returns K1 via relay R",
              isinstance(got, dict) and got.get("node_pubkey") == k1_pub
              and got.get("node_url") == URL_R
              and got.get("via_relay") == {"relay_pub": pub_r, "token": TOK1}
              and got.get("issued_at") == issued1
              and got.get("expires_at") == expires1,
              f"got {got}")
        unseed_peer(tmps["A"], pubs["F"])

        code, resp, rec1, sig2, issued2, expires2 = rotate(
            PORTS["A"], LABEL, k1_priv, k1_pub, k2_priv, k2_pub,
            now - timedelta(minutes=6), now - timedelta(minutes=5),
            now + timedelta(days=60))
        check("A rotates K1 -> K2 via real rotate route",
              code == 200 and resp.get("status") == "rotated",
              f"got {code} {resp}")

        out = run_helper(tmps["A"], privs["A"], {},
                         "core._names_gossip_out()")
        check("A gossip K2 ran to 1 recipient", "sent: 1" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, served_b2 = wait_served(PORTS["B"], LABEL, sig2)
        check("B REPLACED live K1 with designated K2",
              code == 200 and served_b2.get("node_pubkey") == k2_pub
              and served_b2.get("issued_at") == issued2
              and served_b2.get("expires_at") == expires2,
              f"got {code} {served_b2}")
        for n in ("C", "D", "E", "F"):
            code, served_x = get(PORTS[n], f"/api/v1/names/{LABEL}")
            check(f"{n} still serves K1 (rotation crossed one hop only)",
                  code == 200 and served_x.get("signature") == sig1,
                  f"got {code} {served_x}")

        bare = {"name": LABEL, "node_pubkey": k2_pub,
                "issued_at": issued2, "expires_at": expires2,
                "signature": sig2}
        res = ingest_on(tmps["F"], privs["F"], bare)
        check("proof-less K2 binding merge on F returns conflict",
              res.stdout.strip().endswith("conflict"),
              f"stdout={res.stdout!r} stderr={res.stderr[-400:]!r}")
        code, served_fx = get(PORTS["F"], f"/api/v1/names/{LABEL}")
        check("F still serves K1 after proof-less attempt",
              code == 200 and served_fx.get("signature") == sig1,
              f"got {code} {served_fx}")

        for src in ("B", "C", "D", "E"):
            dst = NAMES[NAMES.index(src) + 1]
            out = run_helper(tmps[src], privs[src], {},
                             "core._names_gossip_out()")
            check(f"{src} gossip K2 onward ran to 2 recipients",
                  "sent: 2" in out.stdout,
                  f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
            code, served_d2 = wait_served(PORTS[dst], LABEL, sig2)
            check(f"{dst} REPLACED live K1 with K2 learned onward"
                  f" from {src}",
                  code == 200
                  and served_d2.get("node_pubkey") == k2_pub
                  and served_d2.get("issued_at") == issued2
                  and served_d2.get("expires_at") == expires2,
                  f"got {code} {served_d2}")
            nxt_i = NAMES.index(dst) + 1
            if nxt_i < len(NAMES):
                nxt = NAMES[nxt_i]
                code, served_nx = get(PORTS[nxt],
                                      f"/api/v1/names/{LABEL}")
                check(f"{nxt} still serves K1 before {dst}'s leg runs",
                      code == 200
                      and served_nx.get("signature") == sig1,
                      f"got {code} {served_nx}")
        code, served_f2 = get(PORTS["F"], f"/api/v1/names/{LABEL}")
        check("belt re-verifies F's K2 binding against K2",
              verify(k2_pub, served_f2.get("signature", ""), LABEL,
                     issued2, expires2))
        code, rots_f = get(PORTS["F"], f"/api/v1/names/{LABEL}/rotations")
        hops_f = rots_f.get("rotations", []) if code == 200 else []
        check("F recorded the K1 -> K2 hop",
              code == 200 and len(hops_f) == 1
              and hops_f[0].get("old_pubkey") == k1_pub
              and hops_f[0].get("new_pubkey") == k2_pub,
              f"got {code} {rots_f}")

        seed_peer(tmps["A"], pubs["F"], URLS["F"], "belt-node-f")
        code, _ = get(PORTS["F"], f"/api/v1/names/{LABEL}/reach")
        check("F /reach for stale K1 descriptor reads 404 "
              "(rotation orphans the rendezvous path at fifth hop)",
              code == 404, f"got {code}")
        check("resolve via fifth hop F after rotation is silence",
              resolve_fresh(LABEL, URLS["F"]) is None)
        check_held("orphaned K1", k1_pub)
        out = reach_out(tmps["A"], privs["A"], k1_priv.hex(), pub_r, TOK1)
        check("stale K1 rendezvous re-announce ran to 2 recipients",
              "sent: 2" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, _ = get(PORTS["F"], f"/api/v1/names/{LABEL}/reach")
        check("F still serves no descriptor after stale K1 re-announce",
              code == 404, f"got {code}")
        check("resolve via F still silence after stale K1 re-announce",
              resolve_fresh(LABEL, URLS["F"]) is None)

        daemon2 = threading.Thread(
            target=hold_open.hold_open_cycle,
            args=(URL_R, TOK2, k2_priv.hex(), stop2),
            kwargs={"keepalive_every": 60.0}, daemon=True)
        daemon2.start()
        time.sleep(1.0)
        out = reach_out(tmps["A"], privs["A"], k2_priv.hex(), pub_r, TOK2)
        check("A rendezvous announce under K2 ran to 2 recipients",
              "sent: 2" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, desc = wait_reach(PORTS["F"], LABEL, k2_pub)
        check("F serves the K2 rendezvous descriptor", code == 200
              and desc.get("node_pubkey") == k2_pub,
              f"got {code} {desc}")
        check_descriptor("F K2", desc, TOK2)
        check_held("K2", k2_pub)
        got = resolve_fresh(LABEL, URLS["F"])
        check("resolve via fifth hop F returns K2 via relay R (TOK2)",
              isinstance(got, dict) and got.get("node_pubkey") == k2_pub
              and got.get("node_url") == URL_R
              and got.get("via_relay") == {"relay_pub": pub_r, "token": TOK2}
              and got.get("issued_at") == issued2
              and got.get("expires_at") == expires2,
              f"got {got}")
        check("unclaimed label resolves via F to silence",
              resolve_fresh("nobodyclaimedit", URLS["F"]) is None)
    finally:
        stop1.set()
        stop2.set()
        proc_r.terminate()
        try:
            proc_r.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc_r.kill()
        for p in procs.values():
            p.terminate()
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()

    print(f"\n{CASES['passed']} passed, {CASES['failed']} failed")
    sys.exit(1 if CASES["failed"] else 0)


if __name__ == "__main__":
    main()
