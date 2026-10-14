"""Belt: NINE-HOP gossip chain + KEY ROTATION + DIRECT resolve e2e
(primitives 1 naming + 2 resolution + 3 hosting + 4 identity).

Nine-hop panels so far: direct/relay/rendezvous base resolves and
same-key RENEWAL over direct/relay/rendezvous -- the nine-hop
renewal matrix is complete, but no nine-hop binding has ever been
ROTATED. Rotation is the dangerous lifecycle event: the successor
key must be carried by recorded designation, not bare assertion,
across nine mirrors, and rotation must ORPHAN the direct path at
the far end (unlike renewal, which preserves it). This belt joins
rotation x direct at nine hops, opening the nine-hop rotation
matrix.

Ten INDEPENDENT nodes (separate DBs, separate node keys):
A owner (publicly reachable hoster), B, C, D, E, F, G, H, I
intermediaries in series, J far resolver.

  1. A claims the label under K1 via the real claim route;
     gossip A->B, B->C, C->D, D->E, E->F, F->G, G->H, H->I, I->J
     strictly in series; every hop serves K1 byte-identical; the
     next node still 404s until its predecessor's leg runs; belt
     re-verifies K1 at J
  2. J serves no /reach yet; resolve via J with the binding only
     is silence (a binding alone never guesses an address)
  3. A announces a K1 direct-only descriptor (owner announce, not
     gossip); J serves ONLY the direct strategy at A's URL;
     resolve via ninth hop J returns K1 direct at A
  4. A rotates K1 -> K2 via the real rotate route; gossip replaces
     K1 hop by hop in series only as each leg runs; proof-less K2
     fed to J's real merge returns conflict; J records the
     rotation hop and re-verifies K2
  5. J /reach for the stale K1 descriptor reads 404 and resolve
     via J is silence (rotation orphans the direct path at the
     ninth hop); stale K1 re-announce changes nothing; K2 direct
     re-announce restores resolve via J returning K2 direct at A
  6. An unclaimed label resolves via J to silence

Test-only allowances, twin of the parent belts: helper/belt
processes patch core._reject_nonpublic_node_url to admit the
loopback node URLs only, and the belt clears core._resolve_memo
between resolves. The genesis name is never touched.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/nine-hop-rotation-direct-resolve-e2e-belt-test.py
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
import core  # noqa: E402
from core import _name_claim_payload  # noqa: E402
from rotate_name import mint_rotation  # noqa: E402

CASES = {"passed": 0, "failed": 0}
NAMES = ("A", "B", "C", "D", "E", "F", "G", "H", "I", "J")
PORTS = {n: 20101 + i for i, n in enumerate(NAMES)}
URLS = {n: f"http://127.0.0.1:{PORTS[n]}" for n in NAMES}
LABEL = "ninehoprotadir"

_real_gate = core._reject_nonpublic_node_url


def _gate(url):
    if isinstance(url, str) and url.startswith(tuple(URLS.values())):
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
    urls = ", ".join(repr(u) for u in URLS.values())
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


def reach_out_to_j(k_priv_hex):
    return run_helper(
        tmps["A"], privs["A"],
        {"CYBERNET_HOSTED_NAME": LABEL,
         "CYBERNET_NAME_PRIVKEY": k_priv_hex,
         "CYBERNET_PUBLIC_URL": URLS["A"]},
        "core._reach_out()")


tmps, privs, pubs = {}, {}, {}


def main():
    global tmps, privs, pubs
    procs = {}
    for n in NAMES:
        tmps[n] = tempfile.mkdtemp(prefix=f"9hop-rotadir-{n.lower()}-")
        privs[n] = secrets.token_hex(32)
        pubs[n] = publickey(bytes.fromhex(privs[n])).hex()
    k1_priv = bytes.fromhex(secrets.token_hex(32))
    k1_pub = publickey(k1_priv).hex()
    k2_priv = bytes.fromhex(secrets.token_hex(32))
    k2_pub = publickey(k2_priv).hex()

    ups = {}
    for n in NAMES:
        procs[n], ups[n] = boot(tmps[n], privs[n], PORTS[n])
    try:
        check("ten independent nodes boot", all(ups.values()))
        if not all(ups.values()):
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
        code, _ = get(PORTS["J"], f"/api/v1/names/{LABEL}")
        check("J has never heard of it before gossip", code == 404,
              f"got {code}")

        legs = (("A", 1), ("B", 2), ("C", 2), ("D", 2), ("E", 2), ("F", 2), ("G", 2), ("H", 2), ("I", 2))
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
        code, served_j1 = get(PORTS["J"], f"/api/v1/names/{LABEL}")
        check("belt re-verifies J's K1 binding against K1",
              verify(k1_pub, served_j1.get("signature", ""), LABEL,
                     issued1, expires1))

        code, _ = get(PORTS["J"], f"/api/v1/names/{LABEL}/reach")
        check("J serves no reach descriptor before announce",
              code == 404, f"got {code}")
        check("resolve via J with binding only is silence",
              resolve_fresh(LABEL, URLS["J"]) is None)

        seed_peer(tmps["A"], pubs["J"], URLS["J"], "belt-node-j")
        out = reach_out_to_j(k1_priv.hex())
        check("A reach announce under K1 ran to 2 recipients",
              "sent: 2" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, desc = wait_reach(PORTS["J"], LABEL, k1_pub)
        check("J serves the K1 reach descriptor", code == 200
              and desc.get("node_pubkey") == k1_pub,
              f"got {code} {desc}")
        strats = [s for s in (desc.get("reach") or [])
                  if isinstance(s, dict)]
        check("J descriptor carries ONLY the direct strategy",
              len(strats) == 1 and strats[0].get("kind") == "direct"
              and strats[0].get("url") == URLS["A"],
              f"reach={desc.get('reach')}")
        got = resolve_fresh(LABEL, URLS["J"])
        check("resolve via ninth hop J returns K1 direct at A",
              isinstance(got, dict) and got.get("node_pubkey") == k1_pub
              and got.get("node_url") == URLS["A"]
              and "via_relay" not in got
              and got.get("issued_at") == issued1
              and got.get("expires_at") == expires1,
              f"got {got}")
        unseed_peer(tmps["A"], pubs["J"])

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
        for n in ("C", "D", "E", "F", "G", "H", "I", "J"):
            code, served_x = get(PORTS[n], f"/api/v1/names/{LABEL}")
            check(f"{n} still serves K1 (rotation crossed one hop only)",
                  code == 200 and served_x.get("signature") == sig1,
                  f"got {code} {served_x}")

        bare = {"name": LABEL, "node_pubkey": k2_pub,
                "issued_at": issued2, "expires_at": expires2,
                "signature": sig2}
        res = ingest_on(tmps["J"], privs["J"], bare)
        check("proof-less K2 binding merge on J returns conflict",
              res.stdout.strip().endswith("conflict"),
              f"stdout={res.stdout!r} stderr={res.stderr[-400:]!r}")
        code, served_jx = get(PORTS["J"], f"/api/v1/names/{LABEL}")
        check("J still serves K1 after proof-less attempt",
              code == 200 and served_jx.get("signature") == sig1,
              f"got {code} {served_jx}")

        # remaining legs in series: B->C, C->D, D->E, E->F, F->G, G->H, H->I, I->J
        for src in ("B", "C", "D", "E", "F", "G", "H", "I"):
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
        code, served_j2 = get(PORTS["J"], f"/api/v1/names/{LABEL}")
        check("belt re-verifies J's K2 binding against K2",
              verify(k2_pub, served_j2.get("signature", ""), LABEL,
                     issued2, expires2))
        code, rots_j = get(PORTS["J"], f"/api/v1/names/{LABEL}/rotations")
        hops_j = rots_j.get("rotations", []) if code == 200 else []
        check("J recorded the K1 -> K2 hop",
              code == 200 and len(hops_j) == 1
              and hops_j[0].get("old_pubkey") == k1_pub
              and hops_j[0].get("new_pubkey") == k2_pub,
              f"got {code} {rots_j}")

        seed_peer(tmps["A"], pubs["J"], URLS["J"], "belt-node-j")
        code, _ = get(PORTS["J"], f"/api/v1/names/{LABEL}/reach")
        check("J /reach for stale K1 descriptor reads 404 "
              "(rotation orphans the direct path at ninth hop)",
              code == 404, f"got {code}")
        check("resolve via ninth hop J after rotation is silence",
              resolve_fresh(LABEL, URLS["J"]) is None)
        out = reach_out_to_j(k1_priv.hex())
        check("stale K1 reach re-announce ran to 2 recipients",
              "sent: 2" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, _ = get(PORTS["J"], f"/api/v1/names/{LABEL}/reach")
        check("J still serves no descriptor after stale K1 re-announce",
              code == 404, f"got {code}")
        check("resolve via J still silence after stale K1 re-announce",
              resolve_fresh(LABEL, URLS["J"]) is None)
        out = reach_out_to_j(k2_priv.hex())
        check("A reach announce under K2 ran to 2 recipients",
              "sent: 2" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, desc = wait_reach(PORTS["J"], LABEL, k2_pub)
        check("J serves the K2 reach descriptor", code == 200
              and desc.get("node_pubkey") == k2_pub,
              f"got {code} {desc}")
        strats = [s for s in (desc.get("reach") or [])
                  if isinstance(s, dict)]
        check("J K2 descriptor carries ONLY the direct strategy",
              len(strats) == 1 and strats[0].get("kind") == "direct"
              and strats[0].get("url") == URLS["A"],
              f"reach={desc.get('reach')}")
        got = resolve_fresh(LABEL, URLS["J"])
        check("resolve via ninth hop J returns K2 direct at A",
              isinstance(got, dict) and got.get("node_pubkey") == k2_pub
              and got.get("node_url") == URLS["A"]
              and "via_relay" not in got
              and got.get("issued_at") == issued2
              and got.get("expires_at") == expires2,
              f"got {got}")
        check("unclaimed label resolves via J to silence",
              resolve_fresh("nobodyclaimedit", URLS["J"]) is None)
    finally:
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
