"""Belt: SIX-HOP gossip chain + KEY ROTATION + RENDEZVOUS resolve e2e
(primitives 1 naming + 2 resolution + 3 hosting + 4 identity).

Six-hop renewal matrix is complete (direct/relay/rendezvous) and
rotation+direct is proven at six hops (5679e85) and
rotation+relay at six hops (61b0206). This joins rotation x
rendezvous at six hops -- the last six-hop rotation cell: a
NAT-hidden owner rotates, and rotation must ORPHAN the
relay+rendezvous descriptor at the far end (unlike renewal,
which preserves it) -- even though the relay still holds a
derived point under the dead key's advertised epoch math.

Eight INDEPENDENT nodes: A owner (NAT-hidden), B..F in series,
G far resolver, R relay.

  1. A claims v1 under K1; gossip in series to G byte-identical;
     belt re-verifies K1 at G; binding-only resolve is silence
  2. A holds at R under TOK1, announces K1 relay+rendezvous
     descriptor (epoch_len 600); R holds a derived point under
     the advertised 600-math only and none under frozen
     3600-math; resolve via G returns K1 via_relay TOK1 v1
  3. A rotates K1 -> K2 via the real rotate route; gossip replaces
     K1 hop by hop in series (B first while C..G still K1);
     proof-less K2 merge on G returns conflict; F leg carries K2
     to G byte-identical re-verified vs K2; G records the hop
  4. G /reach for stale K1 reads 404 and resolve via G is silence
     (rotation orphans the rendezvous path at the sixth hop,
     even though R still holds the K1 derived point under the
     600-math); stale K1 re-announce restores nothing; A holds
     under TOK2/K2 and re-announces, R holds a K2 derived point,
     resolve via G returns K2 via_relay TOK2 carrying K2 window
  5. Unclaimed label silence. Genesis never touched.
Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/six-hop-rotation-rendezvous-resolve-e2e-belt-test.py
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
NAMES = ("A", "B", "C", "D", "E", "F", "G")
PORTS = {n: 19211 + i for i, n in enumerate(NAMES)}
PORT_R = 19218
URL_R = f"http://127.0.0.1:{PORT_R}"
ALL_URLS = tuple(f"http://127.0.0.1:{19211+i}" for i in range(7)) + (URL_R,)
TOK1 = "tok1-" + secrets.token_hex(8)
TOK2 = "tok2-" + secrets.token_hex(8)
URLS = {n: f"http://127.0.0.1:{PORTS[n]}" for n in NAMES}
LABEL = "sixhoprotarz"
EPOCH_LEN = 600
os.environ["CYBERNET_RENDEZVOUS_EPOCH_LEN"] = str(EPOCH_LEN)

_real_gate = core._reject_nonpublic_node_url


def _gate(url):
    if isinstance(url, str) and url.startswith(ALL_URLS):
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
    urls = ", ".join(repr(u) for u in ALL_URLS)
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


def held_point(pub_hex, epoch_len, tries=1):
    pts = []
    for _ in range(tries):
        pts = _rz.derive_points(time.time(), pub_hex, epoch_len) or []
        if any(get(PORT_R, "/relay/hold_query?point_id=" + p)[1]
               .get("held") is True for p in pts):
            return True, pts
        time.sleep(1.0)
    return False, pts


def resolve_fresh(label, base):
    core._resolve_memo.clear()
    return core.resolve_cyberspace(label + ".cyberspace", base)


def main():
    tmps, privs, pubs, procs = {}, {}, {}, {}
    for n in NAMES:
        tmps[n] = tempfile.mkdtemp(prefix=f"6hop-rotarz-{n.lower()}-")
        privs[n] = secrets.token_hex(32)
        pubs[n] = publickey(bytes.fromhex(privs[n])).hex()
    k1_priv = bytes.fromhex(secrets.token_hex(32))
    k1_pub = publickey(k1_priv).hex()
    k2_priv = bytes.fromhex(secrets.token_hex(32))
    k2_pub = publickey(k2_priv).hex()

    tmp_r = tempfile.mkdtemp(prefix="6hop-rotarz-r-")
    r_priv = secrets.token_hex(32)
    r_pub = publickey(bytes.fromhex(r_priv)).hex()
    ups = {}
    for n in NAMES:
        procs[n], ups[n] = boot(tmps[n], privs[n], PORTS[n])
    proc_r, up_r = boot(tmp_r, r_priv, PORT_R)
    stop1 = threading.Event()
    stop2 = threading.Event()
    try:
        check("eight independent nodes boot", all(ups.values()) and up_r)
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
        code, _ = get(PORTS["G"], f"/api/v1/names/{LABEL}")
        check("G has never heard of it before gossip", code == 404,
              f"got {code}")

        # serial federation: A->B (1 recipient), then each interior
        # node gossips onward to its 2 known peers
        legs = (("A", 1), ("B", 2), ("C", 2), ("D", 2), ("E", 2), ("F", 2))
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
        code, served_f1 = get(PORTS["G"], f"/api/v1/names/{LABEL}")
        check("belt re-verifies G's K1 binding against K1",
              verify(k1_pub, served_f1.get("signature", ""), LABEL,
                     issued1, expires1))

        code, _ = get(PORTS["G"], f"/api/v1/names/{LABEL}/reach")
        check("G serves no reach descriptor before announce",
              code == 404, f"got {code}")
        check("resolve via G with binding only is silence",
              resolve_fresh(LABEL, URLS["G"]) is None)

        seed_peer(tmps["A"], pubs["G"], URLS["G"], "belt-node-g")
        daemon1 = threading.Thread(
            target=hold_open.hold_open_cycle,
            args=(URL_R, TOK1, k1_priv.hex(), stop1),
            kwargs={"keepalive_every": 60.0}, daemon=True)
        daemon1.start()
        time.sleep(1.0)
        out = run_helper(
            tmps["A"], privs["A"],
            {"CYBERNET_HOSTED_NAME": LABEL,
             "CYBERNET_NAME_PRIVKEY": k1_priv.hex(),
             "CYBERNET_PUBLIC_URL": "",
             "CYBERNET_RELAY_URL": URL_R,
             "CYBERNET_RELAY_PUBKEY": r_pub,
             "CYBERNET_RELAY_TOKEN": TOK1,
             "CYBERNET_RENDEZVOUS": "1",
             "CYBERNET_RENDEZVOUS_EPOCH_LEN": str(EPOCH_LEN)},
            "core._reach_out()")
        check("A reach announce under K1 ran to 2 recipients",
              "sent: 2" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, desc = wait_reach(PORTS["G"], LABEL, k1_pub)
        check("G serves the K1 reach descriptor", code == 200
              and desc.get("node_pubkey") == k1_pub,
              f"got {code} {desc}")
        strats = [s for s in (desc.get("reach") or [])
                  if isinstance(s, dict)]
        relay_s = [s for s in strats if s.get("kind") == "relay"]
        rz_s = [s for s in strats if s.get("kind") == "rendezvous"]
        check("G descriptor carries relay + rendezvous, no direct",
              len(strats) == 2 and len(relay_s) == 1
              and relay_s[0].get("url") == URL_R
              and relay_s[0].get("relay") == r_pub
              and relay_s[0].get("token") == TOK1,
              f"reach={desc.get('reach')}")
        check("rendezvous strategy advertises epoch_len=600 + hold_query",
              len(rz_s) == 1 and rz_s[0].get("epoch_len") == EPOCH_LEN
              and rz_s[0].get("hold_query") == "/relay/hold_query",
              f"reach={desc.get('reach')}")
        held, pts = held_point(k1_pub, EPOCH_LEN, tries=15)
        check("relay R holds a derived point under K1 600-math",
              held, f"points={pts}")
        held3600, pts3600 = held_point(k1_pub, 3600)
        check("no point held under frozen 3600-math (advertised only)",
              not held3600, f"points={pts3600}")
        got = resolve_fresh(LABEL, URLS["G"])
        check("resolve via sixth hop G returns K1 via relay R carrying v1 (rendezvous)",
              isinstance(got, dict) and got.get("node_pubkey") == k1_pub
              and got.get("node_url") == URL_R
              and got.get("via_relay") == {"relay_pub": r_pub, "token": TOK1}
              and got.get("issued_at") == issued1
              and got.get("expires_at") == expires1,
              f"got {got}")
        unseed_peer(tmps["A"], pubs["G"])

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
        for n in ("C", "D", "E", "F", "G"):
            code, served_x = get(PORTS[n], f"/api/v1/names/{LABEL}")
            check(f"{n} still serves K1 (rotation crossed one hop only)",
                  code == 200 and served_x.get("signature") == sig1,
                  f"got {code} {served_x}")
        bare = {"name": LABEL, "node_pubkey": k2_pub,
                "issued_at": issued2, "expires_at": expires2,
                "signature": sig2}
        res = ingest_on(tmps["G"], privs["G"], bare)
        check("proof-less K2 binding merge on G returns conflict",
              res.stdout.strip().endswith("conflict"),
              f"stdout={res.stdout!r} stderr={res.stderr[-400:]!r}")
        code, served_gx = get(PORTS["G"], f"/api/v1/names/{LABEL}")
        check("G still serves K1 after proof-less attempt",
              code == 200 and served_gx.get("signature") == sig1,
              f"got {code} {served_gx}")
        for src in ("B", "C", "D", "E", "F"):
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
        code, served_g2 = get(PORTS["G"], f"/api/v1/names/{LABEL}")
        check("belt re-verifies G's K2 binding against K2",
              verify(k2_pub, served_g2.get("signature", ""), LABEL,
                     issued2, expires2))
        code, rots_g = get(PORTS["G"], f"/api/v1/names/{LABEL}/rotations")
        hops_g = rots_g.get("rotations", []) if code == 200 else []
        check("G recorded the K1 -> K2 hop",
              code == 200 and len(hops_g) == 1
              and hops_g[0].get("old_pubkey") == k1_pub
              and hops_g[0].get("new_pubkey") == k2_pub,
              f"got {code} {rots_g}")

        seed_peer(tmps["A"], pubs["G"], URLS["G"], "belt-node-g")
        code, _ = get(PORTS["G"], f"/api/v1/names/{LABEL}/reach")
        check("G /reach for stale K1 descriptor reads 404 "
              "(rotation orphans the rendezvous path at sixth hop)",
              code == 404, f"got {code}")
        check("resolve via sixth hop G after rotation is silence "
              "(K1 hold at R still live, no old-key relay path)",
              resolve_fresh(LABEL, URLS["G"]) is None)
        held, pts = held_point(k1_pub, EPOCH_LEN)
        check("relay R still holds the orphaned K1 derived point "
              "under 600-math (path orphaned, hold live)",
              held, f"points={pts}")
        out = run_helper(
            tmps["A"], privs["A"],
            {"CYBERNET_HOSTED_NAME": LABEL,
             "CYBERNET_NAME_PRIVKEY": k1_priv.hex(),
             "CYBERNET_PUBLIC_URL": "",
             "CYBERNET_RELAY_URL": URL_R,
             "CYBERNET_RELAY_PUBKEY": r_pub,
             "CYBERNET_RELAY_TOKEN": TOK1,
             "CYBERNET_RENDEZVOUS": "1",
             "CYBERNET_RENDEZVOUS_EPOCH_LEN": str(EPOCH_LEN)},
            "core._reach_out()")
        check("stale K1 reach re-announce ran to 2 recipients",
              "sent: 2" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, _ = get(PORTS["G"], f"/api/v1/names/{LABEL}/reach")
        check("G still serves no descriptor after stale K1 re-announce",
              code == 404, f"got {code}")
        check("resolve via G still silence after stale K1 re-announce",
              resolve_fresh(LABEL, URLS["G"]) is None)
        daemon2 = threading.Thread(
            target=hold_open.hold_open_cycle,
            args=(URL_R, TOK2, k2_priv.hex(), stop2),
            kwargs={"keepalive_every": 60.0}, daemon=True)
        daemon2.start()
        time.sleep(1.0)
        out = run_helper(
            tmps["A"], privs["A"],
            {"CYBERNET_HOSTED_NAME": LABEL,
             "CYBERNET_NAME_PRIVKEY": k2_priv.hex(),
             "CYBERNET_PUBLIC_URL": "",
             "CYBERNET_RELAY_URL": URL_R,
             "CYBERNET_RELAY_PUBKEY": r_pub,
             "CYBERNET_RELAY_TOKEN": TOK2,
             "CYBERNET_RENDEZVOUS": "1",
             "CYBERNET_RENDEZVOUS_EPOCH_LEN": str(EPOCH_LEN)},
            "core._reach_out()")
        check("A reach announce under K2 ran to 2 recipients",
              "sent: 2" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, desc = wait_reach(PORTS["G"], LABEL, k2_pub)
        check("G serves the K2 reach descriptor", code == 200
              and desc.get("node_pubkey") == k2_pub,
              f"got {code} {desc}")
        strats = [s for s in (desc.get("reach") or [])
                  if isinstance(s, dict)]
        relay_s = [s for s in strats if s.get("kind") == "relay"]
        rz_s = [s for s in strats if s.get("kind") == "rendezvous"]
        check("G K2 descriptor carries relay + rendezvous, no direct (TOK2)",
              len(strats) == 2 and len(relay_s) == 1
              and relay_s[0].get("url") == URL_R
              and relay_s[0].get("relay") == r_pub
              and relay_s[0].get("token") == TOK2,
              f"reach={desc.get('reach')}")
        check("K2 rendezvous strategy advertises epoch_len=600 + hold_query",
              len(rz_s) == 1 and rz_s[0].get("epoch_len") == EPOCH_LEN
              and rz_s[0].get("hold_query") == "/relay/hold_query",
              f"reach={desc.get('reach')}")
        held, pts = held_point(k2_pub, EPOCH_LEN, tries=15)
        check("relay R holds a derived point under K2 600-math",
              held, f"points={pts}")
        held3600, pts3600 = held_point(k2_pub, 3600)
        check("no K2 point held under frozen 3600-math (advertised only)",
              not held3600, f"points={pts3600}")
        got = resolve_fresh(LABEL, URLS["G"])
        check("resolve via sixth hop G returns K2 via relay R"
              " carrying the K2 window (rendezvous)",
              isinstance(got, dict) and got.get("node_pubkey") == k2_pub
              and got.get("node_url") == URL_R
              and got.get("via_relay") == {"relay_pub": r_pub, "token": TOK2}
              and got.get("issued_at") == issued2
              and got.get("expires_at") == expires2,
              f"got {got}")
        check("unclaimed label resolves via G to silence",
              resolve_fresh("nobodyclaimedit", URLS["G"]) is None)
    finally:
        stop1.set()
        stop2.set()
        for p in procs.values():
            p.terminate()
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()
        proc_r.terminate()
        try:
            proc_r.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc_r.kill()

    print(f"\n{CASES['passed']} passed, {CASES['failed']} failed")
    sys.exit(1 if CASES["failed"] else 0)


if __name__ == "__main__":
    main()
