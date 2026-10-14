"""Belt: TEN-HOP gossip chain + EXPIRY + RENDEZVOUS resolve e2e
(primitives 1 naming + 2 resolution + 3 hosting + 4 identity).

Ten-hop expiry panels carried direct and relay descriptors.
Never proven together -- the last ten-hop expiry cell: a
SHORT-LIVED binding carried a TENTH hop to a far resolver
with a relay+rendezvous descriptor -- expiry at the far hop
silences rendezvous resolution even though the relay still
holds the TOK1 point open and a derived point under the dead
key's advertised 600-math, a stale copy / stale re-announce
restores nothing, and only a post-expiry claim under a NEW
key, gossiped hop by hop in series, plus a fresh K2 hold and
K2 rendezvous re-announce restores rendezvous resolution at
the tenth hop.

Twelve INDEPENDENT nodes (separate DBs, separate node keys):
A owner (NAT-hidden), B, C, D, E, F, G, H, I, J intermediaries in series,
K far resolver, R relay.

  1. A claims the label under K1 via the real claim route with a
     short (~115s) life; gossip A->B, B->C, C->D, D->E, E->F,
     F->G, G->H, H->I, I->J, J->K in series; every hop serves K1 byte-identical; the
     next node still 404s until its predecessor's leg runs; belt
     re-verifies K1 at K
  2. K serves no /reach yet; resolve via K with the binding only
     is silence (a binding alone never guesses an address)
  3. A holds at relay R under TOK1 and announces a K1
     relay+rendezvous descriptor (epoch_len 600, owner announce,
     not gossip); K serves relay+rendezvous and no direct; R
     holds a derived point under the advertised 600-math only
     and none under frozen 3600-math; resolve via tenth hop K
     returns K1 via_relay TOK1 at R
  4. The belt waits until the binding's expires_at passes (real
     clock); B, C, D, E, F, G, H, I, J and K all serve silence (404) for the
     binding, K serves the descriptor as 404, and resolve via K
     is silence even though R still holds the TOK1 point open
     and the orphaned K1 derived point under the 600-math
  5. Negative controls: stale K1 fed to K's real merge half does
     not resurrect it; a stale K1 rendezvous re-announce restores
     no descriptor and resolve via K stays silence
  6. A claims the same label under K2 via the real claim route
     (post-expiry displacement); gossip replaces the silence hop
     by hop in series to K, byte-identical re-verified; A holds
     at R under fresh TOK2 and a K2 rendezvous re-announce
     restores resolve via K returning K2 via_relay TOK2 at R,
     with R holding a K2 derived point under the 600-math only;
     an unclaimed label resolves via K to silence

Test-only allowances, twin of the parent belts: helper/belt
processes patch core._reject_nonpublic_node_url to admit the
loopback node URLs only, and the belt clears core._resolve_memo
between resolves. The genesis name is never touched.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/ten-hop-expiry-rendezvous-resolve-e2e-belt-test.py
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
NAMES = ("A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K")
PORTS = {n: 20471 + i for i, n in enumerate(NAMES)}
PORT_R = 20482
URLS = {n: f"http://127.0.0.1:{PORTS[n]}" for n in NAMES}
URL_R = f"http://127.0.0.1:{PORT_R}"
ALL_URLS = tuple(URLS.values()) + (URL_R,)
LABEL = "tenhopexprz"
EPOCH_LEN = 600
os.environ["CYBERNET_RENDEZVOUS_EPOCH_LEN"] = str(EPOCH_LEN)
TOK1 = "tok1-" + secrets.token_hex(8)
TOK2 = "tok2-" + secrets.token_hex(8)

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
    tmps, privs, pubs, procs = {}, {}, {}, {}
    for n in NAMES:
        tmps[n] = tempfile.mkdtemp(prefix=f"10hop-exprz-{n.lower()}-")
        privs[n] = secrets.token_hex(32)
        pubs[n] = publickey(bytes.fromhex(privs[n])).hex()
    k1_priv = bytes.fromhex(secrets.token_hex(32))
    k1_pub = publickey(k1_priv).hex()
    k2_priv = bytes.fromhex(secrets.token_hex(32))
    k2_pub = publickey(k2_priv).hex()
    tmp_r = tempfile.mkdtemp(prefix="10hop-exprz-r-")
    priv_r = secrets.token_hex(32)
    pub_r = publickey(bytes.fromhex(priv_r)).hex()

    ups = {}
    for n in NAMES:
        procs[n], ups[n] = boot(tmps[n], privs[n], PORTS[n])
    proc_r, up_r = boot(tmp_r, priv_r, PORT_R)
    stop1 = threading.Event()
    stop2 = threading.Event()
    try:
        check("twelve independent nodes boot", all(ups.values()) and up_r)
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
        expires1_dt = now + timedelta(seconds=115)
        code, sig1, issued1, expires1 = claim(
            PORTS["A"], LABEL, k1_priv, k1_pub,
            now - timedelta(seconds=10), expires1_dt)
        check("A claims kept-key name under K1 via real route (short life)",
              code == 200, f"got {code}")
        code, _ = get(PORTS["K"], f"/api/v1/names/{LABEL}")
        check("K has never heard of it before gossip", code == 404,
              f"got {code}")

        # serial federation: A->B (1 recipient), then each interior
        # node gossips onward to its 2 known peers
        legs = (("A", 1), ("B", 2), ("C", 2), ("D", 2), ("E", 2), ("F", 2), ("G", 2), ("H", 2), ("I", 2), ("J", 2))
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
        code, served_k1 = get(PORTS["K"], f"/api/v1/names/{LABEL}")
        check("belt re-verifies K's K1 binding against K1",
              verify(k1_pub, served_k1.get("signature", ""), LABEL,
                     issued1, expires1))

        code, _ = get(PORTS["K"], f"/api/v1/names/{LABEL}/reach")
        check("K serves no reach descriptor before announce",
              code == 404, f"got {code}")
        check("resolve via K with binding only is silence",
              resolve_fresh(LABEL, URLS["K"]) is None)

        seed_peer(tmps["A"], pubs["K"], URLS["K"], "belt-node-k")
        daemon1 = threading.Thread(
            target=hold_open.hold_open_cycle,
            args=(URL_R, TOK1, k1_priv.hex(), stop1),
            kwargs={"keepalive_every": 60.0}, daemon=True)
        daemon1.start()
        time.sleep(1.0)
        out = reach_out(tmps["A"], privs["A"], k1_priv.hex(), pub_r, TOK1)
        check("A reach announce under K1 ran to 2 recipients",
              "sent: 2" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, desc = wait_reach(PORTS["K"], LABEL, k1_pub)
        check("K serves the K1 rendezvous descriptor", code == 200
              and desc.get("node_pubkey") == k1_pub,
              f"got {code} {desc}")
        strats = [s for s in (desc.get("reach") or [])
                  if isinstance(s, dict)]
        relay_s = [s for s in strats if s.get("kind") == "relay"]
        rz_s = [s for s in strats if s.get("kind") == "rendezvous"]
        check("K descriptor carries relay + rendezvous, no direct",
              len(strats) == 2 and len(relay_s) == 1
              and relay_s[0].get("url") == URL_R
              and relay_s[0].get("relay") == pub_r
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
        got = resolve_fresh(LABEL, URLS["K"])
        check("resolve via tenth hop K returns K1 via relay R (rendezvous)",
              isinstance(got, dict) and got.get("node_pubkey") == k1_pub
              and got.get("node_url") == URL_R
              and got.get("via_relay") == {"relay_pub": pub_r, "token": TOK1}
              and got.get("issued_at") == issued1
              and got.get("expires_at") == expires1,
              f"got {got}")
        while datetime.now(timezone.utc) < expires1_dt + timedelta(seconds=2):
            time.sleep(2)
        check("belt waited past K1 expiry on the real clock",
              datetime.now(timezone.utc) > expires1_dt)
        for n in ("B", "C", "D", "E", "F", "G", "H", "I", "J", "K"):
            check(f"{n} serves silence (404) after expiry",
                  wait_silence(PORTS[n], LABEL))
        code, _ = get(PORTS["K"], f"/api/v1/names/{LABEL}/reach")
        check("K serves the descriptor as 404 after binding expiry",
              code == 404, f"got {code}")
        check("resolve via tenth hop K is silence after expiry "
              "(R still holds the TOK1 point open)",
              resolve_fresh(LABEL, URLS["K"]) is None)
        held, pts = held_point(k1_pub, EPOCH_LEN)
        check("relay R still holds the orphaned K1 derived point "
              "under 600-math (path expired, hold live)",
              held, f"points={pts}")

        stale = {"name": LABEL, "node_pubkey": k1_pub,
                 "issued_at": issued1, "expires_at": expires1,
                 "signature": sig1}
        res = ingest_on(tmps["K"], privs["K"], stale)
        check("stale expired K1 merge on K does not resurrect (not stored)",
              not res.stdout.strip().endswith("stored"),
              f"stdout={res.stdout!r} stderr={res.stderr[-400:]!r}")
        code, _ = get(PORTS["K"], f"/api/v1/names/{LABEL}")
        check("K still silent after stale merge attempt", code == 404,
              f"got {code}")
        out = reach_out(tmps["A"], privs["A"], k1_priv.hex(), pub_r, TOK1)
        check("stale K1 reach re-announce ran to 2 recipients",
              "sent: 2" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, _ = get(PORTS["K"], f"/api/v1/names/{LABEL}/reach")
        check("K still serves no descriptor after stale K1 re-announce",
              code == 404, f"got {code}")
        check("resolve via K still silence after stale K1 re-announce",
              resolve_fresh(LABEL, URLS["K"]) is None)
        stop1.set()

        unseed_peer(tmps["A"], pubs["K"])
        now2 = datetime.now(timezone.utc)
        code, sig2, issued2, expires2 = claim(
            PORTS["A"], LABEL, k2_priv, k2_pub,
            now2 - timedelta(seconds=5), now2 + timedelta(days=30))
        check("A claims same label under NEW key K2 via real route (displacement)",
              code == 200, f"got {code}")
        for src, want in legs:
            dst = NAMES[NAMES.index(src) + 1]
            out = run_helper(tmps[src], privs[src], {},
                             "core._names_gossip_out()")
            check(f"{src} gossip K2 ran to {want} recipient(s)",
                  f"sent: {want}" in out.stdout,
                  f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
            code, served = wait_served(PORTS[dst], LABEL, sig2)
            check(f"{dst} REPLACED post-expiry silence with K2 (learned via {src})",
                  code == 200 and served.get("node_pubkey") == k2_pub
                  and served.get("issued_at") == issued2
                  and served.get("expires_at") == expires2,
                  f"got {code} {served}")
            nxt_i = NAMES.index(dst) + 1
            if nxt_i < len(NAMES):
                nxt = NAMES[nxt_i]
                code, _ = get(PORTS[nxt], f"/api/v1/names/{LABEL}")
                check(f"{nxt} still silent before {dst}'s K2 leg runs",
                      code == 404, f"got {code}")
        code, served_k2 = get(PORTS["K"], f"/api/v1/names/{LABEL}")
        check("belt re-verifies K's K2 binding against K2",
              verify(k2_pub, served_k2.get("signature", ""), LABEL,
                     issued2, expires2))

        seed_peer(tmps["A"], pubs["K"], URLS["K"], "belt-node-k")
        daemon2 = threading.Thread(
            target=hold_open.hold_open_cycle,
            args=(URL_R, TOK2, k2_priv.hex(), stop2),
            kwargs={"keepalive_every": 60.0}, daemon=True)
        daemon2.start()
        time.sleep(1.0)
        out = reach_out(tmps["A"], privs["A"], k2_priv.hex(), pub_r, TOK2)
        check("A reach announce under K2 ran to 2 recipients",
              "sent: 2" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, desc = wait_reach(PORTS["K"], LABEL, k2_pub)
        check("K serves the K2 rendezvous descriptor", code == 200
              and desc.get("node_pubkey") == k2_pub,
              f"got {code} {desc}")
        strats = [s for s in (desc.get("reach") or [])
                  if isinstance(s, dict)]
        relay_s = [s for s in strats if s.get("kind") == "relay"]
        rz_s = [s for s in strats if s.get("kind") == "rendezvous"]
        check("K K2 descriptor carries relay + rendezvous, no direct (TOK2)",
              len(strats) == 2 and len(relay_s) == 1
              and relay_s[0].get("url") == URL_R
              and relay_s[0].get("relay") == pub_r
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
        got = resolve_fresh(LABEL, URLS["K"])
        check("resolve via tenth hop K returns K2 via relay R (TOK2, rendezvous)",
              isinstance(got, dict) and got.get("node_pubkey") == k2_pub
              and got.get("node_url") == URL_R
              and got.get("via_relay") == {"relay_pub": pub_r, "token": TOK2}
              and got.get("issued_at") == issued2
              and got.get("expires_at") == expires2,
              f"got {got}")
        check("unclaimed label resolves via K to silence",
              resolve_fresh("nobodyclaimedit", URLS["K"]) is None)
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
