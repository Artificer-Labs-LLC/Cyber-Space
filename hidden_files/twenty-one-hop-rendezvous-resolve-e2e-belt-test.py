"""Belt: TWENTY-ONE-HOP gossip chain + RENDEZVOUS resolve e2e
(primitives 1 naming + 2 resolution + 3 hosting + 4 identity).

Third twenty-one-hop base cell past twenty-one-hop direct (dffc53d)
and twenty-one-hop relay (3beb659), completing the twenty-one-hop
base matrix: the relay descriptor must additionally advertise
the rendezvous strategy (epoch_len 600), and the relay must
hold a point derived under that advertised math, at twenty-one
hops of remove from the owner.
This belt proves claim, serial federation over twenty-one hops,
relay hold, relay+rendezvous descriptor, resolve at the far end.

Twenty-three INDEPENDENT nodes (separate DBs, separate node keys):
A owner (NAT-hidden), B, C, D, E, F, G, H, I, J, K, L, M, N, O, P, Q, R, S, T, U
intermediaries in series, V far resolver, W relay.

  1. A claims the label under K1 via the real claim route;
     gossip A->B, B->C, C->D, D->E, E->F, F->G, G->H, H->I, I->J, J->K, K->L, L->M, M->N, N->O, O->P, P->Q, Q->R, R->S, S->T, T->U, U->V
     strictly in series; every hop serves K1 byte-identical;
     the next node still 404s until its predecessor's leg runs;
     belt re-verifies K1 at V
  2. V serves no /reach yet; resolve via V with the binding only
     is silence (a binding alone never guesses an address)
  3. A holds at W under TOK1 and announces a K1 relay-only
     descriptor (owner announce, not gossip, epoch_len 600);
     V serves relay + rendezvous, no direct; W holds a derived
     point under the advertised 600-math; resolve via twenty-first
     hop V returns K1 via_relay TOK1
  4. An unclaimed label resolves via V to silence

Test-only allowances, twin of the parent belts: helper/belt
processes patch core._reject_nonpublic_node_url to admit the
loopback node URLs only, and the belt clears core._resolve_memo
between resolves. The genesis name is never touched.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/twenty-one-hop-rendezvous-resolve-e2e-belt-test.py
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
NAMES = ("A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V")
PORTS = {n: 24411 + i for i, n in enumerate(NAMES)}
PORT_W = 24433
URL_W = f"http://127.0.0.1:{PORT_W}"
ALL_URLS = tuple(f"http://127.0.0.1:{24411+i}" for i in range(22)) + (URL_W,)
TOK1 = "tok1-" + secrets.token_hex(8)
URLS = {n: f"http://127.0.0.1:{PORTS[n]}" for n in NAMES}
LABEL = "twentyonehoprz"
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
        if any(get(PORT_W, "/relay/hold_query?point_id=" + p)[1]
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
        tmps[n] = tempfile.mkdtemp(prefix=f"21hop-rz-{n.lower()}-")
        privs[n] = secrets.token_hex(32)
        pubs[n] = publickey(bytes.fromhex(privs[n])).hex()
    k1_priv = bytes.fromhex(secrets.token_hex(32))
    k1_pub = publickey(k1_priv).hex()

    tmp_w = tempfile.mkdtemp(prefix="21hop-rz-w-")
    w_priv = secrets.token_hex(32)
    w_pub = publickey(bytes.fromhex(w_priv)).hex()
    ups = {}
    for n in NAMES:
        procs[n], ups[n] = boot(tmps[n], privs[n], PORTS[n])
    proc_w, up_w = boot(tmp_w, w_priv, PORT_W)
    stop1 = threading.Event()
    try:
        check("twenty-three independent nodes boot", all(ups.values()) and up_w)
        if not (all(ups.values()) and up_w):
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
        code, _ = get(PORTS["V"], f"/api/v1/names/{LABEL}")
        check("V has never heard of it before gossip", code == 404,
              f"got {code}")

        # serial federation: A->B (1 recipient), then each interior
        # node gossips onward to its 2 known peers
        legs = (("A", 1), ("B", 2), ("C", 2), ("D", 2), ("E", 2), ("F", 2), ("G", 2), ("H", 2), ("I", 2), ("J", 2), ("K", 2), ("L", 2), ("M", 2), ("N", 2), ("O", 2), ("P", 2), ("Q", 2), ("R", 2), ("S", 2), ("T", 2), ("U", 2))
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
        code, served_f1 = get(PORTS["V"], f"/api/v1/names/{LABEL}")
        check("belt re-verifies V's K1 binding against K1",
              verify(k1_pub, served_f1.get("signature", ""), LABEL,
                     issued1, expires1))

        code, _ = get(PORTS["V"], f"/api/v1/names/{LABEL}/reach")
        check("V serves no reach descriptor before announce",
              code == 404, f"got {code}")
        check("resolve via V with binding only is silence",
              resolve_fresh(LABEL, URLS["V"]) is None)

        seed_peer(tmps["A"], pubs["V"], URLS["V"], "belt-node-v")
        daemon1 = threading.Thread(
            target=hold_open.hold_open_cycle,
            args=(URL_W, TOK1, k1_priv.hex(), stop1),
            kwargs={"keepalive_every": 60.0}, daemon=True)
        daemon1.start()
        time.sleep(1.0)
        out = run_helper(
            tmps["A"], privs["A"],
            {"CYBERNET_HOSTED_NAME": LABEL,
             "CYBERNET_NAME_PRIVKEY": k1_priv.hex(),
             "CYBERNET_PUBLIC_URL": "",
             "CYBERNET_RELAY_URL": URL_W,
             "CYBERNET_RELAY_PUBKEY": w_pub,
             "CYBERNET_RELAY_TOKEN": TOK1,
             "CYBERNET_RENDEZVOUS": "1",
             "CYBERNET_RENDEZVOUS_EPOCH_LEN": str(EPOCH_LEN)},
            "core._reach_out()")
        check("A reach announce under K1 ran to 2 recipients",
              "sent: 2" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, desc = wait_reach(PORTS["V"], LABEL, k1_pub)
        check("V serves the K1 rendezvous descriptor", code == 200
              and desc.get("node_pubkey") == k1_pub,
              f"got {code} {desc}")
        strats = [s for s in (desc.get("reach") or [])
                  if isinstance(s, dict)]
        relay_s = [x for x in strats if x.get("kind") == "relay"]
        rz_s = [x for x in strats if x.get("kind") == "rendezvous"]
        check("V descriptor carries relay + rendezvous, no direct",
              len(strats) == 2 and len(relay_s) == 1
              and relay_s[0].get("url") == URL_W
              and relay_s[0].get("relay") == w_pub
              and relay_s[0].get("token") == TOK1,
              f"reach={desc.get('reach')}")
        check("rendezvous strategy advertises epoch_len=600 + hold_query",
              len(rz_s) == 1 and rz_s[0].get("epoch_len") == EPOCH_LEN
              and rz_s[0].get("hold_query") == "/relay/hold_query",
              f"reach={desc.get('reach')}")
        held, pts = held_point(k1_pub, EPOCH_LEN, tries=15)
        check("relay W holds a derived point under K1 600-math",
              held, f"points={pts}")
        held3600, pts3600 = held_point(k1_pub, 3600)
        check("no point held under frozen 3600-math (advertised only)",
              not held3600, f"points={pts3600}")
        got = resolve_fresh(LABEL, URLS["V"])
        check("resolve via twenty-first hop V returns K1 via relay W (rendezvous)",
              isinstance(got, dict) and got.get("node_pubkey") == k1_pub
              and got.get("node_url") == URL_W
              and got.get("via_relay") == {"relay_pub": w_pub, "token": TOK1}
              and got.get("issued_at") == issued1
              and got.get("expires_at") == expires1,
              f"got {got}")
        check("unclaimed label resolves via V to silence",
              resolve_fresh("nobodyclaimedit", URLS["V"]) is None)
    finally:
        stop1.set()
        proc_w.terminate()
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
