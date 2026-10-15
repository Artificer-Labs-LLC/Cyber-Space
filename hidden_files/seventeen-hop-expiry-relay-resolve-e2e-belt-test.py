"""Belt: SEVENTEEN-HOP gossip chain + EXPIRY + RELAY resolve e2e
(primitives 1 naming + 2 resolution + 3 hosting + 4 identity).

Seventeen-hop panels carried direct/relay/rendezvous descriptors and
renewed/rotated, and seventeen-hop expiry carried direct only.
Never proven together: a SHORT-LIVED binding carried a SEVENTEENTH
hop to a far resolver with a relay-only descriptor -- expiry
at the far hop silences relay resolution even though the
relay still holds the TOK1 point open, a stale copy / stale
re-announce restores nothing, and only a post-expiry claim
under a NEW key, gossiped hop by hop in series, plus a fresh
K2 hold and K2 relay re-announce restores relay resolution
at the seventeenth hop.

Nineteen INDEPENDENT nodes (separate DBs, separate node keys):
A owner (NAT-hidden), B, C, D, E, F, G, H, I, J, K, L, M, N, O, P, Q
intermediaries in series, R far resolver, S relay.

  1. A claims the label under K1 via the real claim route with a
     short (~115s) life; gossip A->B, B->C, C->D, D->E, E->F,
     F->G, G->H, H->I, I->J, J->K, K->L, L->M, M->N, N->O, O->P, P->Q, Q->R in series; every hop serves K1 byte-identical; the
     next node still 404s until its predecessor's leg runs; belt
     re-verifies K1 at R
  2. R serves no /reach yet; resolve via R with the binding only
     is silence (a binding alone never guesses an address)
  3. A holds at relay S under TOK1 and announces a K1 relay-only
     descriptor (owner announce, not gossip); R serves ONLY the
     relay strategy; resolve via seventeenth hop R returns K1 via_relay
     TOK1 at S
  4. The belt waits until the binding's expires_at passes (real
     clock); B, C, D, E, F, G, H, I, J, K, L, M, N, O, P, Q and R all serve silence (404) for the
     binding, R serves the descriptor as 404, and resolve via R
     is silence even though S still holds the TOK1 point open
  5. Negative controls: stale K1 fed to R's real merge half does
     not resurrect it; a stale K1 reach re-announce restores no
     descriptor and resolve via R stays silence
  6. A claims the same label under K2 via the real claim route
     (post-expiry displacement); gossip replaces the silence hop
     by hop in series to R, byte-identical re-verified; A holds
     at S under fresh TOK2 and a K2 relay re-announce restores
     resolve via R returning K2 via_relay TOK2 at S; an
     unclaimed label resolves via R to silence

Test-only allowances, twin of the parent belts: helper/belt
processes patch core._reject_nonpublic_node_url to admit the
loopback node URLs only, and the belt clears core._resolve_memo
between resolves. The genesis name is never touched.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/seventeen-hop-expiry-relay-resolve-e2e-belt-test.py
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

CASES = {"passed": 0, "failed": 0}
NAMES = ("A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R")
PORTS = {n: 23291 + i for i, n in enumerate(NAMES)}
PORT_S = 23309
URLS = {n: f"http://127.0.0.1:{PORTS[n]}" for n in NAMES}
URL_S = f"http://127.0.0.1:{PORT_S}"
ALL_URLS = tuple(URLS.values()) + (URL_S,)
LABEL = "seventeenhopexprelay"
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


def resolve_fresh(label, base):
    core._resolve_memo.clear()
    return core.resolve_cyberspace(label + ".cyberspace", base)


def reach_out(tmp, priv, name_priv_hex, relay_pub, tok):
    return run_helper(
        tmp, priv,
        {"CYBERNET_HOSTED_NAME": LABEL,
         "CYBERNET_NAME_PRIVKEY": name_priv_hex,
         "CYBERNET_PUBLIC_URL": "",
         "CYBERNET_RELAY_URL": URL_S,
         "CYBERNET_RELAY_PUBKEY": relay_pub,
         "CYBERNET_RELAY_TOKEN": tok},
        "core._reach_out()")


def main():
    tmps, privs, pubs, procs = {}, {}, {}, {}
    for n in NAMES:
        tmps[n] = tempfile.mkdtemp(prefix=f"17hop-exprelay-{n.lower()}-")
        privs[n] = secrets.token_hex(32)
        pubs[n] = publickey(bytes.fromhex(privs[n])).hex()
    k1_priv = bytes.fromhex(secrets.token_hex(32))
    k1_pub = publickey(k1_priv).hex()
    k2_priv = bytes.fromhex(secrets.token_hex(32))
    k2_pub = publickey(k2_priv).hex()
    tmp_s = tempfile.mkdtemp(prefix="17hop-exprelay-r-")
    priv_s = secrets.token_hex(32)
    pub_s = publickey(bytes.fromhex(priv_s)).hex()

    ups = {}
    for n in NAMES:
        procs[n], ups[n] = boot(tmps[n], privs[n], PORTS[n])
    proc_s, up_s = boot(tmp_s, priv_s, PORT_S)
    stop1 = threading.Event()
    stop2 = threading.Event()
    try:
        check("nineteen independent nodes boot", all(ups.values()) and up_s)
        if not (all(ups.values()) and up_s):
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
        code, _ = get(PORTS["R"], f"/api/v1/names/{LABEL}")
        check("R has never heard of it before gossip", code == 404,
              f"got {code}")

        # serial federation: A->B (1 recipient), then each interior
        # node gossips onward to its 2 known peers
        legs = (("A", 1), ("B", 2), ("C", 2), ("D", 2), ("E", 2), ("F", 2), ("G", 2), ("H", 2), ("I", 2), ("J", 2), ("K", 2), ("L", 2), ("M", 2), ("N", 2), ("O", 2), ("P", 2), ("Q", 2))
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
        code, served_k1 = get(PORTS["R"], f"/api/v1/names/{LABEL}")
        check("belt re-verifies R's K1 binding against K1",
              verify(k1_pub, served_k1.get("signature", ""), LABEL,
                     issued1, expires1))

        code, _ = get(PORTS["R"], f"/api/v1/names/{LABEL}/reach")
        check("R serves no reach descriptor before announce",
              code == 404, f"got {code}")
        check("resolve via R with binding only is silence",
              resolve_fresh(LABEL, URLS["R"]) is None)

        seed_peer(tmps["A"], pubs["R"], URLS["R"], "belt-node-r")
        daemon1 = threading.Thread(
            target=hold_open.hold_open_cycle,
            args=(URL_S, TOK1, k1_priv.hex(), stop1),
            kwargs={"keepalive_every": 60.0}, daemon=True)
        daemon1.start()
        time.sleep(1.0)
        out = reach_out(tmps["A"], privs["A"], k1_priv.hex(), pub_s, TOK1)
        check("A reach announce under K1 ran to 2 recipients",
              "sent: 2" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, desc = wait_reach(PORTS["R"], LABEL, k1_pub)
        check("R serves the K1 relay descriptor", code == 200
              and desc.get("node_pubkey") == k1_pub,
              f"got {code} {desc}")
        strats = [s for s in (desc.get("reach") or [])
                  if isinstance(s, dict)]
        check("Q descriptor carries ONLY the relay strategy (NAT-hidden)",
              len(strats) == 1 and strats[0].get("kind") == "relay"
              and strats[0].get("url") == URL_S
              and strats[0].get("relay") == pub_s
              and strats[0].get("token") == TOK1,
              f"reach={desc.get('reach')}")
        got = resolve_fresh(LABEL, URLS["R"])
        check("resolve via seventeenth hop R returns K1 via relay S",
              isinstance(got, dict) and got.get("node_pubkey") == k1_pub
              and got.get("node_url") == URL_S
              and got.get("via_relay") == {"relay_pub": pub_s, "token": TOK1}
              and got.get("issued_at") == issued1
              and got.get("expires_at") == expires1,
              f"got {got}")
        while datetime.now(timezone.utc) < expires1_dt + timedelta(seconds=2):
            time.sleep(2)
        check("belt waited past K1 expiry on the real clock",
              datetime.now(timezone.utc) > expires1_dt)
        for n in ("B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R"):
            check(f"{n} serves silence (404) after expiry",
                  wait_silence(PORTS[n], LABEL))
        code, _ = get(PORTS["R"], f"/api/v1/names/{LABEL}/reach")
        check("R serves the descriptor as 404 after binding expiry",
              code == 404, f"got {code}")
        check("resolve via seventeenth hop R is silence after expiry "
              "(S still holds the TOK1 point open)",
              resolve_fresh(LABEL, URLS["R"]) is None)

        stale = {"name": LABEL, "node_pubkey": k1_pub,
                 "issued_at": issued1, "expires_at": expires1,
                 "signature": sig1}
        res = ingest_on(tmps["Q"], privs["Q"], stale)
        check("stale expired K1 merge on R does not resurrect (not stored)",
              not res.stdout.strip().endswith("stored"),
              f"stdout={res.stdout!r} stderr={res.stderr[-400:]!r}")
        code, _ = get(PORTS["R"], f"/api/v1/names/{LABEL}")
        check("R still silent after stale merge attempt", code == 404,
              f"got {code}")
        out = reach_out(tmps["A"], privs["A"], k1_priv.hex(), pub_s, TOK1)
        check("stale K1 reach re-announce ran to 2 recipients",
              "sent: 2" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, _ = get(PORTS["R"], f"/api/v1/names/{LABEL}/reach")
        check("R still serves no descriptor after stale K1 re-announce",
              code == 404, f"got {code}")
        check("resolve via R still silence after stale K1 re-announce",
              resolve_fresh(LABEL, URLS["R"]) is None)
        stop1.set()

        unseed_peer(tmps["A"], pubs["R"])
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
        code, served_k2 = get(PORTS["R"], f"/api/v1/names/{LABEL}")
        check("belt re-verifies R's K2 binding against K2",
              verify(k2_pub, served_k2.get("signature", ""), LABEL,
                     issued2, expires2))

        seed_peer(tmps["A"], pubs["R"], URLS["R"], "belt-node-r")
        daemon2 = threading.Thread(
            target=hold_open.hold_open_cycle,
            args=(URL_S, TOK2, k2_priv.hex(), stop2),
            kwargs={"keepalive_every": 60.0}, daemon=True)
        daemon2.start()
        time.sleep(1.0)
        out = reach_out(tmps["A"], privs["A"], k2_priv.hex(), pub_s, TOK2)
        check("A reach announce under K2 ran to 2 recipients",
              "sent: 2" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, desc = wait_reach(PORTS["R"], LABEL, k2_pub)
        check("R serves the K2 relay descriptor", code == 200
              and desc.get("node_pubkey") == k2_pub,
              f"got {code} {desc}")
        strats = [s for s in (desc.get("reach") or [])
                  if isinstance(s, dict)]
        check("Q K2 descriptor carries ONLY the relay strategy (TOK2)",
              len(strats) == 1 and strats[0].get("kind") == "relay"
              and strats[0].get("url") == URL_S
              and strats[0].get("relay") == pub_s
              and strats[0].get("token") == TOK2,
              f"reach={desc.get('reach')}")
        got = resolve_fresh(LABEL, URLS["R"])
        check("resolve via seventeenth hop R returns K2 via relay S (TOK2)",
              isinstance(got, dict) and got.get("node_pubkey") == k2_pub
              and got.get("node_url") == URL_S
              and got.get("via_relay") == {"relay_pub": pub_s, "token": TOK2}
              and got.get("issued_at") == issued2
              and got.get("expires_at") == expires2,
              f"got {got}")
        check("unclaimed label resolves via R to silence",
              resolve_fresh("nobodyclaimedit", URLS["R"]) is None)
    finally:
        stop1.set()
        stop2.set()
        proc_s.terminate()
        try:
            proc_s.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc_s.kill()
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
