"""Belt: FIVE-HOP gossip chain + EXPIRY + DIRECT resolve e2e
(primitives 1 naming + 2 resolution + 3 hosting + 4 identity).

Five-hop panels carried direct/relay/rendezvous descriptors and
renewed/rotated, but never expired; expiry panels stopped at
four hops. Never proven together: a SHORT-LIVED binding carried
a FIFTH hop to a far resolver with a direct descriptor --
expiry at the far hop silences direct resolution even though
the hoster is still reachable, a stale copy / stale re-announce
restores nothing, and only a post-expiry claim under a NEW
key, gossiped hop by hop in series, plus its own direct
re-announce restores direct resolution at the fifth hop.

Six INDEPENDENT nodes (separate DBs, separate node keys):
A owner (publicly reachable hoster), B, C, D, E intermediaries
in series, F far resolver.

  1. A claims the label under K1 via the real claim route with a
     short (~115s) life; gossip A->B, B->C, C->D, D->E, E->F in
     series; every hop serves K1 byte-identical; the next node
     still 404s until its predecessor's leg runs; belt
     re-verifies K1 at F
  2. F serves no /reach yet; resolve via F with the binding only
     is silence (a binding alone never guesses an address)
  3. A announces a K1 direct-only descriptor (owner announce, not
     gossip); F serves ONLY the direct strategy at A's URL;
     resolve via fifth hop F returns K1 direct at A
  4. The belt waits until the binding's expires_at passes (real
     clock); B, C, D, E and F all serve silence (404) for the
     binding, F serves the descriptor as 404, and resolve via F
     is silence
  5. Negative controls: stale K1 fed to F's real merge half does
     not resurrect it; a stale K1 reach re-announce restores no
     descriptor and resolve via F stays silence
  6. A claims the same label under K2 via the real claim route
     (post-expiry displacement); gossip replaces the silence hop
     by hop in series to F, byte-identical re-verified; a K2
     direct re-announce restores resolve via F returning K2
     direct at A; an unclaimed label resolves via F to silence

Test-only allowances, twin of the parent belts: helper/belt
processes patch core._reject_nonpublic_node_url to admit the
loopback node URLs only, and the belt clears core._resolve_memo
between resolves. The genesis name is never touched.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/five-hop-expiry-direct-resolve-e2e-belt-test.py
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

CASES = {"passed": 0, "failed": 0}
NAMES = ("A", "B", "C", "D", "E", "F")
PORTS = {n: 19031 + i for i, n in enumerate(NAMES)}
URLS = {n: f"http://127.0.0.1:{PORTS[n]}" for n in NAMES}
LABEL = "fivehopexpdir"

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


def main():
    tmps, privs, pubs, procs = {}, {}, {}, {}
    for n in NAMES:
        tmps[n] = tempfile.mkdtemp(prefix=f"5hop-expdir-{n.lower()}-")
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
        check("six independent nodes boot", all(ups.values()))
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
        expires1_dt = now + timedelta(seconds=115)
        code, sig1, issued1, expires1 = claim(
            PORTS["A"], LABEL, k1_priv, k1_pub,
            now - timedelta(seconds=10), expires1_dt)
        check("A claims kept-key name under K1 via real route (short life)",
              code == 200, f"got {code}")
        code, _ = get(PORTS["F"], f"/api/v1/names/{LABEL}")
        check("F has never heard of it before gossip", code == 404,
              f"got {code}")

        # serial federation: A->B (1 recipient), then each interior
        # node gossips onward to its 2 known peers
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
        out = run_helper(
            tmps["A"], privs["A"],
            {"CYBERNET_HOSTED_NAME": LABEL,
             "CYBERNET_NAME_PRIVKEY": k1_priv.hex(),
             "CYBERNET_PUBLIC_URL": URLS["A"]},
            "core._reach_out()")
        check("A reach announce under K1 ran to 2 recipients",
              "sent: 2" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, desc = wait_reach(PORTS["F"], LABEL, k1_pub)
        check("F serves the K1 reach descriptor", code == 200
              and desc.get("node_pubkey") == k1_pub,
              f"got {code} {desc}")
        strats = [s for s in (desc.get("reach") or [])
                  if isinstance(s, dict)]
        check("F descriptor carries ONLY the direct strategy",
              len(strats) == 1 and strats[0].get("kind") == "direct"
              and strats[0].get("url") == URLS["A"],
              f"reach={desc.get('reach')}")
        got = resolve_fresh(LABEL, URLS["F"])
        check("resolve via fifth hop F returns K1 direct at A",
              isinstance(got, dict) and got.get("node_pubkey") == k1_pub
              and got.get("node_url") == URLS["A"]
              and "via_relay" not in got
              and got.get("issued_at") == issued1
              and got.get("expires_at") == expires1,
              f"got {got}")
        while datetime.now(timezone.utc) < expires1_dt + timedelta(seconds=2):
            time.sleep(2)
        check("belt waited past K1 expiry on the real clock",
              datetime.now(timezone.utc) > expires1_dt)
        for n in ("B", "C", "D", "E", "F"):
            check(f"{n} serves silence (404) after expiry",
                  wait_silence(PORTS[n], LABEL))
        code, _ = get(PORTS["F"], f"/api/v1/names/{LABEL}/reach")
        check("F serves the descriptor as 404 after binding expiry",
              code == 404, f"got {code}")
        check("resolve via fifth hop F is silence after expiry "
              "(A itself is still reachable)",
              resolve_fresh(LABEL, URLS["F"]) is None)

        stale = {"name": LABEL, "node_pubkey": k1_pub,
                 "issued_at": issued1, "expires_at": expires1,
                 "signature": sig1}
        res = ingest_on(tmps["F"], privs["F"], stale)
        check("stale expired K1 merge on F does not resurrect (not stored)",
              not res.stdout.strip().endswith("stored"),
              f"stdout={res.stdout!r} stderr={res.stderr[-400:]!r}")
        code, _ = get(PORTS["F"], f"/api/v1/names/{LABEL}")
        check("F still silent after stale merge attempt", code == 404,
              f"got {code}")
        out = run_helper(
            tmps["A"], privs["A"],
            {"CYBERNET_HOSTED_NAME": LABEL,
             "CYBERNET_NAME_PRIVKEY": k1_priv.hex(),
             "CYBERNET_PUBLIC_URL": URLS["A"]},
            "core._reach_out()")
        check("stale K1 reach re-announce ran to 2 recipients",
              "sent: 2" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, _ = get(PORTS["F"], f"/api/v1/names/{LABEL}/reach")
        check("F still serves no descriptor after stale K1 re-announce",
              code == 404, f"got {code}")
        check("resolve via F still silence after stale K1 re-announce",
              resolve_fresh(LABEL, URLS["F"]) is None)

        unseed_peer(tmps["A"], pubs["F"])
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
        code, served_f2 = get(PORTS["F"], f"/api/v1/names/{LABEL}")
        check("belt re-verifies F's K2 binding against K2",
              verify(k2_pub, served_f2.get("signature", ""), LABEL,
                     issued2, expires2))

        seed_peer(tmps["A"], pubs["F"], URLS["F"], "belt-node-f")
        out = run_helper(
            tmps["A"], privs["A"],
            {"CYBERNET_HOSTED_NAME": LABEL,
             "CYBERNET_NAME_PRIVKEY": k2_priv.hex(),
             "CYBERNET_PUBLIC_URL": URLS["A"]},
            "core._reach_out()")
        check("A reach announce under K2 ran to 2 recipients",
              "sent: 2" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, desc = wait_reach(PORTS["F"], LABEL, k2_pub)
        check("F serves the K2 reach descriptor", code == 200
              and desc.get("node_pubkey") == k2_pub,
              f"got {code} {desc}")
        strats = [s for s in (desc.get("reach") or [])
                  if isinstance(s, dict)]
        check("F K2 descriptor carries ONLY the direct strategy",
              len(strats) == 1 and strats[0].get("kind") == "direct"
              and strats[0].get("url") == URLS["A"],
              f"reach={desc.get('reach')}")
        got = resolve_fresh(LABEL, URLS["F"])
        check("resolve via fifth hop F returns K2 direct at A",
              isinstance(got, dict) and got.get("node_pubkey") == k2_pub
              and got.get("node_url") == URLS["A"]
              and "via_relay" not in got
              and got.get("issued_at") == issued2
              and got.get("expires_at") == expires2,
              f"got {got}")
        check("unclaimed label resolves via F to silence",
              resolve_fresh("nobodyclaimedit", URLS["F"]) is None)
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
