"""Belt: EIGHT-HOP gossip chain + DIRECT resolve e2e
(primitives 1 naming + 2 resolution + 3 hosting + 4 identity).

The six-hop panel matrices (base/renewal/rotation/expiry x
direct/relay/rendezvous) are complete. Never proven: a binding
carried a EIGHTH hop -- federation depth is the depth
primitive's own scaling claim: every extra hop is another chance
for a mirror to drop, mangle, or refuse the binding. This belt
proves the foundational eight-hop cell: claim, serial
federation, direct descriptor, resolve at the far end.

Nine INDEPENDENT nodes (separate DBs, separate node keys):
A owner (publicly reachable hoster), B, C, D, E, F, G, H
intermediaries in series, I far resolver.

  1. A claims the label under K1 via the real claim route;
     gossip A->B, B->C, C->D, D->E, E->F, F->G, G->H strictly in
     series; every hop serves K1 byte-identical; the next node
     still 404s until its predecessor's leg runs; belt
     re-verifies K1 at H
  2. I serves no /reach yet; resolve via I with the binding only
     is silence (a binding alone never guesses an address)
  3. A announces a K1 direct-only descriptor (owner announce, not
     gossip); I serves ONLY the direct strategy at A's URL;
     resolve via eighth hop I returns K1 direct at A
  4. An unclaimed label resolves via I to silence

Test-only allowances, twin of the parent belts: helper/belt
processes patch core._reject_nonpublic_node_url to admit the
loopback node URLs only, and the belt clears core._resolve_memo
between resolves. The genesis name is never touched.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/eight-hop-direct-resolve-e2e-belt-test.py
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
NAMES = ("A", "B", "C", "D", "E", "F", "G", "H", "I")
PORTS = {n: 19241 + i for i, n in enumerate(NAMES)}
URLS = {n: f"http://127.0.0.1:{PORTS[n]}" for n in NAMES}
LABEL = "eighthopdir"

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
        tmps[n] = tempfile.mkdtemp(prefix=f"8hop-dir-{n.lower()}-")
        privs[n] = secrets.token_hex(32)
        pubs[n] = publickey(bytes.fromhex(privs[n])).hex()
    k1_priv = bytes.fromhex(secrets.token_hex(32))
    k1_pub = publickey(k1_priv).hex()

    ups = {}
    for n in NAMES:
        procs[n], ups[n] = boot(tmps[n], privs[n], PORTS[n])
    try:
        check("nine independent nodes boot", all(ups.values()))
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
        code, _ = get(PORTS["I"], f"/api/v1/names/{LABEL}")
        check("I has never heard of it before gossip", code == 404,
              f"got {code}")

        # serial federation: A->B (1 recipient), then each interior
        # node gossips onward to its 2 known peers
        legs = (("A", 1), ("B", 2), ("C", 2), ("D", 2), ("E", 2), ("F", 2), ("G", 2), ("H", 2))
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
        code, served_f1 = get(PORTS["I"], f"/api/v1/names/{LABEL}")
        check("belt re-verifies I's K1 binding against K1",
              verify(k1_pub, served_f1.get("signature", ""), LABEL,
                     issued1, expires1))

        code, _ = get(PORTS["I"], f"/api/v1/names/{LABEL}/reach")
        check("I serves no reach descriptor before announce",
              code == 404, f"got {code}")
        check("resolve via I with binding only is silence",
              resolve_fresh(LABEL, URLS["I"]) is None)

        seed_peer(tmps["A"], pubs["I"], URLS["I"], "belt-node-i")
        out = run_helper(
            tmps["A"], privs["A"],
            {"CYBERNET_HOSTED_NAME": LABEL,
             "CYBERNET_NAME_PRIVKEY": k1_priv.hex(),
             "CYBERNET_PUBLIC_URL": URLS["A"]},
            "core._reach_out()")
        check("A reach announce under K1 ran to 2 recipients",
              "sent: 2" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, desc = wait_reach(PORTS["I"], LABEL, k1_pub)
        check("I serves the K1 reach descriptor", code == 200
              and desc.get("node_pubkey") == k1_pub,
              f"got {code} {desc}")
        strats = [s for s in (desc.get("reach") or [])
                  if isinstance(s, dict)]
        check("I descriptor carries ONLY the direct strategy",
              len(strats) == 1 and strats[0].get("kind") == "direct"
              and strats[0].get("url") == URLS["A"],
              f"reach={desc.get('reach')}")
        got = resolve_fresh(LABEL, URLS["I"])
        check("resolve via eighth hop I returns K1 direct at A",
              isinstance(got, dict) and got.get("node_pubkey") == k1_pub
              and got.get("node_url") == URLS["A"]
              and "via_relay" not in got
              and got.get("issued_at") == issued1
              and got.get("expires_at") == expires1,
              f"got {got}")
        check("unclaimed label resolves via I to silence",
              resolve_fresh("nobodyclaimedit", URLS["I"]) is None)
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
