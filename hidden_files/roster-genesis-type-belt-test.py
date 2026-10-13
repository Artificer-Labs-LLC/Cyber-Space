#!/usr/bin/env python3
"""Belt: the three roster-storage seats refuse a NON-BOOL genesis
instead of bool()-coercing it (primitives 1 naming + 5 discovery).

fed_announce, fed_gossip, and core._seed_bootstrap all stored the
roster genesis flag as int(bool(body/entry.get("genesis"))) with no
shape gate — so a peer serving genesis as the string "false" (or the
number 1) was stored as genesis=1, a claim nobody served in that
form, the same alias _delta_payload's own gate refuses on sight
(delta-payload-shape-type belt: genesis "false"/1 -> ValueError).
Only real bools are roster genesis flags: a present non-bool is
refused at each seat in its own convention (announce 400, gossip
entry ignored, seed skipped); absent keeps False, and bool
True/False are stored byte-exact.

Covers: announce genesis="false" -> 400 + no row; announce
genesis=1 -> 400 + no row; announce genesis=True -> stored 1
(control); announce absent -> stored 0 (control); gossip
genesis="false" -> ignored + no row; gossip genesis=True -> merged,
stored 1 (control); seed genesis="false" -> skipped, no row; seed
genesis=True -> stored 1 (control).

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/roster-genesis-type-belt-test.py
"""
import json
import os
import secrets
import sys
import tempfile
import time

TMP = tempfile.mkdtemp(prefix="roster-genesis-type-belt-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core  # noqa: E402
from core import _db, _db_lock, _NODE_PUB  # noqa: E402
import federation  # noqa: E402
from fed import envelope as fenv, ed25519  # noqa: E402
from fastapi import HTTPException  # noqa: E402

core.init_db()

CASES = {"passed": 0, "failed": 0}


def check(name, cond, extra=""):
    if cond:
        CASES["passed"] += 1
        print(f"  ok  {name}")
    else:
        CASES["failed"] += 1
        print(f"  FAIL {name} {extra}")


URL = "http://93.184.216.34/"


def genesis_of(pub):
    with _db() as conn:
        row = conn.execute(
            "SELECT genesis FROM peers WHERE node_pub=?",
            (pub.lower(),)).fetchone()
    return None if row is None else row["genesis"]


# ---- fed_announce seat ----
def announce(extra):
    sk = secrets.token_bytes(32)
    pk = ed25519.publickey(sk).hex()
    body = {"node_pub": pk, "name": "validnode", "node_url": URL,
            "network": "cybernet", "version": "0.1.0"}
    body.update(extra)
    body["node_pub"] = pk
    env = fenv.make_envelope(sk.hex(), pk, core._NODE_PUB, body)
    try:
        federation.fed_announce(env)
        status = 200
    except HTTPException as e:
        status = e.status_code
    return status, pk


status, pk = announce({"genesis": "false"})
check("announce genesis='false' -> refused 400, no row",
      status == 400 and genesis_of(pk) is None,
      f"{status} genesis={genesis_of(pk)}")

status, pk = announce({"genesis": 1})
check("announce genesis=1 -> refused 400, no row",
      status == 400 and genesis_of(pk) is None,
      f"{status} genesis={genesis_of(pk)}")

status, pk = announce({"genesis": True})
check("announce genesis=True -> stored 1 (control)",
      status == 200 and genesis_of(pk) == 1,
      f"{status} genesis={genesis_of(pk)}")

status, pk = announce({})
check("announce genesis absent -> stored 0 (control)",
      status == 200 and genesis_of(pk) == 0,
      f"{status} genesis={genesis_of(pk)}")

# ---- fed_gossip seat ----
SK = secrets.token_bytes(32)
PK = ed25519.publickey(SK).hex()
TS0 = int(time.time())
ann = fenv.make_envelope(
    SK.hex(), PK, "federation",
    {"node_pub": PK, "name": "peernode", "network": "cybernet",
     "version": "0.1.0", "genesis": False, "capabilities": []}, ts=TS0)
federation.fed_announce(ann)


def gossip(roster, ts):
    env = fenv.make_envelope(SK.hex(), PK, _NODE_PUB,
                             {"from_node_pub": PK, "roster": roster}, ts=ts)
    try:
        return federation.fed_gossip(env)
    except HTTPException as e:
        return {"error": e.status_code, "detail": e.detail}


def entry(pub, name, genesis):
    return {"node_pub": pub, "name": name, "node_url": URL,
            "version": "0.1.0", "genesis": genesis, "capabilities": []}


pk5 = ed25519.publickey(secrets.token_bytes(32)).hex()
r = gossip([entry(pk5, "strgenpeer", "false")], TS0 + 3)
check("gossip genesis='false' -> ignored, no row",
      r.get("merged") == 0 and r.get("ignored") == 1
      and genesis_of(pk5) is None, f"{r} genesis={genesis_of(pk5)}")

pk6 = ed25519.publickey(secrets.token_bytes(32)).hex()
r = gossip([entry(pk6, "boolgenpeer", True)], TS0 + 6)
check("gossip genesis=True -> merged, stored 1 (control)",
      r.get("merged") == 1 and genesis_of(pk6) == 1,
      f"{r} genesis={genesis_of(pk6)}")

# ---- _seed_bootstrap seat ----
SEED_A = "https://93.184.216.34"


def _card(**over):
    priv = secrets.token_hex(32)
    pub = core._fed_ed25519.publickey(bytes.fromhex(priv)).hex()
    body = {"name": "seednode", "network": "cybernet", "version": "0.1.0",
            "node_pub": pub, "genesis": False}
    body.update(over)
    env = core._fed_env.make_envelope(priv, pub, "federation", body)
    return pub, json.dumps(env).encode()


class _Resp:
    def __init__(self, payload):
        self._payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self, n=-1):
        return self._payload


def _run_seed(payload):
    with core._db_lock, core._db() as conn:
        conn.execute("DELETE FROM peers")
    os.environ["CYBERNET_SEED_URL"] = SEED_A
    os.environ.pop("CYBERNET_PUBLIC_URL", None)
    saved = core._peer_urlopen
    core._peer_urlopen = lambda url, timeout=8: _Resp(payload)
    try:
        return core._seed_bootstrap()
    finally:
        core._peer_urlopen = saved


pub, payload = _card(genesis="false")
reached = _run_seed(payload)
check("seed genesis='false' -> skipped, no row",
      reached == 0 and genesis_of(pub) is None,
      f"reached={reached} genesis={genesis_of(pub)}")

pub, payload = _card(genesis=True)
reached = _run_seed(payload)
check("seed genesis=True -> stored 1 (control)",
      reached == 1 and genesis_of(pub) == 1,
      f"reached={reached} genesis={genesis_of(pub)}")

print(f"\n{CASES['passed']} passed, {CASES['failed']} failed")
sys.exit(1 if CASES["failed"] else 0)
