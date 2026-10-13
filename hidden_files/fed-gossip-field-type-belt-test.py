#!/usr/bin/env python3
"""Belt: fed_gossip's roster seat refuses a NON-STRING node_pub/name
instead of str()-aliasing it (primitives 1 naming + 5 discovery).

The seat read both fields through str(): a gossip-carried digit-only
pubkey served as a JSON number stringified to its own hex, passed the
64-hex gate, and MERGED as a peer row; a numeric name likewise merged
as its digit string. Twin of the binding seats' isinstance gate in
core (binding-field-type-belt-test.py): only real strings are roster
identity fields.

Covers: int node_pub ignored + no row; int name ignored + no row;
valid string entry merged exact (control); uppercase-hex string pubkey
merged lowercased (string behaviour unchanged).

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/fed-gossip-field-type-belt-test.py
"""
import os
import secrets
import sys
import tempfile
import time

TMP = tempfile.mkdtemp(prefix="fed-gossip-field-type-belt-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core  # noqa: E402
from core import _db, _NODE_PUB  # noqa: E402
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


SK = secrets.token_bytes(32)
PK = ed25519.publickey(SK).hex()
TS0 = int(time.time())
URL = "https://93.184.216.34:443/"

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


def row_for(pub):
    with _db() as conn:
        return conn.execute(
            "SELECT node_pub, name, version, node_url FROM peers WHERE node_pub=?",
            (pub,)).fetchone()


def entry(pub, name):
    return {"node_pub": pub, "name": name, "node_url": URL,
            "version": "0.1.0", "genesis": False, "capabilities": []}


digit_pub = "1" * 64
r = gossip([entry(int(digit_pub), "intpubpeer")], TS0 + 3)
check("int node_pub ignored", r.get("merged") == 0 and r.get("ignored") == 1, f"{r}")
check("int node_pub stores no row", row_for(digit_pub) is None)

pk2 = ed25519.publickey(secrets.token_bytes(32)).hex()
r = gossip([entry(pk2, 12345)], TS0 + 6)
check("int name ignored", r.get("merged") == 0 and r.get("ignored") == 1, f"{r}")
check("int name stores no row", row_for(pk2.lower()) is None)

pk3 = ed25519.publickey(secrets.token_bytes(32)).hex()
r = gossip([entry(pk3, "stringpeer")], TS0 + 9)
check("valid string entry merged", r.get("merged") == 1, f"{r}")
row = row_for(pk3.lower())
check("valid string entry stored exact",
      row is not None and row["name"] == "stringpeer")

pk4 = ed25519.publickey(secrets.token_bytes(32)).hex()
r = gossip([entry(pk4.upper(), "upperpeer")], TS0 + 12)
check("uppercase-hex string pub merged", r.get("merged") == 1, f"{r}")
check("uppercase-hex string pub stored lowercased",
      row_for(pk4.lower()) is not None)

pk5 = ed25519.publickey(secrets.token_bytes(32)).hex()
e5 = entry(pk5, "intverpeer"); e5["version"] = 1
r = gossip([e5], TS0 + 15)
check("int version ignored", r.get("merged") == 0 and r.get("ignored") == 1, f"{r}")
check("int version stores no row", row_for(pk5.lower()) is None)

pk6 = ed25519.publickey(secrets.token_bytes(32)).hex()
e6 = entry(pk6, "listurlpeer"); e6["node_url"] = [URL]
r = gossip([e6], TS0 + 18)
check("list node_url ignored", r.get("merged") == 0 and r.get("ignored") == 1, f"{r}")
check("list node_url stores no row", row_for(pk6.lower()) is None)

pk7 = ed25519.publickey(secrets.token_bytes(32)).hex()
r = gossip([entry(pk7, "verpeer")], TS0 + 21)
row = row_for(pk7.lower())
check("valid version/node_url stored exact",
      r.get("merged") == 1 and row is not None
      and row["version"] == "0.1.0" and row["node_url"] == URL.rstrip("/"),
      f"{r} {row}")

print(f"{CASES['passed']} passed, {CASES['failed']} failed")
sys.exit(1 if CASES["failed"] else 0)
