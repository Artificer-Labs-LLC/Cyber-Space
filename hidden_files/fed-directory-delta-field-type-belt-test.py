#!/usr/bin/env python3
"""Belt: fed_directory_delta's row seat refuses a NON-STRING row field
instead of str()-aliasing it (primitives 1 naming + 5 discovery).

The seat read row fields through str() at the owner pick, at the
_delta_payload signature check, and at the insert: a delta-carried
numeric name (12345) stringified to the valid label "12345" — the
payload the owner genuinely signed for that string, since
_delta_payload str()-coerces the same way — and was APPLIED and stored
as "12345"; an int network was likewise stored as its digit string.
Twin of fed_gossip's roster gate (fed-gossip-field-type-belt-test.py):
only real strings are directory row fields.

Covers: int name rejected + no row; int network rejected + no row;
valid string delta applied exact (control).

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/fed-directory-delta-field-type-belt-test.py
"""
import os
import secrets
import sys
import tempfile
import time

TMP = tempfile.mkdtemp(prefix="fed-delta-field-type-belt-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core  # noqa: E402
from core import _db, _now, _delta_payload, _NODE_PUB  # noqa: E402
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
URL = "https://8.8.8.8:443/cybernet"

# Register the delta sender as a known, unretired peer.
with _db() as conn:
    conn.execute(
        "INSERT INTO peers (node_pub, name, network, version, genesis,"
        " capabilities, announced_at, first_seen, retired_at)"
        " VALUES (?, 'sender', 'cybernet', '0.1.0', 0, '[]', ?, ?, '')",
        (PK, _now(), _now()))


def mint(osk, opk, row, seq=1):
    sig = ed25519.sign(_delta_payload(row, seq, False),
                       osk, bytes.fromhex(opk)).hex()
    return {"row": row, "seq": seq, "sig": sig, "retire": False}


def deliver(deltas, ts):
    env = fenv.make_envelope(SK.hex(), PK, _NODE_PUB,
                             {"from_node_pub": PK, "deltas": deltas}, ts=ts)
    try:
        return federation.fed_directory_delta(env)
    except HTTPException as e:
        return {"error": e.status_code, "detail": e.detail}


def row_for(pub):
    with _db() as conn:
        return conn.execute(
            "SELECT node_pub, name, network FROM peers WHERE node_pub=?",
            (pub,)).fetchone()


def base_row(opk, name, network="cybernet"):
    return {"node_pub": opk, "name": name, "node_url": URL,
            "capabilities": [], "network": network, "version": "0.1.0",
            "genesis": False}


# 1. int name: signed for the str() alias, must be rejected, no row.
osk1 = secrets.token_bytes(32)
opk1 = ed25519.publickey(osk1).hex()
r = deliver([mint(osk1, opk1, base_row(opk1, 12345))], TS0 + 3)
check("int name rejected", r.get("applied") == 0 and r.get("rejected") == 1, f"{r}")
check("int name stores no row", row_for(opk1) is None)

# 2. int network: valid string name, int network stored as digits pre-fix.
osk2 = secrets.token_bytes(32)
opk2 = ed25519.publickey(osk2).hex()
r = deliver([mint(osk2, opk2, base_row(opk2, "netnode", network=12345))], TS0 + 6)
check("int network rejected", r.get("applied") == 0 and r.get("rejected") == 1, f"{r}")
check("int network stores no row", row_for(opk2) is None)

# 3. valid string control: applied, stored exact.
osk3 = secrets.token_bytes(32)
opk3 = ed25519.publickey(osk3).hex()
r = deliver([mint(osk3, opk3, base_row(opk3, "stringnode"))], TS0 + 9)
check("valid string delta applied", r.get("applied") == 1, f"{r}")
row = row_for(opk3)
check("valid string delta stored exact",
      row is not None and row["name"] == "stringnode"
      and row["network"] == "cybernet")

print(f"{CASES['passed']} passed, {CASES['failed']} failed")
sys.exit(1 if CASES["failed"] else 0)
