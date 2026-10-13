#!/usr/bin/env python3
"""Belt: fed_directory_delta refuses a NON-BOOL retire and a NON-STRING
sig instead of bool()/str()-coercing them (primitives 1 naming +
5 discovery).

The seat read the delta's own fields with coercion:
`retire = bool(delta.get("retire", False))` and
`sig_hex = str(delta.get("sig", ""))` — before calling
_delta_payload, whose own gate (delta-payload-shape-type belt)
refuses a non-bool retire with ValueError. The coercion defeated
that gate at this seat: a delta carrying retire as the string
"false" was read as a retire — bool("false") is True — verified
against the retire payload its owner signature genuinely covered,
and APPLIED as a tombstone. Its twin seat _recv_attestation gates
sig the same way this belt asks for here ("sig" present and not a
string reads as malformed); this seat str()-coerced it instead.
Only the shapes the canonical form actually has are acceptable:
absent retire keeps False, a present one must be a bool; an absent
sig keeps "", a present one must be a string.

Covers: retire="false" signed for the True payload -> rejected, no
tombstone; retire=1 signed for the True payload -> rejected, no
tombstone; int sig -> rejected, no row; valid retire=True control
-> retired, tombstone stored; valid retire=False control ->
applied exact.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/fed-directory-delta-retire-type-belt-test.py
"""
import os
import secrets
import sys
import tempfile
import time

TMP = tempfile.mkdtemp(prefix="fed-delta-retire-type-belt-")
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


def mint(osk, opk, row, seq, retire_signed, retire_wire, sig_wire=None):
    sig = ed25519.sign(_delta_payload(row, seq, retire_signed),
                       osk, bytes.fromhex(opk)).hex()
    return {"row": row, "seq": seq,
            "sig": sig if sig_wire is None else sig_wire,
            "retire": retire_wire}


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
            "SELECT node_pub, name, retired_at FROM peers WHERE node_pub=?",
            (pub,)).fetchone()


def base_row(opk, name):
    return {"node_pub": opk, "name": name, "node_url": URL,
            "capabilities": [], "network": "cybernet", "version": "0.1.0",
            "genesis": False}


# 1. retire="false" (string): bool() coerces it to a retire pre-fix.
osk1 = secrets.token_bytes(32)
opk1 = ed25519.publickey(osk1).hex()
r = deliver([mint(osk1, opk1, base_row(opk1, "strretire"), 1, True, "false")],
            TS0 + 3)
check("string 'false' retire rejected",
      r.get("rejected") == 1 and r.get("retired", 0) == 0, f"{r}")
check("string 'false' retire stores no tombstone", row_for(opk1) is None)

# 2. retire=1 (int): bool() coerces it to a retire pre-fix.
osk2 = secrets.token_bytes(32)
opk2 = ed25519.publickey(osk2).hex()
r = deliver([mint(osk2, opk2, base_row(opk2, "intretire"), 1, True, 1)],
            TS0 + 6)
check("int 1 retire rejected",
      r.get("rejected") == 1 and r.get("retired", 0) == 0, f"{r}")
check("int 1 retire stores no tombstone", row_for(opk2) is None)

# 3. int sig: str() coerced it pre-fix (twin _recv_attestation gates it).
osk3 = secrets.token_bytes(32)
opk3 = ed25519.publickey(osk3).hex()
good = mint(osk3, opk3, base_row(opk3, "intsig"), 1, False, False)
r = deliver([mint(osk3, opk3, base_row(opk3, "intsig"), 1, False, False,
                  sig_wire=int(good["sig"], 16))], TS0 + 9)
check("int sig rejected", r.get("rejected") == 1 and r.get("applied", 0) == 0,
      f"{r}")
check("int sig stores no row", row_for(opk3) is None)

# 4. valid retire=True control: retired, tombstone stored.
osk4 = secrets.token_bytes(32)
opk4 = ed25519.publickey(osk4).hex()
r = deliver([mint(osk4, opk4, base_row(opk4, "boolretire"), 1, True, True)],
            TS0 + 12)
check("valid bool retire applied", r.get("retired") == 1, f"{r}")
row = row_for(opk4)
check("valid bool retire tombstone stored",
      row is not None and row["retired_at"] != "")

# 5. valid retire=False control: applied, stored exact, not retired.
osk5 = secrets.token_bytes(32)
opk5 = ed25519.publickey(osk5).hex()
r = deliver([mint(osk5, opk5, base_row(opk5, "liveone"), 1, False, False)],
            TS0 + 15)
check("valid bool non-retire applied", r.get("applied") == 1, f"{r}")
row = row_for(opk5)
check("valid bool non-retire stored exact",
      row is not None and row["name"] == "liveone" and row["retired_at"] == "")

print(f"{CASES['passed']} passed, {CASES['failed']} failed")
sys.exit(1 if CASES["failed"] else 0)
