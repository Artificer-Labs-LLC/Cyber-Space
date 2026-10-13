#!/usr/bin/env python3
"""Belt: the four /fed/workspace_* receiver seats refuse a non-string
charter_hash / invitee_agent_key / member_key instead of str()-aliasing
it before their [0-9a-f]{64} regex gates (primitive 4 identity).

str(body.get(...)) built the string form first, so a 64-digit JSON
number passed the hex regex as its own string form: a charter_hash
served as int("1"*64) was read, stored and signature-verified as the
label "1"*64, the same alias the canonical payload builders now
refuse in core._ws_payload_gate. Seat fix: isinstance gate at all six
extractions (invite + countersign charter/invitee, leave + removed
member); a non-string reads as "" and fails the seat's own regex 400.
Valid string verdicts byte-exact.

Before: invite int-charter/int-invitee with sigs minted over the
aliased strings verified and stored; countersign int read charter
mismatch / downstream, leave+removed int passed the key gate.
After: all read the seat's own bad-<field> 400.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/fedws-receiver-field-type-belt-test.py
"""
import asyncio
import os
import secrets
import sys
import tempfile
import time

TMP = tempfile.mkdtemp(prefix="fedws-receiver-type-belt-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core  # noqa: E402
from core import _db, _now, _invite_payload  # noqa: E402
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


def expect(fn, name, status, detail):
    try:
        fn()
    except HTTPException as e:
        check(name, e.status_code == status and detail in str(e.detail),
              f"got {e.status_code} {e.detail!r}")
        return
    except Exception as e:  # noqa: BLE001
        check(name, False, f"raised {type(e).__name__}: {e}")
        return
    check(name, False, "succeeded instead of refusing")


RECIP = federation._NODE_PUB
SK = secrets.token_bytes(32)
PK = ed25519.publickey(SK).hex()
with _db() as conn:
    conn.execute(
        "INSERT INTO peers (node_pub, name, network, version, genesis,"
        " capabilities, announced_at, first_seen, retired_at)"
        " VALUES (?, 'sender', 'cybernet', '0.1.0', 0, '[]', ?, ?, '')",
        (PK, _now(), _now()))

WID = 7
CHARTER = "ab" * 32
INVITEE = "cd" * 32
INT_CHARTER = int("1" * 64)   # str() is 64 hex digits
INT_INVITEE = int("2" * 64)
INT_MEMBER = int("3" * 64)


def sig_for(payload):
    return ed25519.sign(payload, SK, bytes.fromhex(PK)).hex()


def env_for(body):
    return fenv.make_envelope(SK.hex(), PK, RECIP, body, ts=int(time.time()))


def invite_env(charter, invitee, alias_charter=None, alias_invitee=None):
    sig = sig_for(_invite_payload(
        WID, alias_charter if alias_charter is not None else charter,
        alias_invitee if alias_invitee is not None else invitee))
    return env_for({"from_node_pub": PK, "workspace_id": WID,
                    "charter_hash": charter, "invitee_agent_key": invitee,
                    "inviter_sig": sig})


# Control: valid string invite succeeds.
res = federation.fed_workspace_invite(invite_env(CHARTER, INVITEE))
check("valid string invite succeeds", res.get("invited") is True
      and res.get("charter_hash") == CHARTER)

# Invite aliases refuse at the seat gate, sigs over the alias notwithstanding.
expect(lambda: federation.fed_workspace_invite(
    invite_env(INT_CHARTER, INVITEE, alias_charter="1" * 64)),
    "invite int charter -> 400 bad charter_hash", 400, "bad charter_hash")
expect(lambda: federation.fed_workspace_invite(
    invite_env(CHARTER, INT_INVITEE, alias_invitee="2" * 64)),
    "invite int invitee -> 400 bad invitee_agent_key", 400,
    "bad invitee_agent_key")
expect(lambda: federation.fed_workspace_invite(
    invite_env(["ab"] * 32, INVITEE, alias_charter=CHARTER)),
    "invite list charter -> 400 bad charter_hash", 400, "bad charter_hash")

# Countersign: gate precedes workspace lookup / sig verify.
def countersign_env(charter, invitee):
    return env_for({"from_node_pub": PK, "workspace_id": WID,
                    "charter_hash": charter, "invitee_agent_key": invitee,
                    "countersign_sig": "00" * 64})

expect(lambda: federation.fed_workspace_countersign(
    countersign_env(INT_CHARTER, INVITEE)),
    "countersign int charter -> 400 bad charter_hash", 400,
    "bad charter_hash")
expect(lambda: federation.fed_workspace_countersign(
    countersign_env(CHARTER, INT_INVITEE)),
    "countersign int invitee -> 400 bad invitee_agent_key", 400,
    "bad invitee_agent_key")
# Control: valid strings pass the gate and reach the workspace lookup.
expect(lambda: federation.fed_workspace_countersign(
    countersign_env(CHARTER, INVITEE)),
    "countersign valid strings -> 404 workspace not found", 404,
    "workspace not found")

# Leave (async) + removed: member_key gate.
def leave_env(member):
    return env_for({"from_node_pub": PK, "workspace_id": WID,
                    "member_key": member, "leave_sig": "00" * 64})

def removed_env(member):
    return env_for({"from_node_pub": PK, "workspace_id": WID,
                    "member_key": member, "removed_sig": "00" * 64})

expect(lambda: asyncio.run(federation.fed_workspace_leave(
    leave_env(INT_MEMBER))),
    "leave int member -> 400 bad member_key", 400, "bad member_key")
expect(lambda: federation.fed_workspace_removed(removed_env(INT_MEMBER)),
       "removed int member -> 400 bad member_key", 400, "bad member_key")
# Control: valid string member passes the gate (reaches sig verify -> 400 sig).
expect(lambda: asyncio.run(federation.fed_workspace_leave(
    leave_env(INVITEE))),
    "leave valid string -> 400 sig does not verify (gate passed)", 400,
    "does not verify")

print(f"\n{CASES['passed']} passed, {CASES['failed']} failed")
sys.exit(1 if CASES["failed"] else 0)
