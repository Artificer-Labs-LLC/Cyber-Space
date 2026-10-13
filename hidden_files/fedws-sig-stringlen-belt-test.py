#!/usr/bin/env python3
"""Belt: the four /fed/workspace_* receiver seats refuse a sig field
whose STRING length is not 128 even when its decode is the right byte
count (inviter_sig / countersign_sig / leave_sig / removed_sig)
(primitive 4 identity).

The seats gated the sig's TYPE (fedws-sig-field-type belt) but never
its string length before checkvalid, and bytes.fromhex ignores
embedded spaces -- so a 129-char signature with an inserted space (or
an outer-padded spelling) decoded to the TRUE 64 bytes and VERIFIED:
a non-canonical spelling every binding/delta seat refuses on sight
(len(signature) != 128) was accepted as proof of invite, countersign,
leave, and removal. Twin of fed_directory_delta 0bcca64 /
_recv_attestation 136c464.

Order matters: each seat's spaced variant is tried BEFORE its valid
control, so a false accept visibly consumes/moves the row (invite
inserted, countersign marked, leave struck) and the valid control
then lands on the wrong state.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/fedws-sig-stringlen-belt-test.py
"""
import asyncio
import hashlib
import os
import secrets
import sys
import tempfile
import time

TMP = tempfile.mkdtemp(prefix="fedws-sig-strlen-belt-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core  # noqa: E402
from core import (_db, _now, _invite_payload, _countersign_payload,  # noqa: E402
                  _leave_payload, _removed_payload)
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
CHARTER_TEXT = "a room at the depth"
CHARTER = hashlib.sha256(CHARTER_TEXT.encode()).hexdigest()
with _db() as conn:
    conn.execute(
        "INSERT INTO workspaces (id, name, charter, state, created_by,"
        " created_at) VALUES (?, 'room', ?, 'live', 1, ?)",
        (WID, CHARTER_TEXT, _now()))
INVITEE = "cd" * 32


def sign(payload):
    return ed25519.sign(payload, SK, bytes.fromhex(PK)).hex()


def spaced(sig):
    return sig[:64] + " " + sig[64:]  # 129 chars, true 64-byte decode


def env_for(body):
    return fenv.make_envelope(SK.hex(), PK, RECIP, body, ts=int(time.time()))


def invite_body(sig):
    return {"from_node_pub": PK, "workspace_id": WID, "charter_hash": CHARTER,
            "invitee_agent_key": INVITEE, "inviter_sig": sig}


def counter_body(sig):
    return {"from_node_pub": PK, "workspace_id": WID, "charter_hash": CHARTER,
            "invitee_agent_key": INVITEE, "countersign_sig": sig}


def leave_body(sig):
    return {"from_node_pub": PK, "workspace_id": WID, "member_key": INVITEE,
            "leave_sig": sig}


def removed_body(sig):
    return {"from_node_pub": PK, "workspace_id": WID, "member_key": INVITEE,
            "removed_sig": sig}


# --- invite ---
good = sign(_invite_payload(WID, CHARTER, INVITEE))
expect(lambda: federation.fed_workspace_invite(env_for(invite_body(spaced(good)))),
       "invite inserted-space 129-char sig -> 400 does not verify",
       400, "does not verify")
expect(lambda: federation.fed_workspace_invite(env_for(invite_body(" " + good + " "))),
       "invite outer-padded sig -> 400 does not verify", 400, "does not verify")
res = federation.fed_workspace_invite(env_for(invite_body(good)))
check("invite valid string sig succeeds", res.get("invited") is True)
res = federation.fed_workspace_invite(env_for(invite_body(good.upper())))
check("invite uppercase sig succeeds (control)", res.get("invited") is True)

# --- countersign ---
good = sign(_countersign_payload(WID, CHARTER, PK, INVITEE))
expect(lambda: federation.fed_workspace_countersign(env_for(counter_body(spaced(good)))),
       "countersign inserted-space 129-char sig -> 400 does not verify",
       400, "does not verify")
res = federation.fed_workspace_countersign(env_for(counter_body(good)))
check("countersign valid string sig succeeds", res.get("countersigned") is True)

# --- leave ---
good = sign(_leave_payload(WID, INVITEE))
tampered = ("0" if good[0] != "0" else "1") + good[1:]
expect(lambda: asyncio.run(federation.fed_workspace_leave(env_for(leave_body(spaced(good))))),
       "leave inserted-space 129-char sig -> 400 does not verify",
       400, "does not verify")
expect(lambda: asyncio.run(federation.fed_workspace_leave(env_for(leave_body(tampered)))),
       "leave tampered clean sig -> 400 does not verify (control)",
       400, "does not verify")
res = asyncio.run(federation.fed_workspace_leave(env_for(leave_body(good))))
check("leave valid string sig succeeds", res.get("left") is True)

# --- removed ---
good = sign(_removed_payload(WID, INVITEE))
expect(lambda: federation.fed_workspace_removed(env_for(removed_body(spaced(good)))),
       "removed inserted-space 129-char sig -> 400 does not verify",
       400, "does not verify")
res = federation.fed_workspace_removed(env_for(removed_body(good)))
check("removed valid string sig succeeds (already struck by leave)",
      res.get("removed") is True and res.get("already_struck") is True)

print(f"\n{CASES['passed']} passed, {CASES['failed']} failed")
sys.exit(1 if CASES["failed"] else 0)
