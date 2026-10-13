#!/usr/bin/env python3
"""Belt: the four /fed/workspace_* receiver seats refuse a non-string
sig field (inviter_sig / countersign_sig / leave_sig / removed_sig)
instead of str()-aliasing it before bytes.fromhex (primitive 4
identity).

The seats read str(body.get(...)), so a 128-digit JSON number was
hex-decoded and carried into ed25519 checkvalid as 64 signature
bytes: a numeric sig whose decimal string decoded to a valid
signature (hex all decimal digits) would have verified as surely as
its string twin — the type was laundered before the one check that
gives the field meaning, the same alias shape the sibling hash/key
seats refused last tick. Seat fix: isinstance gate at all four
extractions; a non-string reads as "" and fails verification.

Proof method: the belt wraps the REAL checkvalid (recording, then
delegating) and inspects the exact signature bytes that reach it for
each seat's canonical payload. Before: the int sig arrives as its
64 decoded bytes. After: it arrives as b""; a valid string sig
arrives byte-exact and still verifies end to end.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/fedws-sig-field-type-belt-test.py
"""
import asyncio
import hashlib
import os
import secrets
import sys
import tempfile
import time

TMP = tempfile.mkdtemp(prefix="fedws-sig-type-belt-")
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

# Recording wrapper over the real verifier.
SEEN = []
_real_checkvalid = ed25519.checkvalid


def recording_checkvalid(sig, msg, pk):
    SEEN.append((bytes(sig), bytes(msg)))
    return _real_checkvalid(sig, msg, pk)


ed25519.checkvalid = recording_checkvalid


def seen_sig_for(msg):
    hits = [s for s, m in SEEN if m == msg]
    return hits[-1] if hits else None


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
INT_SIG = int("1" * 128)  # str() is 128 hex digits -> 64 bytes pre-fix


def sign(payload):
    return ed25519.sign(payload, SK, bytes.fromhex(PK))


def env_for(body):
    return fenv.make_envelope(SK.hex(), PK, RECIP, body, ts=int(time.time()))


# --- invite ---
ip = _invite_payload(WID, CHARTER, INVITEE)
good_invite_sig = sign(ip)
res = federation.fed_workspace_invite(env_for(
    {"from_node_pub": PK, "workspace_id": WID, "charter_hash": CHARTER,
     "invitee_agent_key": INVITEE, "inviter_sig": good_invite_sig.hex()}))
check("invite valid string sig succeeds", res.get("invited") is True)
check("invite string sig reaches verify byte-exact",
      seen_sig_for(ip) == good_invite_sig)
expect(lambda: federation.fed_workspace_invite(env_for(
    {"from_node_pub": PK, "workspace_id": WID, "charter_hash": CHARTER,
     "invitee_agent_key": INVITEE, "inviter_sig": INT_SIG})),
    "invite int sig -> 400 does not verify", 400, "does not verify")
check("invite int sig reaches verify as b'' (not its decoded bytes)",
      seen_sig_for(ip) == b"", f"got {seen_sig_for(ip)!r}")

# --- countersign (sig seat sits after workspace + charter checks) ---
cp = _countersign_payload(WID, CHARTER, PK, INVITEE)
good_counter_sig = sign(cp)
res = federation.fed_workspace_countersign(env_for(
    {"from_node_pub": PK, "workspace_id": WID, "charter_hash": CHARTER,
     "invitee_agent_key": INVITEE,
     "countersign_sig": good_counter_sig.hex()}))
check("countersign valid string sig succeeds (pending invite from above)",
      res.get("countersigned") is True)
check("countersign string sig reaches verify byte-exact",
      seen_sig_for(cp) == good_counter_sig)
expect(lambda: federation.fed_workspace_countersign(env_for(
    {"from_node_pub": PK, "workspace_id": WID, "charter_hash": CHARTER,
     "invitee_agent_key": INVITEE, "countersign_sig": INT_SIG})),
    "countersign int sig -> 400 does not verify", 400, "does not verify")
check("countersign int sig reaches verify as b''",
      seen_sig_for(cp) == b"", f"got {seen_sig_for(cp)!r}")

# --- leave (async; sig seat precedes workspace/row lookups) ---
lp = _leave_payload(WID, INVITEE)
good_leave_sig = sign(lp)
res = asyncio.run(federation.fed_workspace_leave(env_for(
    {"from_node_pub": PK, "workspace_id": WID, "member_key": INVITEE,
     "leave_sig": good_leave_sig.hex()})))
check("leave valid string sig succeeds (row struck)",
      res.get("left") is True)
check("leave string sig reaches verify byte-exact",
      seen_sig_for(lp) == good_leave_sig)
expect(lambda: asyncio.run(federation.fed_workspace_leave(env_for(
    {"from_node_pub": PK, "workspace_id": WID, "member_key": INVITEE,
     "leave_sig": INT_SIG}))),
    "leave int sig -> 400 does not verify", 400, "does not verify")
check("leave int sig reaches verify as b''",
      seen_sig_for(lp) == b"", f"got {seen_sig_for(lp)!r}")
expect(lambda: asyncio.run(federation.fed_workspace_leave(env_for(
    {"from_node_pub": PK, "workspace_id": WID, "member_key": INVITEE,
     "leave_sig": ["11"] * 64}))),
    "leave list sig -> 400 does not verify", 400, "does not verify")

# --- removed ---
rp = _removed_payload(WID, INVITEE)
good_removed_sig = sign(rp)
res = federation.fed_workspace_removed(env_for(
    {"from_node_pub": PK, "workspace_id": WID, "member_key": INVITEE,
     "removed_sig": good_removed_sig.hex()}))
check("removed valid string sig succeeds (already struck by leave)",
      res.get("removed") is True and res.get("already_struck") is True)
check("removed string sig reaches verify byte-exact",
      seen_sig_for(rp) == good_removed_sig)
expect(lambda: federation.fed_workspace_removed(env_for(
    {"from_node_pub": PK, "workspace_id": WID, "member_key": INVITEE,
     "removed_sig": INT_SIG})),
    "removed int sig -> 400 does not verify", 400, "does not verify")
check("removed int sig reaches verify as b''",
      seen_sig_for(rp) == b"", f"got {seen_sig_for(rp)!r}")

print(f"\n{CASES['passed']} passed, {CASES['failed']} failed")
sys.exit(1 if CASES["failed"] else 0)
