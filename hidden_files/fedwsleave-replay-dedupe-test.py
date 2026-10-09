"""fed_workspace_leave replay-dedupe wiring harness (2026-10-09 dev tick).

Step 2 of the seen-sig replay-dedupe build: _claim_seen_sig() is now wired
into fed_workspace_leave (receiver #13). Drives the REAL async
fed_workspace_leave against a throwaway DB (CYBERNET_DB_DIR=tempdir, created
before core imports), with a REAL leave envelope (REAL leave_sig over the
canonical _leave_payload(wid, member_key), verified against the sender's
roster key — the leave body carries {workspace_id, member_key, leave_sig}).

Setup: a known unretired peer (the member's home node), a workspace row, and
an ACTIVE workspace_remote_members row (countersigned_at set, struck_at
NULL) bound to the sender's node key — the home-node side of a leave.

Positive controls (the harness proves itself):
 1. first valid leave -> {"left": True}, row struck_at set, sig claimed in
    fed_seen_sigs
 2. byte-identical replay -> 400 "replay", struck_at untouched, no re-claim
 3. same leave re-signed with a fresh ts -> 409 "already struck" (NOT 400
    "replay": the idempotent no-op lands on the real row state, with the
    fresh sig claimed; a replay of THAT envelope -> 400 "replay")
Hostile/edge cases (named post-claim edges, same family as receivers 1-12):
 4. tampered body -> 400 "invalid envelope" (verify fails before the
    claim); sig never claimed
 5. wrong recipient -> 400 "not addressed to this node" (recipient gate
    precedes the claim); sig never claimed
 6. sender_pub mismatch (from_node_pub != sender_pub) -> 400
    "sender_pub mismatch" AND sig claimed (claim sits before the mismatch
    check)
 7. unknown peer sender -> 404 "unknown peer" AND sig claimed (claim sits
    before the standing gate)
 8. bad leave_sig -> 400 "leave_sig does not verify" AND sig claimed
    (claim sits before the ed25519 verify)
 9. bad member_key shape -> 400 "bad member_key" AND sig claimed
10. no membership row -> 404 "no membership row matches" AND sig claimed
"""
import asyncio
import os
import secrets
import sys
import tempfile
import time

TMP = tempfile.mkdtemp(prefix="cybernet-fedwsleave-replay-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core
from core import _db, _now, _db_lock, _leave_payload
import federation
from federation import _claim_seen_sig
from fed import envelope as fenv, ed25519
from fastapi import HTTPException

core.init_db()
federation.init_fed_db() if hasattr(federation, "init_fed_db") else None

passed = []
def check(label, cond):
    assert cond, f"FAIL: {label}"
    passed.append(label)
    print(f"  ok: {label}", flush=True)

RECIP = federation._NODE_PUB

SK = secrets.token_bytes(32); PK = ed25519.publickey(SK).hex()
SK_UNKNOWN = secrets.token_bytes(32); PK_UNKNOWN = ed25519.publickey(SK_UNKNOWN).hex()

# register the member's home node as a known, unretired peer
with _db() as conn:
    conn.execute(
        "INSERT INTO peers (node_pub, name, network, version, genesis,"
        " capabilities, announced_at, first_seen, retired_at)"
        " VALUES (?, 'sender', 'cybernet', '0.1.0', 0, '[]', ?, ?, '')",
        (PK, _now(), _now()))

WID = 5
MEMBER = "cd" * 32          # 64-hex member key
MEMBER_NOROW = "ef" * 32

with _db() as conn:
    conn.execute(
        "INSERT INTO workspaces (id, name, charter, state, created_by, created_at)"
        " VALUES (?, 'leave-lab', 'a charter', 'live', 1, ?)", (WID, _now()))
    conn.execute(
        "INSERT INTO workspace_remote_members (workspace_id, agent_pub,"
        " node_name, node_pub, countersigned_at, struck_at)"
        " VALUES (?, ?, 'sender', ?, 'counted', NULL)", (WID, MEMBER, PK))

def leave_env(sk, pk, wid, member, tamper=None, recip=None, from_node_pub=None,
              bad_sig=False, ts=None):
    leave_sig = (bytes(64)).hex() if bad_sig else \
        ed25519.sign(_leave_payload(wid, member), sk, bytes.fromhex(pk)).hex()
    body = {"workspace_id": wid, "member_key": member, "leave_sig": leave_sig,
            "from_node_pub": pk if from_node_pub is None else from_node_pub}
    env = fenv.make_envelope(sk.hex(), pk, recip or RECIP, body, ts=ts)
    if tamper:
        env["body"]["member_key"] = tamper
    return env

def run(env):
    return asyncio.run(federation.fed_workspace_leave(env))

def http_code_of(fn):
    try:
        fn()
    except HTTPException as e:
        return e.status_code, e.detail
    return 200, None

def sig_claimed(sig):
    with _db() as conn:
        return conn.execute(
            "SELECT 1 FROM fed_seen_sigs WHERE sig=?", (sig,)).fetchone() is not None

def struck(wid, member):
    with _db() as conn:
        return conn.execute(
            "SELECT struck_at FROM workspace_remote_members"
            " WHERE workspace_id=? AND agent_pub=?", (wid, member)).fetchone()["struck_at"]

# 1. first valid leave -> 200, row struck, sig claimed
env1 = leave_env(SK, PK, WID, MEMBER)
res = run(env1)
check("first valid leave returns left=True", res.get("left") is True)
check("row struck_at set", bool(struck(WID, MEMBER)))
check("sig claimed after first leave", sig_claimed(env1["sig"]))

# 2. byte-identical replay -> 400 'replay', store untouched
code, detail = http_code_of(lambda: run(env1))
check("byte-identical replay 400s", code == 400)
check("replay detail is 'replay'", detail == "replay")
check("struck row not re-touched", struck(WID, MEMBER) is not None)

# 3. same leave re-signed with a fresh ts -> 409 already struck, fresh sig
#    claimed (real no-op, not a replay); replay of THAT -> 400 'replay'
# +2s ts so the re-sign lands on a distinct second (envelope ts is
# int-second; same-second resends are byte-identical by construction —
# this harness flaked on a second boundary, same family as the removed one)
env2 = leave_env(SK, PK, WID, MEMBER, ts=int(time.time()) + 2)
assert env2["sig"] != env1["sig"], "fresh ts must mint a fresh envelope sig"
code, detail = http_code_of(lambda: run(env2))
check("re-signed leave after strike 409s", code == 409)
check("409 detail names the struck state", detail == "already struck; the goodbye already landed.")
check("fresh sig claimed", sig_claimed(env2["sig"]))
code, _ = http_code_of(lambda: run(env2))
check("replay of the re-signed envelope 400s", code == 400)

# 4. tampered body -> 400 invalid envelope, never claimed
env3 = leave_env(SK, PK, WID, MEMBER_NOROW, tamper="00" * 32)
code, detail = http_code_of(lambda: run(env3))
check("tampered body 400s", code == 400 and detail == "invalid envelope")
check("tampered sig never claimed", not sig_claimed(env3["sig"]))

# 5. wrong recipient -> 400, never claimed
env4 = leave_env(SK, PK, WID, MEMBER, recip="deadbeef" * 8)
code, detail = http_code_of(lambda: run(env4))
check("wrong recipient 400s", code == 400 and detail == "not addressed to this node")
check("wrong-recipient sig never claimed", not sig_claimed(env4["sig"]))

# 6. sender_pub mismatch -> 400 + claimed
env5 = leave_env(SK, PK, WID, MEMBER, from_node_pub="ff" * 32)
code, detail = http_code_of(lambda: run(env5))
check("sender_pub mismatch 400s", code == 400 and detail == "sender_pub mismatch")
check("mismatch sig claimed", sig_claimed(env5["sig"]))

# 7. unknown peer -> 404 + claimed
env6 = leave_env(SK_UNKNOWN, PK_UNKNOWN, WID, MEMBER)
code, detail = http_code_of(lambda: run(env6))
check("unknown peer 404s", code == 404 and detail == "unknown peer")
check("unknown-peer sig claimed", sig_claimed(env6["sig"]))

# 8. bad leave_sig -> 400 + claimed
env7 = leave_env(SK, PK, WID, MEMBER, bad_sig=True)
code, detail = http_code_of(lambda: run(env7))
check("bad leave_sig 400s", code == 400 and detail == "leave_sig does not verify")
check("bad-sig sig claimed", sig_claimed(env7["sig"]))

# 9. bad member_key shape -> 400 + claimed
env8 = leave_env(SK, PK, WID, "short")
code, detail = http_code_of(lambda: run(env8))
check("bad member_key shape 400s", code == 400 and detail == "bad member_key")
check("bad-key sig claimed", sig_claimed(env8["sig"]))

# 10. no membership row -> 404 + claimed
env9 = leave_env(SK, PK, WID, MEMBER_NOROW)
code, detail = http_code_of(lambda: run(env9))
check("no-row leave 404s", code == 404 and "no membership row matches" in detail)
check("no-row sig claimed", sig_claimed(env9["sig"]))

print(f"\nfed_workspace_leave replay-dedupe harness: {len(passed)}/{len(passed)} green")
