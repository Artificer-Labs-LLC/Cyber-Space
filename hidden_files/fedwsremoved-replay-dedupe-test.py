"""fed_workspace_removed replay-dedupe wiring harness (2026-10-09 dev tick).

Step 2 of the seen-sig replay-dedupe build: _claim_seen_sig() is now wired
into fed_workspace_removed (receiver #14, the LAST write-surface fed
receiver). Drives the REAL sync fed_workspace_removed against a throwaway
DB (CYBERNET_DB_DIR=tempdir, created before core imports), with a REAL
remove envelope (REAL removed_sig over the canonical
_removed_payload(wid, member_key), verified against the sender's roster
key — the home-initiated remove notice carries
{workspace_id, member_key, removed_sig}).

Setup: a known unretired peer (the member's home node, the envelope
sender), a workspace row, and an ACTIVE workspace_remote_members receipt
(struck_at NULL) bound to the sender's node key.

Positive controls (the harness proves itself):
 1. first valid remove notice -> {"removed": True}, receipt struck_at
    set, sig claimed in fed_seen_sigs
 2. byte-identical replay -> 400 "replay", struck_at untouched, no re-claim
 3. same removal re-signed with a fresh ts -> 200 already_struck=True
    (NOT 400 "replay": the idempotent no-op lands on the real receipt
    state, with the fresh sig claimed; a replay of THAT envelope ->
    400 "replay")
Hostile/edge cases (named post-claim edges, same family as receivers 1-13):
 4. tampered body -> 400 "invalid envelope" (verify fails before the
    claim); sig never claimed
 5. wrong recipient -> 400 "not addressed to this node" (recipient gate
    precedes the claim); sig never claimed
 6. sender_pub mismatch (from_node_pub != sender_pub) -> 400
    "sender_pub mismatch" AND sig claimed (claim sits before the mismatch
    check)
 7. unknown peer sender -> 404 "unknown peer" AND sig claimed (claim sits
    before the standing gate)
 8. bad removed_sig -> 400 "removed_sig does not verify" AND sig claimed
    (claim sits before the ed25519 verify)
 9. bad member_key shape -> 400 "bad member_key" AND sig claimed
10. no membership receipt -> 404 "no membership receipt matches" AND sig
    claimed
"""
import os
import secrets
import sys
import tempfile
import time

TMP = tempfile.mkdtemp(prefix="cybernet-fedwsremoved-replay-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core
from core import _db, _now, _db_lock, _removed_payload
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

# register the member's HOME node (the remove-notice sender) as a known,
# unretired peer
with _db() as conn:
    conn.execute(
        "INSERT INTO peers (node_pub, name, network, version, genesis,"
        " capabilities, announced_at, first_seen, retired_at)"
        " VALUES (?, 'sender', 'cybernet', '0.1.0', 0, '[]', ?, ?, '')",
        (PK, _now(), _now()))

WID = 9
MEMBER = "ab" * 32          # 64-hex member key
MEMBER_NOROW = "cd" * 32

with _db() as conn:
    conn.execute(
        "INSERT INTO workspaces (id, name, charter, state, created_by, created_at)"
        " VALUES (?, 'remove-lab', 'a charter', 'live', 1, ?)", (WID, _now()))
    conn.execute(
        "INSERT INTO workspace_remote_members (workspace_id, agent_pub,"
        " node_name, node_pub, countersigned_at, struck_at)"
        " VALUES (?, ?, 'sender', ?, ?, NULL)", (WID, MEMBER, PK, _now()))

def removed_env(sk, pk, wid, member, tamper=None, recip=None,
                from_node_pub=None, bad_sig=False, ts=None):
    removed_sig = (bytes(64)).hex() if bad_sig else \
        ed25519.sign(_removed_payload(wid, member), sk, bytes.fromhex(pk)).hex()
    body = {"workspace_id": wid, "member_key": member,
            "removed_sig": removed_sig,
            "from_node_pub": pk if from_node_pub is None else from_node_pub}
    env = fenv.make_envelope(sk.hex(), pk, recip or RECIP, body, ts=ts)
    if tamper:
        env["body"]["member_key"] = tamper
    return env

def http_code_of(fn):
    try:
        res = fn()
    except HTTPException as e:
        return e.status_code, e.detail, None
    return 200, None, res

def sig_claimed(sig):
    with _db() as conn:
        return conn.execute(
            "SELECT 1 FROM fed_seen_sigs WHERE sig=?", (sig,)).fetchone() is not None

def struck(wid, member):
    with _db() as conn:
        return conn.execute(
            "SELECT struck_at FROM workspace_remote_members"
            " WHERE workspace_id=? AND agent_pub=?", (wid, member)).fetchone()["struck_at"]

# 1. first valid remove notice -> 200, receipt struck, sig claimed
env1 = removed_env(SK, PK, WID, MEMBER)
code, detail, res = http_code_of(lambda: federation.fed_workspace_removed(env1))
check("first valid remove notice 200s", code == 200)
check("remove notice returns removed=True", res.get("removed") is True)
check("receipt struck_at set", bool(struck(WID, MEMBER)))
check("sig claimed after first notice", sig_claimed(env1["sig"]))

# 2. byte-identical replay -> 400 'replay', store untouched
code, detail, _ = http_code_of(lambda: federation.fed_workspace_removed(env1))
check("byte-identical replay 400s", code == 400)
check("replay detail is 'replay'", detail == "replay")
check("struck receipt not re-touched", struck(WID, MEMBER) is not None)

# 3. same removal re-signed with a fresh ts -> 200 already_struck=True,
#    fresh sig claimed (real no-op, not a replay); replay of THAT ->
#    400 'replay'
# +2s ts so the re-sign lands on a distinct second (envelope ts is
# int-second; same-second resends are byte-identical by construction)
env2 = removed_env(SK, PK, WID, MEMBER, ts=int(time.time()) + 2)
assert env2["sig"] != env1["sig"], "fresh ts must mint a fresh envelope sig"
code, detail, res = http_code_of(lambda: federation.fed_workspace_removed(env2))
check("re-signed notice after strike 200s", code == 200)
check("re-signed notice is the idempotent no-op", res.get("already_struck") is True)
check("fresh sig claimed", sig_claimed(env2["sig"]))
code, _, _ = http_code_of(lambda: federation.fed_workspace_removed(env2))
check("replay of the re-signed envelope 400s", code == 400)

# 4. tampered body -> 400 invalid envelope, never claimed
env3 = removed_env(SK, PK, WID, MEMBER_NOROW, tamper="00" * 32)
code, detail, _ = http_code_of(lambda: federation.fed_workspace_removed(env3))
check("tampered body 400s", code == 400 and detail == "invalid envelope")
check("tampered sig never claimed", not sig_claimed(env3["sig"]))

# 5. wrong recipient -> 400, never claimed
env4 = removed_env(SK, PK, WID, MEMBER, recip="deadbeef" * 8)
code, detail, _ = http_code_of(lambda: federation.fed_workspace_removed(env4))
check("wrong recipient 400s", code == 400 and detail == "not addressed to this node")
check("wrong-recipient sig never claimed", not sig_claimed(env4["sig"]))

# 6. sender_pub mismatch -> 400 + claimed
env5 = removed_env(SK, PK, WID, MEMBER, from_node_pub="ff" * 32)
code, detail, _ = http_code_of(lambda: federation.fed_workspace_removed(env5))
check("sender_pub mismatch 400s", code == 400 and detail == "sender_pub mismatch")
check("mismatch sig claimed", sig_claimed(env5["sig"]))

# 7. unknown peer -> 404 + claimed
env6 = removed_env(SK_UNKNOWN, PK_UNKNOWN, WID, MEMBER)
code, detail, _ = http_code_of(lambda: federation.fed_workspace_removed(env6))
check("unknown peer 404s", code == 404 and detail == "unknown peer")
check("unknown-peer sig claimed", sig_claimed(env6["sig"]))

# 8. bad removed_sig -> 400 + claimed
env7 = removed_env(SK, PK, WID, MEMBER, bad_sig=True)
code, detail, _ = http_code_of(lambda: federation.fed_workspace_removed(env7))
check("bad removed_sig 400s", code == 400 and detail == "removed_sig does not verify")
check("bad-sig sig claimed", sig_claimed(env7["sig"]))

# 9. bad member_key shape -> 400 + claimed
env8 = removed_env(SK, PK, WID, "short")
code, detail, _ = http_code_of(lambda: federation.fed_workspace_removed(env8))
check("bad member_key shape 400s", code == 400 and detail == "bad member_key")
check("bad-key sig claimed", sig_claimed(env8["sig"]))

# 10. no membership receipt -> 404 + claimed
env9 = removed_env(SK, PK, WID, MEMBER_NOROW)
code, detail, _ = http_code_of(lambda: federation.fed_workspace_removed(env9))
check("no-receipt notice 404s", code == 404 and "no membership receipt matches" in detail)
check("no-receipt sig claimed", sig_claimed(env9["sig"]))

print(f"\nfed_workspace_removed replay-dedupe harness: {len(passed)}/{len(passed)} green")
