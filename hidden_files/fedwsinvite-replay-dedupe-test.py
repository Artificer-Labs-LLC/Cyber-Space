"""fed_workspace_invite replay-dedupe wiring harness (2026-10-09 dev tick).

Step 2 of the seen-sig replay-dedupe build: _claim_seen_sig() is now wired
into fed_workspace_invite (receiver #11) — found by the 06:25-tick closure
sweep; the four /fed/workspace_* receivers were missed by the "LAST
write-surface receiver" claim. Drives the REAL fed_workspace_invite (sync)
against a throwaway DB (CYBERNET_DB_DIR=tempdir, created before core
imports), with a REAL sender-signed invite envelope (REAL inviter_sig over
the canonical _invite_payload).

Positive controls (the harness proves itself):
 1. first valid invite -> {"invited": True}, one pending receipt row in
    workspace_remote_members, sig recorded in fed_seen_sigs
 2. byte-identical replay -> 400 "replay", receipt store untouched, no
    re-verify of inviter_sig, no ceiling re-count
 3. same invite re-signed with a fresh ts -> 200 (idempotent re-invite of
    the same row, not a replay), sig claimed
Hostile/edge cases (named post-claim edges, same family as receivers 1-10):
 4. tampered body -> 400 "invalid envelope" (verify fails before the
    claim); sig never claimed
 5. wrong recipient -> 400 "not addressed to this node" (recipient gate
    precedes the claim); sig never claimed
 6. sender_pub mismatch (from_node_pub != sender_pub) -> 400
    "sender_pub mismatch" AND sig claimed (claim sits before the mismatch
    check)
 7. unknown peer sender -> 404 "unknown peer" AND sig claimed (claim sits
    before the standing gate)
 8. bad inviter_sig -> 400 "inviter_sig does not verify" AND sig claimed
    (claim sits before the expensive ed25519 verify)
"""
import os
import secrets
import sys
import tempfile
import time

TMP = tempfile.mkdtemp(prefix="cybernet-fedwsinvite-replay-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core
from core import _db, _now, _invite_payload
import federation
from fed import envelope as fenv, ed25519
from fastapi import HTTPException

core.init_db()

passed = []
def check(label, cond):
    assert cond, f"FAIL: {label}"
    passed.append(label)
    print(f"  ok: {label}", flush=True)

RECIP = federation._NODE_PUB

SK = secrets.token_bytes(32); PK = ed25519.publickey(SK).hex()
SK_UNKNOWN = secrets.token_bytes(32); PK_UNKNOWN = ed25519.publickey(SK_UNKNOWN).hex()

# register the inviter as a known, unretired peer WITH standing (announced)
with _db() as conn:
    conn.execute(
        "INSERT INTO peers (node_pub, name, network, version, genesis,"
        " capabilities, announced_at, first_seen, retired_at)"
        " VALUES (?, 'sender', 'cybernet', '0.1.0', 0, '[]', ?, ?, '')",
        (PK, _now(), _now()))

WID = 7
CHARTER = "ab" * 32          # 64 hex
INVITEE = "cd" * 32          # 64 hex

def inviter_sig_for(sk: bytes, pk_hex: str, wid, charter, invitee):
    payload = _invite_payload(wid, charter, invitee)
    return ed25519.sign(payload, sk, bytes.fromhex(pk_hex)).hex()

def make_invite(sk, pk_hex, ts=None, recip=RECIP, from_node_pub=None,
                wid=WID, charter=CHARTER, invitee=INVITEE, bad_sig=False):
    body = {"from_node_pub": from_node_pub if from_node_pub is not None else pk_hex,
            "workspace_id": wid, "charter_hash": charter,
            "invitee_agent_key": invitee,
            "inviter_sig": ("00" * 64) if bad_sig
                           else inviter_sig_for(sk, pk_hex, wid, charter, invitee)}
    return fenv.make_envelope(sk.hex(), pk_hex, recip, body, ts=ts)

def claim_count(sig):
    with _db() as conn:
        return conn.execute(
            "SELECT COUNT(*) FROM fed_seen_sigs WHERE sig=?",
            (sig,)).fetchone()[0]

def receipt_count():
    with _db() as conn:
        return conn.execute(
            "SELECT COUNT(*) FROM workspace_remote_members").fetchone()[0]

def expect_http(fn, label, status, detail_sub):
    try:
        fn()
    except HTTPException as e:
        assert e.status_code == status, \
            f"{label}: status {e.status_code} != {status}"
        assert detail_sub in str(e.detail), \
            f"{label}: detail {e.detail!r} lacks {detail_sub!r}"
        passed.append(label); print(f"  ok: {label}", flush=True)
        return
    raise AssertionError(f"{label}: expected HTTP {status}, got success")

NOW = int(time.time())

# 1. first valid invite
env1 = make_invite(SK, PK, ts=NOW)
sig1 = env1["sig"]
res = federation.fed_workspace_invite(env1)
check("first invite -> invited True", res.get("invited") is True
      and res.get("workspace_id") == WID)
check("one pending receipt row", receipt_count() == 1)
with _db() as conn:
    row = conn.execute(
        "SELECT node_pub, countersigned_at FROM workspace_remote_members").fetchone()
check("receipt attributed to sender, pending",
      row["node_pub"] == PK and row["countersigned_at"] is None)
check("sig claimed in fed_seen_sigs", claim_count(sig1) == 1)

# 2. byte-identical replay -> 400 "replay", store untouched
expect_http(lambda: federation.fed_workspace_invite(env1),
            "byte-identical replay -> 400 replay", 400, "replay")
check("receipt store untouched by replay", receipt_count() == 1)

# 3. fresh re-sign (new ts) -> idempotent re-invite, not a replay
env3 = make_invite(SK, PK, ts=NOW + 1)
res3 = federation.fed_workspace_invite(env3)
check("fresh re-sign -> 200 invited True (idempotent)", res3.get("invited") is True)
check("still one row (idempotent re-invite)", receipt_count() == 1)
check("fresh sig claimed", claim_count(env3["sig"]) == 1)

# 4. tampered body -> 400 before the claim
env4 = make_invite(SK, PK, ts=NOW + 2)
import copy as _copy
env4 = _copy.deepcopy(env4)
env4["body"] = dict(env4["body"]); env4["body"]["workspace_id"] = 999
expect_http(lambda: federation.fed_workspace_invite(env4),
            "tampered body -> 400 invalid envelope", 400, "invalid envelope")
check("tampered sig never claimed", claim_count(env4["sig"]) == 0)

# 5. wrong recipient -> 400 before the claim
env5 = make_invite(SK, PK, ts=NOW + 3, recip="00" * 64)
expect_http(lambda: federation.fed_workspace_invite(env5),
            "wrong recipient -> 400 not addressed", 400, "not addressed")
check("wrong-recipient sig never claimed", claim_count(env5["sig"]) == 0)

# 6. sender_pub mismatch -> 400 AND sig claimed (named post-claim edge)
env6 = make_invite(SK, PK, ts=NOW + 4, from_node_pub="11" * 32)
expect_http(lambda: federation.fed_workspace_invite(env6),
            "sender_pub mismatch -> 400", 400, "sender_pub mismatch")
check("mismatch sig claimed (named edge)", claim_count(env6["sig"]) == 1)
expect_http(lambda: federation.fed_workspace_invite(env6),
            "mismatch replay -> 400 replay", 400, "replay")

# 7. unknown peer sender -> 404 AND sig claimed (named post-claim edge)
env7 = make_invite(SK_UNKNOWN, PK_UNKNOWN, ts=NOW + 5)
expect_http(lambda: federation.fed_workspace_invite(env7),
            "unknown peer -> 404", 404, "unknown peer")
check("unknown-peer sig claimed (named edge)", claim_count(env7["sig"]) == 1)
expect_http(lambda: federation.fed_workspace_invite(env7),
            "unknown-peer replay -> 400 replay", 400, "replay")

# 8. bad inviter_sig -> 400 AND sig claimed (claim before expensive verify)
env8 = make_invite(SK, PK, ts=NOW + 6, bad_sig=True)
expect_http(lambda: federation.fed_workspace_invite(env8),
            "bad inviter_sig -> 400 does not verify", 400, "does not verify")
check("bad-sig sig claimed (named edge)", claim_count(env8["sig"]) == 1)
check("no receipt row from bad-sig invite", receipt_count() == 1)

print(f"\nALL {len(passed)} CHECKS PASSED")
