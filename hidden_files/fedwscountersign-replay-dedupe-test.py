"""fed_workspace_countersign replay-dedupe wiring harness (2026-10-09 dev tick).

Step 2 of the seen-sig replay-dedupe build: _claim_seen_sig() is now wired
into fed_workspace_countersign (receiver #12). Drives the REAL
fed_workspace_countersign (sync) against a throwaway DB
(CYBERNET_DB_DIR=tempdir, created before core imports), with a REAL
invitee-node-signed countersign envelope (REAL countersign_sig over the
canonical _countersign_payload, verified against the sender's roster key).

Setup: a known unretired peer (the invitee node), a LIVE workspace row with
a charter, and a pending workspace_remote_members row (countersigned_at
NULL, struck_at NULL) bound to the sender's key — the home-node side of the
invite flow.

Positive controls (the harness proves itself):
 1. first valid countersign -> {"countersigned": True}, pending row marked
    countersigned_at, sig claimed in fed_seen_sigs, guest-book touch
    written ({invitee_key}@sender, room "workspaces")
 2. byte-identical replay -> 400 "replay", membership store and visitor
    touch untouched
 3. same countersign re-signed with a fresh ts -> 200 (idempotent
    re-countersign of the already-active row, not a replay), fresh sig
    claimed
Hostile/edge cases (named post-claim edges, same family as receivers 1-11):
 4. tampered body -> 400 "invalid envelope" (verify fails before the
    claim); sig never claimed
 5. wrong recipient -> 400 "not addressed to this node" (recipient gate
    precedes the claim); sig never claimed
 6. sender_pub mismatch (from_node_pub != sender_pub) -> 400
    "sender_pub mismatch" AND sig claimed (claim sits before the mismatch
    check)
 7. unknown peer sender -> 404 "unknown peer" AND sig claimed (claim sits
    before the standing gate)
 8. bad countersign_sig -> 400 "countersign_sig does not verify" AND sig
    claimed (claim sits before the expensive ed25519 verify)
"""
import hashlib
import os
import secrets
import sys
import tempfile
import time

TMP = tempfile.mkdtemp(prefix="cybernet-fedwscountersign-replay-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core
from core import _db, _now, _countersign_payload
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

# register the invitee node as a known, unretired peer (with standing)
with _db() as conn:
    conn.execute(
        "INSERT INTO peers (node_pub, name, network, version, genesis,"
        " capabilities, announced_at, first_seen, retired_at)"
        " VALUES (?, 'sender', 'cybernet', '0.1.0', 0, '[]', ?, ?, '')",
        (PK, _now(), _now()))

WID = 3
CHARTER = "the charter text of the third workspace"
OWN_HASH = hashlib.sha256(CHARTER.encode()).hexdigest()
INVITEE = "ab" * 32          # 64 hex member key

with _db() as conn:
    conn.execute(
        "INSERT INTO workspaces (id, name, charter, state, created_by, created_at)"
        " VALUES (?, 'room-three', ?, 'live', 1, ?)",
        (WID, CHARTER, _now()))
    conn.execute(
        "INSERT INTO workspace_remote_members "
        "(workspace_id, agent_pub, node_name, node_pub, countersigned_at, struck_at)"
        " VALUES (?, ?, 'sender', ?, NULL, NULL)",
        (WID, INVITEE, PK))

def countersign_sig_for(sk, pk_hex, wid, charter_hash, invitee):
    payload = _countersign_payload(wid, charter_hash, pk_hex, invitee)
    return ed25519.sign(payload, sk, bytes.fromhex(pk_hex)).hex()

def make_cs(sk, pk_hex, ts=None, recip=RECIP, from_node_pub=None,
            wid=WID, charter=OWN_HASH, invitee=INVITEE, bad_sig=False):
    body = {"from_node_pub": from_node_pub if from_node_pub is not None else pk_hex,
            "workspace_id": wid, "charter_hash": charter,
            "invitee_agent_key": invitee,
            "countersign_sig": ("00" * 64) if bad_sig
                               else countersign_sig_for(sk, pk_hex, wid, charter, invitee)}
    return fenv.make_envelope(sk.hex(), pk_hex, recip, body, ts=ts)

def claim_count(sig):
    with _db() as conn:
        return conn.execute(
            "SELECT COUNT(*) FROM fed_seen_sigs WHERE sig=?",
            (sig,)).fetchone()[0]

def member_row():
    with _db() as conn:
        return conn.execute(
            "SELECT countersigned_at, struck_at FROM workspace_remote_members "
            "WHERE workspace_id=? AND agent_pub=?",
            (WID, INVITEE)).fetchone()

def touch_count():
    with _db() as conn:
        return conn.execute(
            "SELECT COUNT(*) FROM visitor_touches").fetchone()[0]

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

# 1. first valid countersign
env1 = make_cs(SK, PK, ts=NOW)
sig1 = env1["sig"]
res = federation.fed_workspace_countersign(env1)
check("first countersign -> countersigned True", res.get("countersigned") is True
      and res.get("workspace_id") == WID)
row = member_row()
check("pending row marked countersigned_at", row["countersigned_at"] is not None)
check("row not struck", not row["struck_at"])
check("sig claimed in fed_seen_sigs", claim_count(sig1) == 1)
with _db() as conn:
    t = conn.execute(
        "SELECT rooms FROM visitor_touches WHERE visitor=?",
        (f"{INVITEE}@sender",)).fetchone()
check("guest-book touch written in room workspaces",
      t is not None and "workspaces" in (t[0] or "").split(","))
T0 = touch_count()

# 2. byte-identical replay -> 400 "replay", stores untouched
expect_http(lambda: federation.fed_workspace_countersign(env1),
            "byte-identical replay -> 400 replay", 400, "replay")
check("membership row untouched by replay", member_row()["countersigned_at"]
      == row["countersigned_at"])
check("visitor touch untouched by replay", touch_count() == T0)

# 3. fresh re-sign (new ts) -> idempotent 200, not a replay
env3 = make_cs(SK, PK, ts=NOW + 1)
res3 = federation.fed_workspace_countersign(env3)
check("fresh re-sign -> 200 countersigned True (idempotent)",
      res3.get("countersigned") is True)
check("fresh sig claimed", claim_count(env3["sig"]) == 1)

# 4. tampered body -> 400 before the claim
env4 = make_cs(SK, PK, ts=NOW + 2)
import copy as _copy
env4 = _copy.deepcopy(env4)
env4["body"] = dict(env4["body"]); env4["body"]["workspace_id"] = 999
expect_http(lambda: federation.fed_workspace_countersign(env4),
            "tampered body -> 400 invalid envelope", 400, "invalid envelope")
check("tampered sig never claimed", claim_count(env4["sig"]) == 0)

# 5. wrong recipient -> 400 before the claim
env5 = make_cs(SK, PK, ts=NOW + 3, recip="00" * 64)
expect_http(lambda: federation.fed_workspace_countersign(env5),
            "wrong recipient -> 400 not addressed", 400, "not addressed")
check("wrong-recipient sig never claimed", claim_count(env5["sig"]) == 0)

# 6. sender_pub mismatch -> 400 AND sig claimed (named post-claim edge)
env6 = make_cs(SK, PK, ts=NOW + 4, from_node_pub="11" * 32)
expect_http(lambda: federation.fed_workspace_countersign(env6),
            "sender_pub mismatch -> 400", 400, "sender_pub mismatch")
check("mismatch sig claimed (named edge)", claim_count(env6["sig"]) == 1)
expect_http(lambda: federation.fed_workspace_countersign(env6),
            "mismatch replay -> 400 replay", 400, "replay")

# 7. unknown peer sender -> 404 AND sig claimed (named post-claim edge)
env7 = make_cs(SK_UNKNOWN, PK_UNKNOWN, ts=NOW + 5)
expect_http(lambda: federation.fed_workspace_countersign(env7),
            "unknown peer -> 404", 404, "unknown peer")
check("unknown-peer sig claimed (named edge)", claim_count(env7["sig"]) == 1)
expect_http(lambda: federation.fed_workspace_countersign(env7),
            "unknown-peer replay -> 400 replay", 400, "replay")

# 8. bad countersign_sig -> 400 AND sig claimed (claim before ed25519 verify)
env8 = make_cs(SK, PK, ts=NOW + 6, bad_sig=True)
expect_http(lambda: federation.fed_workspace_countersign(env8),
            "bad countersign_sig -> 400 does not verify", 400, "does not verify")
check("bad-sig sig claimed (named edge)", claim_count(env8["sig"]) == 1)
check("row still marked once (bad sig never re-writes)",
      member_row()["countersigned_at"] is not None)
check("visitor touch count unchanged by bad sig", touch_count() == T0)

print(f"\nALL {len(passed)} CHECKS PASSED")
