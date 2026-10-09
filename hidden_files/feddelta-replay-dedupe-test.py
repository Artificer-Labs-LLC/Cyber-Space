"""fed_directory_delta replay-dedupe wiring harness (2026-10-09 dev tick).

Step 2 of the seen-sig replay-dedupe build: _claim_seen_sig() is now wired
into fed_directory_delta (receiver #9). Drives the REAL fed_directory_delta
against a throwaway DB (CYBERNET_DB_DIR=tempdir, created before core
imports). A REAL owner-signed delta is minted (dedicated owner key signs
core._delta_payload), gossiped inside a valid sender envelope, and the
dir-seq merge half is driven for real.

Positive controls (the harness proves itself):
 1. first valid delta envelope -> 200 {ok: True, applied: 1}, peer row
    stored with dir_seq=1, sig recorded in fed_seen_sigs
 2. byte-identical replay -> 400 "replay", peers store untouched
    (dir_seq unchanged, no new rows)
 3. same delta re-signed with a fresh ts -> 200 (stale: 1, the merge
    counts it stale, not a replay) — and a NEW delta (seq 2, fresh
    envelope) applies clean, proving the feddelta: rate quota survived
Hostile/edge cases:
 4. tampered body -> 400 "invalid envelope" (verify fails before the
    claim); sig never claimed
 5. wrong recipient -> 400 "not addressed to this node" (recipient gate
    precedes the claim); sig never claimed
 6. sender_pub mismatch -> 400 "sender_pub mismatch" AND sig claimed
    (claim sits before the mismatch check — post-claim named edge,
    same family as the other receivers)
 7. unknown peer sender -> 404 "unknown peer" AND sig claimed (claim sits
    before the known-peer gate — named edge)
 8. peers store is untouched by replay (dir_seq and row count identical
    across the replay)
"""
import os
import secrets
import sys
import tempfile
import time

TMP = tempfile.mkdtemp(prefix="cybernet-feddelta-replay-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core
from core import _db, _now, _delta_payload
import federation
from fed import envelope as fenv, ed25519
from fastapi import HTTPException

core.init_db()

passed = []
def check(label, cond):
    assert cond, f"FAIL: {label}"
    passed.append(label)

RECIP = federation._NODE_PUB

SK = secrets.token_bytes(32); PK = ed25519.publickey(SK).hex()
SK_UNKNOWN = secrets.token_bytes(32); PK_UNKNOWN = ed25519.publickey(SK_UNKNOWN).hex()
# dedicated owner key for the gossiped directory row (never the sender key)
OSK = secrets.token_bytes(32); OPK = ed25519.publickey(OSK).hex()

# register the delta sender as a known, unretired peer
with _db() as conn:
    conn.execute(
        "INSERT INTO peers (node_pub, name, network, version, genesis,"
        " capabilities, announced_at, first_seen, retired_at)"
        " VALUES (?, 'sender', 'cybernet', '0.1.0', 0, '[]', ?, ?, '')",
        (PK, _now(), _now()))

def mint_delta(name, seq, retire=False):
    row = {"node_pub": OPK, "name": name, "node_url": "https://8.8.8.8:443/cybernet",
           "capabilities": [], "network": "cybernet", "version": "0.1.0"}
    payload = _delta_payload(row, seq, retire)
    sig = ed25519.sign(payload, OSK, bytes.fromhex(OPK)).hex()
    return {"row": row, "seq": seq, "sig": sig, "retire": retire}

def make_delta_env(sk_hex, pk_hex, deltas, ts, recip=RECIP, from_node_pub=None):
    body = {"from_node_pub": from_node_pub if from_node_pub is not None else pk_hex,
            "deltas": deltas}
    return fenv.make_envelope(sk_hex, pk_hex, recip, body, ts=ts)

def sig_seen(sig_hex):
    with _db() as conn:
        return conn.execute(
            "SELECT 1 FROM fed_seen_sigs WHERE sig=?", (sig_hex,)).fetchone() is not None

def dir_row(pub):
    with _db() as conn:
        row = conn.execute(
            "SELECT name, dir_seq FROM peers WHERE node_pub=?", (pub,)).fetchone()
        return tuple(row) if row else None

def peer_count():
    with _db() as conn:
        return conn.execute("SELECT COUNT(*) c FROM peers").fetchone()["c"]

def deliver(env):
    try:
        payload = federation.fed_directory_delta(env)
    except HTTPException as e:
        return e.status_code, e.detail
    return 200, payload

ts0 = int(time.time())
delta = mint_delta("quillnode", 1)

# 1. first valid delta envelope -> 200, applied, sig claimed
env1 = make_delta_env(SK.hex(), PK, [delta], ts0)
st, pl = deliver(env1)
check("first delta 200", st == 200 and pl["ok"] is True and pl["applied"] == 1)
check("peer row stored", dir_row(OPK) == ("quillnode", 1))
check("sig claimed", sig_seen(env1["sig"]))

# 2. byte-identical replay -> 400 "replay", store untouched
before_row, before_n = dir_row(OPK), peer_count()
st, detail = deliver(env1)
check("replay 400", st == 400 and detail == "replay")
check("no merge on replay", dir_row(OPK) == before_row and peer_count() == before_n)

# 3a. same delta re-signed with a fresh ts -> 200 (stale: 1, merge counts
# it stale, not a replay)
env2 = make_delta_env(SK.hex(), PK, [delta], ts0 + 7)
st, pl = deliver(env2)
check("fresh re-sign 200", st == 200 and pl["ok"] is True and pl["stale"] == 1)
check("fresh re-sign sig claimed", sig_seen(env2["sig"]))
check("fresh re-sign not a replay", dir_row(OPK) == before_row)

# 3b. a NEW delta (seq 2) on a fresh envelope applies -> the feddelta:
# rate quota survived the claimed envelopes above
env3 = make_delta_env(SK.hex(), PK, [mint_delta("quillnode", 2)], ts0 + 9)
st, pl = deliver(env3)
check("new delta after claims 200", st == 200 and pl["ok"] is True and pl["applied"] == 1)
check("dir_seq advanced", dir_row(OPK) == ("quillnode", 2))

# 4. tampered body -> 400 "invalid envelope", sig never claimed
env4 = make_delta_env(SK.hex(), PK, [delta], ts0 + 11)
env4["body"]["deltas"] = [{"row": "forged", "seq": 1, "sig": "aa" * 64}]
st, detail = deliver(env4)
check("tampered body 400 invalid envelope", st == 400 and detail == "invalid envelope")
check("forgery sig not claimed", not sig_seen(env4["sig"]))

# 5. wrong recipient -> 400, sig never claimed
env5 = make_delta_env(SK.hex(), PK, [delta], ts0 + 13, recip="f" * 64)
st, detail = deliver(env5)
check("wrong recipient 400", st == 400 and detail == "not addressed to this node")
check("wrong-recipient sig not claimed", not sig_seen(env5["sig"]))

# 6. sender_pub mismatch -> 400 AND sig claimed (post-claim edge)
env6 = make_delta_env(SK.hex(), PK, [delta], ts0 + 17, from_node_pub=OPK)
st, detail = deliver(env6)
check("sender_pub mismatch 400", st == 400 and detail == "sender_pub mismatch")
check("mismatch envelope sig still claimed", sig_seen(env6["sig"]))
st, detail = deliver(env6)
check("mismatch replay now 400 replay", st == 400 and detail == "replay")

# 7. unknown peer -> 404 AND sig claimed (post-claim edge)
env7 = make_delta_env(SK_UNKNOWN.hex(), PK_UNKNOWN, [delta], ts0 + 19)
st, detail = deliver(env7)
check("unknown peer 404", st == 404 and detail == "unknown peer")
check("unknown-peer sig claimed", sig_seen(env7["sig"]))
st, detail = deliver(env7)
check("unknown-peer replay now 400 replay", st == 400 and detail == "replay")

print(f"{len(passed)}/{len(passed)} checks passed")
