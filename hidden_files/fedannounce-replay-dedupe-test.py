"""fed_announce replay-dedupe wiring harness (2026-10-09 dev tick).

Step 2 of the seen-sig replay-dedupe build: _claim_seen_sig() is now wired
into fed_announce (receiver #5). Drives the REAL fed_announce against a
throwaway DB (CYBERNET_DB_DIR=tempdir, created before core imports).

Positive controls (the harness proves itself):
 1. first valid announce -> 200 {"ok": True}, peers row stored, sig recorded
    in fed_seen_sigs
 2. byte-identical replay of the same envelope -> 400 "replay", no re-upsert
    (announced_at unchanged), no rate-bucket burn observable (roster write
    surface untouched)
 3. same content re-signed with a fresh ts -> 200 (idempotent update, not a
    replay)
Hostile/edge cases:
 4. tampered body (same sig, altered body) -> 400 "invalid envelope" (verify
    fails before the claim); a fresh valid envelope afterwards -> 200, so the
    forgery never poisoned the store
 5. envelope addressed to another node -> 400 "not addressed to this node"
    (recipient gate precedes the claim); the corrected envelope with a fresh
    ts -> 200
 6. sender_pub mismatch (body.node_pub != envelope sender) -> 400
    "sender_pub mismatch" AND the sig is still claimed (named edge: the claim
    sits before the mismatch check, same family as the no-op-leave edge in
    the earlier receiver harnesses)
"""
import json
import os
import secrets
import sys
import tempfile
import time

TMP = tempfile.mkdtemp(prefix="cybernet-fedannounce-replay-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core
from core import _db
import federation
from fed import envelope as fenv, ed25519
from fastapi import HTTPException

core.init_db()

passed = []
def check(label, cond):
    assert cond, f"FAIL: {label}"
    passed.append(label)

RECIP = "federation"

SK = secrets.token_bytes(32); PK = ed25519.publickey(SK).hex()
SK2 = secrets.token_bytes(32); PK2 = ed25519.publickey(SK2).hex()
WRONG_RECIP = "f" * 64

def body_for(pk, name="peernode"):
    return {"node_pub": pk, "name": name, "network": "cybernet",
            "version": "0.1.0", "genesis": False, "capabilities": []}

def make_announce(sk_hex, pk_hex, body, ts, recip=RECIP):
    return fenv.make_envelope(sk_hex, pk_hex, recip, body, ts=ts)

def sig_seen(sig_hex):
    with _db() as conn:
        return conn.execute(
            "SELECT 1 FROM fed_seen_sigs WHERE sig=?", (sig_hex,)).fetchone() is not None

def roster_name(pk_hex):
    with _db() as conn:
        row = conn.execute(
            "SELECT name, announced_at FROM peers WHERE node_pub=?",
            (pk_hex,)).fetchone()
        return (row["name"], row["announced_at"]) if row else (None, None)

def deliver(env):
    try:
        payload = federation.fed_announce(env)
    except HTTPException as e:
        return e.status_code, e.detail
    return 200, payload

ts0 = int(time.time())

# 1. first valid announce -> 200, stored, sig claimed
env1 = make_announce(SK.hex(), PK, body_for(PK), ts0)
st, pl = deliver(env1)
check("first announce 200", st == 200 and pl["ok"] is True and pl["stored"] == "peernode")
check("peers row stored", roster_name(PK)[0] == "peernode")
check("sig claimed", sig_seen(env1["sig"]))

# 2. byte-identical replay -> 400 "replay"
before = roster_name(PK)
st, detail = deliver(env1)
check("replay 400", st == 400 and detail == "replay")
check("no re-upsert on replay", roster_name(PK) == before)

# 3. fresh re-sign, same content -> 200 idempotent update
env2 = make_announce(SK.hex(), PK, body_for(PK), ts0 + 7)
st, pl = deliver(env2)
check("fresh re-sign 200", st == 200 and pl["ok"] is True)
check("fresh re-sign sig claimed", sig_seen(env2["sig"]))
check("fresh re-sign not a replay", roster_name(PK)[0] == "peernode")

# 4. tampered body -> 400 "invalid envelope", sig never claimed
env3 = make_announce(SK.hex(), PK, body_for(PK), ts0 + 11)
env3["body"]["name"] = "evilnode"
st, detail = deliver(env3)
check("tampered body 400 invalid envelope", st == 400 and detail == "invalid envelope")
check("forgery sig not claimed", not sig_seen(env3["sig"]))
env4 = make_announce(SK.hex(), PK, body_for(PK), ts0 + 13)
st, pl = deliver(env4)
check("fresh valid announce after forgery 200", st == 200)

# 5. wrong recipient -> 400 "not addressed to this node", sig never claimed
env5 = make_announce(SK.hex(), PK, body_for(PK), ts0 + 17, recip=WRONG_RECIP)
st, detail = deliver(env5)
check("wrong recipient 400", st == 400 and detail == "not addressed to this node")
check("wrong-recipient sig not claimed", not sig_seen(env5["sig"]))
env6 = make_announce(SK.hex(), PK, body_for(PK), ts0 + 19, recip=RECIP)
st, pl = deliver(env6)
check("corrected-recipient announce 200", st == 200)

# 6. sender_pub mismatch -> 400 AND sig claimed (post-claim named edge)
env7 = make_announce(SK.hex(), PK, body_for(PK2), ts0 + 23)
st, detail = deliver(env7)
check("sender_pub mismatch 400", st == 400 and detail == "sender_pub mismatch")
check("mismatch envelope sig still claimed", sig_seen(env7["sig"]))
st, detail = deliver(env7)
check("mismatch replay now 400 replay", st == 400 and detail == "replay")

print(f"{len(passed)}/{len(passed)} checks passed")
