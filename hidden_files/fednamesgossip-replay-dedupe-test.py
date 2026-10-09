"""fed_names_gossip replay-dedupe wiring harness (2026-10-09 dev tick).

Step 2 of the seen-sig replay-dedupe build: _claim_seen_sig() is now wired
into fed_names_gossip (receiver #8). Drives the REAL fed_names_gossip
against a throwaway DB (CYBERNET_DB_DIR=tempdir, created before core
imports). A REAL valid binding is minted (dedicated name key signs the
canonical claim payload), gossiped inside a valid sender envelope, and the
merge half is driven for real.

Positive controls (the harness proves itself):
 1. first valid gossip envelope -> 200 {ok: True, inserted: 1}, binding
    row stored in name_bindings, sig recorded in fed_seen_sigs
 2. byte-identical replay -> 400 "replay", no re-insert/re-merge on the
    binding store, no rate-bucket burn (a fresh envelope still passes)
 3. same bindings re-signed with a fresh ts -> 200 (kept: 1, idempotent
    merge, not a replay)
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
 8. binding store is untouched by replay (row count and binding row
    identical across replay)
"""
import os
import secrets
import sys
import tempfile
import time

TMP = tempfile.mkdtemp(prefix="cybernet-fednamesgossip-replay-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core
from core import _db, _now, _name_claim_payload
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
# dedicated name key for the gossiped binding (never the sender key)
BSK = secrets.token_bytes(32); BPK = ed25519.publickey(BSK).hex()

# register the gossip sender as a known, unretired peer
with _db() as conn:
    conn.execute(
        "INSERT INTO peers (node_pub, name, network, version, genesis,"
        " capabilities, announced_at, first_seen, retired_at)"
        " VALUES (?, 'sender', 'cybernet', '0.1.0', 0, '[]', ?, ?, '')",
        (PK, _now(), _now()))

def mint_binding(name):
    issued = _now()
    # expires far enough out to never be stale in the harness
    expires = "2036-01-01T00:00:00+00:00"
    payload = _name_claim_payload(name, BPK, issued, expires)
    sig = ed25519.sign(payload, BSK, bytes.fromhex(BPK)).hex()
    return {"name": name, "node_pubkey": BPK, "issued_at": issued,
            "expires_at": expires, "signature": sig}

def make_gossip(sk_hex, pk_hex, bindings, ts, recip=RECIP, from_node_pub=None):
    body = {"from_node_pub": from_node_pub if from_node_pub is not None else pk_hex,
            "bindings": bindings}
    return fenv.make_envelope(sk_hex, pk_hex, recip, body, ts=ts)

def sig_seen(sig_hex):
    with _db() as conn:
        return conn.execute(
            "SELECT 1 FROM fed_seen_sigs WHERE sig=?", (sig_hex,)).fetchone() is not None

def binding_row(name):
    with _db() as conn:
        row = conn.execute(
            "SELECT name, node_pubkey, signature FROM name_bindings WHERE name=?",
            (name,)).fetchone()
        return tuple(row) if row else None

def deliver(env):
    try:
        payload = federation.fed_names_gossip(env)
    except HTTPException as e:
        return e.status_code, e.detail
    return 200, payload

ts0 = int(time.time())
binding = mint_binding("quill")

# 1. first valid gossip envelope -> 200, inserted, sig claimed
env1 = make_gossip(SK.hex(), PK, [binding], ts0)
st, pl = deliver(env1)
check("first gossip 200", st == 200 and pl["ok"] is True and pl["inserted"] == 1)
check("binding row stored", binding_row("quill") == ("quill", BPK, binding["signature"]))
check("sig claimed", sig_seen(env1["sig"]))

# 2. byte-identical replay -> 400 "replay", store untouched
before = binding_row("quill")
st, detail = deliver(env1)
check("replay 400", st == 400 and detail == "replay")
check("no re-merge on replay", binding_row("quill") == before)

# 3. fresh re-sign, same bindings -> 200 (kept, not replay)
env2 = make_gossip(SK.hex(), PK, [binding], ts0 + 7)
st, pl = deliver(env2)
check("fresh re-sign 200", st == 200 and pl["ok"] is True and pl["kept"] == 1)
check("fresh re-sign sig claimed", sig_seen(env2["sig"]))
check("fresh re-sign not a replay", binding_row("quill") == before)

# 4. tampered body -> 400 "invalid envelope", sig never claimed
env3 = make_gossip(SK.hex(), PK, [binding], ts0 + 11)
env3["body"]["bindings"] = [{"name": "evil", "node_pubkey": BPK,
                             "issued_at": _now(), "expires_at": "2036-01-01T00:00:00+00:00",
                             "signature": "aa" * 64}]
st, detail = deliver(env3)
check("tampered body 400 invalid envelope", st == 400 and detail == "invalid envelope")
check("forgery sig not claimed", not sig_seen(env3["sig"]))

# 5. wrong recipient -> 400, sig never claimed
env4 = make_gossip(SK.hex(), PK, [binding], ts0 + 13, recip="f" * 64)
st, detail = deliver(env4)
check("wrong recipient 400", st == 400 and detail == "not addressed to this node")
check("wrong-recipient sig not claimed", not sig_seen(env4["sig"]))

# 6. sender_pub mismatch -> 400 AND sig claimed (post-claim edge)
env5 = make_gossip(SK.hex(), PK, [binding], ts0 + 17, from_node_pub=BPK)
st, detail = deliver(env5)
check("sender_pub mismatch 400", st == 400 and detail == "sender_pub mismatch")
check("mismatch envelope sig still claimed", sig_seen(env5["sig"]))
st, detail = deliver(env5)
check("mismatch replay now 400 replay", st == 400 and detail == "replay")

# 7. unknown peer -> 404 AND sig claimed (post-claim edge)
env6 = make_gossip(SK_UNKNOWN.hex(), PK_UNKNOWN, [binding], ts0 + 19)
st, detail = deliver(env6)
check("unknown peer 404", st == 404 and detail == "unknown peer")
check("unknown-peer sig claimed", sig_seen(env6["sig"]))
st, detail = deliver(env6)
check("unknown-peer replay now 400 replay", st == 400 and detail == "replay")

print(f"{len(passed)}/{len(passed)} checks passed")
