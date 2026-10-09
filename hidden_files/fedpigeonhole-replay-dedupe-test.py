"""fed_pigeonholes_proxy replay-dedupe wiring harness (2026-10-09 dev tick).

Step 2 of the seen-sig replay-dedupe build: _claim_seen_sig() is now wired
into fed_pigeonholes_proxy (receiver #10 — the LAST write-surface fed
receiver; its writes are the lazy TTL prune + the _touch_visitor board
visit + the signed reply). Drives the REAL fed_pigeonholes_proxy against
a throwaway DB (CYBERNET_DB_DIR=tempdir, created before core imports).

Positive controls (the harness proves itself):
 1. first valid proxy envelope -> 200 signed reply envelope (body:
    origin_node == NODE_NAME, pigeonholes == [], count == 0 — honest
    empty board), sig recorded in fed_seen_sigs, one visitor_touches row
    (the guest stood at the board)
 2. byte-identical replay -> 400 "replay", fed_seen_sigs row count
    unchanged, visitor_touches row untouched (no second board visit), the
    fedpigeonhole: rate quota untouched (a fresh envelope later still
    200s — replay storms are absorbed by the claim, not the bucket)
 3. same request re-signed with a fresh ts -> 200 again (genuine re-asks
    re-sign; new sig claims fine)
Hostile/edge cases:
 4. tampered body -> 400 "invalid envelope" (verify fails before the
    claim); sig never claimed
 5. wrong recipient -> 400 "not addressed to this node" (recipient gate
    precedes the claim); sig never claimed
 6. sender_pub mismatch -> 400 "sender_pub mismatch" AND sig claimed
    (claim sits before the mismatch check — post-claim named edge, same
    family as the other receivers)
 7. unknown peer sender -> 404 "unknown peer" AND sig claimed (claim sits
    before the known-peer gate — named edge)
"""
import copy
import os
import secrets
import sys
import tempfile
import time

TMP = tempfile.mkdtemp(prefix="cybernet-fedpigeonhole-replay-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core
from core import _db, _now
import federation
from fed import envelope as fenv, ed25519
from fastapi import HTTPException

core.init_db()

passed = []
def check(label, cond):
    assert cond, f"FAIL: {label}"
    passed.append(label)

RECIP = federation._NODE_PUB
SK_HEX = secrets.token_bytes(32).hex()
PK = ed25519.publickey(bytes.fromhex(SK_HEX)).hex()
SK_UNKNOWN_HEX = secrets.token_bytes(32).hex()
PK_UNKNOWN = ed25519.publickey(bytes.fromhex(SK_UNKNOWN_HEX)).hex()

# register the proxy sender as a known, unretired peer
with _db() as conn:
    conn.execute(
        "INSERT INTO peers (node_pub, name, network, version, genesis,"
        " capabilities, announced_at, first_seen, retired_at)"
        " VALUES (?, 'sender', 'cybernet', '0.1.0', 0, '[]', ?, ?, '')",
        (PK, _now(), _now()))

def make_proxy_env(sk_hex, pk_hex, ts, recip=RECIP, from_node_pub=None,
                    limit=20):
    body = {"from_node_pub": from_node_pub if from_node_pub is not None else pk_hex,
            "limit": limit}
    return fenv.make_envelope(sk_hex, pk_hex, recip, body, ts=ts)

def call(env):
    try:
        return federation.fed_pigeonholes_proxy(env)
    except HTTPException as e:
        return e

def sig_count():
    with _db() as conn:
        return conn.execute("SELECT COUNT(*) FROM fed_seen_sigs").fetchone()[0]

def visitor_rows():
    with _db() as conn:
        return conn.execute(
            "SELECT visitor, origin_node, rooms FROM visitor_touches").fetchall()

def sig_claimed(sig_hex):
    with _db() as conn:
        return conn.execute(
            "SELECT 1 FROM fed_seen_sigs WHERE sig=?", (sig_hex,)).fetchone() is not None

ts0 = int(time.time())
env0 = make_proxy_env(SK_HEX, PK, ts0)
n_sig0, n_vis0 = sig_count(), visitor_rows()

# 1. first valid proxy envelope
out = call(env0)
check("first 200 envelope dict", isinstance(out, dict))
payload = out.get("body") if isinstance(out, dict) else None
check("reply carries board payload", isinstance(payload, dict))
check("origin_node is NODE_NAME", payload.get("origin_node") == federation.NODE_NAME)
check("honest empty board", payload.get("pigeonholes") == [] and payload.get("count") == 0)
check("sig claimed after first", sig_claimed(env0["sig"]))
vis = visitor_rows()
check("one visitor touch row", len(vis) == 1)
check("visitor key is peer_name@NODE_NAME",
      vis[0][0] == f"sender@{federation.NODE_NAME}" and vis[0][2] == "boards")
n_sig1 = sig_count()
check("exactly one sig row stored", n_sig1 == n_sig0 + 1)

# 2. byte-identical replay
replay = call(copy.deepcopy(env0))
check("replay 400", isinstance(replay, HTTPException) and replay.status_code == 400)
check("replay detail", replay.detail == "replay")
check("no new sig row on replay", sig_count() == n_sig1)
check("visitor untouched by replay", visitor_rows() == vis)

# 3. genuine re-ask with a fresh ts still renders (quota survived)
env_fresh = make_proxy_env(SK_HEX, PK, ts0 + 3)
out2 = call(env_fresh)
out2_body = out2.get("body") if isinstance(out2, dict) else None
check("fresh re-sign 200", isinstance(out2_body, dict) and out2_body.get("count") == 0)
check("fresh sig claimed", sig_claimed(env_fresh["sig"]))

# 4. tampered body: verify fails before the claim
bad = copy.deepcopy(make_proxy_env(SK_HEX, PK, ts0 + 7))
bad["body"]["limit"] = 99
n_before = sig_count()
out = call(bad)
check("tamper 400 invalid envelope",
      isinstance(out, HTTPException) and out.status_code == 400
      and out.detail == "invalid envelope")
check("tamper never claims", sig_count() == n_before
      and not sig_claimed(bad["sig"]))

# 5. wrong recipient: recipient gate precedes the claim
bad = make_proxy_env(SK_HEX, PK, ts0 + 8, recip=PK_UNKNOWN)
n_before = sig_count()
out = call(bad)
check("wrong recipient 400",
      isinstance(out, HTTPException) and out.status_code == 400
      and out.detail == "not addressed to this node")
check("wrong recipient never claims", sig_count() == n_before
      and not sig_claimed(bad["sig"]))

# 6. sender_pub mismatch: still claims (post-claim named edge)
bad = make_proxy_env(SK_HEX, PK, ts0 + 9, from_node_pub=PK_UNKNOWN)
out = call(bad)
check("mismatch 400",
      isinstance(out, HTTPException) and out.status_code == 400
      and out.detail == "sender_pub mismatch")
check("mismatch claims sig (named edge)", sig_claimed(bad["sig"]))

# 7. unknown peer: 404 but still claims (post-claim named edge)
bad = make_proxy_env(SK_UNKNOWN_HEX, PK_UNKNOWN, ts0 + 10)
out = call(bad)
check("unknown peer 404",
      isinstance(out, HTTPException) and out.status_code == 404
      and out.detail == "unknown peer")
check("unknown peer claims sig (named edge)", sig_claimed(bad["sig"]))

print(f"ALL {len(passed)}/{len(passed)} PASS")
