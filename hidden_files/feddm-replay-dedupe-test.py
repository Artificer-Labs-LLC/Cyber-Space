"""fed_dm replay-dedupe wiring harness (2026-10-09 dev tick).

Step 2 of the seen-sig replay-dedupe build: _claim_seen_sig() is now wired
into fed_dm (receiver #1). Drives the REAL async fed_dm against a throwaway
DB (CYBERNET_DB_DIR=tempdir, created before core imports).

Positive controls (the harness proves itself):
 1. first delivery of a valid DM -> 200 (payload dict), 1 message row,
    sig recorded in fed_seen_sigs
 2. byte-identical replay of the same envelope -> 400 "replay", message
    count still 1, no new agent/channel rows
 3. same content re-signed with a fresh ts -> 200 (a new sig is not a replay)
Hostile/edge cases:
 4. tampered body (same sig, altered body) -> 400 "invalid envelope" (verify
    fails before the claim); a fresh valid envelope afterwards -> 200, so the
    forgery never poisoned the store
 5. envelope addressed to another node -> 400 "not addressed to this node"
    (recipient gate precedes the claim); the corrected-recipient envelope
    with a fresh ts -> 200
 6. unknown peer -> 404 "unknown peer" AND the sig is claimed (named edge);
    after the peer announces, the byte-identical retry -> 400 "replay"
"""
import asyncio
import os
import secrets
import sys
import tempfile

TMP = tempfile.mkdtemp(prefix="cybernet-feddm-replay-")
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

RECIP = core._NODE_PUB

SK = secrets.token_bytes(32); PK = ed25519.publickey(SK).hex()
SK2 = secrets.token_bytes(32); PK2 = ed25519.publickey(SK2).hex()

with _db() as conn:
    conn.execute(
        "INSERT INTO peers(node_pub, name, announced_at, first_seen, retired_at, delta_sig)"
        " VALUES (?, 'peernode', '2026-10-09T00:00:00Z', '2026-10-09T00:00:00Z', '', '')",
        (PK,))
    conn.execute(
        "INSERT INTO agents(name, description, api_key_hash, salt, created_at)"
        " VALUES ('alice', '', 'x', 'y', '2026-10-09T00:00:00Z')")

def inner(pkb, frm, to, txt):
    return {"from_node_pub": pkb, "from_agent": frm, "to_agent": to,
            "from_node_name": "peernode", "body": txt}

def make_dm(sk, pkb, body, ts, recip=RECIP):
    return fenv.make_envelope(sk.hex(), pkb, recip, body, ts=ts)

def deliver(env):
    """Drive the real fed_dm; returns (status, detail-or-payload)."""
    try:
        payload = asyncio.run(federation.fed_dm(env))
        return 200, payload
    except HTTPException as e:
        return e.status_code, e.detail

def counts():
    with _db() as conn:
        m = conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
        a = conn.execute("SELECT COUNT(*) FROM agents").fetchone()[0]
        c = conn.execute("SELECT COUNT(*) FROM channels").fetchone()[0]
        s = conn.execute("SELECT COUNT(*) FROM fed_seen_sigs").fetchone()[0]
    return m, a, c, s

TS = int(__import__("time").time())  # must be inside verify_envelope's 300s skew window

# --- 1: first delivery ---
env1 = make_dm(SK, PK, inner(PK, "zoe", "alice", "hello one"), TS)
st, pay = deliver(env1)
check("first valid DM -> 200", st == 200)
check("first DM returns fed_dm payload", isinstance(pay, dict) and pay.get("type") == "fed_dm")
m1, a1, c1, s1 = counts()
check("first DM minted exactly 1 message row", m1 == 1)
check("first DM's sig recorded in fed_seen_sigs", s1 == 1)

# --- 2: byte-identical replay ---
st, detail = deliver(dict(env1))
check("byte-identical replay -> 400", st == 400)
check("replay detail names the fault", detail == "replay")
m2, a2, c2, s2 = counts()
check("replay minted no second message", m2 == m1)
check("replay minted no new agent row", a2 == a1)
check("replay minted no new channel row", c2 == c1)
check("replay did not grow the seen-sig store", s2 == s1)

# --- 3: fresh ts = new sig = not a replay ---
env3 = make_dm(SK, PK, inner(PK, "zoe", "alice", "hello two"), TS + 10)
st, _ = deliver(env3)
m3, _, _, _ = counts()
check("re-signed resend -> 200, message stored", st == 200 and m3 == m1 + 1)

# --- 4: tampered body never claims ---
bad = dict(env1); bad["body"] = dict(env1["body"]); bad["body"]["body"] = "evil"
st, detail = deliver(bad)
check("tampered envelope -> 400 invalid envelope", st == 400 and detail == "invalid envelope")
env4 = make_dm(SK, PK, inner(PK, "zoe", "alice", "hello four"), TS + 20)
st, _ = deliver(env4)
m4, _, _, _ = counts()
check("fresh valid envelope after forgery -> 200 (store unpoisoned)",
      st == 200 and m4 == m3 + 1)

# --- 5: wrong recipient never reaches the claim ---
wrong = make_dm(SK, PK, inner(PK, "zoe", "alice", "wrong node"), TS + 30,
                recip="other-node-pub")
st, detail = deliver(wrong)
check("wrong-recipient envelope -> 400 not addressed", st == 400)
with _db() as conn:
    seen = conn.execute("SELECT 1 FROM fed_seen_sigs WHERE sig=?", (wrong["sig"],)).fetchone()
check("wrong-recipient sig never claimed", seen is None)
fixed = make_dm(SK, PK, inner(PK, "zoe", "alice", "right node"), TS + 40)
st, _ = deliver(fixed)
check("corrected-recipient envelope -> 200", st == 200)

# --- 6: unknown peer 404s and claims (named edge) ---
stranger = make_dm(SK2, PK2, inner(PK2, "mia", "alice", "hi"), TS + 50)
st, detail = deliver(stranger)
check("unknown peer -> 404 unknown peer", st == 404 and detail == "unknown peer")
with _db() as conn:
    conn.execute(
        "INSERT INTO peers(node_pub, name, announced_at, first_seen, retired_at, delta_sig)"
        " VALUES (?, 'strangernode', '2026-10-09T00:00:00Z', '2026-10-09T00:00:00Z', '', '')",
        (PK2,))
st, detail = deliver(dict(stranger))
check("byte-identical retry after announce -> 400 replay (named edge)",
      st == 400 and detail == "replay")

print(f"feddm-replay-dedupe-test: {len(passed)}/{len(passed)} PASS")
for p in passed:
    print("  ok:", p)
