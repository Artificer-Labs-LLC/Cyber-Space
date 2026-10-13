"""fed_retire replay-dedupe wiring harness (2026-10-13 dev tick).

Step 2 of the seen-sig replay-dedupe restoration: _claim_seen_sig wired
into fed_retire (seventh non-workspace receiver). Drives the REAL
fed_retire against a throwaway DB (CYBERNET_DB_DIR=tempdir).

 1. first valid retire -> 200 retired True, tombstone set, sig claimed
 2. byte-identical replay -> 400 "replay", retired_at unchanged
 3. fresh re-sign -> 200 already-retired (idempotent), new sig claimed
 4. tampered body -> 400 "invalid envelope", sig never claimed
 5. wrong recipient -> 400 "not addressed to this node", sig never claimed;
    corrected envelope (fresh ts) -> 200
 6. sender_pub mismatch -> 400 AND sig claimed (named edge);
    byte-identical retry -> 400 "replay"
 7. unknown peer -> 404 "unknown peer" AND sig claimed (named edge);
    byte-identical retry -> 400 "replay"
"""
import os
import secrets
import sys
import tempfile
import time

TMP = tempfile.mkdtemp(prefix="cybernet-fedretire-replay-")
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
WRONG_RECIP = "f" * 64

SK = secrets.token_bytes(32); PK = ed25519.publickey(SK).hex()
SK2 = secrets.token_bytes(32); PK2 = ed25519.publickey(SK2).hex()
SK3 = secrets.token_bytes(32); PK3 = ed25519.publickey(SK3).hex()

with _db() as conn:
    conn.execute(
        "INSERT INTO peers(node_pub, name, announced_at, first_seen, retired_at, delta_sig)"
        " VALUES (?, 'peernode', '2026-10-13T00:00:00Z', '2026-10-13T00:00:00Z', '', '')",
        (PK,))

def make_retire(sk, pk, body_from, ts, recip=RECIP):
    return fenv.make_envelope(sk.hex(), pk, recip, {"from_node_pub": body_from}, ts=ts)

def sig_seen(sig_hex):
    with _db() as conn:
        return conn.execute(
            "SELECT 1 FROM fed_seen_sigs WHERE sig=?", (sig_hex,)).fetchone() is not None

def retired_at(pk):
    with _db() as conn:
        row = conn.execute("SELECT retired_at FROM peers WHERE node_pub=?", (pk,)).fetchone()
        return row["retired_at"] if row else None

def deliver(env):
    try:
        payload = federation.fed_retire(env)
    except HTTPException as e:
        return e.status_code, e.detail
    return 200, payload

ts0 = int(time.time())

# 1. first valid retire
env1 = make_retire(SK, PK, PK, ts0)
st, pl = deliver(env1)
check("first retire 200 retired", st == 200 and isinstance(pl, dict) and pl.get("retired") is True)
check("tombstone set", bool(retired_at(PK)))
check("sig claimed", sig_seen(env1["sig"]))

# 2. byte-identical replay
before = retired_at(PK)
st, detail = deliver(env1)
check("replay 400 replay", st == 400 and detail == "replay")
check("no re-retire on replay", retired_at(PK) == before)

# 3. fresh re-sign -> already retired, idempotent
env2 = make_retire(SK, PK, PK, ts0 + 7)
st, pl = deliver(env2)
check("fresh re-sign 200 already retired", st == 200 and isinstance(pl, dict) and pl.get("retired") is False)
check("fresh re-sign sig claimed", sig_seen(env2["sig"]))

# 4. tampered body -> invalid envelope, never claimed
env3 = make_retire(SK, PK, PK, ts0 + 11)
env3["body"]["from_node_pub"] = PK2
st, detail = deliver(env3)
check("tampered body 400 invalid envelope", st == 400 and detail == "invalid envelope")
check("forgery sig not claimed", not sig_seen(env3["sig"]))

# 5. wrong recipient -> not addressed, never claimed; corrected -> 200
env5 = make_retire(SK, PK, PK, ts0 + 17, recip=WRONG_RECIP)
st, detail = deliver(env5)
check("wrong recipient 400", st == 400 and detail == "not addressed to this node")
check("wrong-recipient sig not claimed", not sig_seen(env5["sig"]))
env6 = make_retire(SK, PK, PK, ts0 + 19)
st, pl = deliver(env6)
check("corrected-recipient retire 200", st == 200)

# 6. sender_pub mismatch -> 400 AND claimed
env7 = make_retire(SK, PK, PK2, ts0 + 23)
st, detail = deliver(env7)
check("sender_pub mismatch 400", st == 400 and detail == "sender_pub mismatch")
check("mismatch envelope sig still claimed", sig_seen(env7["sig"]))
st, detail = deliver(env7)
check("mismatch replay now 400 replay", st == 400 and detail == "replay")

# 7. unknown peer -> 404 AND claimed
env8 = make_retire(SK3, PK3, PK3, ts0 + 29)
st, detail = deliver(env8)
check("unknown peer 404", st == 404 and detail == "unknown peer")
check("unknown-peer sig still claimed", sig_seen(env8["sig"]))
st, detail = deliver(env8)
check("unknown-peer replay now 400 replay", st == 400 and detail == "replay")

print(f"{len(passed)}/{len(passed)} checks passed")
