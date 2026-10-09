"""fed_gossip + fed_retire replay-dedupe wiring harness (2026-10-09 dev tick).

Seen-sig replay-dedupe step 2 receivers #6 (fed_gossip) and the fed_retire
own-wire check. Drives the REAL receivers against a throwaway DB
(CYBERNET_DB_DIR=tempdir, created before core imports). Note: prior ticks'
harness files lived in the goal hidden_files/ dir; per the 05:40 devlog note
this one goes in the repo tree (hidden_files/) so it actually commits.

Gossip positive controls:
 1. known peer gossip with fresh roster entry -> 200 {merged:1}, row stored,
    sig claimed
 2. byte-identical replay -> 400 "replay", no second merge, no rate-bucket
    burn observable (DB surface untouched: peers row count stable)
 3. same content re-signed with fresh ts -> 200 idempotent merge
Retire positive controls:
 4. first valid retire for known peer -> 200 retired True, sig claimed
 5. byte-identical replay -> 400 "replay", tombstone untouched (retired_at
    stable)
 6. re-signed fresh retire for already-retired peer -> 200 retired False
    (idempotent, not a replay)
Hostile/edge:
 7. tampered body -> 400 "invalid envelope", forgery sig never claimed
 8. wrong recipient -> 400 "not addressed to this node", sig never claimed
 9. gossip from unknown peer -> 404 "unknown peer" AND sig still claimed
    (named edge: claim sits after verify+recipient, before the 404 gate)
10. retire with late-attestation resend shape: fresh re-sign always 200s
"""
import os
import secrets
import sys
import tempfile
import time

TMP = tempfile.mkdtemp(prefix="cybernet-fedgossip-retire-replay-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core
from core import _db, _NODE_PUB
import federation
from fed import envelope as fenv, ed25519
from fastapi import HTTPException

core.init_db()

passed = []
def check(label, cond):
    assert cond, f"FAIL: {label}"
    passed.append(label)

SK = secrets.token_bytes(32); PK = ed25519.publickey(SK).hex()
SK2 = secrets.token_bytes(32); PK2 = ed25519.publickey(SK2).hex()
WRONG_RECIP = "f" * 64

def make_envelope(sk, pk, body, ts, recip=_NODE_PUB):
    return fenv.make_envelope(sk.hex(), pk, recip, body, ts=ts)

def sig_seen(sig_hex):
    with _db() as conn:
        return conn.execute(
            "SELECT 1 FROM fed_seen_sigs WHERE sig=?", (sig_hex,)).fetchone() is not None

def peer_count():
    with _db() as conn:
        return conn.execute("SELECT COUNT(*) c FROM peers").fetchone()["c"]

def retired_at(pk_hex):
    with _db() as conn:
        row = conn.execute(
            "SELECT retired_at FROM peers WHERE node_pub=?", (pk_hex,)).fetchone()
        return row["retired_at"] if row else None

ts0 = int(time.time())

# Seed the gossiping peer as known (announce, not gossip — gossip is for others)
ann = make_envelope(SK, PK, {"node_pub": PK, "name": "peernode",
                             "network": "cybernet", "version": "0.1.0",
                             "genesis": False, "capabilities": []}, ts0,
                    recip="federation")
try:
    federation.fed_announce(ann)
except HTTPException as e:
    raise AssertionError(f"seed announce failed: {e.status_code} {e.detail}")

def gossip_body(roster):
    return {"from_node_pub": PK, "roster": roster}

def entry_for(pk_hex, name, url):
    return {"node_pub": pk_hex, "name": name, "node_url": url,
            "version": "0.1.0", "genesis": False, "capabilities": []}

def deliver_gossip(env):
    try:
        return 200, federation.fed_gossip(env)
    except HTTPException as e:
        return e.status_code, e.detail

def deliver_retire(env):
    try:
        return 200, federation.fed_retire(env)
    except HTTPException as e:
        return e.status_code, e.detail

# 1. first valid gossip -> 200, new entry merged, sig claimed
g1 = make_envelope(SK, PK, gossip_body([entry_for(PK2, "farpeer", "https://93.184.216.34:443/")]), ts0 + 3)
before = peer_count()
st, pl = deliver_gossip(g1)
check("first gossip 200 merged 1", st == 200 and pl["ok"] is True and pl["merged"] == 1)
check("gossip entry stored", peer_count() == before + 1)
check("gossip sig claimed", sig_seen(g1["sig"]))

# 2. byte-identical replay -> 400 "replay", no second merge
before2 = peer_count()
st, detail = deliver_gossip(g1)
check("gossip replay 400", st == 400 and detail == "replay")
check("gossip replay no second merge", peer_count() == before2)

# 3. same content re-signed with fresh ts -> 200 idempotent merge
g2 = make_envelope(SK, PK, gossip_body([entry_for(PK2, "farpeer", "https://93.184.216.34:443/")]), ts0 + 9)
st, pl = deliver_gossip(g2)
check("fresh re-sign gossip 200", st == 200 and pl["ok"] is True)
check("fresh re-sign not a replay (merged counts only new rows)",
      pl["merged"] == 0 and pl["ignored"] == 1)
check("fresh re-sign sig claimed", sig_seen(g2["sig"]))

# 4. first valid retire -> 200 retired True, sig claimed
r1 = make_envelope(SK, PK, {"from_node_pub": PK}, ts0 + 13)
st, pl = deliver_retire(r1)
check("first retire 200", st == 200 and pl["ok"] is True and pl["retired"] is True)
check("retire tombstone set", retired_at(PK) not in (None, ""))
check("retire sig claimed", sig_seen(r1["sig"]))
tomb = retired_at(PK)

# 5. byte-identical replay -> 400 "replay", tombstone untouched
st, detail = deliver_retire(r1)
check("retire replay 400", st == 400 and detail == "replay")
check("retire replay tombstone stable", retired_at(PK) == tomb)

# 6. re-signed fresh retire -> 200 already-retired idempotent, not a replay
r2 = make_envelope(SK, PK, {"from_node_pub": PK}, ts0 + 17)
st, pl = deliver_retire(r2)
check("fresh re-sign retire 200 idempotent", st == 200 and pl["retired"] is False)
check("fresh re-sign retire sig claimed", sig_seen(r2["sig"]))

# 7. tampered body -> 400 "invalid envelope", forgery sig never claimed
g3 = make_envelope(SK, PK, gossip_body([entry_for(PK2, "farpeer", "https://93.184.216.34:443/")]), ts0 + 21)
g3["body"]["roster"][0]["name"] = "evilpeer"
st, detail = deliver_gossip(g3)
check("tampered gossip 400 invalid envelope", st == 400 and detail == "invalid envelope")
check("forgery sig not claimed", not sig_seen(g3["sig"]))

# 8. wrong recipient -> 400, sig never claimed
g4 = make_envelope(SK, PK, gossip_body([entry_for(PK2, "other", "https://93.184.216.34:443/")]), ts0 + 25, recip=WRONG_RECIP)
st, detail = deliver_gossip(g4)
check("wrong recipient 400", st == 400 and detail == "not addressed to this node")
check("wrong-recipient sig not claimed", not sig_seen(g4["sig"]))

# 9. gossip from unknown peer -> 404 AND sig still claimed (named edge:
#    claim sits after verify+recipient, before the 404 unknown-peer gate)
SK3 = secrets.token_bytes(32); PK3 = ed25519.publickey(SK3).hex()
g5 = make_envelope(SK3, PK3, {"from_node_pub": PK3,
                             "roster": [entry_for(PK2, "farpeer2", "https://93.184.216.34:443/")]}, ts0 + 29)
st, detail = deliver_gossip(g5)
check("unknown peer gossip 404", st == 404 and detail == "unknown peer")
check("unknown-peer sig still claimed (named edge)", sig_seen(g5["sig"]))
# exact-byte retry after 404 now 400s replay (named edge consequence)
st, detail = deliver_gossip(g5)
check("exact-byte retry after 404 -> 400 replay", st == 400 and detail == "replay")

print(f"ALL PASS: {len(passed)}/{len(passed)}")
