"""Audit pin: federation replay ACROSS time windows (2026-10-09 dev tick).

The belt so far: every inbound /fed/* receiver verifies the envelope first
(freshness: |now - ts| <= MAX_SKEW_SEC=300) and only then claims the signature
in fed_seen_sigs with horizon _SEEN_SIG_HORIZON_SEC=600. The claimed
invariant: replay-window ⊆ freshness-window ⊆ dedupe-horizon, so there is
no window where a captured envelope can be replayed — inside the horizon
the dedupe catches it; past the horizon the skew check catches it first.

Drives the REAL fed_announce + _claim_seen_sig on a throwaway DB
(CYBERNET_DB_DIR=tempdir, created before core imports).

Cases:
 1. fresh envelope -> 200; sig recorded in fed_seen_sigs
 2. byte-identical replay -> 400 "replay" (dedupe catches it inside freshness)
 3. stale envelope (ts = now-601, never seen) -> 400 "invalid envelope";
    its sig is NOT in fed_seen_sigs (verify runs before the claim — verify-first
    ordering proven at the store level)
 4. old-but-within-skew envelope (ts = now-250, never seen) -> 200: the receiver
    does NOT run a blanket age ban; the replay family is exactly
    sig-dedupe + skew, nothing broader
 5. _claim_seen_sig window math on the primitive: claim at t -> first sight;
    again at t -> replay; at t+599 -> still replay (inside horizon);
    at t+601 -> NOT replay (pruned — horizon expired)
 6. the cross-window composition: an envelope first seen at t0, replayed at
    t0+601 (dedupe horizon expired, sig pruned from the store) -> still
    rejected, and rejected as "invalid envelope" (freshness), never "replay".
    The horizon/skew overlap leaves no seam.

Negative control: a fresh envelope from a fresh key after case 6 -> 200, so
the pruned store accepts genuinely new traffic.
"""
import os
import secrets
import sys
import tempfile
import time

TMP = tempfile.mkdtemp(prefix="cybernet-fed-replay-window-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core
from core import _db, _db_lock
import federation
from federation import _claim_seen_sig, _SEEN_SIG_HORIZON_SEC, fed_announce
from fed import envelope as fenv, ed25519
from fed.envelope import MAX_SKEW_SEC
from fastapi import HTTPException

core.init_db()

passed = []
def check(label, cond):
    assert cond, f"FAIL: {label}"
    passed.append(label)

def keypair():
    sk = secrets.token_bytes(32)
    return sk.hex(), ed25519.publickey(sk).hex()

def body_for(pk, name):
    return {"node_pub": pk, "name": name, "network": "cybernet",
            "version": "0.1.0", "genesis": False, "capabilities": []}

def call_announce(env):
    try:
        return fed_announce(env), None
    except HTTPException as e:
        return None, e

def sig_seen(sig_hex):
    with _db_lock, _db() as conn:
        row = conn.execute("SELECT 1 FROM fed_seen_sigs WHERE sig=?",
                           (sig_hex,)).fetchone()
    return row is not None

SK1, PK1 = keypair()
now = int(time.time())

# 1. fresh envelope -> 200, sig recorded
env1 = fenv.make_envelope(SK1, PK1, "federation", body_for(PK1, "windowt1"),
                          ts=now)
r, e = call_announce(env1)
check("fresh envelope -> 200", e is None and r is not None)
check("sig recorded in fed_seen_sigs", sig_seen(env1["sig"]))

# 2. byte-identical replay -> 400 "replay"
r, e = call_announce(env1)
check("replay inside freshness window -> 400 replay",
      e is not None and e.status_code == 400 and e.detail == "replay")

# 3. stale envelope, never seen -> 400 "invalid envelope", sig never claimed
SK3, PK3 = keypair()
env3 = fenv.make_envelope(SK3, PK3, "federation", body_for(PK3, "windowt3"),
                          ts=now - 601)
r, e = call_announce(env3)
check("stale envelope -> 400 invalid envelope",
      e is not None and e.status_code == 400 and e.detail == "invalid envelope")
check("stale envelope sig never claimed (verify-first ordering)",
      not sig_seen(env3["sig"]))

# 4. old-but-within-skew envelope, never seen -> 200 (no blanket age ban)
SK4, PK4 = keypair()
env4 = fenv.make_envelope(SK4, PK4, "federation", body_for(PK4, "windowt4"),
                          ts=now - 250)
r, e = call_announce(env4)
check("ts=now-250 envelope -> 200 (skew, not age, is the bar)",
      e is None and r is not None)

# 5. _claim_seen_sig window math, driven with explicit `now`
sig5 = secrets.token_hex(64)
t0 = time.time()
with _db_lock, _db() as conn:
    first = _claim_seen_sig(conn, sig5, now=t0)
    again = _claim_seen_sig(conn, sig5, now=t0)
check("first claim -> not replay", first is False)
check("second claim same instant -> replay", again is True)
with _db_lock, _db() as conn:
    inside = _claim_seen_sig(conn, sig5, now=t0 + _SEEN_SIG_HORIZON_SEC - 1)
check("claim at t0+horizon-1 -> still replay", inside is True)
with _db_lock, _db() as conn:
    expired = _claim_seen_sig(conn, sig5, now=t0 + _SEEN_SIG_HORIZON_SEC + 1)
check("claim at t0+horizon+1 -> not replay (pruned)", expired is False)
check("horizon 600s > skew 300s (belt, not the only defense)",
      _SEEN_SIG_HORIZON_SEC > MAX_SKEW_SEC)

# 6. cross-window composition: envelope first seen at t0, replayed at t0+601
SK6, PK6 = keypair()
env6 = fenv.make_envelope(SK6, PK6, "federation", body_for(PK6, "windowt6"),
                          ts=now - 601)
# simulate first sight at t0 (600s of staleness already baked into ts)
with _db_lock, _db() as conn:
    _claim_seen_sig(conn, env6["sig"], now=now - 601)
with _db_lock, _db() as conn:
    gone = _claim_seen_sig(conn, env6["sig"], now=now)
check("dedupe store pruned the sig by t0+601", gone is False)
r, e = call_announce(env6)
check("replay past horizon -> still rejected as invalid envelope, not replay",
      e is not None and e.status_code == 400 and e.detail == "invalid envelope")

# negative control: fresh key, fresh envelope -> 200 after the prune
SK7, PK7 = keypair()
env7 = fenv.make_envelope(SK7, PK7, "federation", body_for(PK7, "windowt7"))
r, e = call_announce(env7)
check("fresh envelope after prune -> 200 (store accepts new traffic)",
      e is None and r is not None)

print(f"fed-replay-window audit pin: {len(passed)}/{len(passed)} checks green")
for p in passed:
    print("  OK:", p)
