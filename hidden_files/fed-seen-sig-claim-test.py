"""Seen-sig replay-dedupe primitive harness (2026-10-09 dev tick).

Step 1 of the seen-sig replay-dedupe build: table + _claim_seen_sig() only,
not yet wired into any /fed/* receiver (wiring is the next tick). Drives the
REAL federation._claim_seen_sig against a throwaway DB
(CYBERNET_DB_DIR=tempdir, created before core imports).

Positive controls (the harness proves itself):
 1. first claim of a real envelope's sig -> False (not a replay)
 2. same sig claimed again -> True (replay detected)
 3. a different envelope's sig -> False
Hostile/edge cases:
 4. dict sig -> ValueError (fail-closed, never touches the store)
 5. int sig -> ValueError
 6. 64-char (short) hex sig -> ValueError
 7. 128-char non-hex sig ("zz"*64) -> ValueError
 8. expiry: claim at t0 -> False; claim again at t0+700 (past the 600s
    horizon) -> False again (not a replay — horizon passed), and the first
    claim's row was pruned, so the table holds exactly 1 row
 9. re-claim at the late time -> True (replay still detected inside horizon)
10. table exists with the right shape after init_db (schema check)
"""
import os
import secrets
import sys
import tempfile

TMP = tempfile.mkdtemp(prefix="cybernet-seen-sig-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core
from core import _db
import federation
from fed import envelope as fenv, ed25519

core.init_db()

passed = []
def check(label, cond):
    assert cond, f"FAIL: {label}"
    passed.append(label)

# --- schema (10) ---
with _db() as conn:
    cols = {r[1]: r[2] for r in conn.execute("PRAGMA table_info(fed_seen_sigs)")}
check("table exists with sig TEXT PK + seen_at REAL",
      cols.get("sig") == "TEXT" and cols.get("seen_at") == "REAL")
with _db() as conn:
    pks = [r[1] for r in conn.execute("PRAGMA table_info(fed_seen_sigs)") if r[5] == 1]
check("sig is the primary key", pks == ["sig"])

SK = secrets.token_bytes(32)
PK = ed25519.publickey(SK).hex()
RECIP = core._NODE_PUB

def sig_of(body, ts=1_000_000_000):
    return fenv.make_envelope(SK.hex(), PK, RECIP, body, ts=ts)["sig"]

T0 = 1_750_000_000.0  # fixed epoch for expiry cases

# --- positive controls (1-3) ---
sig_a = sig_of({"ping": 1})
with _db() as conn:
    check("first claim -> False", federation._claim_seen_sig(conn, sig_a, now=T0) is False)
    conn.commit()
with _db() as conn:
    check("duplicate claim -> True (replay)", federation._claim_seen_sig(conn, sig_a, now=T0) is True)
    conn.commit()
sig_b = sig_of({"ping": 2})
with _db() as conn:
    check("different sig -> False", federation._claim_seen_sig(conn, sig_b, now=T0) is False)
    conn.commit()

# --- hostile shapes (4-7): all must raise ValueError ---
with _db() as conn:
    before = conn.execute("SELECT COUNT(*) FROM fed_seen_sigs").fetchone()[0]
    for bad, label in [
        ({"sig": "x"}, "dict sig"),
        (12345, "int sig"),
        ("ab" * 32, "short hex sig"),
        ("zz" * 64, "non-hex sig"),
        ("", "empty sig"),
    ]:
        try:
            federation._claim_seen_sig(conn, bad, now=T0)
        except ValueError:
            passed.append(f"ValueError on {label}")
        else:
            raise AssertionError(f"FAIL: {bad!r} did not raise")
    after = conn.execute("SELECT COUNT(*) FROM fed_seen_sigs").fetchone()[0]
check("hostile claims never wrote rows", after == before)

# --- expiry (8-9) ---
sig_c = sig_of({"ping": 3})
with _db() as conn:
    check("claim at t0 -> False", federation._claim_seen_sig(conn, sig_c, now=T0) is False)
    conn.commit()
with _db() as conn:
    # t0+700 > 600s horizon: the t0 row is expired and pruned, so re-claim is
    # NOT a replay; other in-horizon rows must survive the prune
    check("re-claim past horizon -> False (expired, not a replay)",
          federation._claim_seen_sig(conn, sig_c, now=T0 + 700) is False)
    conn.commit()
with _db() as conn:
    n = conn.execute("SELECT COUNT(*) FROM fed_seen_sigs").fetchone()[0]
    # sig_a/sig_b claimed at T0 are pruned (700s later); only sig_c's late
    # claim remains (claimed at T0+700, inside its own horizon)
    check("expired rows pruned, in-horizon row kept", n == 1)
with _db() as conn:
    check("re-claim at late time -> True",
          federation._claim_seen_sig(conn, sig_c, now=T0 + 700) is True)
    conn.commit()

print(f"SEEN-SIG PRIMITIVE: {len(passed)}/{len(passed)} checks pass")
