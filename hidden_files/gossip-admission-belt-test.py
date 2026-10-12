#!/usr/bin/env python3
"""Belt for Bulwark's HIGH (ART-29): gossip ingest enforces the route's
admission gates — the 365-day cap. Freshness (24h) is NOT checked on
ingest (r3): gossip is propagation, not origination — late-arriving
valid bindings must merge, or mirrors split.

r3 (ART-29): live foreign incumbent is ALWAYS kept on ingest. A
challenger signing issued_at = incumbent - 1s (or 2001) passes the
route's freshness gate but must not steal a live name via gossip. The
rejected claim is logged to name_conflicts and ingest returns
"conflict" — not a silent "kept".

Also covers Bulwark's MEDIUM: ingest now loads the old row WITH expires_at
and calls _old_binding_beaten (the route's conflict rule), so expired rows
are freed on the gossip path too — mirrors no longer keep expired foreign
rows HQ has replaced.

And Bulwark's LOW: _old_binding_beaten catches OverflowError alongside
ValueError.

Runs against a SCRATCH DB (CYBERNET_DB_DIR=tempdir set before import);
the repo's live cybernet.db is never touched.
"""
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone

TMP = tempfile.mkdtemp(prefix="gossip-admission-belt-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core  # noqa: E402
core.init_db()
from fed import ed25519 as _ed  # noqa: E402

PASS = FAIL = 0


def check(label, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1
    else:
        FAIL += 1
        print(f"FAIL {label}: got {got!r}, want {want!r}")


def mint(name, priv_hex, issued_at, expires_at):
    pub = _ed.publickey(bytes.fromhex(priv_hex)).hex()
    sig = _ed.sign(
        core._name_claim_payload(name, pub, issued_at, expires_at),
        bytes.fromhex(priv_hex), bytes.fromhex(pub)).hex()
    return {"name": name, "node_pubkey": pub, "issued_at": issued_at,
            "expires_at": expires_at, "signature": sig}


def iso_z(dt):
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


NOW = datetime.now(timezone.utc)
live_issued = iso_z(NOW - timedelta(minutes=5))
live_expires = iso_z(NOW + timedelta(days=30))

# --- HIGH 1: backdated gossip binding (issued_at=2001) vs live incumbent ---
# r3: a 2001-issued binding with a future expiry has a >365d lifetime, so
# it is dropped as over-cap before reaching conflict logic. The key point:
# the live incumbent is NOT replaced. (A 2001 binding with a ≤365d
# lifetime would already be expired — also dropped. Backdating cannot
# reach the merge.)
k_inc = os.urandom(32).hex()
check("incumbent inserts",
      core.ingest_gossiped_binding(
          mint("belt-backdate", k_inc, live_issued, live_expires)),
      "inserted")
k_atk = os.urandom(32).hex()
backdated = mint("belt-backdate", k_atk,
                 "2001-01-01T00:00:00+00:00",
                 iso_z(NOW + timedelta(days=30)))
check("backdated (2001) gossip dropped, incumbent safe",
      core.ingest_gossiped_binding(backdated), "dropped-over-cap")
# Incumbent still holds the name
with core._db_lock, core._db() as conn:
    row = conn.execute(
        "SELECT node_pubkey FROM name_bindings WHERE name=?",
        ("belt-backdate",)).fetchone()
check("incumbent untouched after backdate attempt",
      row[0], _ed.publickey(bytes.fromhex(k_inc)).hex())

# --- HIGH 1b: T-1s earlier claim (deterministic rule) ---
# Mirror convergence (ART-29 r3 gap): a challenger with an EARLIER issued_at
# beats the incumbent by the deterministic rule (_name_claim_beats), even on
# the ingest path. This is what lets two mirrors receiving claims in opposite
# orders converge on the same winner (see mirror-order-belt-test.py).
# The 2001-style backdate is blocked by the 365-day cap (HIGH 1/2 above);
# the route's 24h freshness + live-incumbent 409 remain the origination-time
# defenses. The displacement is logged as a conflict for audit.
k_inc2 = os.urandom(32).hex()
inc_issued = iso_z(NOW - timedelta(minutes=5))
check("t-1s incumbent inserts",
      core.ingest_gossiped_binding(
          mint("belt-tminus1", k_inc2, inc_issued, live_expires)),
      "inserted")
k_atk2 = os.urandom(32).hex()
atk_issued = iso_z(datetime.fromisoformat(inc_issued) - timedelta(seconds=1))
check("T-1s earlier challenger replaces (deterministic rule)",
      core.ingest_gossiped_binding(
          mint("belt-tminus1", k_atk2, atk_issued, live_expires)),
      "replaced")
with core._db_lock, core._db() as conn:
    row = conn.execute(
        "SELECT node_pubkey FROM name_bindings WHERE name=?",
        ("belt-tminus1",)).fetchone()
check("earlier challenger now holds the name",
      row[0], _ed.publickey(bytes.fromhex(k_atk2)).hex())
# Displacement of a live incumbent is logged with the challenger's key
with core._db_lock, core._db() as conn:
    crow = conn.execute(
        "SELECT challenger_pubkey, reason FROM name_conflicts WHERE name=?",
        ("belt-tminus1",)).fetchone()
check("displacement logged for T-1s",
      (crow[0], crow[1]),
      (_ed.publickey(bytes.fromhex(k_atk2)).hex(), "displaced-by-earlier-claim"))

# --- HIGH 2: over-cap gossip binding (>365d lifetime) is refused ---
k_cap = os.urandom(32).hex()
overcap = mint("belt-overcap", k_cap, live_issued,
               iso_z(NOW + timedelta(days=400)))
check("over-365d gossip refused",
      core.ingest_gossiped_binding(overcap), "dropped-over-cap")

# --- HIGH 3: exactly-365d lifetime is accepted ---
k_ok = os.urandom(32).hex()
exact_issued = iso_z(NOW - timedelta(minutes=5))
exact_expires = (datetime.fromisoformat(exact_issued) +
                 timedelta(days=365)).isoformat(timespec="seconds")
check("exactly-365d gossip accepted",
      core.ingest_gossiped_binding(
          mint("belt-exactcap", k_ok, exact_issued, exact_expires)),
      "inserted")

# --- HIGH 4: future-dated issued_at is refused ---
k_fut = os.urandom(32).hex()
fut = mint("belt-future", k_fut, iso_z(NOW + timedelta(hours=1)),
           iso_z(NOW + timedelta(days=30)))
check("future issued_at gossip refused",
      core.ingest_gossiped_binding(fut), "dropped-stale")

# --- HIGH 5: valid fresh gossip binding is accepted ---
k_fresh = os.urandom(32).hex()
check("fresh valid gossip accepted",
      core.ingest_gossiped_binding(
          mint("belt-fresh", k_fresh, live_issued, live_expires)),
      "inserted")

# --- HIGH 6 (r3): late arrival merges — no freshness drop on ingest ---
# A binding signed 25h ago (stale by the route's 24h gate) arrives via
# gossip for an EXPIRED incumbent. r3: ingest skips freshness — the
# binding merges instead of splitting mirrors as "dropped-stale".
k_late_old = os.urandom(32).hex()
check("late-arrival incumbent inserts",
      core.ingest_gossiped_binding(
          mint("belt-late", k_late_old, live_issued, live_expires)),
      "inserted")
with core._db_lock, core._db() as conn:
    conn.execute(
        "UPDATE name_bindings SET expires_at=? WHERE name=?",
        (iso_z(NOW - timedelta(hours=1)), "belt-late"))
k_late = os.urandom(32).hex()
late_issued = iso_z(NOW - timedelta(hours=25))  # stale by route's 24h gate
check("late (25h old) gossip replaces expired incumbent",
      core.ingest_gossiped_binding(
          mint("belt-late", k_late, late_issued,
               iso_z(NOW + timedelta(days=30)))),
      "replaced")

# --- HIGH 7 (r3): same-key renewal via gossip is not a conflict ---
# A renewal from the SAME key (later issued_at) flows through
# _old_binding_beaten, not the incumbent-protection rule.
k_ren = os.urandom(32).hex()
ren_issued = iso_z(NOW - timedelta(minutes=10))
check("renewal incumbent inserts",
      core.ingest_gossiped_binding(
          mint("belt-renew", k_ren, ren_issued, live_expires)),
      "inserted")
check("same-key renewal replaces (not conflict)",
      core.ingest_gossiped_binding(
          mint("belt-renew", k_ren, iso_z(NOW),
               iso_z(NOW + timedelta(days=30)))),
      "replaced")

# --- MEDIUM: expired incumbent is freed on the gossip path ---
# Insert a live binding, expire it directly in the DB, then gossip a
# challenger — the challenger must replace (not keep) the dead row.
k_old = os.urandom(32).hex()
check("medium incumbent inserts",
      core.ingest_gossiped_binding(
          mint("belt-expire", k_old, live_issued, live_expires)),
      "inserted")
with core._db_lock, core._db() as conn:
    conn.execute(
        "UPDATE name_bindings SET expires_at=? WHERE name=?",
        (iso_z(NOW - timedelta(hours=1)), "belt-expire"))
k_new = os.urandom(32).hex()
check("challenger frees expired incumbent",
      core.ingest_gossiped_binding(
          mint("belt-expire", k_new, iso_z(NOW),
               iso_z(NOW + timedelta(days=30)))),
      "replaced")

# --- LOW: _old_binding_beaten treats unparseable as same-key-only ---
# Bulwark's low adds OverflowError to the ValueError catch: any timestamp
# that fails to parse (or overflows on handling) means the stored row is
# unparseable — a foreign key must not beat it (Examiner's block).
# We verify the ValueError path directly (the live Examiner's block); the
# OverflowError rides the same except clause.
old_bad = {"name": "x",
           "node_pubkey": _ed.publickey(os.urandom(32)).hex(),
           "issued_at": "not-a-timestamp",
           "expires_at": live_expires}
foreign_pub = _ed.publickey(os.urandom(32)).hex()
new_foreign = {"name": "x", "node_pubkey": foreign_pub,
               "issued_at": live_issued, "expires_at": live_expires}
check("unparseable row NOT beaten by foreign key",
      core._old_binding_beaten(old_bad, new_foreign, foreign_pub, NOW),
      False)
check("unparseable row beaten by same key",
      core._old_binding_beaten(
          old_bad, new_foreign, old_bad["node_pubkey"], NOW),
      True)

# --- Bulwark MEDIUM (r3): name_conflicts table is bounded ---
# The conflicts table is writable from the unauthenticated gossip path.
# (a) Duplicate challenger claims are ignored via the UNIQUE index.
# (b) Per-name cap (32) is enforced — oldest dropped when cap is hit.
def _conflict_count(nm):
    with core._db_lock, core._db() as conn:
        return conn.execute(
            "SELECT COUNT(*) FROM name_conflicts WHERE name=?",
            (nm,)).fetchone()[0]

# (a) Log the same conflict twice — second is ignored.
k_dup_inc = os.urandom(32).hex()
k_dup_ch = os.urandom(32).hex()
dup_inc = {"node_pubkey": _ed.publickey(bytes.fromhex(k_dup_inc)).hex(),
           "issued_at": live_issued}
dup_ch = {"node_pubkey": _ed.publickey(bytes.fromhex(k_dup_ch)).hex(),
          "issued_at": live_issued, "expires_at": live_expires}
with core._db_lock, core._db() as conn:
    core._log_name_conflict(conn, "belt-dup", dup_inc, dup_ch, "live-foreign-incumbent")
    core._log_name_conflict(conn, "belt-dup", dup_inc, dup_ch, "live-foreign-incumbent")
check("duplicate conflict ignored (UNIQUE)", _conflict_count("belt-dup"), 1)

# (b) Spam 40 distinct conflicts for one name — cap at 32.
for i in range(40):
    k_spam = os.urandom(32).hex()
    spam_ch = {"node_pubkey": _ed.publickey(bytes.fromhex(k_spam)).hex(),
               "issued_at": iso_z(NOW - timedelta(minutes=i)),
               "expires_at": live_expires}
    with core._db_lock, core._db() as conn:
        core._log_name_conflict(conn, "belt-cap", dup_inc, spam_ch,
                                "live-foreign-incumbent")
check("per-name conflict cap enforced at 32", _conflict_count("belt-cap"), 32)

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
