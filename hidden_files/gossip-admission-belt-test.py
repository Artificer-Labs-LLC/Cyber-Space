#!/usr/bin/env python3
"""Belt for Bulwark's HIGH (ART-29): gossip ingest enforces the route's
admission gates — the 365-day cap and NAME_CLAIM_FRESHNESS (24h).
ART-29 ruling (a) withdraws the r3 gossip exemption: a binding older
than 24h is dropped-stale. The originator re-signs fresh.

r3 (ART-29) / ruling (a): live foreign incumbent is ALWAYS kept on
ingest. A challenger signing issued_at = incumbent - 1s passes the
24h freshness gate but must not steal a live name via gossip. The
rejected claim is logged to name_conflicts and ingest returns
"conflict" — not a silent "kept", and not "replaced".

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

# --- HIGH 1b: T-1s steal attempt (freshness-passing backdate) ---
# ART-29 ruling (a): a challenger with issued_at = incumbent - 1s passes
# the 24h freshness gate and must NOT replace the live foreign incumbent.
# Ingest returns conflict, the incumbent stays, and the attempt is logged
# as live-foreign-incumbent — never displaced-by-earlier-claim.
k_inc2 = os.urandom(32).hex()
inc_issued = iso_z(NOW - timedelta(minutes=5))
check("t-1s incumbent inserts",
      core.ingest_gossiped_binding(
          mint("belt-tminus1", k_inc2, inc_issued, live_expires)),
      "inserted")
k_atk2 = os.urandom(32).hex()
atk_issued = iso_z(datetime.fromisoformat(inc_issued) - timedelta(seconds=1))
check("T-1s challenger -> conflict, incumbent kept",
      core.ingest_gossiped_binding(
          mint("belt-tminus1", k_atk2, atk_issued, live_expires)),
      "conflict")
with core._db_lock, core._db() as conn:
    row = conn.execute(
        "SELECT node_pubkey FROM name_bindings WHERE name=?",
        ("belt-tminus1",)).fetchone()
check("incumbent untouched after T-1s attempt",
      row[0], _ed.publickey(bytes.fromhex(k_inc2)).hex())
# Conflict record was written with the challenger's key and reason
with core._db_lock, core._db() as conn:
    crow = conn.execute(
        "SELECT challenger_pubkey, reason FROM name_conflicts WHERE name=?",
        ("belt-tminus1",)).fetchone()
check("conflict record logged for T-1s",
      (crow[0], crow[1]),
      (_ed.publickey(bytes.fromhex(k_atk2)).hex(), "live-foreign-incumbent"))

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

# --- HIGH 6: stale gossip (>24h) is dropped; originator re-signs fresh ---
# ART-29 ruling (a): NAME_CLAIM_FRESHNESS applies on ingest. A binding
# signed 25h ago is dropped-stale. It does not insert, and it does not
# displace an expired row. The originator re-signs issued_at=now; that
# fresh claim then frees the dead row.
k_late = os.urandom(32).hex()
late_issued = iso_z(NOW - timedelta(hours=25))
check("stale (25h) gossip dropped on an empty name",
      core.ingest_gossiped_binding(
          mint("belt-stale-new", k_late, late_issued,
               iso_z(NOW + timedelta(days=30)))),
      "dropped-stale")
with core._db_lock, core._db() as conn:
    row = conn.execute(
        "SELECT node_pubkey FROM name_bindings WHERE name=?",
        ("belt-stale-new",)).fetchone()
check("stale gossip did not insert", row, None)
k_late_old = os.urandom(32).hex()
check("late-arrival incumbent inserts",
      core.ingest_gossiped_binding(
          mint("belt-late", k_late_old, live_issued, live_expires)),
      "inserted")
with core._db_lock, core._db() as conn:
    conn.execute(
        "UPDATE name_bindings SET expires_at=? WHERE name=?",
        (iso_z(NOW - timedelta(hours=1)), "belt-late"))
check("stale (25h) gossip does not replace expired incumbent",
      core.ingest_gossiped_binding(
          mint("belt-late", k_late, late_issued,
               iso_z(NOW + timedelta(days=30)))),
      "dropped-stale")
with core._db_lock, core._db() as conn:
    row = conn.execute(
        "SELECT node_pubkey FROM name_bindings WHERE name=?",
        ("belt-late",)).fetchone()
check("expired incumbent untouched by stale gossip",
      row[0], _ed.publickey(bytes.fromhex(k_late_old)).hex())
check("originator fresh re-sign replaces expired incumbent",
      core.ingest_gossiped_binding(
          mint("belt-late", k_late, iso_z(NOW),
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

# --- Villhaze (b) / Loom: name_conflicts never evicts ---
# One slot per challenger key. The first N distinct challengers stay.
# A repeat of the same key is ignored. The (N+1)th distinct key increments
# the overflow counter and is not inserted. The first row's signed bytes
# remain.
def _conflict_count(nm):
    with core._db_lock, core._db() as conn:
        return conn.execute(
            "SELECT COUNT(*) FROM name_conflicts WHERE name=?",
            (nm,)).fetchone()[0]

def _overflow(nm):
    with core._db_lock, core._db() as conn:
        row = conn.execute(
            "SELECT overflow_count FROM name_conflict_overflow WHERE name=?",
            (nm,)).fetchone()
    return row[0] if row else 0

k_dup_inc = os.urandom(32).hex()
k_dup_ch = os.urandom(32).hex()
dup_pub = _ed.publickey(bytes.fromhex(k_dup_ch)).hex()
dup_inc = {"node_pubkey": _ed.publickey(bytes.fromhex(k_dup_inc)).hex(),
           "issued_at": live_issued}
dup_sig = "ab" * 64
dup_ch = {"node_pubkey": dup_pub, "issued_at": live_issued,
          "expires_at": live_expires, "signature": dup_sig}
dup_again = {"node_pubkey": dup_pub,
             "issued_at": iso_z(NOW - timedelta(minutes=1)),
             "expires_at": live_expires, "signature": "cd" * 64}
with core._db_lock, core._db() as conn:
    core._log_name_conflict(conn, "belt-dup", dup_inc, dup_ch, "live-foreign-incumbent")
    core._log_name_conflict(conn, "belt-dup", dup_inc, dup_again, "live-foreign-incumbent")
check("duplicate challenger ignored (UNIQUE pubkey)", _conflict_count("belt-dup"), 1)
check("duplicate re-sign does not overflow", _overflow("belt-dup"), 0)
with core._db_lock, core._db() as conn:
    kept = conn.execute(
        "SELECT challenger_issued_at, challenger_signature, signed_payload "
        "FROM name_conflicts WHERE name=?",
        ("belt-dup",)).fetchone()
want_payload = core._name_claim_payload(
    "belt-dup", dup_pub, live_issued, live_expires)
check("first slot keeps original issued_at and signature",
      (kept[0], kept[1]), (live_issued, dup_sig))
check("signed payload stored for audit", bytes(kept[2]), want_payload)

# First N distinct challengers insert. The genuine first row is the
# audit trail that must survive the flood.
first_pubs = []
first_sig = "11" * 64
for i in range(core.NAME_CONFLICT_CAP):
    k_spam = os.urandom(32).hex()
    pub = _ed.publickey(bytes.fromhex(k_spam)).hex()
    first_pubs.append(pub)
    sig = first_sig if i == 0 else ("%02x" % (i % 256)) * 64
    spam_ch = {"node_pubkey": pub,
               "issued_at": iso_z(NOW - timedelta(minutes=i + 1)),
               "expires_at": live_expires, "signature": sig}
    with core._db_lock, core._db() as conn:
        core._log_name_conflict(conn, "belt-cap", dup_inc, spam_ch,
                                "live-foreign-incumbent")
check("first N challengers stored",
      _conflict_count("belt-cap"), core.NAME_CONFLICT_CAP)
check("no overflow while at the cap", _overflow("belt-cap"), 0)

extra = 0
for i in range(8):
    k_spam = os.urandom(32).hex()
    spam_ch = {"node_pubkey": _ed.publickey(bytes.fromhex(k_spam)).hex(),
               "issued_at": iso_z(NOW - timedelta(seconds=i + 1)),
               "expires_at": live_expires, "signature": "ee" * 64}
    with core._db_lock, core._db() as conn:
        core._log_name_conflict(conn, "belt-cap", dup_inc, spam_ch,
                                "live-foreign-incumbent")
    extra += 1
check("N+1th does not insert",
      _conflict_count("belt-cap"), core.NAME_CONFLICT_CAP)
check("N+1th increments overflow", _overflow("belt-cap"), extra)
with core._db_lock, core._db() as conn:
    trail = conn.execute(
        "SELECT challenger_pubkey, challenger_signature FROM name_conflicts "
        "WHERE name=? ORDER BY id ASC LIMIT 1",
        ("belt-cap",)).fetchone()
check("audit trail preserved (first challenger still stored)",
      (trail[0], trail[1]), (first_pubs[0], first_sig))

# Same key re-signing many times cannot evict the genuine row and is
# not an overflow (the slot already exists).
for i in range(40):
    resign = {"node_pubkey": first_pubs[0],
              "issued_at": iso_z(NOW - timedelta(seconds=30 + i)),
              "expires_at": live_expires, "signature": "ff" * 64}
    with core._db_lock, core._db() as conn:
        core._log_name_conflict(conn, "belt-cap", dup_inc, resign,
                                "live-foreign-incumbent")
check("re-sign flood does not evict",
      _conflict_count("belt-cap"), core.NAME_CONFLICT_CAP)
check("re-sign flood does not overflow", _overflow("belt-cap"), extra)
with core._db_lock, core._db() as conn:
    trail = conn.execute(
        "SELECT challenger_signature FROM name_conflicts "
        "WHERE name=? AND challenger_pubkey=?",
        ("belt-cap", first_pubs[0])).fetchone()
check("re-sign leaves the original signature", trail[0], first_sig)

# Migration: an old unique key (pubkey + issued_at) collapses to the
# first row per challenger, and rows beyond N are not deleted.
with core._db_lock, core._db() as conn:
    conn.execute("DROP INDEX IF EXISTS idx_name_conflicts_challenger")
    conn.execute(
        "INSERT INTO name_conflicts (name, incumbent_pubkey,"
        " incumbent_issued_at, challenger_pubkey, challenger_issued_at,"
        " challenger_expires_at, reason, recorded_at, challenger_signature)"
        " VALUES (?,?,?,?,?,?,?,?,?)",
        ("belt-mig", "inc", live_issued, "aa" * 32, live_issued,
         live_expires, "live-foreign-incumbent", live_issued, "mig-first"))
    conn.execute(
        "INSERT INTO name_conflicts (name, incumbent_pubkey,"
        " incumbent_issued_at, challenger_pubkey, challenger_issued_at,"
        " challenger_expires_at, reason, recorded_at, challenger_signature)"
        " VALUES (?,?,?,?,?,?,?,?,?)",
        ("belt-mig", "inc", live_issued, "aa" * 32,
         iso_z(NOW - timedelta(minutes=3)),
         live_expires, "live-foreign-incumbent", live_issued, "mig-second"))
    for i in range(40):
        conn.execute(
            "INSERT INTO name_conflicts (name, incumbent_pubkey,"
            " incumbent_issued_at, challenger_pubkey, challenger_issued_at,"
            " challenger_expires_at, reason, recorded_at)"
            " VALUES (?,?,?,?,?,?,?,?)",
            ("belt-mig", "inc", live_issued, ("%064x" % (i + 1)),
             live_issued, live_expires, "live-foreign-incumbent", live_issued))
    conn.commit()
core.init_db()
check("migration keeps first row of a repeated challenger",
      _conflict_count("belt-mig"), 41)  # 1 collapsed key + 40 distinct
with core._db_lock, core._db() as conn:
    mig = conn.execute(
        "SELECT challenger_signature FROM name_conflicts "
        "WHERE name=? AND challenger_pubkey=?",
        ("belt-mig", "aa" * 32)).fetchone()
    idx = conn.execute(
        "SELECT sql FROM sqlite_master WHERE name='idx_name_conflicts_challenger'"
    ).fetchone()
check("migration kept the earliest signature", mig[0], "mig-first")
check("unique index is (name, challenger_pubkey)",
      "challenger_issued_at" not in (idx[0] or "")
      and "challenger_pubkey" in (idx[0] or ""), True)

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
