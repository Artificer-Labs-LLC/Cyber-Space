#!/usr/bin/env python3
"""Belt for Bulwark's HIGH (ART-29): gossip ingest enforces the route's
admission gates — freshness (24h) and the 365-day cap.

Before the fix, ingest_gossiped_binding checked signature, parse, and
not-expired only. A fresh key signing issued_at=2001, expires_at=2027 was
refused by the route but REPLACED any live incumbent via gossip
(Lodestar's backdating hole, open on the second path).

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

# --- HIGH 1: backdated gossip binding (issued_at=2001) is refused ---
# A live incumbent exists; attacker gossips a backdated binding from a
# fresh key. _name_claim_beats would let earlier-issued_at win — the
# freshness gate must drop it first.
k_inc = os.urandom(32).hex()
check("incumbent inserts",
      core.ingest_gossiped_binding(
          mint("belt-backdate", k_inc, live_issued, live_expires)),
      "inserted")
k_atk = os.urandom(32).hex()
backdated = mint("belt-backdate", k_atk,
                 "2001-01-01T00:00:00+00:00",
                 iso_z(NOW + timedelta(days=30)))
check("backdated (2001) gossip refused",
      core.ingest_gossiped_binding(backdated), "dropped-stale")
# Incumbent still holds the name
with core._db_lock, core._db() as conn:
    row = conn.execute(
        "SELECT node_pubkey FROM name_bindings WHERE name=?",
        ("belt-backdate",)).fetchone()
check("incumbent untouched after backdate attempt",
      row[0], _ed.publickey(bytes.fromhex(k_inc)).hex())

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

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
