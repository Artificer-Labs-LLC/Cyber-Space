#!/usr/bin/env python3
"""Belt for the gossip merge-half expiry fix (primitive 1, naming).

ingest_gossiped_binding() compared expiry as a STRING against _now().
A binding stamped "+05:00" (hours dead) sorts AFTER a "+00:00" now and
read as live — gossip would INSERT a dead binding the claim route would
refuse. The fix compares chronologically (_parse_claim_time); unparseable
expiry is malformed (fail-closed, never guessed).

Runs against a SCRATCH DB (CYBERNET_DB_DIR=tempdir set before import);
the repo's live cybernet.db is never touched.
"""
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone

TMP = tempfile.mkdtemp(prefix="gossip-merge-belt-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import order matters: `import core` FIRST (the app.py order). core.py ends
# with `from core_serve import *`; importing core_serve first leaves core
# with a partial namespace (NAME_LABEL_MAX/_now missing) — pre-existing
# circular-import fragility, not belted here.
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


def iso_off(dt, hours):
    tz = timezone(timedelta(hours=hours))
    return dt.astimezone(tz).isoformat(timespec="seconds")


NOW = datetime.now(timezone.utc)
live_issued = iso_z(NOW - timedelta(minutes=5))
live_expires = iso_z(NOW + timedelta(days=30))

# 1: live binding inserts
k1 = os.urandom(32).hex()
check("live inserts", core.ingest_gossiped_binding(
    mint("belt-live", k1, live_issued, live_expires)), "inserted")

# 2: same name, same key, later re-sign renews
k2 = os.urandom(32).hex()
b2a = mint("belt-renew", k2, live_issued, live_expires)
check("renew first", core.ingest_gossiped_binding(b2a), "inserted")
b2b = mint("belt-renew", k2, iso_z(NOW), iso_z(NOW + timedelta(days=60)))
check("same key later re-sign replaces", core.ingest_gossiped_binding(b2b),
      "replaced")

# 3: different key, earlier issued_at beats (first-claim wins)
k3a, k3b = os.urandom(32).hex(), os.urandom(32).hex()
check("challenger first", core.ingest_gossiped_binding(
    mint("belt-contest", k3a, iso_z(NOW - timedelta(hours=2)),
         iso_z(NOW + timedelta(days=30)))), "inserted")
late = mint("belt-contest", k3b, live_issued, iso_z(NOW + timedelta(days=30)))
check("later issued_at kept out", core.ingest_gossiped_binding(late), "kept")
early = mint("belt-contest", k3b, iso_z(NOW - timedelta(hours=5)),
             iso_z(NOW + timedelta(days=30)))
check("earlier issued_at replaces", core.ingest_gossiped_binding(early),
      "replaced")

# 4: THE BUG CASE — dead binding that string-sorts as live.
# Chronologically dead (UTC 4.5h ago) but lexicographically AFTER _now():
# old code returned "inserted"; fixed code must drop-expired.
dead_issued = iso_off(NOW - timedelta(hours=6), 5)
dead_expires = iso_off(NOW - timedelta(hours=4, minutes=30), 5)
assert dead_expires > core._now(), "fixture must string-sort as live"
k4 = os.urandom(32).hex()
check("hours-dead +05:00 binding dropped-expired",
      core.ingest_gossiped_binding(mint("belt-dead", k4, dead_issued,
                                        dead_expires)), "dropped-expired")

# 5: plain dead binding (same shape _now() emits)
k5 = os.urandom(32).hex()
check("plain expired dropped-expired", core.ingest_gossiped_binding(
    mint("belt-old", k5, iso_z(NOW - timedelta(days=3)),
         iso_z(NOW - timedelta(days=1)))), "dropped-expired")

# 6: unparseable expiry is malformed, never guessed
k6 = os.urandom(32).hex()
b6 = mint("belt-badtime", k6, live_issued, "not-a-time")
check("garbage expiry dropped-malformed",
      core.ingest_gossiped_binding(b6), "dropped-malformed")

# 7: tampered signature
k7 = os.urandom(32).hex()
b7 = mint("belt-tamper", k7, live_issued, live_expires)
b7["signature"] = "ab" * 64
check("bad sig dropped-unverifiable",
      core.ingest_gossiped_binding(b7), "dropped-unverifiable")

# 8: bad label / non-dict
check("bad label dropped-malformed", core.ingest_gossiped_binding(
    mint("BAD_LABEL!", os.urandom(32).hex(), live_issued, live_expires)),
    "dropped-malformed")
check("non-dict dropped-malformed",
      core.ingest_gossiped_binding("not a binding"), "dropped-malformed")

# 9: nothing leaked into the repo's live DB
live_db = os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "cybernet.db")
import sqlite3
names = {r[0] for r in sqlite3.connect(live_db).execute(
    "SELECT name FROM name_bindings")}
check("live DB untouched", names.isdisjoint(
    {"belt-live", "belt-renew", "belt-contest", "belt-dead", "belt-old",
     "belt-badtime", "belt-tamper"}), True)

print(f"{PASS} passed, {FAIL} failed (scratch db {TMP})")
sys.exit(1 if FAIL else 0)
