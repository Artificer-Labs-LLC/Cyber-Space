"""Lazy reap of reach-descriptor rows on the ingest path: the mirror's
_reap_expired_reach_descriptors drops rows the serve side already reads
as absent (expired/unparseable descriptor expiry; binding gone, expired,
or re-keyed under the row), once per ingest. Test-driven. Drives the
REAL core helpers + DB on a throwaway CYBERNET_DB_DIR — no network.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/reach-reap-test.py
"""

import os
import secrets
import sqlite3
import sys
import tempfile
from datetime import datetime, timedelta, timezone

TMP = tempfile.mkdtemp(prefix="reach-reap-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from core import (  # noqa: E402
    _fed_ed25519, _name_claim_payload, _reach_mint,
    ingest_gossiped_binding, ingest_reach_descriptor, init_db,
)
from fed import ed25519 as _ed  # noqa: E402

CASES = {"passed": 0, "failed": 0}


def check(name, cond, extra=""):
    if cond:
        CASES["passed"] += 1
        print(f"  ok  {name}")
    else:
        CASES["failed"] += 1
        print(f"  FAIL {name} {extra}")


NOW = datetime.now(timezone.utc)
AT = lambda s: (NOW + timedelta(seconds=s)).isoformat()  # noqa: E731
PAST = AT(-86400)


def _keypair():
    seed = secrets.token_hex(32)
    return seed, _ed.publickey(bytes.fromhex(seed)).hex()


def _mint_binding(name, seed, pub, issued_at, expires_at):
    sig = _fed_ed25519.sign(_name_claim_payload(name, pub, issued_at, expires_at),
                            bytes.fromhex(seed), bytes.fromhex(pub)).hex()
    return {"name": name, "node_pubkey": pub, "issued_at": issued_at,
            "expires_at": expires_at, "signature": sig}


def _raw(sql, args=()):
    conn = sqlite3.connect(os.path.join(TMP, "cybernet.db"))
    rows = conn.execute(sql, args).fetchall()
    conn.commit()
    conn.close()
    return rows


def _rows(name):
    return _raw("SELECT name FROM reach_descriptors WHERE name=?", (name,))


def _plant_descriptor(name, pub, expires_at):
    """Plant a descriptor row directly, bypassing merge rules, to simulate
    stale state."""
    _raw("INSERT OR REPLACE INTO reach_descriptors (name, node_pubkey, reach,"
         " issued_at, expires_at, signature) VALUES (?,?,?,?,?,?)",
         (name, pub, "[]", AT(0), expires_at, "ab" * 64))


def _plant_binding(name, pub, expires_at):
    """Plant a binding row directly, bypassing merge rules (the merge
    refuses expired bindings and pins re-keys by the deterministic
    conflict rule; the reap exists precisely for decayed state the merge
    could never have produced)."""
    _raw("INSERT OR REPLACE INTO name_bindings (name, node_pubkey, issued_at,"
         " expires_at, signature) VALUES (?,?,?,?,?)",
         (name, pub, AT(0), expires_at, "ab" * 128))


init_db()
SKA, PKA = _keypair()
SKB, PKB = _keypair()

check("bind atlas", ingest_gossiped_binding(
    _mint_binding("atlas", SKA, PKA, AT(0), AT(2592000))) == "inserted")
check("merge atlas", ingest_reach_descriptor(_reach_mint(
    SKA, PKA, "atlas", [{"kind": "direct", "url": "https://a.example/"}],
    AT(0), AT(2592000))) == "inserted")


def _poke_atlas(issued):
    """Trigger the reap by merging a fresh descriptor for atlas."""
    return ingest_reach_descriptor(_reach_mint(
        SKA, PKA, "atlas", [{"kind": "direct", "url": "https://a.example/"}],
        AT(issued), AT(2592000)))


# 1: expired descriptor row reaped on the next ingest.
_plant_descriptor("relic", PKA, PAST)
check("relic row planted", len(_rows("relic")) == 1)
check("ingest proceeds", _poke_atlas(60) == "replaced")
check("expired descriptor reaped", len(_rows("relic")) == 0)
check("live atlas row survives", len(_rows("atlas")) == 1)

# 2: unparseable expires_at is fail-closed dead, reaped too.
_plant_descriptor("ghost", PKA, "not-a-time")
check("ghost row planted", len(_rows("ghost")) == 1)
check("ingest proceeds", _poke_atlas(120) == "replaced")
check("unparseable-expires reaped", len(_rows("ghost")) == 0)

# 3: a descriptor row whose binding DECAYED after the merge (live
# descriptor expiry, expired binding) is reaped — the serve side already
# reads it as absent; nothing else GCs it.
_plant_binding("relic", PKA, PAST)
_plant_descriptor("relic", PKA, AT(2592000))
check("decayed relic state planted", len(_rows("relic")) == 1)
check("ingest proceeds", _poke_atlas(180) == "replaced")
check("dead-binding row reaped", len(_rows("relic")) == 0)

# 4: binding re-keyed under the row (binding under B, descriptor row
# under A) — the serve side reads the row as absent, the reap drops it.
_plant_binding("atlas", PKB, AT(2592000))
_plant_descriptor("atlas", PKA, AT(2592000))
check("rekeyed atlas state planted", len(_rows("atlas")) == 1)
check("ingest proceeds", _poke_atlas(240) == "dropped-key-mismatch")
check("rekeyed row reaped", len(_rows("atlas")) == 0)

# 5: reap never raises and keeps the merge's fail-closed contract intact.
check("garbage still dropped", ingest_reach_descriptor(None) == "dropped-malformed")

print(f"\n{CASES['passed']}/{CASES['passed'] + CASES['failed']} cases passed")
sys.exit(1 if CASES["failed"] else 0)
