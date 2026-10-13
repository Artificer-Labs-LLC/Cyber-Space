#!/usr/bin/env python3
"""Belt: ingest_reach_descriptor refuses a NON-STRING name/node_pubkey/
signature as dropped-malformed instead of str()-aliasing them in its
expiry diagnosis (primitives 1 naming + 2 resolution + 3 hosting).

ingest_reach_descriptor (core.py) extracted name/node_pubkey through
str() with no seat gate, trusting _reach_descriptor_verify transitively.
Verify does refuse those aliases — but on refusal the merge's expiry
diagnosis ran over the ALIASED name: an expired descriptor served with
name=true (bool) read as dropped-expired for the label "true", and one
with an int node_pubkey or a list signature read the same, instead of
dropped-malformed — the verdict the twin binding merge
(ingest_gossiped_binding) returns for the identical rows. Seat gate:
name/node_pubkey/signature must be real strings, else dropped-malformed.
Times keep the established contract (the merge trusts verify for them:
a time alias still reads dropped-unverifiable).

Covers: valid expired string descriptor -> dropped-expired (control);
valid live string descriptor, no binding -> dropped-unbound (control);
bool name / int pubkey / list signature on an expired descriptor ->
dropped-malformed, no row; time alias -> dropped-unverifiable (twin
contract preserved).

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/reach-merge-field-type-belt-test.py
"""
import os
import secrets
import sys
import tempfile
from datetime import datetime, timedelta, timezone

TMP = tempfile.mkdtemp(prefix="reach-merge-type-belt-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core  # noqa: E402

CASES = {"passed": 0, "failed": 0}


def check(name, cond, extra=""):
    if cond:
        CASES["passed"] += 1
        print(f"  ok  {name}")
    else:
        CASES["failed"] += 1
        print(f"  FAIL {name} {extra}")


core.init_db()

PRIV = secrets.token_hex(32)
PUB = core._fed_ed25519.publickey(bytes.fromhex(PRIV)).hex()
NOW = datetime.now(timezone.utc)
ISSUED_OLD = (NOW - timedelta(days=40)).strftime("%Y-%m-%dT%H:%M:%SZ")
EXPIRED = (NOW - timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
ISSUED = (NOW - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
EXPIRES = (NOW + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
REACH = [{"kind": "direct", "url": "https://93.184.216.34"}]

DEAD = core._reach_mint(PRIV, PUB, "true", REACH, ISSUED_OLD, EXPIRED)
LIVE = core._reach_mint(PRIV, PUB, "beltname", REACH, ISSUED, EXPIRES)

check("valid expired string descriptor -> dropped-expired (control)",
      core.ingest_reach_descriptor(dict(DEAD)) == "dropped-expired",
      f"got {core.ingest_reach_descriptor(dict(DEAD))!r}")

check("valid live string descriptor, unbound -> dropped-unbound (control)",
      core.ingest_reach_descriptor(dict(LIVE)) == "dropped-unbound",
      f"got {core.ingest_reach_descriptor(dict(LIVE))!r}")

check("bool name on expired descriptor -> dropped-malformed",
      core.ingest_reach_descriptor({**DEAD, "name": True})
      == "dropped-malformed",
      f"got {core.ingest_reach_descriptor({**DEAD, 'name': True})!r}")

check("int node_pubkey on expired descriptor -> dropped-malformed",
      core.ingest_reach_descriptor({**DEAD, "node_pubkey": 123})
      == "dropped-malformed",
      f"got {core.ingest_reach_descriptor({**DEAD, 'node_pubkey': 123})!r}")

check("list signature on expired descriptor -> dropped-malformed",
      core.ingest_reach_descriptor({**DEAD, "signature": ["ab"]})
      == "dropped-malformed",
      f"got {core.ingest_reach_descriptor({**DEAD, 'signature': ['ab']})!r}")


class _AliasTime:
    def __init__(self, stamp):
        self._stamp = stamp

    def __str__(self):
        return self._stamp


check("time alias keeps twin contract -> dropped-unverifiable",
      core.ingest_reach_descriptor({**LIVE, "issued_at": _AliasTime(ISSUED)})
      == "dropped-unverifiable",
      f"got {core.ingest_reach_descriptor({**LIVE, 'issued_at': _AliasTime(ISSUED)})!r}")

with core._db_lock, core._db() as conn:
    rows = conn.execute(
        "SELECT COUNT(*) c FROM reach_descriptors").fetchone()["c"]
check("no descriptor row stored", rows == 0, f"rows={rows}")

print(f"\n{CASES['passed']} passed, {CASES['failed']} failed")
sys.exit(1 if CASES["failed"] else 0)
