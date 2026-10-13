#!/usr/bin/env python3
"""Belt: _reach_descriptor_verify refuses a NON-STRING issued_at/
expires_at instead of str()-aliasing it (primitives 1 naming +
2 resolution + 3 hosting).

_reach_descriptor_verify (core.py) is the gatekeeper every descriptor
seat trusts — resolve step 5, dial step 4, and the descriptor merge
(ingest_reach_descriptor) all call it instead of gating times
themselves — and it read issued_at/expires_at through str() with no
gate: a non-string time whose string form is a valid ISO stamp passed
the parse, the ordering/lifetime floors, AND the signature check
(the canonical form is built from the stringified alias, and the
signer genuinely signed that string), so the descriptor verified
True for a claim nobody served in that form — the SAME alias the
binding seats refuse on sight (their verify is only ever called with
isinstance-gated strings). isinstance gate at the source: a
non-string time reads as refusal (False, never raises), valid string
descriptors verify byte-exact.

Covers: valid string times -> True (control); exotic str()-alias
issued_at -> False; exotic str()-alias expires_at -> False;
int/bool/list issued_at -> False; alias descriptor through the
merge -> dropped-unverifiable, no row (the merge trusts verify).

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/reach-verify-time-field-type-belt-test.py
"""
import os
import secrets
import sys
import tempfile
from datetime import datetime, timedelta, timezone

TMP = tempfile.mkdtemp(prefix="reach-verify-time-belt-")
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
ISSUED = (NOW - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
EXPIRES = (NOW + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
REACH = [{"kind": "direct", "url": "https://93.184.216.34"}]

GOOD = core._reach_mint(PRIV, PUB, "beltname", REACH, ISSUED, EXPIRES)


class _AliasTime:
    """A non-string time whose str() is exactly the signed stamp."""

    def __init__(self, stamp):
        self._stamp = stamp

    def __str__(self):
        return self._stamp


check("valid string times -> verify True (control)",
      core._reach_descriptor_verify(dict(GOOD)) is True,
      f"got {core._reach_descriptor_verify(dict(GOOD))!r}")

check("str()-alias issued_at -> verify False (alias)",
      core._reach_descriptor_verify({**GOOD, "issued_at": _AliasTime(ISSUED)})
      is False)

check("str()-alias expires_at -> verify False (alias)",
      core._reach_descriptor_verify({**GOOD, "expires_at": _AliasTime(EXPIRES)})
      is False)

for bad in (123, True, [ISSUED], None):
    check(f"non-string issued_at {bad!r} -> verify False",
          core._reach_descriptor_verify({**GOOD, "issued_at": bad}) is False)

# The merge trusts verify alone for times: an alias descriptor must
# read as dropped-unverifiable there too, never inserted.
res = core.ingest_reach_descriptor({**GOOD, "issued_at": _AliasTime(ISSUED)})
check("alias descriptor through merge -> dropped-unverifiable",
      res == "dropped-unverifiable", f"got {res!r}")
with core._db_lock, core._db() as conn:
    rows = conn.execute(
        "SELECT COUNT(*) c FROM reach_descriptors").fetchone()["c"]
check("alias descriptor stored no row", rows == 0, f"rows={rows}")

print(f"\n{CASES['passed']} passed, {CASES['failed']} failed")
sys.exit(1 if CASES["failed"] else 0)
