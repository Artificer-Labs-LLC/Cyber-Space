#!/usr/bin/env python3
"""Belt test for resolver.answer._ttl_for's caller-supplied cap.

_ttl_for promises an int TTL in [0, cap], but the cap itself was never
type-checked: bool aliased through min/max (True -> 1, False -> 0),
a float returned a float TTL (which build_response refuses inside
handle_query), and a string/None raised TypeError from the comparison.
A cap that is not a real int now falls back to DEFAULT_TTL_CAP (300),
twin of daemon._env_int's bad-env fallback; real ints keep their exact
semantics (0, negatives floored at 0, huge caps bounded by seconds).

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/ttl-cap-shape-belt-test.py
"""
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from resolver.answer import DEFAULT_TTL_CAP, _ttl_for  # noqa: E402

PASSED = FAILED = 0


def check(name, cond, extra=""):
    global PASSED, FAILED
    if cond:
        PASSED += 1
        print(f"  ok: {name}")
    else:
        FAILED += 1
        print(f"  FAIL: {name} {extra}")


EXP = (datetime.now(timezone.utc) + timedelta(hours=2)).strftime(
    "%Y-%m-%dT%H:%M:%S+00:00")

# Valid caps keep exact semantics.
check("cap 300 caps a 2h binding at 300", _ttl_for(EXP, 300) == 300)
check("cap 10 caps at 10", _ttl_for(EXP, 10) == 10)
check("cap 0 yields 0", _ttl_for(EXP, 0) == 0)
check("negative cap floors at 0", _ttl_for(EXP, -5) == 0)
big = _ttl_for(EXP, 10**9)
check("huge cap bounded by seconds-to-expiry",
      isinstance(big, int) and 7000 < big <= 7200, f"got {big!r}")

# Malformed caps fall back to the default, never alias, never raise.
for bad in (True, False, 2.5, "300", None):
    got = _ttl_for(EXP, bad)
    check(f"cap {bad!r} falls back to default {DEFAULT_TTL_CAP}",
          got == DEFAULT_TTL_CAP and isinstance(got, int), f"got {got!r}")

# A malformed expiry still floors at 0 whatever the cap.
check("malformed expiry floors at 0", _ttl_for("not-a-stamp", 300) == 0)
check("malformed expiry + malformed cap floors at 0",
      _ttl_for("not-a-stamp", "300") == 0)

print(f"\n{PASSED} passed, {FAILED} failed")
sys.exit(1 if FAILED else 0)
