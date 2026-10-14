#!/usr/bin/env python3
"""Belt: resolver.daemon._env_int refuses integer spellings int()
aliases -- Unicode decimal digits and underscore separators -- instead
of silently deriving a port/TTL the operator never wrote in ASCII
(primitives 2 resolution + 6 client daemon).

_env_int parsed env values with bare int(): on str, int() parses
Unicode decimal digits (Arabic-Indic/fullwidth 5353 -> 5353) and
accepts underscore separators (5_353 -> 5353), so a non-ASCII or
underscored spelling of CYBERNET_RESOLVER_PORT / CYBERNET_TTL_CAP
became a second spelling of the same value -- the B1 aliasing the
_NODE_URL_RE port class (b65258c) and _parse_upstream (1c6502c) seats
already refuse. _daemon_config_warnings mirrored the parse with bare
int() too, so it called those spellings valid integers in silence.
Fix: ASCII-digits-only gate (one optional leading sign, preserving
the floor semantics for negatives) at the _env_int seat, mirrored in
both warning blocks; valid ASCII spellings byte-exact.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/env-int-unicode-belt-test.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from resolver import daemon  # noqa: E402

CASES = {"passed": 0, "failed": 0}


def check(name, cond, extra=""):
    if cond:
        CASES["passed"] += 1
        print(f"  ok  {name}")
    else:
        CASES["failed"] += 1
        print(f"  FAIL {name} {extra}")


def env_int(var, raw, default, floor=0):
    old = os.environ.get(var)
    os.environ[var] = raw
    try:
        return daemon._env_int(var, default, floor=floor)
    finally:
        if old is None:
            os.environ.pop(var, None)
        else:
            os.environ[var] = old


ARABIC = "٥٣٥٤"      # Arabic-Indic 5354: int() parses it
FULLWIDTH = "５３５４"  # fullwidth 5354: int() parses it
SUPER = "²"          # superscript: int() raises (already fell back)
assert int(ARABIC) == 5354 and int(FULLWIDTH) == 5354 and int("5_354") == 5354

# Controls: ASCII spellings keep their exact prior semantics.
check("ascii port parsed", env_int("CYBERNET_RESOLVER_PORT", "5354", 5353, floor=1) == 5354)
check("ascii ttl parsed", env_int("CYBERNET_TTL_CAP", "60", 300) == 60)
check("negative -> floor", env_int("CYBERNET_TTL_CAP", "-5", 300) == 0)
check("signed ascii parsed", env_int("CYBERNET_TTL_CAP", "+60", 300) == 60)
check("garbage -> default", env_int("CYBERNET_TTL_CAP", "banana", 300) == 300)
check("empty -> default", env_int("CYBERNET_TTL_CAP", "", 300) == 300)

# The aliasing spellings now fall back to the default, never alias.
check("arabic-indic port -> default", env_int("CYBERNET_RESOLVER_PORT", ARABIC, 5353, floor=1) == 5353)
check("fullwidth port -> default", env_int("CYBERNET_RESOLVER_PORT", FULLWIDTH, 5353, floor=1) == 5353)
check("mixed ascii+unicode ttl -> default", env_int("CYBERNET_TTL_CAP", "30١", 300) == 300)
check("underscore port -> default", env_int("CYBERNET_RESOLVER_PORT", "5_354", 5353, floor=1) == 5353)
check("superscript ttl -> default, no raise", env_int("CYBERNET_TTL_CAP", SUPER, 300) == 300)

# The warnings mirror must call the same spellings not-an-integer.
def warns_for(var, raw):
    old = {v: os.environ.get(v) for v in
           ("CYBERNET_RESOLVER_PORT", "CYBERNET_TTL_CAP", "CYBERNET_UPSTREAM_DNS",
            "CYBERNET_MIRROR_URL", "CYBERNET_RESOLVER_BIND")}
    for v in old:
        os.environ.pop(v, None)
    os.environ[var] = raw
    try:
        return daemon._daemon_config_warnings()
    finally:
        for v, val in old.items():
            if val is None:
                os.environ.pop(v, None)
            else:
                os.environ[v] = val


check("warnings: arabic-indic port named not-an-integer",
      any("CYBERNET_RESOLVER_PORT is not an integer" in w for w in warns_for("CYBERNET_RESOLVER_PORT", ARABIC)))
check("warnings: underscore ttl named not-an-integer",
      any("CYBERNET_TTL_CAP is not an integer" in w for w in warns_for("CYBERNET_TTL_CAP", "3_00")))
check("warnings: ascii port silent", warns_for("CYBERNET_RESOLVER_PORT", "5354") == [])

print(f"\n{CASES['passed']} passed, {CASES['failed']} failed")
sys.exit(1 if CASES["failed"] else 0)
