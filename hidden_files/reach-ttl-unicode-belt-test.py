#!/usr/bin/env python3
"""Belt: CYBERNET_REACH_TTL refuses integer spellings int() aliases --
Unicode decimal digits and underscore separators -- at both seats
(primitives 1 naming + 3 hosting + 6 client daemon).

core._reach_build parsed the TTL with bare int() and
host._reach_ttl_warnings mirrored it with bare int(): int() parses
Unicode decimal digits (Arabic-Indic/fullwidth 3600 -> 3600) and
accepts underscore separators (3_600 -> 3600), so a non-ASCII or
underscored spelling minted a descriptor lifetime the operator never
wrote in ASCII, and the startup warning twin blessed it in silence --
where every _env_int seat (1212c00/02e7d75) refuses those spellings.
Fix: ASCII-digits gate (one optional leading sign, floor/cap
semantics preserved) at _reach_build, mirrored in _reach_ttl_warnings;
valid ASCII spellings byte-exact, aliasing spellings fall back to the
86400 default at the build seat and warn not-an-integer at hostd.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/reach-ttl-unicode-belt-test.py
"""
import os
import secrets
import sys
import tempfile

TMP = tempfile.mkdtemp(prefix="reach-ttl-unicode-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "resolver"))

import core  # noqa: E402
import host as host_mod  # noqa: E402

CASES = {"passed": 0, "failed": 0}


def check(name, cond, extra=""):
    if cond:
        CASES["passed"] += 1
        print(f"  ok  {name}")
    else:
        CASES["failed"] += 1
        print(f"  FAIL {name} {extra}")


_real_gate = core._reject_nonpublic_node_url


def _test_gate(url):
    if url.startswith("http://127.0.0.1:"):
        return "127.0.0.1"
    return _real_gate(url)


core._reject_nonpublic_node_url = _test_gate
os.environ["CYBERNET_PUBLIC_URL"] = "http://127.0.0.1:9999"
os.environ.pop("CYBERNET_RELAY_URL", None)
os.environ.pop("CYBERNET_RENDEZVOUS", None)

PRIV = secrets.token_bytes(32).hex()
VAR = "CYBERNET_REACH_TTL"


def lifetime(raw):
    if raw is None:
        os.environ.pop(VAR, None)
    else:
        os.environ[VAR] = raw
    built = core._reach_build("ttlprobe", PRIV)
    if not built:
        return None
    desc = built[0]
    return (core._parse_claim_time(desc["expires_at"])
            - core._parse_claim_time(desc["issued_at"])).total_seconds()


def warns(raw):
    if raw is None:
        os.environ.pop(VAR, None)
    else:
        os.environ[VAR] = raw
    return host_mod._reach_ttl_warnings()


ARABIC_3600 = "٣٦٠٠"        # Arabic-Indic 3600
FULLWIDTH_3600 = "３６００"  # fullwidth 3600
assert int(ARABIC_3600) == 3600 and int("3_600") == 3600

# Controls: ASCII semantics unchanged at both seats.
for raw, want in (("3600", 3600), ("600", 600), ("60", 600), ("-5", 600),
                  ("+3600", 3600), ("86400", 86400), ("banana", 86400),
                  ("", 86400), (None, 86400)):
    check(f"build ascii {raw!r} -> {want}", lifetime(raw) == want,
          f"got {lifetime(raw)}")
check("build at-cap", lifetime(str(365 * 86400)) == 365 * 86400)
check("build over-cap clamps", lifetime(str(400 * 86400)) == 365 * 86400)
check("warnings ascii valid silent", warns("3600") == [])
check("warnings ascii below-floor", any("below the 600 floor" in w for w in warns("60")))
check("warnings ascii non-integer", any("not an integer" in w for w in warns("banana")))

# Aliasing spellings: build falls back to 86400, warnings say not-an-integer.
for raw in (ARABIC_3600, FULLWIDTH_3600, "3_600", "86_400"):
    check(f"build alias {raw!r} -> 86400", lifetime(raw) == 86400,
          f"got {lifetime(raw)}")
    check(f"warnings alias {raw!r}", any("not an integer" in w for w in warns(raw)),
          f"got {warns(raw)}")

print(f"\n{CASES['passed']} passed, {CASES['failed']} failed")
sys.exit(1 if CASES["failed"] else 0)
