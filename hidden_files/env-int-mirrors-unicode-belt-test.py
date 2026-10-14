#!/usr/bin/env python3
"""Belt: the _env_int mirrors refuse integer spellings int() aliases --
Unicode decimal digits and underscore separators -- instead of deriving
a port/refresh daemon._env_int (1212c00) already refuses
(primitives 2 resolution + 3 hosting + 6 client daemon).

client._default_port, wiring/smoke._default_port and host._env_int each
parsed their env var with bare int(): int() parses Unicode decimal
digits (Arabic-Indic/fullwidth 5354 -> 5354) and accepts underscore
separators (5_354 -> 5354), so those seats silently disagreed with the
daemon -- the client/smoke queried/smoked a port the daemon refused,
and hostd re-announced on a cadence never written in ASCII. Their
warning twins mirrored bare int() and blessed the spellings in silence.
Fix: ASCII-digits-only gate (one optional leading sign, floor semantics
preserved) at all three seats, mirrored in client._client_port_warnings,
smoke._port_warnings and host._hostd_refresh_warnings; ASCII byte-exact.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/env-int-mirrors-unicode-belt-test.py
"""
import importlib.util
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "resolver"))

from resolver import client, daemon  # noqa: E402
import host as host_mod  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "smoke", os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          "resolver", "wiring", "smoke.py"))
smoke = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(smoke)

CASES = {"passed": 0, "failed": 0}


def check(name, cond, extra=""):
    if cond:
        CASES["passed"] += 1
        print(f"  ok  {name}")
    else:
        CASES["failed"] += 1
        print(f"  FAIL {name} {extra}")


def with_env(var, raw, fn):
    old = os.environ.get(var)
    if raw is None:
        os.environ.pop(var, None)
    else:
        os.environ[var] = raw
    try:
        return fn()
    finally:
        if old is None:
            os.environ.pop(var, None)
        else:
            os.environ[var] = old


ARABIC = "٥٣٥٤"      # Arabic-Indic 5354
FULLWIDTH = "５３５４"  # fullwidth 5354
assert int(ARABIC) == 5354 and int("5_354") == 5354

PORT = "CYBERNET_RESOLVER_PORT"
# Controls: ASCII semantics unchanged, and agreement with the daemon.
for raw, want in (("5354", 5354), ("-5", 1), ("+5354", 5354), ("banana", 5353), ("", 5353)):
    check(f"client ascii {raw!r}", with_env(PORT, raw, client._default_port) == want)
    check(f"smoke ascii {raw!r}", with_env(PORT, raw, smoke._default_port) == want)
    check(f"client==daemon {raw!r}", with_env(PORT, raw, client._default_port) == with_env(PORT, raw, lambda: daemon._env_int(PORT, 5353, floor=1)))
# Aliasing spellings now fall back everywhere, in agreement.
for raw in (ARABIC, FULLWIDTH, "5_354"):
    check(f"client alias {raw!r} -> 5353", with_env(PORT, raw, client._default_port) == 5353)
    check(f"smoke alias {raw!r} -> 5353", with_env(PORT, raw, smoke._default_port) == 5353)
    check(f"warnings client alias {raw!r}", any("not an integer" in w for w in with_env(PORT, raw, client._client_port_warnings)))
    check(f"warnings smoke alias {raw!r}", any("not an integer" in w for w in with_env(PORT, raw, smoke._port_warnings)))
check("warnings client ascii silent", with_env(PORT, "5354", client._client_port_warnings) == [])
check("warnings smoke ascii silent", with_env(PORT, "5354", smoke._port_warnings) == [])

REF = "CYBERNET_HOSTD_REFRESH"
check("host ascii", with_env(REF, "60", lambda: host_mod._env_int(REF, 600)) == 60)
check("host negative -> floor", with_env(REF, "-5", lambda: host_mod._env_int(REF, 600)) == 1)
for raw in (ARABIC, "6_00"):
    check(f"host alias {raw!r} -> 600", with_env(REF, raw, lambda: host_mod._env_int(REF, 600)) == 600)
    check(f"host warnings alias {raw!r}", any("not an integer" in w for w in with_env(REF, raw, host_mod._hostd_refresh_warnings)))
check("host warnings ascii silent", with_env(REF, "60", host_mod._hostd_refresh_warnings) == [])

print(f"\n{CASES['passed']} passed, {CASES['failed']} failed")
sys.exit(1 if CASES["failed"] else 0)
