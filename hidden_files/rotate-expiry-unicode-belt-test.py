#!/usr/bin/env python3
"""Belt: rotate_name --expiry-days refuses integer spellings bare int()
aliases -- Unicode decimal digits and underscore separators -- at the
main() parse seat (primitives 1 naming + 4 identity / rotation).

main() declared --expiry-days with argparse type=int: int() parses
Unicode decimal digits (an Arabic-Indic or fullwidth spelling of 365
became 365) and accepts underscore separators (3_65 became 365), so a
non-ASCII or underscored spelling set a new-binding lifetime the
operator never wrote in ASCII -- where every _env_int / mint-expiry
seat (1212c00..aa8d2d0) refuses those spellings. Fix: the raw string
reaches main and an ASCII-digits gate (one optional leading sign,
surrounding whitespace preserved) refuses it with return 2 before the
combination/range gates; valid ASCII spellings keep their exact fate.

Probe design (in-process main, scratch HOME, --submit cases): a value
that PASSES every argument gate reaches the missing-record state
verdict (exit 1), a below-floor value the floor refusal, an over-cap
value the cap refusal, an offline value the combination refusal, and
an aliasing spelling must now reach the integer refusal (exit 2).
Nothing is minted, promoted or sent on any path.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/rotate-expiry-unicode-belt-test.py
"""
import os
import sys
import tempfile
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import rotate_name  # noqa: E402

CASES = {"passed": 0, "failed": 0}
MIRROR = "http://127.0.0.1:8471"


def check(name, cond, extra=""):
    if cond:
        CASES["passed"] += 1
        print(f"  ok  {name}")
    else:
        CASES["failed"] += 1
        print(f"  FAIL {name} {extra}")


def run(argv):
    home = Path(tempfile.mkdtemp(prefix="rotate-expiry-unicode-"))
    err = StringIO()
    with mock.patch.dict(os.environ, {"HOME": str(home)}), redirect_stderr(err):
        rc = rotate_name.main(argv)
    return rc, err.getvalue()


def fate(value, submit=True):
    argv = ["somename"]
    if submit:
        argv += ["--submit", MIRROR]
    argv += ["--expiry-days", value]
    rc, err = run(argv)
    if "must be an integer" in err:
        return "integer"
    if "only applies with --submit" in err:
        return "combination"
    if "below the 1-day" in err:
        return "floor"
    if "exceeds the namespace" in err:
        return "cap"
    if "rotation record missing" in err:
        return "passed-gates"
    return f"rc={rc} err={err!r}"


AR365 = "٣٦٥"      # Arabic-Indic 365
FW365 = "３６５"      # fullwidth 365

check("ASCII 365 + submit -> passes gates (missing record)", fate("365") == "passed-gates", fate("365"))
check("ASCII 364 + submit -> passes gates (missing record)", fate("364") == "passed-gates", fate("364"))
check("ASCII +365 + submit -> passes gates (missing record)", fate("+365") == "passed-gates", fate("+365"))
check("ASCII ' 365 ' + submit -> passes gates (missing record)", fate(" 365 ") == "passed-gates", fate(" 365 "))
check("ASCII -5 + submit -> floor refusal", fate("-5") == "floor", fate("-5"))
check("ASCII 0 + submit -> floor refusal", fate("0") == "floor", fate("0"))
check("ASCII 366 + submit -> cap refusal", fate("366") == "cap", fate("366"))
check("ASCII 10 offline -> combination refusal", fate("10", submit=False) == "combination", fate("10", submit=False))
check("Arabic-Indic 365 -> integer refusal (no alias)", fate(AR365) == "integer", fate(AR365))
check("fullwidth 365 -> integer refusal (no alias)", fate(FW365) == "integer", fate(FW365))
check("underscore 3_65 -> integer refusal (no alias)", fate("3_65") == "integer", fate("3_65"))
check("superscript -> integer refusal (no alias, no raise)", fate("²") == "integer", fate("²"))
check("garbage '10m' -> integer refusal", fate("10m") == "integer", fate("10m"))
check("empty -> integer refusal", fate("") == "integer", fate(""))

print(f"\n{CASES['passed']}/{CASES['passed'] + CASES['failed']} passed")
sys.exit(1 if CASES["failed"] else 0)
