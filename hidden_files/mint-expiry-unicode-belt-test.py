#!/usr/bin/env python3
"""Belt: mint_name --expiry-days refuses integer spellings bare int()
aliases -- Unicode decimal digits and underscore separators -- at the
main() parse seat (primitives 1 naming + 6 client daemon).

main() parsed --expiry-days with bare int(): int() parses Unicode
decimal digits (an Arabic-Indic or fullwidth spelling of 365 became
365) and accepts underscore separators (3_65 became 365), so a
non-ASCII or underscored spelling minted a binding lifetime the
operator never wrote in ASCII -- where every _env_int / reach-TTL /
epoch_len seat (1212c00..550a888) refuses those spellings. Fix:
ASCII-digits gate (one optional leading sign, surrounding whitespace
preserved) at the seat; valid ASCII spellings keep their exact fate.

Probe design: an invalid mirror (ftp://x) is the stop after the
expiry gates, so a value that PASSES expiry/bounds reaches the
mirror refusal, a below-floor value reaches the floor refusal, an
over-cap value reaches the cap refusal, and an aliasing spelling
must now reach the integer refusal. HOME is a temp dir; nothing is
minted on any path (every case exits at an argument gate).

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/mint-expiry-unicode-belt-test.py
"""
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CASES = {"passed": 0, "failed": 0}


def check(name, cond, extra=""):
    if cond:
        CASES["passed"] += 1
        print(f"  ok  {name}")
    else:
        CASES["failed"] += 1
        print(f"  FAIL {name} {extra}")


def run(value):
    env = dict(os.environ, HOME=tempfile.mkdtemp(prefix="mint-expiry-"))
    argv = [sys.executable, os.path.join(ROOT, "mint_name.py"),
            "beltlabel", "ftp://x"]
    if value is not None:
        argv += ["--expiry-days", value]
    r = subprocess.run(argv, capture_output=True, text=True, env=env)
    return r.returncode, (r.stderr or "") + (r.stdout or "")


def fate(value):
    rc, out = run(value)
    if "must be an integer" in out:
        return "integer"
    if "below the 1-day" in out:
        return "floor"
    if "exceeds the namespace" in out:
        return "cap"
    if "mirror is not a dialable" in out:
        return "mirror"
    return f"rc/out: {out!r}"


AR365 = "٣٦٥"      # Arabic-Indic 365
FW365 = "３６５"      # fullwidth 365

check("ASCII 365 -> passes expiry (mirror stop)", fate("365") == "mirror", fate("365"))
check("ASCII 364 -> passes expiry (mirror stop)", fate("364") == "mirror", fate("364"))
check("ASCII +365 -> passes expiry (mirror stop)", fate("+365") == "mirror", fate("+365"))
check("ASCII ' 365 ' -> passes expiry (mirror stop)", fate(" 365 ") == "mirror", fate(" 365 "))
check("absent -> default passes (mirror stop)", fate(None) == "mirror", fate(None))
check("ASCII -5 -> floor refusal", fate("-5") == "floor", fate("-5"))
check("ASCII 0 -> floor refusal", fate("0") == "floor", fate("0"))
check("ASCII 366 -> cap refusal", fate("366") == "cap", fate("366"))
check("Arabic-Indic 365 -> integer refusal (no alias)", fate(AR365) == "integer", fate(AR365))
check("fullwidth 365 -> integer refusal (no alias)", fate(FW365) == "integer", fate(FW365))
check("underscore 3_65 -> integer refusal (no alias)", fate("3_65") == "integer", fate("3_65"))
check("superscript -> integer refusal (no alias, no raise)", fate("²") == "integer", fate("²"))
check("garbage '10m' -> integer refusal", fate("10m") == "integer", fate("10m"))
check("empty -> integer refusal", fate("") == "integer", fate(""))

print(f"\n{CASES['passed']}/{CASES['passed'] + CASES['failed']} passed")
sys.exit(1 if CASES["failed"] else 0)
