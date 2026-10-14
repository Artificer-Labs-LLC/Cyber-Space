#!/usr/bin/env python3
"""Belt: CYBERNET_WORKSPACE_ENTRY_CAP refuses integer spellings bare
int() aliases -- Unicode decimal digits and underscore separators --
at the core_serve._workspace_entry_cap seat (primitive 3 hosting).

_workspace_entry_cap parsed the env override with bare int(): int()
parses Unicode decimal digits (an Arabic-Indic or fullwidth spelling
of 2000 became 2000) and accepts underscore separators (2_000 became
2000), so a non-ASCII or underscored spelling set a per-workspace
entry cap the operator never wrote in ASCII -- where every _env_int /
reach-TTL / epoch_len / gossip-announce seat (1212c00..df82ba3)
refuses those spellings. Fix: ASCII-digits gate (one optional leading
sign, max(cap, 1) floor preserved) at the seat; valid ASCII spellings
byte-exact, aliasing spellings fall back to the 1000 default.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/workspace-entry-cap-unicode-belt-test.py
"""
import os
import sys
import tempfile

TMP = tempfile.mkdtemp(prefix="entrycap-unicode-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core_serve  # noqa: E402

CASES = {"passed": 0, "failed": 0}


def check(name, cond, extra=""):
    if cond:
        CASES["passed"] += 1
        print(f"  ok  {name}")
    else:
        CASES["failed"] += 1
        print(f"  FAIL {name} {extra}")


VAR = "CYBERNET_WORKSPACE_ENTRY_CAP"


def cap(value):
    if value is None:
        os.environ.pop(VAR, None)
    else:
        os.environ[VAR] = value
    return core_serve._workspace_entry_cap()


AR2000 = "٢٠٠٠"      # Arabic-Indic 2000
FW2000 = "２０００"      # fullwidth 2000

check("ASCII 2000 -> 2000", cap("2000") == 2000)
check("ASCII 1 -> 1", cap("1") == 1)
check("ASCII 0 -> floor 1", cap("0") == 1)
check("ASCII -5 -> floor 1", cap("-5") == 1)
check("ASCII +42 -> 42", cap("+42") == 42)
check("unset -> 1000", cap(None) == 1000)
check("empty -> 1000", cap("") == 1000)
check("garbage '10m' -> 1000", cap("10m") == 1000)
check("Arabic-Indic 2000 -> 1000 (no alias)", cap(AR2000) == 1000)
check("fullwidth 2000 -> 1000 (no alias)", cap(FW2000) == 1000)
check("underscore 2_000 -> 1000 (no alias)", cap("2_000") == 1000)
check("superscript -> 1000 (no alias, no raise)", cap("²") == 1000)

print(f"\n{CASES['passed']}/{CASES['passed'] + CASES['failed']} passed")
sys.exit(1 if CASES["failed"] else 0)
