#!/usr/bin/env python3
"""Belt for M-1 + M-2 red-team fixes (allocation rule v0.6.3, Bulwark;
primitive 1 naming).

M-1: _name_claim_beats compares PARSED instants, not strings. Two bindings
with equal instants in different spellings ("...Z" vs "...+00:00") are a
TIE — the pubkey tiebreak decides, identically on every mirror regardless
of arrival order. (Before: string comparison let mirror A keep "Z" and
mirror B keep "+00:00" for the same instant.)

M-2: _parse_claim_time accepts EXACTLY the canonical form
(`YYYY-MM-DDTHH:MM:SS` + `Z`/`±HH:MM`) via strict regex + manual
construction — no datetime.fromisoformat, so no Python-version-dependent
spellings (week dates, space separators, basic format, +23:59 offsets,
fractional seconds all rejected). The verify_name.py twin must agree.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/m1-m2-redteam-belt-test.py
"""
import os
import sys
import tempfile

TMP = tempfile.mkdtemp(prefix="m1-m2-belt-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core  # noqa: E402
core.init_db()
from core_serve import _parse_claim_time  # noqa: E402
import verify_name  # noqa: E402

PASSED = FAILED = 0


def check(desc, cond, extra=""):
    global PASSED, FAILED
    if cond:
        PASSED += 1
        print(f"  ok  {desc}")
    else:
        FAILED += 1
        print(f"  FAIL {desc} {extra}")


def raises_ve(fn):
    try:
        fn()
    except ValueError:
        return True
    except Exception:
        return False
    return False


def binding(issued_at, pubkey):
    return {"node_pubkey": pubkey, "issued_at": issued_at}


# Two distinct pubkeys; lower one wins ties.
PUB_LOW = "aa" * 32
PUB_HIGH = "bb" * 32

print("M-1: tiebreak uses parsed instants, not strings")
# Same instant, different spellings, different keys.
b_low_z = binding("2026-10-10T00:00:00Z", PUB_LOW)
b_high_plus = binding("2026-10-10T00:00:00+00:00", PUB_HIGH)
b_low_plus = binding("2026-10-10T00:00:00+00:00", PUB_LOW)
b_high_z = binding("2026-10-10T00:00:00Z", PUB_HIGH)

# Tie on instant -> lower pubkey wins, regardless of spelling or order.
check("low-pubkey/Z beats high-pubkey/+00:00",
      core._name_claim_beats(b_low_z, b_high_plus) is True)
check("high-pubkey/+00:00 loses to low-pubkey/Z",
      core._name_claim_beats(b_high_plus, b_low_z) is False)
check("low-pubkey/+00:00 beats high-pubkey/Z",
      core._name_claim_beats(b_low_plus, b_high_z) is True)
check("high-pubkey/Z loses to low-pubkey/+00:00",
      core._name_claim_beats(b_high_z, b_low_plus) is False)
# Mirror-divergence scenario: arrival order must not change the outcome.
# Mirror A sees Z first, then +00:00; mirror B sees the reverse.
# Both must converge on the lower-pubkey binding.
a_keeps_low = not core._name_claim_beats(b_high_plus, b_low_z)  # A: new=+00:00(high) vs old=Z(low)
b_keeps_low = not core._name_claim_beats(b_high_z, b_low_plus)  # B: new=Z(high) vs old=+00:00(low)
check("mirrors converge on lower pubkey regardless of arrival order",
      a_keeps_low and b_keeps_low)

# Different instants still order correctly (parsed, not lexicographic).
b_early = binding("2026-10-10T00:00:00+05:00", PUB_HIGH)  # 2026-10-09T19:00Z
b_late = binding("2026-10-10T00:00:00+00:00", PUB_LOW)    # 2026-10-10T00:00Z
check("earlier instant wins across spellings",
      core._name_claim_beats(b_early, b_late) is True)
check("later instant loses across spellings",
      core._name_claim_beats(b_late, b_early) is False)

# Same-key renew: later issued_at supersedes (parsed).
b_old = binding("2026-10-10T00:00:00Z", PUB_LOW)
b_new = binding("2026-10-11T00:00:00+00:00", PUB_LOW)
check("same-key later instant supersedes",
      core._name_claim_beats(b_new, b_old) is True)
check("same-key earlier instant does not supersede",
      core._name_claim_beats(b_old, b_new) is False)

print("M-2: strict canonical parser (accept)")
for s in ["2026-10-10T00:00:00Z",
          "2026-10-10T00:00:00+00:00",
          "2026-10-10T00:00:00+05:00",
          "2026-10-10T00:00:00-05:00",
          "2026-10-10T00:00:00+14:00"]:
    try:
        dt = _parse_claim_time(s)
        check(f"accept {s}", dt.tzinfo is not None)
    except ValueError:
        check(f"accept {s}", False, "raised")

print("M-2: strict canonical parser (reject)")
rejects = [
    "2026-10-10T00:00:00",            # naive
    "2026-10-10",                     # date-only
    "2026-W41-3T00:00:00+00:00",      # week date
    "2026-10-10 00:00:00+00:00",      # space separator
    "20261010T000000+0000",           # basic format
    "2026-10-10T00:00:00.123+00:00",  # fractional seconds
    "2026-10-10T00:00:00+23:59",      # absurd offset
    "2026-10-10T00:00:00+00",         # short offset
    "2026-10-10T00:00:00+0000",       # no-colon offset
    "2026-13-10T00:00:00+00:00",      # bad month
    "2026-10-10T25:00:00+00:00",      # bad hour
    "2026-10-10T00:00:00+15:00",      # offset > +14
    "not-a-timestamp",
    "",
]
for s in rejects:
    check(f"reject {s!r}", raises_ve(lambda s=s: _parse_claim_time(s)))

print("M-2: twin agreement (verify_name._parse_ts)")
for s in ["2026-10-10T00:00:00Z", "2026-10-10T00:00:00+05:00"]:
    try:
        a = _parse_claim_time(s)
        b = verify_name._parse_ts(s, "issued_at")
        check(f"twins agree accept {s}", a == b)
    except ValueError:
        check(f"twins agree accept {s}", False, "raised")
for s in ["2026-10-10T00:00:00", "2026-W41-3", "2026-10-10T00:00:00+23:59"]:
    ra = raises_ve(lambda s=s: _parse_claim_time(s))
    rb = raises_ve(lambda s=s: verify_name._parse_ts(s, "issued_at"))
    check(f"twins agree reject {s!r}", ra and rb)

print(f"\n{PASSED} passed, {FAILED} failed")
sys.exit(1 if FAILED else 0)
