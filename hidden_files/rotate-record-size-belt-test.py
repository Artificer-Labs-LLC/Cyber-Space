#!/usr/bin/env python3
"""Belt test for rotate_name.py bounded rotation-record read.

Before this tick both record seats (submit_rotation, promote_rotation)
loaded <label>-rotate.json via read_text() unbounded before json.loads
ran; every sibling input is capped at 64KB (verify_name._INPUT_MAX,
resolve_chain._FETCH_MAX, the tools' own _MIRROR_RESP_MAX) and a
rotation record is a few hundred bytes. _load_record now reads at
most _RECORD_MAX+1 and oversize refuses at both seats.

Checks (library calls, temp home, no network — oversize/badjson refuse
before any key read or mirror post):
  oversize record -> submit (False, names the cap, "nothing was sent")
  oversize record -> promote (False, names the cap)
  exactly-at-cap record (valid JSON padded) -> parsed, reaches
    verify_rotation's verdict (not an oversize/badjson refusal)
  small garbage record -> both seats keep the "not readable JSON" refusal
  missing record -> submit keeps the "missing ... mint one first" refusal

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/rotate-record-size-belt-test.py
"""

import os
import sys
import tempfile
from pathlib import Path

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)

import rotate_name  # noqa: E402

CAP = rotate_name._RECORD_MAX
MIRROR = "http://127.0.0.1:8471"

PASSED = FAILED = 0


def check(name, cond):
    global PASSED, FAILED
    if cond:
        PASSED += 1
        print(f"  ok: {name}")
    else:
        FAILED += 1
        print(f"  FAIL: {name}")


def home_with(record_text):
    home = Path(tempfile.mkdtemp())
    if record_text is not None:
        (home / "foo-rotate.json").write_text(record_text)
    # promote refuses before the record load unless the .next seed exists
    (home / "foo-name.key.next").write_text("ab" * 32)
    return home


# oversize record: both seats refuse naming the cap, before any send
big = home_with("x" * (CAP + 1))
ok, msg = rotate_name.submit_rotation("foo", MIRROR, big)
check("submit oversize refuses", ok is False)
check("submit oversize names cap", "exceeds" in msg and str(CAP) in msg)
check("submit oversize nothing sent", "nothing was sent" in msg)
ok, msg = rotate_name.promote_rotation("foo", big)
check("promote oversize refuses", ok is False)
check("promote oversize names cap", "exceeds" in msg and str(CAP) in msg)

# exactly at cap: valid JSON padded with trailing spaces parses and
# reaches verify_rotation's own verdict, not a read refusal
padded = '{"a": 1}' + " " * (CAP - len('{"a": 1}'))
assert len(padded) == CAP
ok, msg = rotate_name.submit_rotation("foo", MIRROR, home_with(padded))
check("at-cap record parsed (verify verdict, not read refusal)",
      ok is False and "does not verify" in msg)

# small garbage: unchanged badjson wording at both seats
ok, msg = rotate_name.submit_rotation("foo", MIRROR, home_with("not json"))
check("submit garbage is badjson refusal",
      ok is False and "not readable JSON" in msg)
ok, msg = rotate_name.promote_rotation("foo", home_with("not json"))
check("promote garbage is badjson refusal",
      ok is False and "not readable JSON" in msg)

# missing record: submit keeps its missing/mint-first wording
ok, msg = rotate_name.submit_rotation("foo", MIRROR, home_with(None))
check("submit missing keeps wording",
      ok is False and "missing" in msg and "mint one first" in msg)

print(f"---\n{PASSED} passed, {FAILED} failed")
sys.exit(1 if FAILED else 0)
