#!/usr/bin/env python3
"""Belt test for rotate_name.py --expiry-days front-door gate.

Before this tick --expiry-days only applied on submit (rotation
records carry no expiry), yet was silently ignored on the mint and
promote paths, and on submit an out-of-range value came back from
submit_rotation as exit 1 (a state verdict). main() now gates its
combination (submit only) and range (1..365) before any file or wire
use, exit 2, twin of the --new-key-seed gate.

Checks (scratch HOME; submit cases use a mirror that is never reached
because the record is missing once the gate passes):
  expiry 0 / 366 + --submit -> exit 2 bad argument
  expiry 10 (valid range) offline / + --promote -> exit 2 combination
  expiry 10 + --submit + missing record -> exit 1 state verdict
  no expiry + missing key offline -> exit 1 state verdict (unchanged)

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/rotate-expiry-gate-belt-test.py
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

PASSED = FAILED = 0
MIRROR = "http://127.0.0.1:8471"


def check(name, cond):
    global PASSED, FAILED
    if cond:
        PASSED += 1
        print(f"  ok: {name}")
    else:
        FAILED += 1
        print(f"  FAIL: {name}")


def run(argv, home):
    err = StringIO()
    with mock.patch.dict(os.environ, {"HOME": str(home)}), redirect_stderr(err):
        rc = rotate_name.main(argv)
    return rc, err.getvalue()


def main():
    for days in ("0", "366"):
        home = Path(tempfile.mkdtemp(prefix="rotate-expiry-"))
        rc, err = run(["somename", "--submit", MIRROR, "--expiry-days", days], home)
        check(f"expiry {days} + submit -> exit 2 bad argument",
              rc == 2 and "bad argument" in err)
    home = Path(tempfile.mkdtemp(prefix="rotate-expiry-"))
    rc, err = run(["somename", "--expiry-days", "10"], home)
    check("expiry 10 offline -> exit 2 combination",
          rc == 2 and "only applies with --submit" in err)
    rc, err = run(["somename", "--expiry-days", "10", "--promote"], home)
    check("expiry 10 + promote -> exit 2 combination",
          rc == 2 and "only applies with --submit" in err)
    home = Path(tempfile.mkdtemp(prefix="rotate-expiry-"))
    rc, err = run(["somename", "--submit", MIRROR, "--expiry-days", "10"], home)
    check("expiry 10 + submit + missing record -> exit 1 state verdict",
          rc == 1 and "rotation record missing" in err)
    home = Path(tempfile.mkdtemp(prefix="rotate-expiry-"))
    rc, err = run(["somename"], home)
    check("no expiry + missing key -> exit 1 state verdict",
          rc == 1 and "no existing name key" in err)
    print(f"\n{PASSED} passed, {FAILED} failed")
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
