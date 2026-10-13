#!/usr/bin/env python3
"""Belt test for rotate_name.py --new-key-seed front-door gate.

Before this tick the seed was parsed only in the offline-mint path,
AFTER the existing-key read: a malformed seed against a missing key
read as exit 1 "no existing name key" (a verdict on local state) when
the argument itself was at fault, and a seed passed with
--submit/--promote was silently ignored. main() now gates the seed's
shape (64 hex / 32 bytes) and its only meaningful combination before
any file is read or anything is sent, exit 2, and reuses the parse.

Checks (all against a scratch HOME; no network):
  malformed seed (zz / short-hex / 31-byte) + missing key -> exit 2
  valid seed + missing key -> exit 1 (gate passes, state verdict stands)
  seed + --submit -> exit 2; seed + --promote -> exit 2
  valid seed + existing key -> exit 0 and .next seed is the given seed

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/rotate-seed-gate-belt-test.py
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
    valid_seed = "11" * 32
    # 1-3: malformed seeds are bad arguments even with no key on disk.
    for seed, label in [("zz", "non-hex"), ("ab", "1-byte"),
                        ("22" * 31, "31-byte")]:
        home = Path(tempfile.mkdtemp(prefix="rotate-seed-"))
        rc, err = run(["somename", "--new-key-seed", seed], home)
        check(f"{label} seed + missing key -> exit 2", rc == 2 and "bad argument" in err)
    # 4: a valid seed passes the gate; the missing-key verdict stands.
    home = Path(tempfile.mkdtemp(prefix="rotate-seed-"))
    rc, err = run(["somename", "--new-key-seed", valid_seed], home)
    check("valid seed + missing key -> exit 1 state verdict",
          rc == 1 and "no existing name key" in err)
    # 5-6: seed is meaningless with --submit/--promote; refuse, don't ignore.
    home = Path(tempfile.mkdtemp(prefix="rotate-seed-"))
    rc, _ = run(["somename", "--new-key-seed", valid_seed, "--submit"], home)
    check("seed + --submit -> exit 2", rc == 2)
    rc, _ = run(["somename", "--new-key-seed", valid_seed, "--promote"], home)
    check("seed + --promote -> exit 2", rc == 2)
    # 7: happy path — valid seed + existing key mints, .next is the seed.
    home = Path(tempfile.mkdtemp(prefix="rotate-seed-"))
    cy = home / ".cyberspace"
    cy.mkdir(parents=True)
    (cy / "somename-name.key").write_text("33" * 32)
    rc, _ = run(["somename", "--new-key-seed", valid_seed], home)
    nxt = cy / "somename-name.key.next"
    check("valid seed + key -> exit 0, .next == seed",
          rc == 0 and nxt.exists() and nxt.read_text().strip() == valid_seed)
    print(f"\n{PASSED} passed, {FAILED} failed")
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
