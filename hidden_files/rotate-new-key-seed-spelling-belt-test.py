#!/usr/bin/env python3
"""Belt test for rotate_name.py --new-key-seed canonical spelling.

Before: main() handed _normalize(args.new_key_seed) straight to
bytes.fromhex, which ignores embedded whitespace -- so a 65-char
inserted-space (or line-wrapped, or tabbed) seed argument decoded to
the TRUE 32 bytes and minted a rotation happily, while every seed
FILE seat (mint_name._read_seed / rotate_name._read_seed, db659a5)
and resolver/host._config gate the seed at exactly 64 hex chars and
refuse those spellings on sight. An argument the rotator accepted
produced a .next seed file hostd refuses: rotated but unhostable,
the same desync the file-seat fix closed, left open on the CLI-arg
surface.

Checks (scratch HOME, no network, missing-key path so the gate is
isolated): clean 64-hex passes the gate (exit 1 state verdict);
uppercase passes; outer padding strips and passes; inserted-space,
line-wrapped, and tab-inserted spellings -> exit 2 bad argument;
short seed still -> exit 2.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/rotate-new-key-seed-spelling-belt-test.py
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
    seed = "ab" * 32
    spaced = seed[:32] + " " + seed[32:]
    wrapped = seed[:32] + "\n" + seed[32:]
    tabbed = seed[:32] + "\t" + seed[32:]

    # Gate-passing spellings reach the missing-key state verdict (1).
    for label, s in [("clean", seed), ("uppercase", seed.upper()),
                     ("outer-padded", "  " + seed + " ")]:
        home = Path(tempfile.mkdtemp(prefix="rotate-argseed-"))
        rc, err = run(["somename", "--new-key-seed", s], home)
        check(f"{label} seed passes gate -> exit 1 state verdict",
              rc == 1 and "no existing name key" in err)

    # Non-canonical spellings are bad arguments (2), never decoded.
    for label, s in [("inserted-space", spaced), ("line-wrapped", wrapped),
                     ("tab-inserted", tabbed), ("short", "ab" * 31)]:
        home = Path(tempfile.mkdtemp(prefix="rotate-argseed-"))
        rc, err = run(["somename", "--new-key-seed", s], home)
        check(f"{label} seed refused -> exit 2 bad argument",
              rc == 2 and "bad argument" in err)

    print(f"\n{PASSED} passed, {FAILED} failed")
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
