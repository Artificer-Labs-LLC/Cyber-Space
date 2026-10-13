#!/usr/bin/env python3
"""Belt test for push_one.py bounded read + argv-ceiling refusal.

Before this tick push_one.py slurped the whole local file with
f.read() before building --arguments-json — the last flagged
unbounded local read. A 2MB file was read whole, then the run died
with an unhandled OSError E2BIG traceback, because the github CLI
takes --arguments-json as ONE argv entry and the kernel caps a
single argv entry at MAX_ARG_STRLEN (131072 incl. NUL).

Now: the read asks for _FILE_MAX+1 (131072 — a larger file can
never fit the argv entry even unescaped) and refuses oversize at
exit 2 with no push attempted; the encoded arguments get a second
check against the ceiling because JSON escaping grows the string.
The github binary is faked via CYBERNET_GITHUB_BIN, so no real
push can fire from this belt.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/push-one-size-belt-test.py
"""

import os
import subprocess
import sys
import tempfile

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PY = os.path.join(ROOT, "venv", "bin", "python")
TOOL = os.path.join(ROOT, "push_one.py")
FILE_MAX = 131072

PASSED = FAILED = 0


def check(name, cond, extra=""):
    global PASSED, FAILED
    if cond:
        PASSED += 1
        print(f"  ok: {name}")
    else:
        FAILED += 1
        print(f"  FAIL: {name} {extra}")


TMP = tempfile.mkdtemp(prefix="push-one-belt-")
FAKE = os.path.join(TMP, "fake-github")
with open(FAKE, "w") as f:
    f.write("#!/bin/sh\necho FAKECALLED\nexit 0\n")
os.chmod(FAKE, 0o755)
ENV = dict(os.environ, CYBERNET_GITHUB_BIN=FAKE)


def run(args):
    p = subprocess.run([PY, TOOL] + args, capture_output=True, text=True,
                       cwd=ROOT, env=ENV, timeout=60)
    return p.returncode, p.stdout, p.stderr


def write(name, text):
    p = os.path.join(TMP, name)
    with open(p, "w") as f:
        f.write(text)
    return p


# Oversize file: refused before any push, exit 2, names the cap.
big = write("big.txt", "a" * (FILE_MAX + 1))
rc, out, err = run([big, "big.txt", "msg"])
check("oversize file exit 2", rc == 2, f"rc={rc} out={out!r} err={err!r}")
check("oversize refusal names cap", "exceeds" in err and str(FILE_MAX) in err,
      f"err={err!r}")
check("oversize attempted no push", "FAKECALLED" not in out and "RC:" not in out,
      f"out={out!r}")

# Escape bomb: under the file cap, over the argv ceiling once encoded.
bomb = write("bomb.txt", '"' * 70000)
rc, out, err = run([bomb, "bomb.txt", "msg"])
check("escape-bomb exit 2", rc == 2, f"rc={rc} err={err!r}")
check("escape-bomb refusal is the encoded check",
      "encoded arguments exceed" in err, f"err={err!r}")
check("escape-bomb attempted no push", "FAKECALLED" not in out,
      f"out={out!r}")

# Small file: the ordinary push path runs unchanged.
small = write("small.txt", "hello cyberspace\n")
rc, out, err = run([small, "small.txt", "msg"])
check("small file exit 0 with RC 0", rc == 0 and "RC: 0" in out,
      f"rc={rc} out={out!r} err={err!r}")
check("small file reached the (fake) github bin", "FAKECALLED" in out,
      f"out={out!r}")

# Large-but-fitting file (100KB plain): still pushes — the cap is the
# argv ceiling, not the 64KB sibling bound.
large = write("large.txt", "a" * 100000)
rc, out, err = run([large, "large.txt", "msg"])
check("100KB file still pushes", rc == 0 and "FAKECALLED" in out,
      f"rc={rc} out={out!r} err={err!r}")

# Missing file: clean exit 2 cannot-read, not a traceback.
rc, out, err = run([os.path.join(TMP, "nope.txt"), "x", "msg"])
check("missing file exit 2 cannot-read",
      rc == 2 and "cannot read" in err and "Traceback" not in err,
      f"rc={rc} err={err!r}")

# Wrong argc: usage at exit 2.
rc, out, err = run([small])
check("wrong argc exit 2 usage", rc == 2 and "usage:" in err,
      f"rc={rc} err={err!r}")

print(f"\n{PASSED} passed, {FAILED} failed")
sys.exit(1 if FAILED else 0)
