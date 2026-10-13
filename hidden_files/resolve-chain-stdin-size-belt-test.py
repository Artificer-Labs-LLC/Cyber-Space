#!/usr/bin/env python3
"""Belt test for resolve_chain's bounded stdin read.

The stdin (offline) mode read sys.stdin.read() whole before json.loads,
while the same tool's mirror fetch caps at _FETCH_MAX (64KB) and every
sibling tool caps its input (verify_name._INPUT_MAX). A rotations
document is a handful of short hops; an endless stdin could stream
into memory before any verdict ran. The read now asks for
_FETCH_MAX+1 and refuses oversize at exit 2 (no verdict) before
parsing; at-cap input still parses whole and reaches the verdict path.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/resolve-chain-stdin-size-belt-test.py
"""

import os
import subprocess
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
MAX = 65536

PASSED = FAILED = 0


def check(name, cond, extra=""):
    global PASSED, FAILED
    if cond:
        PASSED += 1
        print(f"  ok: {name}")
    else:
        FAILED += 1
        print(f"  FAIL: {name} {extra}")


def _cli(stdin_text):
    p = subprocess.run([sys.executable, "resolve_chain.py", "-"],
                       capture_output=True, text=True, input=stdin_text,
                       cwd=ROOT, timeout=30)
    return p.returncode, p.stdout.strip(), p.stderr.strip()


# Oversize valid JSON: refused exit 2 before parsing, no verdict.
rc, out, err = _cli('{"name": "x", "pad": "' + "a" * MAX + '"}')
check("oversize stdin refused exit 2", rc == 2, f"rc={rc} err={err!r}")
check("oversize refusal names the bound", "exceeds" in err and str(MAX) in err,
      f"err={err!r}")
check("oversize refusal is no verdict", "broken" not in err and "ok" not in out,
      f"out={out!r} err={err!r}")

# Oversize non-JSON (a stream that never parses): still the size
# refusal, proving the bound runs before the parser.
rc, out, err = _cli("z" * (MAX + 1))
check("oversize non-JSON reads as size refusal, not parse refusal",
      rc == 2 and "exceeds" in err, f"rc={rc} err={err!r}")

# Exactly at cap: parses whole, reaches the verdict path (this doc is
# a JSON object with no rotations, so the chain verdict runs).
at_cap = '{"a": "' + "a" * (MAX - len('{"a": ""}')) + '"}'
assert len(at_cap) == MAX
rc, out, err = _cli(at_cap)
check("at-cap stdin parses and reaches verdict (not size refusal)",
      "exceeds" not in err and rc in (0, 1), f"rc={rc} err={err!r}")

# Small contracts unchanged.
rc, out, err = _cli("not json")
check("small non-JSON still refused exit 2 as not-JSON",
      rc == 2 and "not JSON" in err, f"rc={rc} err={err!r}")
rc, out, err = _cli("[]")
check("small array doc still reads broken exit 1",
      rc == 1 and "Traceback" not in err, f"rc={rc} err={err!r}")

print(f"\n{PASSED} passed, {FAILED} failed")
sys.exit(1 if FAILED else 0)
