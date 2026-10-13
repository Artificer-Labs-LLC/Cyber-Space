#!/usr/bin/env python3
"""Belt test for verify_name.py bounded input read.

Before this tick main() slurped the whole binding file/stdin into
memory before json.loads ran; every sibling tool caps its read at
64KB (resolve_chain._FETCH_MAX, mint/rotate _MIRROR_RESP_MAX) and a
binding is a few hundred bytes. main() now reads at most
_INPUT_MAX+1 and refuses oversize input at exit 2 (no verdict).

Checks (subprocess, no network):
  oversize stdin -> exit 2, names the cap, no verdict words
  oversize file  -> exit 2, names the cap
  exactly-at-cap stdin (valid JSON padded) -> parsed, verdict path (exit 1 invalid, not 2)
  small garbage stdin -> exit 2 "not JSON" (unchanged)
  small valid-shape binding -> reaches verify() (exit 1 reason, not a read refusal)

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/verify-name-input-size-belt-test.py
"""

import json
import os
import subprocess
import sys
import tempfile

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PY = os.path.join(ROOT, "venv", "bin", "python")
TOOL = os.path.join(ROOT, "verify_name.py")
CAP = 65536

PASSED = FAILED = 0


def check(name, cond):
    global PASSED, FAILED
    if cond:
        PASSED += 1
        print(f"  ok: {name}")
    else:
        FAILED += 1
        print(f"  FAIL: {name}")


def run(args, stdin_text=None):
    p = subprocess.run([PY, TOOL] + args, input=stdin_text,
                       capture_output=True, text=True, cwd=ROOT)
    return p.returncode, p.stderr


# oversize stdin: refused before parsing, exit 2, no verdict
rc, err = run(["-"], "x" * (CAP + 1))
check("oversize stdin exit 2", rc == 2)
check("oversize stdin names cap", "exceeds" in err and str(CAP) in err)
check("oversize stdin no verdict", "invalid:" not in err)

# oversize file: same refusal
with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
    f.write("x" * (CAP + 1))
    big = f.name
try:
    rc, err = run([big])
    check("oversize file exit 2", rc == 2)
    check("oversize file names cap", "exceeds" in err)
finally:
    os.unlink(big)

# exactly at cap: a JSON doc padded to exactly CAP bytes is read whole
doc = {"pad": ""}
doc["pad"] = "x" * (CAP - len(json.dumps(doc)))
exact = json.dumps(doc)
assert len(exact) == CAP
rc, err = run(["-"], exact)
check("at-cap input is parsed (verdict path, exit 1)", rc == 1)

# small garbage still reads as not-JSON exit 2
rc, err = run(["-"], "nope")
check("small garbage exit 2 not-JSON", rc == 2 and "not JSON" in err)

# missing file still exit 2 cannot-read
rc, err = run(["/nonexistent/binding.json"])
check("missing file exit 2 cannot-read", rc == 2 and "cannot read" in err)

print(f"\n{PASSED} passed, {FAILED} failed")
sys.exit(1 if FAILED else 0)
