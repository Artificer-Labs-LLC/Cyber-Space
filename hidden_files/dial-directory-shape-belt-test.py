#!/usr/bin/env python3
"""Belt test for dial.plan's directory-shape guard.

The legacy directory fallback is mirror-controlled: plan() fetches
/api/v1/directory and iterates its entries. A directory whose entries
value is not a list (123, 4.5, true) died in a TypeError traceback on
the iteration instead of reading as no matching entry — plan()
promises "never raises on bad input". Only a list can hold entries;
every other shape now reads as the silent-host exit 3, and a
well-formed directory still plans the direct dial as the control.
The mirror is mocked at core._resolve_get_json (test_dial's seam).

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/dial-directory-shape-belt-test.py
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import test_dial as t  # noqa: E402  (fixture helpers only)
import dial  # noqa: E402

PASSED = FAILED = 0


def check(name, cond, extra=""):
    global PASSED, FAILED
    if cond:
        PASSED += 1
        print(f"  ok: {name}")
    else:
        FAILED += 1
        print(f"  FAIL: {name} {extra}")


def _plan(directory):
    priv, pub = t._name_key()
    issued, expires = t._live_times()
    binding = t._signed_binding(t.LABEL, priv, pub, issued, expires)
    try:
        with t._fixture(binding=binding, directory=directory):
            return dial.plan(t.ADDR, t.MIRROR), pub
    except Exception as exc:  # a crash is the failure this belt hunts
        return f"CRASH {type(exc).__name__}: {exc}", pub


# 1-4. Non-list entries read silent-host (exit 3), never a traceback.
for bad in (123, 4.5, True, None):
    res, _ = _plan({"entries": bad})
    check(f"entries={bad!r} reads exit 3, no crash",
          isinstance(res, tuple) and res[0] == 3
          and any("no reach" in line for line in res[1]), f"res={res!r}")

# 5. String entries (iterable, but not a list) also read exit 3.
res, _ = _plan({"entries": "abc"})
check("entries='abc' reads exit 3, no crash",
      isinstance(res, tuple) and res[0] == 3, f"res={res!r}")

# 6. Control: well-formed directory still plans the direct dial.
priv, pub = t._name_key()
issued, expires = t._live_times()
binding = t._signed_binding(t.LABEL, priv, pub, issued, expires)
directory = {"entries": [{"node_pub": pub,
                          "node_url": "https://93.184.216.36/"}]}
try:
    with t._fixture(binding=binding, directory=directory):
        res = dial.plan(t.ADDR, t.MIRROR)
except Exception as exc:
    res = f"CRASH {type(exc).__name__}: {exc}"
check("well-formed directory still plans direct (exit 0)",
      isinstance(res, tuple) and res[0] == 0
      and any(line == "plan: direct https://93.184.216.36"
              for line in res[1]), f"res={res!r}")

print(f"\ndial-directory-shape belt: {PASSED}/{PASSED + FAILED}")
sys.exit(1 if FAILED else 0)
