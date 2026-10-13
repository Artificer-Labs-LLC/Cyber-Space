#!/usr/bin/env python3
"""Belt test for mint_name's mirror-response shape guards.

The claim response and the resolve-back read are both mirror-controlled.
Valid JSON that is not an object ('[]', '123', '"ok"') died in
result.get with an AttributeError traceback, and a resolve-back binding
whose node_pubkey is not a string (123, null) died in .lower() the same
way — instead of the 'refused' exit-1 verdict every other bad mirror
answer gets. Both now read refused (exit 1, no exception). A well-formed
claim + matching resolve-back still mints clean as the control.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/mint-response-shape-belt-test.py
"""
import os
import sys
import tempfile

os.environ["HOME"] = tempfile.mkdtemp(prefix="mint-shape-home-")
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)

import mint_name  # noqa: E402
from fed import ed25519 as _fed_ed25519  # noqa: E402

PASSED = FAILED = 0


def check(name, cond, extra=""):
    global PASSED, FAILED
    if cond:
        PASSED += 1
        print(f"  ok: {name}")
    else:
        FAILED += 1
        print(f"  FAIL: {name} {extra}")


def _run(label):
    try:
        return mint_name.main([label])
    except Exception as exc:  # a crash is the failure this belt hunts
        return f"CRASH {type(exc).__name__}: {exc}"


# Non-object claim bodies read refused (exit 1), never a traceback.
for label, body in (("shapearr", "[]"), ("shapenum", "123"),
                    ("shapestr", '"ok"')):
    mint_name._post_form = lambda url, fields, timeout=30.0, b=body: (200, b)
    rc = _run(label)
    check(f"claim body {body!r} reads refused (exit 1), no crash",
          rc == 1, f"rc={rc!r}")

# Non-string resolve-back node_pubkey reads refused (exit 1).
mint_name._post_form = lambda url, fields, timeout=30.0: (
    200, '{"status": "claimed"}')
for label, bad in (("shapeint", 123), ("shapenull", None)):
    mint_name._get_json = lambda url, timeout=30.0, b=bad: {"node_pubkey": b}
    rc = _run(label)
    check(f"resolve-back node_pubkey {bad!r} reads refused (exit 1), no crash",
          rc == 1, f"rc={rc!r}")


# Control: well-formed claim + matching resolve-back mints (exit 0).
def _good_get(label):
    def _get(url, timeout=30.0):
        key = os.path.join(os.environ["HOME"], ".cyberspace",
                           f"{label}-name.key")
        seed = bytes.fromhex(open(key).read().strip())
        return {"node_pubkey": _fed_ed25519.publickey(seed).hex()}
    return _get


mint_name._get_json = _good_get("shapegood")
rc = _run("shapegood")
check("well-formed claim + resolve-back still mints (exit 0)",
      rc == 0, f"rc={rc!r}")

print(f"\nmint-response-shape belt: {PASSED}/{PASSED + FAILED}")
sys.exit(1 if FAILED else 0)
