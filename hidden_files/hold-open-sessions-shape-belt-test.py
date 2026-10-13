#!/usr/bin/env python3
"""Belt test for hold_open_cycle_once's sessions-shape guard.

The /relay/wait answer is relay-controlled: hold_open._post proves
only that the body is an object, never the shape of its fields. A
sessions value that is not a list (123, 4.5, true) died in a TypeError
traceback on the iteration instead of reading as no pending sessions —
hold_open promises never to raise across its boundary, and the daemon
loop calls the cycle unguarded, so the crash killed the hold-open.
Only a list can hold sessions; every other shape reads as a healthy
cycle that answered nothing, and a well-formed session still gets
signed and answered as the control. The relay is mocked at
hold_open._post (the module's own seam).

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/hold-open-sessions-shape-belt-test.py
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import hold_open  # noqa: E402
from fed import ed25519 as _ed  # noqa: E402

PASSED = FAILED = 0


def check(name, cond, extra=""):
    global PASSED, FAILED
    if cond:
        PASSED += 1
        print(f"  ok: {name}")
    else:
        FAILED += 1
        print(f"  FAIL: {name} {extra}")


PRIV = bytes(range(32)).hex()
PUB = _ed.publickey(bytes.fromhex(PRIV))
CHALLENGE = (b"\x07" * 32).hex()
SIG = _ed.sign(bytes.fromhex(CHALLENGE), bytes.fromhex(PRIV), PUB).hex()

POSTS = []


def _run(wait_body):
    POSTS.clear()
    orig = hold_open._post

    def fake(url, path, payload, timeout):
        POSTS.append((path, payload))
        if path == "/relay/wait":
            return wait_body
        return {}  # /relay/answer accepted

    hold_open._post = fake
    try:
        return hold_open.hold_open_cycle_once(
            "http://relay.example", "tok", PRIV)
    except Exception as exc:  # a crash is the failure this belt hunts
        return f"CRASH {type(exc).__name__}: {exc}"
    finally:
        hold_open._post = orig


# 1-5. Non-list sessions read as a healthy, empty cycle — no crash.
for bad in (123, 4.5, True, None, "abc"):
    res = _run({"sessions": bad})
    check(f"sessions={bad!r} reads (True, 0), no crash",
          res == (True, 0), f"res={res!r}")

# 6. Missing sessions key reads the same.
res = _run({})
check("missing sessions reads (True, 0), no crash",
      res == (True, 0), f"res={res!r}")

# 7. Control: a well-formed session is signed and answered.
res = _run({"sessions": [{"session_id": "s1", "challenge": CHALLENGE}]})
check("well-formed session answered (True, 1)",
      res == (True, 1)
      and any(p == "/relay/answer"
              and pay == {"session_id": "s1", "name_key_sig": SIG}
              for p, pay in POSTS), f"res={res!r} posts={POSTS!r}")

# 8. Control: non-object entries inside a list are still skipped.
res = _run({"sessions": ["junk", 7, None]})
check("non-object list entries skipped (True, 0)",
      res == (True, 0), f"res={res!r}")

print(f"\nhold-open-sessions-shape belt: {PASSED}/{PASSED + FAILED}")
sys.exit(1 if FAILED else 0)
