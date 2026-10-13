#!/usr/bin/env python3
"""Belt test for core._reannounce_loop's interval fallback.

Twin of the gossip-interval belt: the loop parsed
CYBERNET_ANNOUNCE_INTERVAL with a bare int() inside the try whose
`except Exception: pass` loops back with NO sleep: a non-integer
value (an operator's "1h", or a set-but-empty value) raised
ValueError on every pass — verified live before the fix, the loop
burned 1.50s of CPU in 1.5s of wall time, recorded zero sleeps, and
announcements never ran. The parse now falls back to the 3600
default (resolver _env_int semantics: bad values degrade, never
spin), so the sleep is always reached.

Checks (in-process; a fake time module records the sleep and breaks
the loop with a BaseException the loop's `except Exception` cannot
swallow):
  "1h"   -> first sleep is the 3600 default under +/-20% jitter
  ""     -> first sleep is the 3600 default under jitter
  "abc"  -> first sleep is the 3600 default under jitter
  "600"  -> first sleep is 600 under jitter (valid value honored)
  "100"  -> first sleep is the 300 floor under jitter (floor intact)

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/announce-interval-fallback-belt-test.py
"""

import os
import sys
import tempfile
import threading
import types

os.environ.setdefault("CYBERNET_DB_DIR", tempfile.mkdtemp(prefix="announce-belt-"))
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)

import core  # noqa: E402

PASSED = FAILED = 0


def check(name, cond):
    global PASSED, FAILED
    if cond:
        PASSED += 1
        print(f"  ok: {name}")
    else:
        FAILED += 1
        print(f"  FAIL: {name}")


class _StopLoop(BaseException):
    pass


_default_excepthook = threading.excepthook


def _quiet_hook(args):
    if not issubclass(args.exc_type, _StopLoop):
        _default_excepthook(args)


threading.excepthook = _quiet_hook


def first_sleep(env_value):
    """Run _reannounce_loop with CYBERNET_ANNOUNCE_INTERVAL=env_value
    and a fake clock; return the first sleep duration it asks for."""
    recorded = []
    fake_time = types.SimpleNamespace(
        sleep=lambda secs: (recorded.append(secs), (_ for _ in ()).throw(_StopLoop()))[0],
        time=core.time.time,
    )
    old_env = os.environ.get("CYBERNET_ANNOUNCE_INTERVAL")
    old_time = core.time
    os.environ["CYBERNET_ANNOUNCE_INTERVAL"] = env_value
    core.time = fake_time
    try:
        t = threading.Thread(target=core._reannounce_loop, daemon=True)
        t.start()
        t.join(timeout=5)
    finally:
        core.time = old_time
        if old_env is None:
            os.environ.pop("CYBERNET_ANNOUNCE_INTERVAL", None)
        else:
            os.environ["CYBERNET_ANNOUNCE_INTERVAL"] = old_env
    return recorded[0] if recorded else None


def in_jitter(secs, base):
    return secs is not None and base * 0.8 - 0.01 <= secs <= base * 1.2 + 0.01


check('"1h" falls back to the 3600 default', in_jitter(first_sleep("1h"), 3600))
check('set-but-empty falls back to the 3600 default', in_jitter(first_sleep(""), 3600))
check('"abc" falls back to the 3600 default', in_jitter(first_sleep("abc"), 3600))
check('"600" is honored', in_jitter(first_sleep("600"), 600))
check('"100" is clamped to the 300 floor', in_jitter(first_sleep("100"), 300))

print(f"\nannounce-interval-fallback belt: {PASSED}/{PASSED + FAILED}")
sys.exit(1 if FAILED else 0)
