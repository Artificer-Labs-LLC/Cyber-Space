#!/usr/bin/env python3
"""Belt test for core._gossip_loop's interval fallback.

The loop parsed CYBERNET_GOSSIP_INTERVAL with a bare int() inside the
try whose `except Exception: pass` loops back with NO sleep: a
non-integer value (an operator's "10m", or a set-but-empty value)
raised ValueError on every pass — verified live before the fix, the
loop burned 0.89s of CPU in 1s of wall time and gossip never ran (a
valid value burns 0.0). The parse now falls back to the 600 default
(resolver _env_int semantics: bad values degrade, never spin), so the
sleep is always reached.

Checks (in-process; a fake time module records the sleep and breaks
the loop with a BaseException the loop's `except Exception` cannot
swallow):
  "10m"  -> first sleep is the 600 default under +/-20% jitter
  ""     -> first sleep is the 600 default under jitter
  "abc"  -> first sleep is the 600 default under jitter
  "120"  -> first sleep is 120 under jitter (valid value honored)
  "30"   -> first sleep is the 60 floor under jitter (floor intact)

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/gossip-interval-fallback-belt-test.py
"""

import os
import sys
import tempfile
import threading
import types

os.environ.setdefault("CYBERNET_DB_DIR", tempfile.mkdtemp(prefix="gossip-belt-"))
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


# The stop signal is the test working, not an error — keep stderr clean.
_default_excepthook = threading.excepthook


def _quiet_hook(args):
    if not issubclass(args.exc_type, _StopLoop):
        _default_excepthook(args)


threading.excepthook = _quiet_hook


def first_sleep(env_value):
    """Run _gossip_loop with CYBERNET_GOSSIP_INTERVAL=env_value and a
    fake clock; return the first sleep duration it asks for."""
    recorded = []
    fake_time = types.SimpleNamespace(
        sleep=lambda secs: (recorded.append(secs), (_ for _ in ()).throw(_StopLoop()))[0],
        time=core.time.time,
    )
    old_env = os.environ.get("CYBERNET_GOSSIP_INTERVAL")
    old_time = core.time
    os.environ["CYBERNET_GOSSIP_INTERVAL"] = env_value
    core.time = fake_time
    try:
        t = threading.Thread(target=core._gossip_loop, daemon=True)
        t.start()
        t.join(timeout=5)
    finally:
        core.time = old_time
        if old_env is None:
            os.environ.pop("CYBERNET_GOSSIP_INTERVAL", None)
        else:
            os.environ["CYBERNET_GOSSIP_INTERVAL"] = old_env
    return recorded[0] if recorded else None


def in_jitter(secs, base):
    return secs is not None and base * 0.8 - 0.01 <= secs <= base * 1.2 + 0.01


check('"10m" falls back to the 600 default', in_jitter(first_sleep("10m"), 600))
check('set-but-empty falls back to the 600 default', in_jitter(first_sleep(""), 600))
check('"abc" falls back to the 600 default', in_jitter(first_sleep("abc"), 600))
check('"120" is honored', in_jitter(first_sleep("120"), 120))
check('"30" is clamped to the 60 floor', in_jitter(first_sleep("30"), 60))

print(f"\ngossip-interval-fallback belt: {PASSED}/{PASSED + FAILED}")
sys.exit(1 if FAILED else 0)
