#!/usr/bin/env python3
"""hold_open keepalive belt: hold_open_cycle() promises "Never
raises", but its keepalive gate was a raw `keepalive_every <= 0` —
a string/None interval escaped as TypeError before the loop, True
aliased to a 1-second keepalive, and NaN/inf compared False against
every elapsed time, silently disabling keepalives so the relay
would reap the hold-open (primitive 3: hosting)."""
import os
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import hold_open  # noqa: E402

fails = 0

for bad in ("240", None, True, False, float("nan"), float("inf"),
            float("-inf"), 0, -5, b"240"):
    if hold_open._keepalive_every_ok(bad):
        print(f"FAIL: _keepalive_every_ok({bad!r}) is True")
        fails += 1
    stop = threading.Event()
    stop.set()
    try:
        hold_open.hold_open_cycle("http://127.0.0.1:9", "tok",
                                  "ab" * 32, stop, keepalive_every=bad)
    except Exception as e:  # noqa: BLE001
        print(f"FAIL: hold_open_cycle(keepalive_every={bad!r}) raised "
              f"{type(e).__name__}: {e}")
        fails += 1

for good in (1, 0.5, 240.0, hold_open._KEEPALIVE_EVERY):
    if not hold_open._keepalive_every_ok(good):
        print(f"FAIL: _keepalive_every_ok({good!r}) is False")
        fails += 1

if fails:
    print(f"test_hold_open: {fails} FAIL")
    sys.exit(1)
print("test_hold_open: OK")
