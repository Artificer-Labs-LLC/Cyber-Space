#!/usr/bin/env python3
"""Belt: CYBERNET_GOSSIP_INTERVAL / CYBERNET_ANNOUNCE_INTERVAL refuse
integer spellings bare int() aliases -- Unicode decimal digits and
underscore separators -- at both loop seats (primitive 4 identity /
federation cadence).

core._gossip_loop and core._reannounce_loop parsed their intervals
with bare int(): int() parses Unicode decimal digits (an Arabic-Indic
or fullwidth spelling of 900 became 900) and accepts underscore
separators (9_00 / 7_200 became 900 / 7200), so a non-ASCII or
underscored spelling set a federation cadence the operator never
wrote in ASCII -- where every _env_int / reach-TTL / epoch_len seat
(1212c00..c333316) refuses those spellings. Fix: ASCII-digits gate
(one optional leading sign, floors and fallbacks preserved) at both
seats; valid ASCII spellings byte-exact, aliasing spellings fall back
to the 600 / 3600 defaults (bad values degrade, never spin).

The loops are infinite: the belt patches core's time.sleep to record
its first argument and park, and random.uniform to 1.0 (no jitter),
then runs each loop on a daemon thread and reads the recorded cadence.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/gossip-announce-interval-unicode-belt-test.py
"""
import os
import sys
import tempfile
import threading

TMP = tempfile.mkdtemp(prefix="interval-unicode-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core  # noqa: E402

CASES = {"passed": 0, "failed": 0}


def check(name, cond, extra=""):
    if cond:
        CASES["passed"] += 1
        print(f"  ok  {name}")
    else:
        CASES["failed"] += 1
        print(f"  FAIL {name} {extra}")


_recorded = []
_park = threading.Event()


def _fake_sleep(seconds):
    _recorded.append(seconds)
    _park.wait(30)  # park the loop thread inside its first sleep


core.time.sleep = _fake_sleep
core.random.uniform = lambda a, b: 1.0  # noqa: E731


def cadence(loop_fn, env_name, value):
    """Run loop_fn on a daemon thread with env_name set to value (None
    = unset); return the first sleep duration it computes."""
    if value is None:
        os.environ.pop(env_name, None)
    else:
        os.environ[env_name] = value
    del _recorded[:]
    t = threading.Thread(target=loop_fn, daemon=True)
    t.start()
    got = threading.Event()
    for _ in range(500):
        if _recorded:
            return _recorded[0]
        got.wait(0.01)
    return None


AR900 = "٩٠٠"          # Arabic-Indic 900
FW900 = "９００"          # fullwidth 900
AR7200 = "٧٢٠٠"        # Arabic-Indic 7200

# --- gossip loop: CYBERNET_GOSSIP_INTERVAL, default 600, floor 60 ---
g = lambda v: cadence(core._gossip_loop, "CYBERNET_GOSSIP_INTERVAL", v)  # noqa: E731
check("gossip ASCII 900 -> 900", g("900") == 900)
check("gossip ASCII 30 -> floor 60", g("30") == 60)
check("gossip ASCII -5 -> floor 60", g("-5") == 60)
check("gossip unset -> 600", g(None) == 600)
check("gossip empty -> 600", g("") == 600)
check("gossip '10m' -> 600", g("10m") == 600)
check("gossip Arabic-Indic 900 -> 600 (no alias)", g(AR900) == 600)
check("gossip fullwidth 900 -> 600 (no alias)", g(FW900) == 600)
check("gossip underscore 9_00 -> 600 (no alias)", g("9_00") == 600)

# --- announce loop: CYBERNET_ANNOUNCE_INTERVAL, default 3600, floor 300 ---
a = lambda v: cadence(core._reannounce_loop, "CYBERNET_ANNOUNCE_INTERVAL", v)  # noqa: E731
check("announce ASCII 7200 -> 7200", a("7200") == 7200)
check("announce ASCII 100 -> floor 300", a("100") == 300)
check("announce ASCII -5 -> floor 300", a("-5") == 300)
check("announce unset -> 3600", a(None) == 3600)
check("announce empty -> 3600", a("") == 3600)
check("announce '1h' -> 3600", a("1h") == 3600)
check("announce Arabic-Indic 7200 -> 3600 (no alias)", a(AR7200) == 3600)
check("announce underscore 7_200 -> 3600 (no alias)", a("7_200") == 3600)

print(f"\n{CASES['passed']}/{CASES['passed'] + CASES['failed']} passed")
sys.exit(1 if CASES["failed"] else 0)
