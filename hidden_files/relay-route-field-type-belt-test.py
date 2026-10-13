#!/usr/bin/env python3
"""Belt: _relay_route refuses a NON-STRING relay field instead of
str()-aliasing it (primitives 1 naming + 3 hosting).

_relay_route (core.py) extracts the dial-side relay strategy from a
caller-verified descriptor's reach list, and it read kind/relay/url
through str() with no gate (token alone was already isinstance-gated):
a digit-only relay pubkey served as a JSON number (int) stringified
to its own 64-char hex and was RETURNED as that relay route — the
SAME alias the binding/descriptor seats refuse on sight. isinstance
gate at the seat: kind/relay/url must be real strings; a non-string
member is skipped like any malformed strategy (never raises), and a
valid string descriptor returns its route byte-exact.

Covers: int relay pubkey -> None (alias refused); int relay with a
valid string strategy second -> second strategy wins (skip, not
poison); non-string url/kind -> None; valid string descriptor ->
route exact (control).

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/relay-route-field-type-belt-test.py
"""
import os
import sys
import tempfile

TMP = tempfile.mkdtemp(prefix="relay-route-belt-")
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


DIGITS = "1" * 64  # digit-only 64-hex pubkey: str(int(...)) == itself
URL = "http://8.8.8.8:8443"
GOOD_STRAT = {"kind": "relay", "relay": DIGITS, "url": URL, "token": "tok-abc"}
GOOD_ROUTE = {"relay_pub": DIGITS, "url": URL, "token": "tok-abc"}


def route(strat):
    return core._relay_route({"reach": [strat]})


check("valid string descriptor -> route exact (control)",
      route(dict(GOOD_STRAT)) == GOOD_ROUTE,
      f"got {route(dict(GOOD_STRAT))!r}")

check("int relay pubkey -> refused, no route (alias)",
      route({**GOOD_STRAT, "relay": int(DIGITS)}) is None,
      f"got {route({**GOOD_STRAT, 'relay': int(DIGITS)})!r}")

check("int relay first, valid string second -> second wins",
      core._relay_route({"reach": [{**GOOD_STRAT, "relay": int(DIGITS)},
                                   dict(GOOD_STRAT)]}) == GOOD_ROUTE)

check("non-string url -> refused, no route",
      route({**GOOD_STRAT, "url": 8443}) is None)

check("non-string kind -> refused, no route",
      route({**GOOD_STRAT, "kind": ["relay"]}) is None)

print(f"\n{CASES['passed']}/{CASES['passed'] + CASES['failed']} passed")
sys.exit(1 if CASES["failed"] else 0)
