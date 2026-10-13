#!/usr/bin/env python3
"""Belt: core._relay_route refuses a relay pubkey whose DECODE is not
32 bytes (primitive 3 hosting).

_relay_route gated only the STRING length (64 chars), but
bytes.fromhex ignores embedded spaces: a 64-char string carrying two
spaces decoded to a 31-byte key and was still extracted as a
well-formed relay route — returned as the relay's 32-byte node
identity in resolve results and printed in dial plans — where strict
seats (rendezvous._name_pub_bytes, the pin gates in verify_name /
resolve_chain) check len(bytes.fromhex(exp)) == 32 alongside the
string length. Nothing downstream re-checks the byte length (the
relay session's live-proof rides the NAME key, never the relay key),
so the gate belongs at this seat: only a decode of exactly 32 bytes
is a relay identity; a spaced member is skipped like any malformed
member, never fatal to a later well-formed one.

Covers: valid 64-hex -> route exact (control); uppercase hex -> route
with lowercased pub (control); space-shrunk 31-byte decode (trailing
and mid-string) -> skipped (None alone, later good member wins);
short/long/non-hex/non-string -> skipped (as before).

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/relay-route-pubkey-length-belt-test.py
"""
import os
import sys

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


GOOD = "ab" * 32                      # 64 hex chars, 32 bytes
SPACED = "ab" * 31 + "  "             # 64 chars, only 62 hex digits
SPACED_MID = "ab" * 15 + "  " + "ab" * 16  # 64 chars, spaces mid-string
URL = "https://93.184.216.35/"
TOK = "sess-tok-1"


def desc(relay):
    return {"reach": [{"kind": "relay", "relay": relay,
                       "url": URL, "token": TOK}]}


route = core._relay_route(desc(GOOD))
check("valid key -> route exact (control)",
      route == {"relay_pub": GOOD, "url": "https://93.184.216.35",
                "token": TOK}, f"got {route!r}")
route = core._relay_route(desc(GOOD.upper()))
check("uppercase hex -> route, pub lowercased (control)",
      route is not None and route["relay_pub"] == GOOD,
      f"got {route!r}")

for label, bad in (("trailing spaces", SPACED), ("mid spaces", SPACED_MID)):
    check(f"{label}: 64-char string, 31-byte decode -> no route",
          core._relay_route(desc(bad)) is None,
          f"got {core._relay_route(desc(bad))!r}")
    mixed = {"reach": [{"kind": "relay", "relay": bad,
                        "url": URL, "token": TOK},
                       {"kind": "relay", "relay": GOOD,
                        "url": URL, "token": TOK}]}
    route = core._relay_route(mixed)
    check(f"{label}: spaced member skipped, later good member wins",
          route is not None and route["relay_pub"] == GOOD,
          f"got {route!r}")

for label, bad in (("short", "ab" * 16), ("long", "ab" * 33),
                   ("non-hex", "zz" * 32), ("non-string", 12345),
                   ("none", None)):
    check(f"{label} -> no route (as before)",
          core._relay_route(desc(bad)) is None)

print(f"\n{CASES['passed']} passed, {CASES['failed']} failed")
sys.exit(1 if CASES["failed"] else 0)
