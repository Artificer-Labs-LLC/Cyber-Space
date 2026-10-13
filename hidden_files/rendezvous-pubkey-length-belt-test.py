#!/usr/bin/env python3
"""Belt: rendezvous._name_pub_bytes refuses a hex string whose DECODE
is not 32 bytes (primitives 1 naming + 3 hosting).

_name_pub_bytes gated only the STRING length (64 chars), but
bytes.fromhex ignores embedded spaces: a 64-char string carrying two
spaces decoded to a 31-byte key and derive_point_id happily derived a
rendezvous point for it — a meeting point for a key that is not the
32-byte name key, where strict seats (the pin gates in verify_name /
resolve_chain check len(bytes.fromhex(exp)) == 32 alongside the string
length) refuse the same value on sight. Decoded-length gate at the
seat: only a decode of exactly 32 bytes is a name key; anything else
is None, and every derivation built on it fails closed.

Covers: valid 64-hex -> 32 bytes + point exact (control); uppercase
hex -> same point (control); space-shrunk 31-byte decode -> None at
the parser, None from derive_point_id / derive_points, False from
point_is_current; odd/short/long/non-hex/non-string -> None (as
before).

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/rendezvous-pubkey-length-belt-test.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import rendezvous  # noqa: E402

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

check("valid key -> 32 raw bytes (control)",
      rendezvous._name_pub_bytes(GOOD) == bytes.fromhex(GOOD))
check("valid key derives a point (control)",
      rendezvous.derive_point_id(GOOD, 100) is not None)
check("uppercase hex -> same point (control)",
      rendezvous.derive_point_id(GOOD.upper(), 100)
      == rendezvous.derive_point_id(GOOD, 100))

for label, bad in (("trailing spaces", SPACED), ("mid spaces", SPACED_MID)):
    check(f"{label}: 64-char string, 31-byte decode -> parser None",
          rendezvous._name_pub_bytes(bad) is None,
          f"got {rendezvous._name_pub_bytes(bad)!r}")
    check(f"{label}: derive_point_id -> None (fail closed)",
          rendezvous.derive_point_id(bad, 100) is None)
    check(f"{label}: derive_points -> None (fail closed)",
          rendezvous.derive_points(100 * 3600, bad, 3600) is None)
    check(f"{label}: point_is_current -> False (fail closed)",
          rendezvous.point_is_current("00" * 32, 100 * 3600, bad, 3600)
          is False)

for label, bad in (("short", "ab" * 16), ("long", "ab" * 33),
                   ("non-hex", "zz" * 32), ("non-string", 12345),
                   ("none", None)):
    check(f"{label} -> parser None (as before)",
          rendezvous._name_pub_bytes(bad) is None)

print(f"\n{CASES['passed']} passed, {CASES['failed']} failed")
sys.exit(1 if CASES["failed"] else 0)
