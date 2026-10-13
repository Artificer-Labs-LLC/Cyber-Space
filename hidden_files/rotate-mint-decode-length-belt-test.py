#!/usr/bin/env python3
"""Belt: rotate_name.mint_rotation refuses a new pubkey whose DECODE
is not 32 bytes (primitives 1 naming + 4 identity).

mint_rotation gated new_pub_hex on STRING length only (64 chars +
bytes.fromhex parses), but bytes.fromhex ignores embedded spaces:
a spaced 64-char pubkey decodes to 31 bytes and minted a rotation
record verify_rotation itself refuses (its len(raw)*2 gate) — a
rotation no seat will ever accept, contradicting mint_rotation's own
contract that a minted record is one the verifier can vouch for.
Decoded-length gate at the mint seat (twin of verify_rotation /
hold_open 17387df / rendezvous 5f37a3e).

Covers: valid pub -> mints + verifies (control); uppercase pub ->
mints (lowered) + verifies (control); spaced pub (31-byte and
33-byte-equivalent shapes) -> ValueError, nothing minted; short /
non-hex pub -> as before.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/rotate-mint-decode-length-belt-test.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import rotate_name  # noqa: E402
from fed.ed25519 import publickey  # noqa: E402

CASES = {"passed": 0, "failed": 0}


def check(name, cond, extra=""):
    if cond:
        CASES["passed"] += 1
        print(f"  ok  {name}")
    else:
        CASES["failed"] += 1
        print(f"  FAIL {name} {extra}")


OLD = b"\x11" * 32
NEW_PUB = publickey(b"\x22" * 32).hex()
SPACED = NEW_PUB[:30] + "  " + NEW_PUB[32:]  # 64 chars, 31-byte decode
assert len(SPACED) == 64 and len(bytes.fromhex(SPACED)) == 31
TAB_SPACED = NEW_PUB[:30] + "\t " + NEW_PUB[32:]  # fromhex skips all whitespace
assert len(TAB_SPACED) == 64 and len(bytes.fromhex(TAB_SPACED)) == 31

# control: valid pub mints and verifies
rec = rotate_name.mint_rotation("testname", OLD, NEW_PUB)
check("valid pub mints", rec["new_pubkey"] == NEW_PUB)
check("valid pub verifies", rotate_name.verify_rotation(rec) is None)

# control: uppercase pub mints (lowered) and verifies
rec_up = rotate_name.mint_rotation("testname", OLD, NEW_PUB.upper())
check("uppercase pub mints lowered", rec_up["new_pubkey"] == NEW_PUB)
check("uppercase pub verifies", rotate_name.verify_rotation(rec_up) is None)

# spaced pubs are refused at mint, nothing minted
for label, bad in (("spaced", SPACED), ("tab-spaced", TAB_SPACED)):
    try:
        rotate_name.mint_rotation("testname", OLD, bad)
        check(f"{label} pub refused", False, "minted a record")
    except ValueError:
        check(f"{label} pub refused", True)

# pre-existing refusals unchanged: short and non-hex
for label, bad in (("short", NEW_PUB[:62]), ("non-hex", "zz" * 32)):
    try:
        rotate_name.mint_rotation("testname", OLD, bad)
        check(f"{label} pub refused", False, "minted a record")
    except ValueError:
        check(f"{label} pub refused", True)

print(f"{CASES['passed']}/{CASES['passed'] + CASES['failed']} passed")
sys.exit(1 if CASES["failed"] else 0)
