#!/usr/bin/env python3
"""Belt: core._reach_mint refuses a name seed / pubkey whose DECODE
is not 32 bytes (primitives 1 naming + 3 hosting + 4 identity).

_reach_mint passed privkey_hex/node_pubkey straight to
bytes.fromhex + sign(), with no length gate at all: bytes.fromhex
ignores embedded spaces, so a spaced 64-char seed decoded to 31
bytes and sign() silently minted a descriptor
_reach_descriptor_verify itself refuses (checkvalid length-gates
both decodes) — a descriptor no seat accepts, contradicting mint's
own contract that a minted descriptor is one the verifier can
vouch for. The production caller (_reach_build) gates its seed
upstream, but the mint seat itself was left behind (twin of
mint_rotation b7a6bb9 / _reach_build 31b08ce). Decoded-length
gates at the mint seat; valid + uppercase keys byte-exact.

Covers: valid keys -> mints + verifies (control); uppercase keys
-> mints + verifies (control); spaced seed, tab-spaced seed,
spaced pub -> ValueError, nothing minted; short / non-hex -> as
before.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/reach-mint-decode-length-belt-test.py
"""
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core  # noqa: E402

CASES = {"passed": 0, "failed": 0}


def check(name, cond, extra=""):
    if cond:
        CASES["passed"] += 1
        print(f"  ok  {name}")
    else:
        CASES["failed"] += 1
        print(f"  FAIL {name} {extra}")


PRIV = "ab" * 32
PUB = core._fed_ed25519.publickey(bytes.fromhex(PRIV)).hex()
REACH = [{"kind": "direct", "url": "http://127.0.0.1:8000"}]
_now = datetime.now(timezone.utc)
ISSUED = _now.strftime("%Y-%m-%dT%H:%M:%S+00:00")
EXPIRES = (_now + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%S+00:00")

SPACED_PRIV = PRIV[:30] + "  " + PRIV[32:]  # 64 chars, 31-byte decode
assert len(SPACED_PRIV) == 64 and len(bytes.fromhex(SPACED_PRIV)) == 31
TAB_PRIV = PRIV[:30] + "\t " + PRIV[32:]  # fromhex skips all whitespace
assert len(TAB_PRIV) == 64 and len(bytes.fromhex(TAB_PRIV)) == 31
SPACED_PUB = PUB[:30] + "  " + PUB[32:]
assert len(SPACED_PUB) == 64 and len(bytes.fromhex(SPACED_PUB)) == 31

# control: valid keys mint and verify
desc = core._reach_mint(PRIV, PUB, "beltname", REACH, ISSUED, EXPIRES)
check("valid keys mint", desc["node_pubkey"] == PUB and len(desc["signature"]) == 128)
check("valid keys verify", core._reach_descriptor_verify(desc) is True)

# control: uppercase keys mint (canonical lowers pub) and verify
desc_up = core._reach_mint(PRIV.upper(), PUB.upper(), "beltname", REACH, ISSUED, EXPIRES)
check("uppercase keys mint same sig", desc_up["signature"] == desc["signature"])
check("uppercase keys verify", core._reach_descriptor_verify(desc_up) is True)

# spaced keys are refused at mint, nothing minted
for label, priv, pub in (("spaced seed", SPACED_PRIV, PUB),
                         ("tab-spaced seed", TAB_PRIV, PUB),
                         ("spaced pub", PRIV, SPACED_PUB)):
    try:
        core._reach_mint(priv, pub, "beltname", REACH, ISSUED, EXPIRES)
        check(f"{label} refused", False, "minted a descriptor")
    except ValueError:
        check(f"{label} refused", True)

# pre-existing refusals unchanged: short seed and non-hex pub
for label, priv, pub in (("short seed", "ab" * 16, PUB),
                         ("non-hex pub", PRIV, "zz" * 32)):
    try:
        core._reach_mint(priv, pub, "beltname", REACH, ISSUED, EXPIRES)
        check(f"{label} refused", False, "minted a descriptor")
    except ValueError:
        check(f"{label} refused", True)

print(f"{CASES['passed']}/{CASES['passed'] + CASES['failed']} passed")
sys.exit(1 if CASES["failed"] else 0)
