#!/usr/bin/env python3
"""Belt: core._reach_mint refuses a name seed / pubkey whose STRING
length is not 64, even when its decode is the true 32 bytes
(primitives 1 naming + 3 hosting + 4 identity).

_reach_mint gated only the DECODED length (reach-mint decode-length
belt): bytes.fromhex ignores embedded whitespace, so a 65-char
seed/pubkey with an inserted space (or a line wrap, or a tab)
decodes to the TRUE 32 bytes, passed that gate, and minted — but
the descriptor carries node_pubkey VERBATIM, so the minted
descriptor bore a 65-char identity string that
_reach_descriptor_verify itself refuses on sight
(len(node_pubkey) != 64): minted-but-unverifiable, a second
spelling of the same key, in a spelling every binding/verify seat
refuses. Twin of fed make_envelope (5cb3d5b) and mint/rotate
_read_seed (db659a5): string-length (64) gate at the mint seat.
Valid + uppercase keys byte-exact (case left alone).

Covers: valid keys -> mints + verifies (control); uppercase keys
-> mints + verifies (control); inserted-space seed, line-wrapped
seed, tabbed seed, inserted-space pub, line-wrapped pub -> ValueError,
nothing minted (each decodes to the true 32 bytes, so the decoded
gate alone passed them).

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/reach-mint-stringlen-belt-test.py
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

# 65-char spellings whose decode is the TRUE 32 bytes.
SPACE_PRIV = PRIV[:32] + " " + PRIV[32:]
WRAP_PRIV = PRIV[:32] + "\n" + PRIV[32:]
TAB_PRIV = PRIV[:32] + "\t" + PRIV[32:]
SPACE_PUB = PUB[:32] + " " + PUB[32:]
WRAP_PUB = PUB[:32] + "\n" + PUB[32:]
for s, raw in ((SPACE_PRIV, PRIV), (WRAP_PRIV, PRIV), (TAB_PRIV, PRIV),
               (SPACE_PUB, PUB), (WRAP_PUB, PUB)):
    assert len(s) == 65 and bytes.fromhex(s) == bytes.fromhex(raw)

# control: valid keys mint and verify
desc = core._reach_mint(PRIV, PUB, "beltname", REACH, ISSUED, EXPIRES)
check("valid keys mint", desc["node_pubkey"] == PUB and len(desc["signature"]) == 128)
check("valid keys verify", core._reach_descriptor_verify(desc) is True)

# control: uppercase keys mint (canonical lowers pub) and verify
desc_up = core._reach_mint(PRIV.upper(), PUB.upper(), "beltname", REACH, ISSUED, EXPIRES)
check("uppercase keys mint same sig", desc_up["signature"] == desc["signature"])
check("uppercase keys verify", core._reach_descriptor_verify(desc_up) is True)

# true-decode non-64-char spellings are refused at mint, nothing minted
for label, priv, pub in (("inserted-space seed", SPACE_PRIV, PUB),
                         ("line-wrapped seed", WRAP_PRIV, PUB),
                         ("tabbed seed", TAB_PRIV, PUB),
                         ("inserted-space pub", PRIV, SPACE_PUB),
                         ("line-wrapped pub", PRIV, WRAP_PUB)):
    try:
        core._reach_mint(priv, pub, "beltname", REACH, ISSUED, EXPIRES)
        check(f"{label} refused", False, "minted a descriptor")
    except ValueError:
        check(f"{label} refused", True)

print(f"{CASES['passed']}/{CASES['passed'] + CASES['failed']} passed")
sys.exit(1 if CASES["failed"] else 0)
