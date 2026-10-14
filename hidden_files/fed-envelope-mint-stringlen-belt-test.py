#!/usr/bin/env python3
"""Belt: fed.envelope.make_envelope refuses a sender seed / pubkey
whose STRING length is not 64, even when its decode is the true
32 bytes (primitives 4 identity + 5 discovery).

make_envelope gated only the DECODED length (fed-envelope-mint
decode-length belt): bytes.fromhex ignores embedded whitespace, so
a 65-char seed/pubkey with an inserted space (or a line wrap, or a
tab) decodes to the TRUE 32 bytes, passed that gate, and minted —
but the envelope carries sender_pub VERBATIM, so the minted envelope
bore a 65-char identity string that verify_envelope itself refuses
on sight (len(sender_pub) != 64): minted-but-unverifiable, a second
spelling of the same key, in a spelling every binding/verify seat
refuses. Twin of mint/rotate _read_seed (db659a5) and the rotate
--new-key-seed CLI gate (8655426): string-length (64) gate at the
mint seat. Valid + uppercase keys byte-exact (case left alone).

Covers: valid keys -> mints + verifies (control); uppercase keys
-> mints + verifies (control); inserted-space seed, line-wrapped
seed, tabbed seed, inserted-space pub, line-wrapped pub -> ValueError,
nothing minted (each decodes to the true 32 bytes, so the decoded
gate alone passed them).

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/fed-envelope-mint-stringlen-belt-test.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fed import ed25519, envelope  # noqa: E402

CASES = {"passed": 0, "failed": 0}


def check(name, cond, extra=""):
    if cond:
        CASES["passed"] += 1
        print(f"  ok  {name}")
    else:
        CASES["failed"] += 1
        print(f"  FAIL {name} {extra}")


PRIV = "ab" * 32
PUB = ed25519.publickey(bytes.fromhex(PRIV)).hex()
BODY = {"ping": 1}

# 65-char spellings whose decode is the TRUE 32 bytes.
SPACE_PRIV = PRIV[:32] + " " + PRIV[32:]
WRAP_PRIV = PRIV[:32] + "\n" + PRIV[32:]
TAB_PRIV = PRIV[:32] + "\t" + PRIV[32:]
SPACE_PUB = PUB[:32] + " " + PUB[32:]
WRAP_PUB = PUB[:32] + "\n" + PUB[32:]
for s, raw in ((SPACE_PRIV, PRIV), (WRAP_PRIV, PRIV), (TAB_PRIV, PRIV),
               (SPACE_PUB, PUB), (WRAP_PUB, PUB)):
    assert len(s) == 65 and bytes.fromhex(s) == bytes.fromhex(raw)

TS = 1_700_000_000  # pinned, twin of the decode-length belt

# control: valid keys mint and verify
env = envelope.make_envelope(PRIV, PUB, "peer-node", BODY, ts=TS)
check("valid keys mint", env["sender_pub"] == PUB and len(env["sig"]) == 128)
check("valid keys verify", envelope.verify_envelope(env, now=TS) is True)

# control: uppercase keys mint and verify
env_up = envelope.make_envelope(PRIV.upper(), PUB.upper(), "peer-node", BODY, ts=TS)
check("uppercase keys mint same sig", env_up["sig"] == env["sig"])
check("uppercase keys verify", envelope.verify_envelope(env_up, now=TS) is True)

# true-decode non-64-char spellings are refused at mint, nothing minted
for label, priv, pub in (("inserted-space seed", SPACE_PRIV, PUB),
                         ("line-wrapped seed", WRAP_PRIV, PUB),
                         ("tabbed seed", TAB_PRIV, PUB),
                         ("inserted-space pub", PRIV, SPACE_PUB),
                         ("line-wrapped pub", PRIV, WRAP_PUB)):
    try:
        envelope.make_envelope(priv, pub, "peer-node", BODY, ts=TS)
        check(f"{label} refused", False, "minted an envelope")
    except ValueError:
        check(f"{label} refused", True)

print(f"{CASES['passed']}/{CASES['passed'] + CASES['failed']} passed")
sys.exit(1 if CASES["failed"] else 0)
