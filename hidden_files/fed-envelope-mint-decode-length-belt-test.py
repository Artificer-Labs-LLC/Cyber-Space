#!/usr/bin/env python3
"""Belt: fed.envelope.make_envelope refuses a sender seed / pubkey
whose DECODE is not 32 bytes (primitives 4 identity + 5 discovery).

make_envelope passed privkey_hex/sender_pub_hex straight to
bytes.fromhex + ed25519.sign() with no length gate: bytes.fromhex
ignores embedded spaces, so a spaced 64-char seed decoded to 31
bytes and sign() silently minted an envelope verify_envelope
itself refuses (checkvalid length-gates the pubkey decode) — an
envelope no seat accepts, contradicting the mint contract that a
minted envelope is one the verifier can vouch for. Production
callers gate upstream (host._reach_build / core seats), but the
mint seat itself was left behind (twin of core._reach_mint 99fd597
/ mint_rotation b7a6bb9). Decoded-length gates at the mint seat;
valid + uppercase keys byte-exact.

Covers: valid keys -> mints + verifies (control); uppercase keys
-> mints + verifies (control); spaced seed, tab-spaced seed,
spaced pub -> ValueError, nothing minted; short decodes fall
under the same gate; non-hex -> refused as before.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/fed-envelope-mint-decode-length-belt-test.py
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

SPACED_PRIV = PRIV[:30] + "  " + PRIV[32:]  # 64 chars, 31-byte decode
assert len(SPACED_PRIV) == 64 and len(bytes.fromhex(SPACED_PRIV)) == 31
TAB_PRIV = PRIV[:30] + "\t " + PRIV[32:]  # fromhex skips all whitespace
assert len(TAB_PRIV) == 64 and len(bytes.fromhex(TAB_PRIV)) == 31
SPACED_PUB = PUB[:30] + "  " + PUB[32:]
assert len(SPACED_PUB) == 64 and len(bytes.fromhex(SPACED_PUB)) == 31

TS = 1_700_000_000  # pinned: the pure-Python signer is slow enough
# that two unpinned mints can cross a timestamp second

# control: valid keys mint and verify
env = envelope.make_envelope(PRIV, PUB, "peer-node", BODY, ts=TS)
check("valid keys mint", env["sender_pub"] == PUB and len(env["sig"]) == 128)
check("valid keys verify", envelope.verify_envelope(env, now=TS) is True)

# control: uppercase keys mint and verify
env_up = envelope.make_envelope(PRIV.upper(), PUB.upper(), "peer-node", BODY, ts=TS)
check("uppercase keys mint same sig", env_up["sig"] == env["sig"])
check("uppercase keys verify", envelope.verify_envelope(env_up, now=TS) is True)

# spaced keys are refused at mint, nothing minted
for label, priv, pub in (("spaced seed", SPACED_PRIV, PUB),
                         ("tab-spaced seed", TAB_PRIV, PUB),
                         ("spaced pub", PRIV, SPACED_PUB)):
    try:
        envelope.make_envelope(priv, pub, "peer-node", BODY)
        check(f"{label} refused", False, "minted an envelope")
    except ValueError:
        check(f"{label} refused", True)

# short decodes fall under the same gate; non-hex refused as before
for label, priv, pub in (("short seed", "ab" * 16, PUB),
                         ("short pub", PRIV, "ab" * 16),
                         ("non-hex pub", PRIV, "zz" * 32)):
    try:
        envelope.make_envelope(priv, pub, "peer-node", BODY, ts=TS)
        check(f"{label} refused", False, "minted an envelope")
    except ValueError:
        check(f"{label} refused", True)

print(f"{CASES['passed']}/{CASES['passed'] + CASES['failed']} passed")
sys.exit(1 if CASES["failed"] else 0)
