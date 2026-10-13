#!/usr/bin/env python3
"""Belt: hold_open refuses a hex string whose DECODE is not 32 bytes
(primitives 3 hosting + 4 identity).

_sign_challenge and _name_pub_from_priv gated only the STRING length
(64 chars), but bytes.fromhex ignores embedded spaces: a spaced priv
seed decoded to 31 bytes and the key derivation silently accepted it
— _name_pub_from_priv returned a pubkey that is NOT the name's key
(rendezvous points registered under it are points no dialer derives:
the hoster reads as absent, silently), and _sign_challenge signed a
31-byte challenge decode nobody minted. Decoded-length gates at both
seats (twin of rendezvous._name_pub_bytes 5f37a3e): only a decode of
exactly 32 bytes is a seed / a challenge; anything else is None.

Covers: valid priv -> true pub (control); valid pair -> sig that
verifies against the true pub over the true challenge (control);
uppercase priv -> same pub (control); spaced priv -> None from both
seats; spaced challenge -> None; short/non-hex/non-string -> None
(as before).

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/hold-open-decode-length-belt-test.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fed import ed25519  # noqa: E402
import hold_open  # noqa: E402

CASES = {"passed": 0, "failed": 0}


def check(name, cond, extra=""):
    if cond:
        CASES["passed"] += 1
        print(f"  ok  {name}")
    else:
        CASES["failed"] += 1
        print(f"  FAIL {name} {extra}")


PRIV = "ab" * 32
CHAL = "cd" * 32
TRUE_PUB = ed25519.publickey(bytes.fromhex(PRIV)).hex()
SPACED_PRIV = PRIV[:10] + "  " + PRIV[12:]   # 64 chars, 31-byte decode
SPACED_CHAL = CHAL[:10] + "  " + CHAL[12:]   # 64 chars, 31-byte decode

check("valid priv -> true pub (control)",
      hold_open._name_pub_from_priv(PRIV) == TRUE_PUB)
check("uppercase priv -> same pub (control)",
      hold_open._name_pub_from_priv(PRIV.upper()) == TRUE_PUB)
_sig = hold_open._sign_challenge(CHAL, PRIV)
check("valid pair -> sig verifies vs true pub (control)",
      _sig is not None and ed25519.checkvalid(
          bytes.fromhex(_sig), bytes.fromhex(CHAL),
          bytes.fromhex(TRUE_PUB)))

check("spaced priv -> _name_pub_from_priv None (not a wrong key)",
      hold_open._name_pub_from_priv(SPACED_PRIV) is None,
      f"got {hold_open._name_pub_from_priv(SPACED_PRIV)!r}")
check("spaced priv -> _sign_challenge None",
      hold_open._sign_challenge(CHAL, SPACED_PRIV) is None)
check("spaced challenge -> _sign_challenge None",
      hold_open._sign_challenge(SPACED_CHAL, PRIV) is None)

for label, bad in (("short", "ab" * 16), ("non-hex", "zz" * 32),
                   ("non-string", 12345), ("none", None)):
    check(f"{label} priv -> _name_pub_from_priv None (as before)",
          hold_open._name_pub_from_priv(bad) is None)
    check(f"{label} priv -> _sign_challenge None (as before)",
          hold_open._sign_challenge(CHAL, bad) is None)

print(f"\n{CASES['passed']} passed, {CASES['failed']} failed")
sys.exit(1 if CASES["failed"] else 0)
