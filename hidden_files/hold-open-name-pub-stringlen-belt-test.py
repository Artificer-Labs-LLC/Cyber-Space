#!/usr/bin/env python3
"""Belt: hold_open._name_pub_from_priv refuses a name seed whose STRING
length is not 64 even when its decode is the true 32 bytes (primitives
3 hosting + 4 identity).

_name_pub_from_priv gated only the DECODED length, and bytes.fromhex
ignores embedded whitespace: a 65-char inserted-space (or line-wrapped,
or tabbed) seed decoded to the TRUE 32 bytes and derived the true
pubkey -- while its twin in the same file, _sign_challenge, refuses any
name_priv_hex whose length is not 64 on sight, and resolver/host._config
string-gates the hostd seed at exactly 64 chars. The same hold-open
cycle (hold_open.py:266/318) therefore registered rendezvous points
under a key it would refuse to sign a challenge for: points advertised,
answers refused -- the hoster reads as present at the relay and absent
to every dialer that challenges it. String-length (64) gate at the
derivation seat, twin of _sign_challenge + host._config + fed
make_envelope (5cb3d5b); valid + uppercase seeds derive byte-exact.
Production callers pass host._config-gated seeds, so no live path
changes.

Covers: valid seed -> true pub (control); uppercase seed -> same pub
(control); inserted-space / line-wrapped / tabbed 65-char true-decode
seeds -> None; spaced 64-char 31-byte-decode seed -> None (as before);
short / non-hex / non-str -> None (as before).

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/hold-open-name-pub-stringlen-belt-test.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import hold_open  # noqa: E402
from fed import ed25519  # noqa: E402

CASES = {"passed": 0, "failed": 0}


def check(name, cond, extra=""):
    if cond:
        CASES["passed"] += 1
        print(f"  ok  {name}")
    else:
        CASES["failed"] += 1
        print(f"  FAIL {name} {extra}")


seed = bytes(range(32))
seed_hex = seed.hex()
true_pub = ed25519.publickey(seed).hex()

spaced = seed_hex[:20] + " " + seed_hex[20:]
wrapped = seed_hex[:32] + "\n" + seed_hex[32:]
tabbed = seed_hex[:10] + "\t" + seed_hex[10:]
spaced64 = seed_hex[:20] + " " + seed_hex[20:63]  # 64 chars, 31-byte decode

check("valid seed -> true pub",
      hold_open._name_pub_from_priv(seed_hex) == true_pub)
check("uppercase seed -> same pub",
      hold_open._name_pub_from_priv(seed_hex.upper()) == true_pub)
check("inserted-space 65-char true-decode seed -> None",
      hold_open._name_pub_from_priv(spaced) is None)
check("line-wrapped 65-char true-decode seed -> None",
      hold_open._name_pub_from_priv(wrapped) is None)
check("tabbed 65-char true-decode seed -> None",
      hold_open._name_pub_from_priv(tabbed) is None)
check("spaced 64-char 31-byte-decode seed -> None",
      hold_open._name_pub_from_priv(spaced64) is None)
check("short seed -> None",
      hold_open._name_pub_from_priv(seed_hex[:40]) is None)
check("non-hex seed -> None",
      hold_open._name_pub_from_priv("z" * 64) is None)
check("non-str seed -> None",
      hold_open._name_pub_from_priv(None) is None)

print(f"--- {CASES['passed']} passed, {CASES['failed']} failed")
sys.exit(1 if CASES["failed"] else 0)
