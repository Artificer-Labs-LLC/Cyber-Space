#!/usr/bin/env python3
"""Belt: verify_envelope refuses a sig/sender_pub whose STRING length
is not 128/64 even when its decode is the right byte count
(primitives 4 identity + 5 discovery).

verify_envelope (fed/envelope.py) is the one gate every federation
receiver trusts (/fed/ping, /fed/announce, DM relay, channel links),
but it carried NO length gate at all before checkvalid, and
bytes.fromhex ignores embedded spaces — so a 129-char signature with
an inserted space decoded to the TRUE 64 bytes and the envelope
VERIFIED, and a 65-char sender_pub with an inserted space decoded to
the true 32-byte key and verified too. Neither field is part of the
signed canonical form as a STRING, yet downstream receivers use
env["sender_pub"] as the identity string (rate-limit keys, row-owner
comparisons, writes) — a spaced spelling is a second identity for the
same key, and a spelling every binding seat refuses on sight
(len(signature) != 128). Twin of verify_rotation 3fbb38b and
_reach_descriptor_verify 93c1a79.

Covers: valid envelope verifies (control); uppercase sig/pub verify
(control); inserted-space 129-char sig refused; outer-padded sig
refused; spaced 128-char sig (63-byte decode) refused; inserted-space
65-char sender_pub refused; spaced 64-char sender_pub (31-byte
decode) refused; non-string sig refused; non-string sender_pub
refused; tampered clean sig refused (control).

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/envelope-verify-stringlen-belt-test.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fed import envelope  # noqa: E402

CASES = {"passed": 0, "failed": 0}


def check(name, cond, extra=""):
    if cond:
        CASES["passed"] += 1
        print(f"  ok  {name}")
    else:
        CASES["failed"] += 1
        print(f"  FAIL {name} {extra}")


SEED = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
from fed import ed25519  # noqa: E402
PUB = ed25519.publickey(bytes.fromhex(SEED)).hex()

ENV = envelope.make_envelope(SEED, PUB, "peer.cyberspace", {"hello": 1})
SIG = ENV["sig"]
SPACED_SIG = SIG[:64] + " " + SIG[64:]          # 129 chars, true 64-byte decode
PADDED_SIG = " " + SIG + " "                    # outer padding, true decode
SPACED_SIG_SAME_LEN = SIG[:10] + " " + SIG[11:]  # 128 chars, 63-byte decode
SPACED_PUB = PUB[:32] + " " + PUB[32:]          # 65 chars, true 32-byte decode
SPACED_PUB_SAME_LEN = PUB[:10] + " " + PUB[11:]  # 64 chars, 31-byte decode
TAMPERED = ("0" if SIG[0] != "0" else "1") + SIG[1:]


def variant(**kw):
    env = dict(ENV)
    env.update(kw)
    return env


check("valid envelope verifies (control)",
      envelope.verify_envelope(dict(ENV)) is True)
check("uppercase sig verifies (control)",
      envelope.verify_envelope(variant(sig=SIG.upper())) is True)
check("uppercase sender_pub verifies (control)",
      envelope.verify_envelope(variant(sender_pub=PUB.upper())) is True)
check("inserted-space 129-char sig refused",
      envelope.verify_envelope(variant(sig=SPACED_SIG)) is False)
check("outer-padded sig refused",
      envelope.verify_envelope(variant(sig=PADDED_SIG)) is False)
check("spaced 128-char sig (63-byte decode) refused",
      envelope.verify_envelope(variant(sig=SPACED_SIG_SAME_LEN)) is False)
check("inserted-space 65-char sender_pub refused",
      envelope.verify_envelope(variant(sender_pub=SPACED_PUB)) is False)
check("spaced 64-char sender_pub (31-byte decode) refused",
      envelope.verify_envelope(variant(sender_pub=SPACED_PUB_SAME_LEN)) is False)
check("non-string sig refused",
      envelope.verify_envelope(variant(sig=123)) is False)
check("non-string sender_pub refused",
      envelope.verify_envelope(variant(sender_pub=[PUB])) is False)
check("tampered clean sig refused (control)",
      envelope.verify_envelope(variant(sig=TAMPERED)) is False)

print(f"\n{CASES['passed']}/{CASES['passed'] + CASES['failed']} passed")
sys.exit(1 if CASES["failed"] else 0)
