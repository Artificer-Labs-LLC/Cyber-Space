#!/usr/bin/env python3
"""Belt: _relay_open_session refuses a live-proof CHALLENGE whose
decoded length is not 32 bytes (primitives 1 naming + 3 hosting).

_relay_open_session (core.py) gated only the STRING lengths of the
relay's {challenge, name_key_sig} answer (64/128 chars) before handing
bytes.fromhex(challenge) to checkvalid as the signed message.
bytes.fromhex ignores embedded spaces, so a 64-char challenge with two
spaces decoded to 31 bytes and a genuine name-key signature over those
31 bytes VERIFIED — live-proof accepted for a challenge that is not
the 32-byte challenge any relay serves (twin of verify_name /
_name_binding_verify decoded-length gates; checkvalid gates the sig
and pubkey lengths, never the message's). Decoded-length gate at the
seat: challenge must decode to exactly 32 bytes, sig to exactly 64;
valid and uppercase proofs verify byte-exact.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/relay-open-challenge-declen-belt-test.py
"""
import json
import os
import secrets
import sys
import tempfile

TMP = tempfile.mkdtemp(prefix="relay-open-declen-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core  # noqa: E402
from fed import ed25519 as _fed_ed25519  # noqa: E402

CASES = {"passed": 0, "failed": 0}


def check(name, cond, extra=""):
    if cond:
        CASES["passed"] += 1
        print(f"  ok  {name}")
    else:
        CASES["failed"] += 1
        print(f"  FAIL {name} {extra}")


NAME_PRIV = secrets.token_hex(32)
NAME_PUB = _fed_ed25519.publickey(bytes.fromhex(NAME_PRIV)).hex()
CHAL = secrets.token_hex(32)
SIG = _fed_ed25519.sign(bytes.fromhex(CHAL), bytes.fromhex(NAME_PRIV),
                        bytes.fromhex(NAME_PUB)).hex()
RELAY = "http://8.8.8.8:8443"
_HOLDER = {}


class _FakeResp:
    def __init__(self, payload):
        self.status = 200
        self._raw = json.dumps(payload).encode()

    def read(self, n=-1):
        return self._raw if n < 0 else self._raw[:n]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


core._relay_hold_probe = lambda *a, **k: None  # legacy session-open path
core._peer_urlopen = lambda req, timeout=8: _FakeResp(_HOLDER["p"])


def open_with(payload):
    _HOLDER["p"] = payload
    return core._relay_open_session(RELAY, "someone", NAME_PUB, "tok")


check("valid proof verifies", open_with(
    {"challenge": CHAL, "name_key_sig": SIG}) is True)
check("uppercase challenge verifies", open_with(
    {"challenge": CHAL.upper(), "name_key_sig": SIG}) is True)

# Spaced challenge: 62 hex chars + 2 spaces = 64 chars, decodes to the
# 31 bytes formed by the first 62 hex chars; sign THOSE bytes genuinely.
spaced = CHAL[:62] + "  "
spaced_bytes = bytes.fromhex(spaced)
assert len(spaced) == 64 and len(spaced_bytes) == 31
spaced_sig = _fed_ed25519.sign(spaced_bytes, bytes.fromhex(NAME_PRIV),
                               bytes.fromhex(NAME_PUB)).hex()
check("spaced 64-char challenge (31-byte decode) refused", open_with(
    {"challenge": spaced, "name_key_sig": spaced_sig}) is False)

# Padded challenge: 64 true hex chars + trailing space is 65 chars and
# already dies at the string gate; a leading-space 64-char string drops
# one hex char and decodes to 31 bytes too.
lead = "  " + CHAL[:62]
lead_bytes = bytes.fromhex(lead)
assert len(lead) == 64 and len(lead_bytes) == 31
lead_sig = _fed_ed25519.sign(lead_bytes, bytes.fromhex(NAME_PRIV),
                             bytes.fromhex(NAME_PUB)).hex()
check("leading-space challenge (31-byte decode) refused", open_with(
    {"challenge": lead, "name_key_sig": lead_sig}) is False)

# Spaced sig over the true challenge: decodes to 63 bytes (control —
# checkvalid's own length gate already refused this; seat must too).
spaced_sig2 = SIG[:126] + "  "
assert len(spaced_sig2) == 128 and len(bytes.fromhex(spaced_sig2)) == 63
check("spaced sig refused", open_with(
    {"challenge": CHAL, "name_key_sig": spaced_sig2}) is False)

print(f"{CASES['passed']}/{CASES['passed'] + CASES['failed']} passed")
sys.exit(1 if CASES["failed"] else 0)
