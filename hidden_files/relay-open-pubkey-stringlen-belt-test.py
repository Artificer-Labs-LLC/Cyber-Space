#!/usr/bin/env python3
"""Belt: _relay_open_session refuses a NAME PUBKEY whose string length
is not 64 even when its decode is the true key (primitives 1 naming +
3 hosting).

_relay_open_session (core.py) string-gated the relay's challenge (64)
and name_key_sig (128) spellings but handed node_pubkey to checkvalid
ungated, and bytes.fromhex ignores embedded whitespace, so a 65-char
inserted-space (or line-wrapped, or tabbed) pubkey decoded to the TRUE
32 bytes and the genuine name-key signature VERIFIED — live-proof
accepted under a second spelling of the name key, a spelling every
binding seat refuses on sight (len(node_pubkey) != 64 at resolve step
2, dial step 3, _name_binding_verify). String-length (64) + decoded-
length (32) gates at the seat, twin of _name_binding_verify's helper
gate; valid + uppercase pubkeys verify byte-exact, and the production
caller (resolve step 6) passes the step-2-gated key so no live path
changes.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/relay-open-pubkey-stringlen-belt-test.py
"""
import json
import os
import secrets
import sys
import tempfile

TMP = tempfile.mkdtemp(prefix="relay-open-publen-")
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
OTHER_PRIV = secrets.token_hex(32)
OTHER_PUB = _fed_ed25519.publickey(bytes.fromhex(OTHER_PRIV)).hex()
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
_HOLDER["p"] = {"challenge": CHAL, "name_key_sig": SIG}


def open_with(pub):
    return core._relay_open_session(RELAY, "someone", pub, "tok")


check("valid proof verifies", open_with(NAME_PUB) is True)
check("uppercase pubkey verifies", open_with(NAME_PUB.upper()) is True)

# True-decode spellings: 65 chars, decode to the TRUE 32 bytes — the
# genuine signature verified before the gate.
spaced = NAME_PUB[:32] + " " + NAME_PUB[32:]
assert len(spaced) == 65 and bytes.fromhex(spaced) == bytes.fromhex(NAME_PUB)
check("spaced 65-char pubkey refused", open_with(spaced) is False)

wrapped = NAME_PUB[:32] + "\n" + NAME_PUB[32:]
assert len(wrapped) == 65 and bytes.fromhex(wrapped) == bytes.fromhex(NAME_PUB)
check("wrapped 65-char pubkey refused", open_with(wrapped) is False)

tabbed = NAME_PUB[:32] + "\t" + NAME_PUB[32:]
assert len(tabbed) == 65 and bytes.fromhex(tabbed) == bytes.fromhex(NAME_PUB)
check("tabbed 65-char pubkey refused", open_with(tabbed) is False)

padded = NAME_PUB + " "
assert len(padded) == 65 and bytes.fromhex(padded) == bytes.fromhex(NAME_PUB)
check("outer-padded 65-char pubkey refused", open_with(padded) is False)

# 64-char spaced spelling: decodes to 31 bytes — not the name key at
# all (decoded-length half of the gate).
short = NAME_PUB[:62] + "  "
assert len(short) == 64 and len(bytes.fromhex(short)) == 31
check("spaced 64-char pubkey (31-byte decode) refused",
      open_with(short) is False)

# Controls: a different well-formed key and a non-string key refuse.
check("wrong key refused", open_with(OTHER_PUB) is False)
check("non-string pubkey refused", open_with(123) is False)
check("empty pubkey refused", open_with("") is False)

print(f"{CASES['passed']}/{CASES['passed'] + CASES['failed']} passed")
sys.exit(1 if CASES["failed"] else 0)
