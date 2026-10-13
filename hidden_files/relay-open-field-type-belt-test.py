#!/usr/bin/env python3
"""Belt: _relay_open_session refuses a NON-STRING live-proof field
instead of str()-aliasing it (primitives 1 naming + 3 hosting).

_relay_open_session (core.py) is the dial-side live-proof seat: the
relay answers POST /relay/open with {challenge, name_key_sig} and the
dialer verifies the name-key signature over the challenge fail-closed.
It read both fields through str() with no gate: a digit-only challenge
served as a JSON number (int) stringified to its own 64-char hex, and
a genuine name-key signature over that challenge verified — live-proof
ACCEPTED for a challenge nobody ever served in that form, the SAME
alias the binding/descriptor seats refuse on sight. isinstance gate
at the seat: challenge/name_key_sig must be real strings, anything
else reads as silence (False, never raises); valid string proofs
verify byte-exact.

The harness stubs only the transport (core._relay_hold_probe -> None,
the legacy path; core._peer_urlopen -> a canned relay answer) — the
signature check under test is core's REAL Ed25519 verify.

Covers: valid string proof -> True (control); int challenge with a
genuine signature over the aliased bytes -> False (alias refused);
int sig -> False; bool challenge -> False; missing fields -> False.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/relay-open-field-type-belt-test.py
"""
import json
import os
import secrets
import sys
import tempfile

TMP = tempfile.mkdtemp(prefix="relay-open-belt-")
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
CHALLENGE = "1" * 64  # digit-only 64-hex: str(int(...)) == itself
SIG = _fed_ed25519.sign(bytes.fromhex(CHALLENGE), bytes.fromhex(NAME_PRIV),
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
    return core._relay_open_session(RELAY, "somewhere", NAME_PUB, "tok-abc")


check("valid string proof -> True (control)",
      open_with({"challenge": CHALLENGE, "name_key_sig": SIG}) is True)

check("int challenge -> refused, no live-proof (alias)",
      open_with({"challenge": int(CHALLENGE), "name_key_sig": SIG}) is False)

check("int sig -> refused, no live-proof",
      open_with({"challenge": CHALLENGE,
                 "name_key_sig": int("2" * 128)}) is False)

check("bool challenge -> refused, no live-proof",
      open_with({"challenge": True, "name_key_sig": SIG}) is False)

check("missing fields -> refused, no live-proof",
      open_with({}) is False)

print(f"\n{CASES['passed']}/{CASES['passed'] + CASES['failed']} passed")
sys.exit(1 if CASES["failed"] else 0)
