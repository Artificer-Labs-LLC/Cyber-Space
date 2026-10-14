#!/usr/bin/env python3
"""Belt: core._reach_build refuses a name seed whose STRING length is
not 64 even when its decode is the true 32 bytes (primitives 1 naming
+ 3 hosting + 4 identity).

_reach_build gated only the DECODED length of name_priv_hex, and
bytes.fromhex ignores embedded whitespace: a 65-char inserted-space (or
line-wrapped, or tabbed) seed decoded to the TRUE 32 bytes and derived
the true pubkey -- then the seed went VERBATIM into _reach_mint, which
since 07d9447 string-gates and RAISES ValueError. The exception escaped
_reach_build entirely, breaking its documented fail-closed contract
(no honest reach -> None, never a raise): a caller without a guard
(_reach_out) died on a spelling every sibling seat refuses quietly --
resolver/host._config string-gates the hostd seed at exactly 64 chars,
hold_open._sign_challenge refuses len != 64, fed make_envelope
(5cb3d5b) string-gates its seed. Its own relay-pub seat in the same
function already string-gates (len != 64). String-length (64) gate at
the seed seat, twin of _reach_mint (07d9447) and fed make_envelope
(5cb3d5b); valid + uppercase seeds build byte-exact, and the true-
decode spellings return None like every other refused seed.
Production callers strip their env/config seeds before this seat, so
no live path changes.

Covers: valid priv -> true pub + verifying descriptor (control);
uppercase priv -> same pub (control); inserted-space / line-wrapped /
tabbed 65-char true-decode privs -> build None; spaced 64-char
31-byte-decode priv -> None (as before); short / non-hex priv -> None
(as before).

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/reach-build-stringlen-belt-test.py
"""
import os
import sys
import tempfile

os.environ["CYBERNET_DB_DIR"] = tempfile.mkdtemp(prefix="reach-build-strlen-")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core  # noqa: E402
from fed import ed25519  # noqa: E402

CASES = {"passed": 0, "failed": 0}


def check(name, cond, extra=""):
    if cond:
        CASES["passed"] += 1
        print(f"  ok  {name}")
    else:
        CASES["failed"] += 1
        print(f"  FAIL {name} {extra}")


_real_gate = core._reject_nonpublic_node_url


def _test_gate(url):
    if url.startswith("http://127.0.0.1:"):
        return "127.0.0.1"
    return _real_gate(url)


core._reject_nonpublic_node_url = _test_gate
os.environ["CYBERNET_PUBLIC_URL"] = "http://127.0.0.1:9999"
for _k in ("CYBERNET_RELAY_URL", "CYBERNET_RELAY_PUBKEY",
           "CYBERNET_RELAY_TOKEN", "CYBERNET_RENDEZVOUS"):
    os.environ.pop(_k, None)

PRIV = "ab" * 32
TRUE_PUB = ed25519.publickey(bytes.fromhex(PRIV)).hex()
SPACE_PRIV = PRIV[:32] + " " + PRIV[32:]
WRAP_PRIV = PRIV[:32] + "\n" + PRIV[32:]
TAB_PRIV = PRIV[:32] + "\t" + PRIV[32:]
SHORT_DECODE = PRIV[:10] + "  " + PRIV[12:]  # 64 chars, 31-byte decode
for s in (SPACE_PRIV, WRAP_PRIV, TAB_PRIV):
    assert len(s) == 65 and bytes.fromhex(s) == bytes.fromhex(PRIV)

_b = core._reach_build("alice", PRIV)
check("valid priv -> true pub (control)", _b is not None and _b[1] == TRUE_PUB)
check("valid priv -> descriptor verifies (control)",
      _b is not None and core._reach_descriptor_verify(_b[0]) is True)
_b = core._reach_build("alice", PRIV.upper())
check("uppercase priv -> same pub (control)", _b is not None and _b[1] == TRUE_PUB)

for label, bad in (("inserted-space", SPACE_PRIV), ("line-wrapped", WRAP_PRIV),
                   ("tabbed", TAB_PRIV)):
    check(f"{label} 65-char true-decode priv -> build None",
          core._reach_build("alice", bad) is None,
          f"got {core._reach_build('alice', bad)!r}")
check("spaced 64-char 31-byte-decode priv -> build None (as before)",
      core._reach_build("alice", SHORT_DECODE) is None)
for label, bad in (("short", "ab" * 16), ("non-hex", "zz" * 32)):
    check(f"{label} priv -> build None (as before)",
          core._reach_build("alice", bad) is None)

print(f"\n{CASES['passed']} passed, {CASES['failed']} failed")
sys.exit(1 if CASES["failed"] else 0)
