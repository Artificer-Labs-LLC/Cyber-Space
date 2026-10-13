#!/usr/bin/env python3
"""Belt: core._reach_build refuses a hex string whose DECODE is not
32 bytes (primitives 1 naming + 3 hosting + 4 identity).

_reach_build derived the name pubkey and gated the relay pubkey on
STRING length only, but bytes.fromhex ignores embedded spaces: a
64-char spaced name seed decoded to 31 bytes and publickey() silently
derived a pubkey that is NOT the name's key — the descriptor minted
under it verifies True at its own seat (self-consistent wrong key),
but no binding seat keys the name to it, so the hoster's reach reads
as absent everywhere; a spaced relay pubkey rode into the signed
descriptor verbatim, a strategy every dialer refuses since 81af8fa.
Decoded-length gates at both seats (twin of hold_open 17387df and
rendezvous 5f37a3e): a non-32-byte name-seed decode -> build None;
a non-32-byte relay-pub decode -> relay strategy omitted, valid
strategies still advertised.

Covers: valid priv -> true pub + verifying descriptor (control);
uppercase priv -> same pub (control); spaced priv -> None; short /
non-hex priv -> None (as before); valid relay pub -> relay strategy
(control); spaced relay pub -> relay strategy omitted, direct kept.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/reach-build-decode-length-belt-test.py
"""
import os
import sys
import tempfile

os.environ["CYBERNET_DB_DIR"] = tempfile.mkdtemp(prefix="reach-build-len-")
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
SPACED_PRIV = PRIV[:10] + "  " + PRIV[12:]  # 64 chars, 31-byte decode
RELAY_PUB = "ef" * 32
SPACED_RELAY = RELAY_PUB[:10] + "  " + RELAY_PUB[12:]

_b = core._reach_build("alice", PRIV)
check("valid priv -> true pub (control)", _b is not None and _b[1] == TRUE_PUB)
check("valid priv -> descriptor verifies (control)",
      _b is not None and core._reach_descriptor_verify(_b[0]) is True)
_b = core._reach_build("alice", PRIV.upper())
check("uppercase priv -> same pub (control)", _b is not None and _b[1] == TRUE_PUB)

check("spaced priv -> build None (not a wrong key)",
      core._reach_build("alice", SPACED_PRIV) is None,
      f"got {core._reach_build('alice', SPACED_PRIV)!r}")
for label, bad in (("short", "ab" * 16), ("non-hex", "zz" * 32)):
    check(f"{label} priv -> build None",
          core._reach_build("alice", bad) is None)

os.environ["CYBERNET_RELAY_URL"] = "http://127.0.0.1:9998"
os.environ["CYBERNET_RELAY_TOKEN"] = "tok123"
os.environ["CYBERNET_RELAY_PUBKEY"] = RELAY_PUB
_b = core._reach_build("alice", PRIV)
_relays = [s for s in _b[0]["reach"] if s.get("kind") == "relay"] if _b else []
check("valid relay pub -> relay strategy (control)",
      len(_relays) == 1 and _relays[0]["relay"] == RELAY_PUB)

os.environ["CYBERNET_RELAY_PUBKEY"] = SPACED_RELAY
_b = core._reach_build("alice", PRIV)
_kinds = [s.get("kind") for s in _b[0]["reach"]] if _b else []
check("spaced relay pub -> relay strategy omitted, direct kept",
      _b is not None and "relay" not in _kinds and "direct" in _kinds,
      f"kinds={_kinds!r}")

print(f"\n{CASES['passed']} passed, {CASES['failed']} failed")
sys.exit(1 if CASES["failed"] else 0)
