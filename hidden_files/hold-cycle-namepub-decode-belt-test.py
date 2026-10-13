#!/usr/bin/env python3
"""Belt: hold_open_cycle refuses an explicit name_pub whose DECODE is
not a 32-byte key (primitives 3 hosting + 4 identity).

hold_open_cycle gated an explicit name_pub_hex on STRING length only
(64 chars, no hex check at all): a spaced 64-char pub (31-byte decode)
or a non-hex 64-char pub passed the gate, suppressed the fallback
derivation from name_priv_hex, and flowed to _rendezvous_hold_maybe —
where rendezvous.derive_points refuses it, so NO rendezvous points
were ever registered: the hoster reads as absent under rendezvous,
silently, though the true pub was derivable from the seed all along.
Gate at the seat (twin of _name_pub_from_priv / rendezvous
_name_pub_bytes): only a 64-char string decoding to exactly 32 bytes
is an explicit name pub; anything else falls back to the derivation.
A well-formed explicit pub (incl. uppercase) is used byte-exact.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/hold-cycle-namepub-decode-belt-test.py
"""
import os
import sys
import threading
import time

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


SEED = "ab" * 32
TRUE_PUB = ed25519.publickey(bytes.fromhex(SEED)).hex()
OTHER_PUB = ed25519.publickey(bytes.fromhex("cd" * 32)).hex()
SPACED_PUB = TRUE_PUB[:10] + "  " + TRUE_PUB[12:]  # 64 chars, 31-byte decode
NONHEX_PUB = "zz" * 32                            # 64 chars, not hex

real_register = hold_open._rendezvous_points_register
real_post = hold_open._post
real_once = hold_open.hold_open_cycle_once


def run_cycle(explicit_pub):
    calls = []
    hold_open._rendezvous_points_register = (
        lambda u, tok, pub, epoch_len=None: calls.append(pub) or 2)
    hold_open._post = lambda u, p, payload, timeout: {"ok": True}
    hold_open.hold_open_cycle_once = lambda u, tok, priv: (True, 0)
    stop = threading.Event()
    kwargs = {"keepalive_every": 0.2}
    if explicit_pub is not _ABSENT:
        kwargs["name_pub_hex"] = explicit_pub
    ct = threading.Thread(
        target=hold_open.hold_open_cycle,
        args=("http://relay.invalid", "tok", SEED, stop),
        kwargs=kwargs, daemon=True)
    try:
        ct.start()
        time.sleep(0.6)
    finally:
        stop.set()
        ct.join(timeout=5)
        hold_open._rendezvous_points_register = real_register
        hold_open._post = real_post
        hold_open.hold_open_cycle_once = real_once
    return calls


_ABSENT = object()

calls = run_cycle(_ABSENT)
check("no explicit pub -> derived true pub (control)",
      calls and all(c == TRUE_PUB for c in calls), f"calls={calls}")
calls = run_cycle(OTHER_PUB)
check("well-formed explicit pub -> used verbatim (control)",
      calls and all(c == OTHER_PUB for c in calls), f"calls={calls}")
calls = run_cycle(TRUE_PUB.upper())
check("uppercase explicit pub -> used byte-exact (control)",
      calls and all(c == TRUE_PUB.upper() for c in calls), f"calls={calls}")
calls = run_cycle(SPACED_PUB)
check("spaced explicit pub -> falls back to derived true pub",
      calls and all(c == TRUE_PUB for c in calls), f"calls={calls}")
calls = run_cycle(NONHEX_PUB)
check("non-hex explicit pub -> falls back to derived true pub",
      calls and all(c == TRUE_PUB for c in calls), f"calls={calls}")
calls = run_cycle("ab" * 16)
check("short explicit pub -> falls back to derived true pub (as before)",
      calls and all(c == TRUE_PUB for c in calls), f"calls={calls}")

print(f"\n{CASES['passed']} passed, {CASES['failed']} failed")
sys.exit(1 if CASES["failed"] else 0)
