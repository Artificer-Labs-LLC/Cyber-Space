#!/usr/bin/env python3
"""Belt: resolver/host.py relay seats refuse a relay pubkey whose
DECODE is not 32 bytes (primitives 1 naming + 3 hosting + 4 identity).

_relay_cfg, _relay_warnings, and _relay_strategy_present gated the
relay pubkey on STRING length only (64 chars + bytes.fromhex parses),
but bytes.fromhex ignores embedded spaces: a spaced 64-char pubkey
decodes to 31 bytes. core._reach_build (31b08ce) refuses exactly that
decode, so before this fix the host seats diverged from core:
_relay_cfg returned a relay config core would never advertise,
_relay_warnings stayed silent on an unusable relay, and
_relay_strategy_present claimed True for a strategy the signed
descriptor omits — the operator believes relay hosting is on while
dialers never see it. Decoded-length gates at all three seats (twin
of core._reach_build / hold_open 17387df / rendezvous 5f37a3e).

Covers: valid pub -> cfg present + silent + strategy True (control);
uppercase pub -> same (control, lowered); spaced pub -> cfg None +
warning + strategy False; short / non-hex pub -> as before.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/host-relay-decode-length-belt-test.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from resolver import host  # noqa: E402

CASES = {"passed": 0, "failed": 0}


def check(name, cond, extra=""):
    if cond:
        CASES["passed"] += 1
        print(f"  ok  {name}")
    else:
        CASES["failed"] += 1
        print(f"  FAIL {name} {extra}")


_KEYS = ("CYBERNET_RELAY_URL", "CYBERNET_RELAY_PUBKEY", "CYBERNET_RELAY_TOKEN")
_SAVED = {k: os.environ.get(k) for k in _KEYS}


def _set(pub):
    os.environ["CYBERNET_RELAY_URL"] = "http://185.143.228.228:8471"
    os.environ["CYBERNET_RELAY_TOKEN"] = "tok"
    if pub is None:
        os.environ.pop("CYBERNET_RELAY_PUBKEY", None)
    else:
        os.environ["CYBERNET_RELAY_PUBKEY"] = pub


try:
    PUB = "ab" * 32
    SPACED = PUB[:10] + "  " + PUB[12:]  # 64 chars, 31-byte decode
    assert len(SPACED) == 64 and len(bytes.fromhex(SPACED)) == 31

    _set(PUB)
    check("valid pub -> cfg present (control)", host._relay_cfg() is not None)
    check("valid pub -> warnings silent (control)", host._relay_warnings() == [])
    check("valid pub -> strategy present (control)",
          host._relay_strategy_present() is True)

    _set(PUB.upper())
    check("uppercase pub -> cfg present (control)", host._relay_cfg() is not None)
    check("uppercase pub -> warnings silent (control)", host._relay_warnings() == [])
    check("uppercase pub -> strategy present (control)",
          host._relay_strategy_present() is True)

    _set(SPACED)
    check("spaced pub -> cfg None", host._relay_cfg() is None,
          f"got {host._relay_cfg()!r}")
    _w = host._relay_warnings()
    check("spaced pub -> warning raised",
          any("CYBERNET_RELAY_PUBKEY" in w for w in _w), f"got {_w!r}")
    check("spaced pub -> warning leaks no value",
          all(SPACED not in w for w in _w))
    check("spaced pub -> strategy absent",
          host._relay_strategy_present() is False)

    _set("ab" * 16)
    check("short pub -> cfg None", host._relay_cfg() is None)
    check("short pub -> strategy absent", host._relay_strategy_present() is False)

    _set("zz" * 32)
    check("non-hex pub -> cfg None", host._relay_cfg() is None)
    check("non-hex pub -> not-hex warning",
          any("not hex" in w for w in host._relay_warnings()))
    check("non-hex pub -> strategy absent", host._relay_strategy_present() is False)
finally:
    for k in _KEYS:
        os.environ.pop(k, None)
        if _SAVED[k] is not None:
            os.environ[k] = _SAVED[k]

print(f"\n{CASES['passed']} passed, {CASES['failed']} failed")
sys.exit(1 if CASES["failed"] else 0)
