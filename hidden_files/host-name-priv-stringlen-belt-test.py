#!/usr/bin/env python3
"""Belt: resolver/host.py name-priv seats refuse a seed whose STRING
length is not 64 even when its decode is 32 bytes (primitives 3 hosting
+ 4 identity + 6 client daemon).

_config and _startup_problems gated CYBERNET_NAME_PRIVKEY only on the
DECODED length (len(bytes.fromhex(priv)) == 32), never the string
length, and bytes.fromhex ignores embedded spaces: a 65-char seed with
an inserted space decoded to the TRUE 32 bytes, so both seats called
the daemon runnable and stayed silent. Downstream the seats split:
core._reach_build and fed make_envelope decode-gate, so the reach
announce minted and signed fine — but hold_open._sign_challenge gates
len(name_priv_hex) != 64, so the relay hold-open could NEVER answer a
challenge. The hoster advertised relay reach, dialers opened sessions,
no answer ever came, and the name read as absent via relay while the
daemon reported healthy. String-length (64) gate at both host seats
(twin of names/rotate c128594 / verify_rotation 3fbb38b): the daemon
now refuses to start, loud, instead of half-hosting.

Covers: valid seed -> runnable + silent (control); uppercase seed ->
same (control, _config lowers); OUTER-padded seed -> stripped, same
(control); inserted-space seed -> not runnable + startup problem
names the var (no value echoed);
64-char double-spaced seed (31-byte decode) -> refused as before;
short / non-hex seeds -> refused as before; the downstream divergence
proof: _sign_challenge refuses the inserted-space seed while
_name_pub_from_priv derives from it.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/host-name-priv-stringlen-belt-test.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import hold_open  # noqa: E402
from resolver import host  # noqa: E402

CASES = {"passed": 0, "failed": 0}


def check(name, cond, extra=""):
    if cond:
        CASES["passed"] += 1
        print(f"  ok  {name}")
    else:
        CASES["failed"] += 1
        print(f"  FAIL {name} {extra}")


_KEYS = ("CYBERNET_HOSTED_NAME", "CYBERNET_NAME_PRIVKEY", "CYBERNET_MIRROR_URL")
_SAVED = {k: os.environ.get(k) for k in _KEYS}


def _set(priv):
    os.environ["CYBERNET_HOSTED_NAME"] = "alice"
    os.environ["CYBERNET_MIRROR_URL"] = "https://8.8.8.8:8471"
    if priv is None:
        os.environ.pop("CYBERNET_NAME_PRIVKEY", None)
    else:
        os.environ["CYBERNET_NAME_PRIVKEY"] = priv


def _problems():
    return [p for p in host._startup_problems()
            if "CYBERNET_NAME_PRIVKEY" in p]


try:
    SEED = "ab" * 32
    INSERTED = SEED[:10] + " " + SEED[10:]          # 65 chars, 32-byte decode
    DOUBLE_SPACED = SEED[:10] + "  " + SEED[12:]     # 64 chars, 31-byte decode
    assert len(SEED) == 64 and len(bytes.fromhex(SEED)) == 32
    assert len(INSERTED) == 65 and len(bytes.fromhex(INSERTED)) == 32
    assert len(DOUBLE_SPACED) == 64 and len(bytes.fromhex(DOUBLE_SPACED)) == 31

    # control: valid seed runnable + silent
    _set(SEED)
    check("valid seed runnable", host._config()[4] is True)
    check("valid seed silent", _problems() == [])

    # control: uppercase seed runnable + silent (_config lowers it)
    _set(SEED.upper())
    check("uppercase seed runnable", host._config()[4] is True)
    check("uppercase seed silent", _problems() == [])

    # control: outer padding is stripped by both seats before any gate
    _set("  " + SEED + "  ")
    check("outer-padded seed runnable (stripped)", host._config()[4] is True)
    check("outer-padded seed silent (stripped)", _problems() == [])

    # the wound: inserted-space seed decodes true yet must refuse
    _set(INSERTED)
    check("inserted-space seed NOT runnable", host._config()[4] is False)
    probs = _problems()
    check("inserted-space seed loud", len(probs) == 1, str(probs))
    check("problem names the var, echoes no value",
          bool(probs) and "CYBERNET_NAME_PRIVKEY" in probs[0]
          and INSERTED not in probs[0] and SEED not in probs[0])

    # downstream divergence proof (unchanged seats): the seed derives a
    # pubkey but can never sign a relay challenge at string length 65
    check("divergence: pub derives from inserted-space seed",
          hold_open._name_pub_from_priv(INSERTED) is not None)
    check("divergence: _sign_challenge refuses inserted-space seed",
          hold_open._sign_challenge("cd" * 32, INSERTED) is None)
    check("control: _sign_challenge signs with valid seed",
          hold_open._sign_challenge("cd" * 32, SEED) is not None)

    # as before: 64-char spaced seed decoding short, short, non-hex
    _set(DOUBLE_SPACED)
    check("double-spaced 31-byte seed NOT runnable", host._config()[4] is False)
    check("double-spaced seed loud", len(_problems()) == 1)
    _set("ab" * 16)
    check("short seed NOT runnable", host._config()[4] is False)
    _set("zz" * 32)
    check("non-hex seed NOT runnable", host._config()[4] is False)
    check("non-hex seed loud (not hex)", any("not hex" in p for p in _problems()))
finally:
    for k, v in _SAVED.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v

print(f"\n{CASES['passed']} passed, {CASES['failed']} failed")
sys.exit(1 if CASES["failed"] else 0)
