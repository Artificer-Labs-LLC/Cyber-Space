#!/usr/bin/env python3
"""resolve_chain.walk() argument-shape belt: a non-string queried name
or pinned original key must come back as ChainError, never an
AttributeError from .strip() (walk()'s contract is ChainError; the CLI
always passes strings, but the library seat is the chain-following
surface of primitive 4, identity)."""
import os
import secrets
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import resolve_chain  # noqa: E402
import rotate_name  # noqa: E402
from fed.ed25519 import publickey  # noqa: E402

SK_A = secrets.token_bytes(32)
PK_A = publickey(SK_A).hex()
PK_B = publickey(secrets.token_bytes(32)).hex()
REC = rotate_name.mint_rotation("foo", SK_A, PK_B,
                                issued_at="2026-01-01T00:00:00Z")
DOC = {"name": "foo", "rotations": [REC]}

fails = 0
for bad in (123, 1.5, True, b"foo", ["foo"], None):
    try:
        resolve_chain.walk(DOC, bad)
        print(f"FAIL: name={bad!r} walked")
        fails += 1
    except resolve_chain.ChainError as e:
        if "not a string" not in str(e):
            print(f"FAIL: name={bad!r} -> ChainError {e!r}")
            fails += 1
    except Exception as e:  # noqa: BLE001
        print(f"FAIL: name={bad!r} raised {type(e).__name__}: {e}")
        fails += 1

for bad in (123, 1.5, True, b"x", ["x"]):
    try:
        resolve_chain.walk(DOC, "foo", bad)
        print(f"FAIL: pin={bad!r} walked")
        fails += 1
    except resolve_chain.ChainError as e:
        if "not a string" not in str(e):
            print(f"FAIL: pin={bad!r} -> ChainError {e!r}")
            fails += 1
    except Exception as e:  # noqa: BLE001
        print(f"FAIL: pin={bad!r} raised {type(e).__name__}: {e}")
        fails += 1

# A well-formed walk still walks, with and without the pin.
terminal, hops = resolve_chain.walk(DOC, "foo", PK_A)
if terminal != PK_B.lower() or len(hops) != 1:
    print(f"FAIL: valid walk changed: {terminal!r} {hops!r}")
    fails += 1
terminal2, _ = resolve_chain.walk(DOC, "foo")
if terminal2 != PK_B.lower():
    print(f"FAIL: unpinned walk changed: {terminal2!r}")
    fails += 1

# check_live()'s twin gate: non-string name/mirror/terminal key must
# come back as ChainError before any fetch, never AttributeError/
# TypeError. Fetch and binding verification are stubbed (no network);
# the gate must fire with the stub untouched.
_fetch_calls = []
resolve_chain._fetch = lambda url: _fetch_calls.append(url) or {  # noqa: E731
    "node_pubkey": PK_B, "issued_at": "2026-01-01T00:00:00Z"}
resolve_chain.verify_binding = lambda b: None  # noqa: E731
for label, args in (
        ("name", (123, "http://x:1", PK_B)),
        ("name", (None, "http://x:1", PK_B)),
        ("mirror", ("foo", 123, PK_B)),
        ("mirror", ("foo", None, PK_B)),
        ("terminal", ("foo", "http://x:1", 123)),
        ("terminal", ("foo", "http://x:1", None)),
        ("terminal", ("foo", "http://x:1", b"x"))):
    try:
        resolve_chain.check_live(*args)
        print(f"FAIL: check_live {label}={args!r} returned")
        fails += 1
    except resolve_chain.ChainError as e:
        if "not a string" not in str(e):
            print(f"FAIL: check_live {args!r} -> ChainError {e!r}")
            fails += 1
    except Exception as e:  # noqa: BLE001
        print(f"FAIL: check_live {args!r} raised {type(e).__name__}: {e}")
        fails += 1
if _fetch_calls:
    print(f"FAIL: check_live gate fetched anyway: {_fetch_calls!r}")
    fails += 1
verdict = resolve_chain.check_live("foo", "http://x:1", PK_B)
if "terminal key" not in verdict:
    print(f"FAIL: valid check_live changed: {verdict!r}")
    fails += 1

# _label rides verify_name._normalize_expected: a non-string name must
# read as the "" no-name sentinel, never AttributeError from .strip()
# or a bytes alias compared against str names downstream.
for bad in (123, 1.5, True, b"Foo", ["Foo"], {"a": 1}, None):
    try:
        got = resolve_chain._label(bad)
    except Exception as e:  # noqa: BLE001
        print(f"FAIL: _label({bad!r}) raised {type(e).__name__}: {e}")
        fails += 1
        continue
    if got != "":
        print(f"FAIL: _label({bad!r}) -> {got!r}, want ''")
        fails += 1
if resolve_chain._label("  Foo-Bar ") != "foo-bar":
    print("FAIL: _label valid value changed")
    fails += 1

# Regression-note belt: hops compare PARSED instants, never strings.
# A canonical stamp has two spellings for one instant ("...Z" vs
# "...+00:00"); string order puts "+00:00" first, so a same-instant
# second hop read as regressed in one spelling order only. Both
# orders must read as a tie (no note), and a true 1s regression must
# still be noted in either spelling.
_SK_B2 = secrets.token_bytes(32)
_PK_B2 = publickey(_SK_B2).hex()
_PK_C2 = publickey(secrets.token_bytes(32)).hex()
for first, second, want_note in (
        ("2026-01-01T00:00:00Z", "2026-01-01T00:00:00+00:00", False),
        ("2026-01-01T00:00:00+00:00", "2026-01-01T00:00:00Z", False),
        ("2026-01-01T00:00:02Z", "2026-01-01T00:00:01+00:00", True),
        ("2026-01-01T00:00:02+00:00", "2026-01-01T00:00:01Z", True),
        ("2026-01-01T00:00:00Z", "2026-01-01T00:00:01+00:00", False)):
    _r0 = rotate_name.mint_rotation("foo", SK_A, _PK_B2, issued_at=first)
    _r1 = rotate_name.mint_rotation("foo", _SK_B2, _PK_C2,
                                    issued_at=second)
    _, _hops = resolve_chain.walk(
        {"name": "foo", "rotations": [_r0, _r1]}, "foo")
    _noted = bool(_hops[1]["note"])
    if _noted != want_note:
        print(f"FAIL: regression note {first!r} -> {second!r}: "
              f"noted={_noted}, want {want_note}")
        fails += 1

if fails:
    print(f"test_resolve_chain: {fails} FAIL")
    sys.exit(1)
print("test_resolve_chain: OK")
