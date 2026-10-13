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

if fails:
    print(f"test_resolve_chain: {fails} FAIL")
    sys.exit(1)
print("test_resolve_chain: OK")
