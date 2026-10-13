#!/usr/bin/env python3
"""verify_name.verify() pin-shape belt: a non-string pin must come back
as a refusal reason, never an AttributeError from .strip() (verify()'s
contract is reason-or-None; the CLI always passes strings, but the
library seat is the anyone-can-verify surface of primitive 1)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import verify_name  # noqa: E402

BINDING = {
    "name": "foo",
    "node_pubkey": "ab" * 32,
    "issued_at": "2026-01-01T00:00:00Z",
    "expires_at": "2027-01-01T00:00:00Z",
    "signature": "cd" * 64,
}

fails = 0
for pin in (123, 1.5, True, b"foo", ["foo"]):
    for kw in ("expect_name", "expect_pubkey"):
        try:
            reason = verify_name.verify(BINDING, **{kw: pin})
        except Exception as e:  # noqa: BLE001
            print(f"FAIL: {kw}={pin!r} raised {type(e).__name__}: {e}")
            fails += 1
            continue
        if not (isinstance(reason, str) and "not a string" in reason):
            print(f"FAIL: {kw}={pin!r} -> {reason!r}")
            fails += 1

# A well-formed string pin still reaches the real verdict path.
reason = verify_name.verify(BINDING, expect_name="bar")
if not (isinstance(reason, str) and "not the expected" in reason):
    print(f"FAIL: string pin verdict changed: {reason!r}")
    fails += 1

if fails:
    print(f"test_verify_name: {fails} FAIL")
    sys.exit(1)
print("test_verify_name: OK")
