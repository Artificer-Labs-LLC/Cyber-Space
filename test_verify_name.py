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

# _valid_label is a bool predicate: a non-string must come back False,
# never a TypeError/AttributeError (twin of the mint_name belt).
for bad in (123, 1.5, True, b"foo", ["foo"], None):
    try:
        got = verify_name._valid_label(bad)
    except Exception as e:  # noqa: BLE001
        print(f"FAIL: _valid_label({bad!r}) raised {type(e).__name__}: {e}")
        fails += 1
        continue
    if got is not False:
        print(f"FAIL: _valid_label({bad!r}) -> {got!r}, want False")
        fails += 1
if verify_name._valid_label("foo-bar1") is not True:
    print("FAIL: _valid_label('foo-bar1') no longer True")
    fails += 1
for bad in ("", "Foo", "a.b", "-a", "a-", "a" * 64):
    if verify_name._valid_label(bad) is not False:
        print(f"FAIL: _valid_label({bad!r}) no longer False")
        fails += 1

# _parse_ts contract is ValueError on any unparseable input (its only
# caller guards ValueError alone): a non-string stamp from a binding JSON
# must refuse as ValueError, never leak TypeError from re.match.
for bad in (123, 1.5, True, b"2026-01-01T00:00:00Z", ["x"], {"a": 1}, None):
    try:
        verify_name._parse_ts(bad, "issued_at")
    except ValueError:
        continue
    except Exception as e:  # noqa: BLE001
        print(f"FAIL: _parse_ts({bad!r}) raised {type(e).__name__}, want ValueError")
        fails += 1
        continue
    print(f"FAIL: _parse_ts({bad!r}) did not raise")
    fails += 1
if verify_name._parse_ts("2026-01-01T00:00:00Z", "issued_at").year != 2026:
    print("FAIL: _parse_ts canonical Z no longer parses")
    fails += 1

# _normalize_expected is the shared normalizer every pin/binding field
# passes through: a non-string must come back as the "" no-value
# sentinel, never AttributeError from .strip() — and never bytes,
# which bytes' own .strip()/.lower() aliased through as a bytes value
# compared against str downstream.
for bad in (123, 1.5, True, b"Foo", ["Foo"], {"a": 1}, None):
    try:
        got = verify_name._normalize_expected(bad)
    except Exception as e:  # noqa: BLE001
        print(f"FAIL: _normalize_expected({bad!r}) raised {type(e).__name__}: {e}")
        fails += 1
        continue
    if got != "":
        print(f"FAIL: _normalize_expected({bad!r}) -> {got!r}, want ''")
        fails += 1
if verify_name._normalize_expected("  Foo-Bar ") != "foo-bar":
    print("FAIL: _normalize_expected valid value changed")
    fails += 1

# _claim_payload is the byte-for-byte twin of core._name_claim_payload:
# a non-string field in any position must refuse as ValueError, never
# AttributeError from .encode()/.lower(); valid bytes stay exact.
_good = ("foo", "ab" * 32, "2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z")
if verify_name._claim_payload(*_good) != (
        b"name-claim|foo|" + b"ab" * 32
        + b"|2026-01-01T00:00:00Z|2027-01-01T00:00:00Z"):
    print("FAIL: _claim_payload valid bytes changed")
    fails += 1
for _i in range(4):
    for _bad in (123, 1.5, True, None, b"foo", ["foo"]):
        _args = list(_good)
        _args[_i] = _bad
        try:
            verify_name._claim_payload(*_args)
        except ValueError:
            continue
        except Exception as e:  # noqa: BLE001
            print(f"FAIL: _claim_payload field{_i} {_bad!r} raised {type(e).__name__}")
            fails += 1
            continue
        print(f"FAIL: _claim_payload field{_i} {_bad!r} built instead of ValueError")
        fails += 1

if fails:
    print(f"test_verify_name: {fails} FAIL")
    sys.exit(1)
print("test_verify_name: OK")
