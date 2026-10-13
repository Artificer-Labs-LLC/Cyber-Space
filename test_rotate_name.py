#!/usr/bin/env python3
"""rotate_name.mint_rotation() argument-shape belt: every refused input
must come back as ValueError, never an AttributeError/TypeError from
.strip()/len()/.encode() inside (mint_rotation's contract is ValueError;
the CLI always passes validated values, but the library seat is the
anyone-can-rotate surface of primitive 4, identity). An explicit
issued_at must also be canonical — a record minted over a non-canonical
stamp is one verify_rotation itself refuses, a rotation no seat accepts.
"""
import os
import secrets
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rotate_name  # noqa: E402
from fed.ed25519 import publickey  # noqa: E402

SK = secrets.token_bytes(32)
PK = publickey(secrets.token_bytes(32)).hex()
GOOD_TS = "2026-01-01T00:00:00Z"

fails = 0


def _refused(label, priv, pub, issued, why):
    global fails
    try:
        rec = rotate_name.mint_rotation(label, priv, pub, issued_at=issued)
    except ValueError:
        return
    except Exception as e:  # noqa: BLE001
        print(f"FAIL: {why} raised {type(e).__name__}: {e}")
        fails += 1
        return
    print(f"FAIL: {why} minted {rec!r}")
    fails += 1


for bad in (123, 1.5, True, b"foo", ["foo"], None):
    _refused(bad, SK, PK, GOOD_TS, f"label={bad!r}")
for bad in (None, 123, "x" * 32, [b"x" * 32], b"short", b"x" * 33):
    _refused("foo", bad, PK, GOOD_TS, f"old_priv={bad!r}")
for bad in (123, 1.5, True, b"x" * 64, ["x"], None):
    _refused("foo", SK, bad, GOOD_TS, f"new_pubkey={bad!r}")
for bad in (123, 1.5, True, b"2026-01-01T00:00:00Z", ["x"]):
    _refused("foo", SK, PK, bad, f"issued_at={bad!r}")
for bad in ("garbage", "2026-01-01 00:00:00", "2026-01-01",
            "2026-01-01T00:00:00", "2026-13-01T00:00:00Z"):
    _refused("foo", SK, PK, bad, f"issued_at={bad!r}")

# A well-formed mint still mints and self-verifies, explicit stamp or not.
for issued in (GOOD_TS, None, ""):
    rec = rotate_name.mint_rotation("foo", SK, PK, issued_at=issued)
    reason = rotate_name.verify_rotation(rec)
    if issued == GOOD_TS and reason is not None:
        print(f"FAIL: valid mint no longer verifies: {reason!r}")
        fails += 1
    if issued != GOOD_TS and rec["issued_at"] == "":
        print(f"FAIL: default issued_at mint changed: {rec!r}")
        fails += 1
# A bytearray seed is the same seed, not a refusal.
rec = rotate_name.mint_rotation("foo", bytearray(SK), PK, issued_at=GOOD_TS)
if rec["old_pubkey"] != publickey(SK).hex():
    print(f"FAIL: bytearray seed mint changed: {rec!r}")
    fails += 1

# _valid_label is a bool predicate: a non-string must come back False,
# never a TypeError/AttributeError (twin of the mint_name belt).
for bad in (123, 1.5, True, b"foo", ["foo"], None):
    try:
        got = rotate_name._valid_label(bad)
    except Exception as e:  # noqa: BLE001
        print(f"FAIL: _valid_label({bad!r}) raised {type(e).__name__}: {e}")
        fails += 1
        continue
    if got is not False:
        print(f"FAIL: _valid_label({bad!r}) -> {got!r}, want False")
        fails += 1
if rotate_name._valid_label("foo-bar1") is not True:
    print("FAIL: _valid_label('foo-bar1') no longer True")
    fails += 1
for bad in ("", "Foo", "a.b", "-a", "a-", "a" * 64):
    if rotate_name._valid_label(bad) is not False:
        print(f"FAIL: _valid_label({bad!r}) no longer False")
        fails += 1

# _parse_canonical_ts contract is ValueError on any non-canonical input:
# a non-string stamp from a stored/JSON record must refuse as ValueError,
# never leak TypeError from re.match.
for bad in (123, 1.5, True, b"2026-01-01T00:00:00Z", ["x"], {"a": 1}, None):
    try:
        rotate_name._parse_canonical_ts(bad)
    except ValueError:
        continue
    except Exception as e:  # noqa: BLE001
        print(f"FAIL: _parse_canonical_ts({bad!r}) raised {type(e).__name__}, want ValueError")
        fails += 1
        continue
    print(f"FAIL: _parse_canonical_ts({bad!r}) did not raise")
    fails += 1
if rotate_name._parse_canonical_ts("2026-01-01T00:00:00Z").year != 2026:
    print("FAIL: _parse_canonical_ts canonical Z no longer parses")
    fails += 1

if fails:
    print(f"test_rotate_name: {fails} FAIL")
    sys.exit(1)
print("test_rotate_name: OK")
