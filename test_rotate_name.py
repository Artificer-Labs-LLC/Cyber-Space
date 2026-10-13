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

# promote/submit promise (False, reason) — never raises on input: a
# non-string label must refuse in-contract, not leak AttributeError
# from _normalize, and a non-int expiry_days must refuse, not leak
# TypeError (or alias True to 1 day).
import tempfile
from pathlib import Path as _Path
_home = _Path(tempfile.mkdtemp())
for bad in (123, 1.5, True, ["foo"], {"a": 1}, None):
    for fn, args in ((rotate_name.promote_rotation, (bad, _home)),
                     (rotate_name.submit_rotation,
                      (bad, "http://127.0.0.1:8471", _home))):
        try:
            ok, _msg = fn(*args)
        except Exception as e:  # noqa: BLE001
            print(f"FAIL: {fn.__name__}({bad!r}) raised {type(e).__name__}: {e}")
            fails += 1
            continue
        if ok is not False:
            print(f"FAIL: {fn.__name__}({bad!r}) -> ok={ok!r}, want False")
            fails += 1
for bad in ("364", 1.5, True, None, [364]):
    try:
        ok, _msg = rotate_name.submit_rotation(
            "foo", "http://127.0.0.1:8471", _home, bad)
    except Exception as e:  # noqa: BLE001
        print(f"FAIL: submit_rotation expiry={bad!r} raised {type(e).__name__}: {e}")
        fails += 1
        continue
    if ok is not False:
        print(f"FAIL: submit_rotation expiry={bad!r} -> ok={ok!r}, want False")
        fails += 1
# A valid label still reaches the ordinary missing-rotation refusal.
ok, _msg = rotate_name.promote_rotation("foo", _home)
if ok is not False:
    print("FAIL: promote_rotation('foo') on empty home no longer refuses")
    fails += 1

# _normalize twin of verify_name._normalize_expected: a non-string
# must come back as the "" no-value sentinel, never AttributeError
# from .strip() or a bytes alias through bytes' .strip()/.lower().
for bad in (123, 1.5, True, b"Foo", ["Foo"], {"a": 1}, None):
    try:
        got = rotate_name._normalize(bad)
    except Exception as e:  # noqa: BLE001
        print(f"FAIL: _normalize({bad!r}) raised {type(e).__name__}: {e}")
        fails += 1
        continue
    if got != "":
        print(f"FAIL: _normalize({bad!r}) -> {got!r}, want ''")
        fails += 1
if rotate_name._normalize("  Foo-Bar ") != "foo-bar":
    print("FAIL: _normalize valid value changed")
    fails += 1

# _rotate_payload twin of core._name_claim_payload's gate: a non-string
# field in any position must refuse as ValueError, never AttributeError
# from .encode(); valid bytes stay exact.
_good = ("foo", "ab" * 32, "cd" * 32, "2026-01-01T00:00:00Z")
if rotate_name._rotate_payload(*_good) != (
        b"name-rotate|foo|" + b"ab" * 32 + b"|" + b"cd" * 32
        + b"|2026-01-01T00:00:00Z"):
    print("FAIL: _rotate_payload valid bytes changed")
    fails += 1
for _i in range(4):
    for _bad in (123, 1.5, True, None, b"foo", ["foo"]):
        _args = list(_good)
        _args[_i] = _bad
        try:
            rotate_name._rotate_payload(*_args)
        except ValueError:
            continue
        except Exception as e:  # noqa: BLE001
            print(f"FAIL: _rotate_payload field{_i} {_bad!r} raised {type(e).__name__}")
            fails += 1
            continue
        print(f"FAIL: _rotate_payload field{_i} {_bad!r} built instead of ValueError")
        fails += 1

# _refresh_hostd_env_text: a non-string in any position must read as
# "foreign" (a key we cannot account for — text untouched, caller only
# writes on "updated"), never AttributeError/TypeError from
# .splitlines()/.lower(), and never an "updated" that writes a
# non-string new key (None) into the env in place of the seed.
_env = "CYBERNET_HOSTED_NAME=foo\nCYBERNET_NAME_PRIVKEY=" + "a" * 64 + "\n"
for _args in ((123, "a" * 64, "b" * 64), (None, "a" * 64, "b" * 64),
              (b"x", "a" * 64, "b" * 64),
              (_env, 123, "b" * 64), (_env, None, "b" * 64),
              (_env, "a" * 64, None), (_env, "a" * 64, 123),
              (_env, "a" * 64, "b" * 64, 123)):
    try:
        _txt, _st = rotate_name._refresh_hostd_env_text(*_args)
    except Exception as e:  # noqa: BLE001
        print(f"FAIL: _refresh_hostd_env_text{_args!r} raised {type(e).__name__}: {e}")
        fails += 1
        continue
    if _st != "foreign" or _txt != (_args[0] if isinstance(_args[0], str) else ""):
        print(f"FAIL: _refresh_hostd_env_text{_args!r} -> {_st!r}, want 'foreign' + untouched text")
        fails += 1
_txt, _st = rotate_name._refresh_hostd_env_text(_env, "a" * 64, "b" * 64, "foo")
if _st != "updated" or "b" * 64 not in _txt:
    print("FAIL: _refresh_hostd_env_text valid update changed")
    fails += 1

if fails:
    print(f"test_rotate_name: {fails} FAIL")
    sys.exit(1)
print("test_rotate_name: OK")
