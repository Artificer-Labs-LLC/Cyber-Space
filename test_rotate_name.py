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

# _installed_env_note: a malformed argument must read as a warning
# note, never AttributeError from .exists()/.lower() — promote calls
# it AFTER the keys have moved, so a crash would swallow a successful
# promotion's report. A non-string key/label can match nothing: the
# generic different/no-key warning. A non-path path: a warning. A
# string path is coerced and reads exactly like the Path. Absent
# file still reads "" even with malformed keys.
import tempfile as _tempfile
from pathlib import Path as _Path
with _tempfile.TemporaryDirectory() as _td:
    _ip = _Path(_td) / "hostd.env"
    _ip.write_text("CYBERNET_HOSTED_NAME=foo\n"
                   "CYBERNET_NAME_PRIVKEY=" + "b" * 64 + "\n")
    if "already holds the new key" not in rotate_name._installed_env_note(
            _ip, "a" * 64, "b" * 64, "foo"):
        print("FAIL: _installed_env_note valid current changed")
        fails += 1
    if "still holds the OLD key" not in rotate_name._installed_env_note(
            str(_ip), "b" * 64, "c" * 64, "foo"):
        print("FAIL: _installed_env_note string path / valid old changed")
        fails += 1
    if "NOT this name's env" not in rotate_name._installed_env_note(
            _ip, "a" * 64, "b" * 64, "bar"):
        print("FAIL: _installed_env_note valid wrong-name changed")
        fails += 1
    for _args in ((_ip, "a" * 64, 123), (_ip, "a" * 64, None),
                  (_ip, 123, "b" * 64), (_ip, None, "b" * 64),
                  (_ip, "a" * 64, "b" * 64, 123),
                  (_ip, "a" * 64, "b" * 64, None if False else b"foo")):
        try:
            _note = rotate_name._installed_env_note(*_args)
        except Exception as e:  # noqa: BLE001
            print(f"FAIL: _installed_env_note{_args!r} raised {type(e).__name__}: {e}")
            fails += 1
            continue
        if "different or no CYBERNET_NAME_PRIVKEY" not in _note:
            print(f"FAIL: _installed_env_note{_args!r} -> {_note!r}, want generic warning")
            fails += 1
    for _bad_path in (None, 123, ["x"], b"/tmp/x"):
        try:
            _note = rotate_name._installed_env_note(_bad_path, "a" * 64, "b" * 64)
        except Exception as e:  # noqa: BLE001
            print(f"FAIL: _installed_env_note path {_bad_path!r} raised {type(e).__name__}: {e}")
            fails += 1
            continue
        if "not a path" not in _note:
            print(f"FAIL: _installed_env_note path {_bad_path!r} -> {_note!r}, want path warning")
            fails += 1
    if rotate_name._installed_env_note(_Path(_td) / "absent.env", 123, None) != "":
        print("FAIL: _installed_env_note absent file must stay ''")
        fails += 1

# main()'s home seat: home holds the name key and the .next seed
# main writes (both 0600), so a dir rotate itself creates is born
# 0700 via mint_name._ensure_dir (rotate imports it — no twin to
# drift); a pre-existing home is left exactly as found.
import stat as _stat
import subprocess as _subprocess
import tempfile as _tempfile2
from pathlib import Path as _Path2

if rotate_name._ensure_dir is not __import__("mint_name")._ensure_dir:
    print("FAIL: rotate_name._ensure_dir is not mint_name._ensure_dir")
    fails += 1
with _tempfile2.TemporaryDirectory() as _td:
    _base = _Path2(_td) / "a" / ".cyberspace"
    rotate_name._ensure_dir(_base)
    for _p in (_Path2(_td) / "a", _base):
        _m = _stat.S_IMODE(os.stat(_p).st_mode)
        if _m != 0o700:
            print(f"FAIL: rotate _ensure_dir created {_p} at {oct(_m)}, want 0o700")
            fails += 1
    _pre = _Path2(_td) / "pre"
    _pre.mkdir()
    os.chmod(_pre, 0o755)
    rotate_name._ensure_dir(_pre)
    if _stat.S_IMODE(os.stat(_pre).st_mode) != 0o755:
        print("FAIL: rotate _ensure_dir tightened a pre-existing dir")
        fails += 1
    # End-to-end: main() mints into a pre-existing 0755 home and
    # leaves its mode untouched; the .next seed is born 0600.
    _home = _Path2(_td) / "home"
    _cs = _home / ".cyberspace"
    _cs.mkdir(parents=True)
    os.chmod(_cs, 0o755)
    (_cs / "foo-name.key").write_text(SK.hex() + "\n")
    _env = dict(os.environ, HOME=str(_home))
    _r = _subprocess.run(
        [sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                     "rotate_name.py"), "foo"],
        capture_output=True, text=True, env=_env)
    if _r.returncode != 0:
        print(f"FAIL: rotate main() rc={_r.returncode}: {_r.stderr.strip()[:200]}")
        fails += 1
    if _stat.S_IMODE(os.stat(_cs).st_mode) != 0o755:
        print("FAIL: rotate main() changed a pre-existing home's mode")
        fails += 1
    _next = _cs / "foo-name.key.next"
    if not _next.exists() or _stat.S_IMODE(os.stat(_next).st_mode) != 0o600:
        print("FAIL: rotate main() .next seed missing or not 0600")
        fails += 1
    # Re-run while a rotation is pending: must refuse cleanly
    # (rc 1, no traceback) and leave the pending pair byte-identical
    # — the old order clobbered the record, then crashed on the
    # existing .next, stranding the rotation.
    _rec_before = (_cs / "foo-rotate.json").read_bytes()
    _next_before = _next.read_bytes()
    _r2 = _subprocess.run(
        [sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                     "rotate_name.py"), "foo"],
        capture_output=True, text=True, env=_env)
    if _r2.returncode != 1 or "Traceback" in _r2.stderr:
        print(f"FAIL: rotate re-run rc={_r2.returncode}: {_r2.stderr.strip()[:200]}")
        fails += 1
    if (_cs / "foo-rotate.json").read_bytes() != _rec_before:
        print("FAIL: rotate re-run clobbered the pending record")
        fails += 1
    if _next.read_bytes() != _next_before:
        print("FAIL: rotate re-run clobbered the pending .next seed")
        fails += 1
    # The record lands atomically (unique temp sibling + os.replace):
    # no temp siblings remain, the record loads whole under the read
    # bound, and an orphan record (its .next gone) is recovered by a
    # fresh mint whose new pair is consistent — never truncated in
    # place, the badjson stranding a crashed write_text left behind.
    if list(_cs.glob("foo-rotate.json.tmp-*")):
        print("FAIL: rotate main() left record temp siblings behind")
        fails += 1
    _loaded, _lerr = rotate_name._load_record(_cs / "foo-rotate.json")
    if _loaded is None or _lerr is not None:
        print(f"FAIL: rotate main() record does not load: {_lerr}")
        fails += 1
    _next.unlink()
    _r3 = _subprocess.run(
        [sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                     "rotate_name.py"), "foo"],
        capture_output=True, text=True, env=_env)
    if _r3.returncode != 0:
        print(f"FAIL: rotate orphan-record re-mint rc={_r3.returncode}: "
              f"{_r3.stderr.strip()[:200]}")
        fails += 1
    else:
        _loaded2, _lerr2 = rotate_name._load_record(_cs / "foo-rotate.json")
        _seed2 = bytes.fromhex((_cs / "foo-name.key.next").read_text().strip())
        if _loaded2 is None or _loaded2["new_pubkey"] != publickey(_seed2).hex():
            print("FAIL: rotate orphan-record re-mint pair is inconsistent")
            fails += 1
    # _write_record failure seat: replacing onto a directory raises,
    # the target is untouched, and its own temp is cleaned up.
    _rdir = _Path2(_td) / "recseat"
    _rdir.mkdir()
    _rtarget = _rdir / "foo-rotate.json"
    _rtarget.mkdir()
    try:
        rotate_name._write_record(_rtarget, "{}\n")
        print("FAIL: _write_record onto a directory did not raise")
        fails += 1
    except OSError:
        pass
    if not _rtarget.is_dir() or list(_rdir.glob("foo-rotate.json.tmp-*")):
        print("FAIL: _write_record failure left debris or harmed the target")
        fails += 1
    # _write_record fsyncs its temp before close: os.replace alone
    # does not make the renamed bytes durable, so a crash after a
    # successful return could still leave an empty/truncated record
    # that _load_record's badjson refusal strands beside a valid
    # .next seed — the _write_secret fsync rule (0bddade), one layer
    # down in the record half of the pair.
    _fsyncs = []
    _dir_fsyncs = []
    _orig_fsync = os.fsync
    def _probe_fsync(fd):
        _fsyncs.append(fd)
        if _stat.S_ISDIR(os.fstat(fd).st_mode):
            _dir_fsyncs.append(fd)
    os.fsync = _probe_fsync
    try:
        _ftarget = _rdir / "fsync-rotate.json"
        rotate_name._write_record(_ftarget, "{}\n")
        if not _fsyncs:
            print("FAIL: _write_record did not fsync before close")
            fails += 1
        if not _dir_fsyncs:
            print("FAIL: _write_record did not fsync the parent dir after replace")
            fails += 1
        if _ftarget.read_text() != "{}\n":
            print("FAIL: _write_record fsync probe content did not land")
            fails += 1
        if list(_rdir.glob("fsync-rotate.json.tmp-*")):
            print("FAIL: _write_record fsync probe left temp siblings")
            fails += 1
    finally:
        os.fsync = _orig_fsync

# Second rotation promote: the first promote leaves .prev behind,
# and the second promote must overwrite that single latest-
# predecessor slot atomically — the O_EXCL write raised
# FileExistsError and stranded every later rotation unpromotable.
import json as _json
import tempfile as _tempfile3
from pathlib import Path as _Path3

import mint_name as _mint_name
with _tempfile3.TemporaryDirectory() as _td:
    _home = _Path3(_td)
    _absent = _home / "absent.env"
    _k1, _k2, _k3 = (secrets.token_bytes(32) for _ in range(3))

    def _stage(_old, _new):
        _rec = rotate_name.mint_rotation(
            "foo", _old, publickey(_new).hex())
        (_home / "foo-rotate.json").write_text(_json.dumps(_rec) + "\n")
        _mint_name._write_secret(_home / "foo-name.key.next", _new.hex())

    _mint_name._write_secret(_home / "foo-name.key", _k1.hex())
    _stage(_k1, _k2)
    _ok, _msg = rotate_name.promote_rotation("foo", _home,
                                             installed_env=_absent)
    if not _ok or (_home / "foo-name.key.prev").read_text().strip() != _k1.hex():
        print(f"FAIL: first promote in two-rotation run: {_msg!r}")
        fails += 1
    _stage(_k2, _k3)
    try:
        _ok, _msg = rotate_name.promote_rotation("foo", _home,
                                                 installed_env=_absent)
    except Exception as e:  # noqa: BLE001
        print(f"FAIL: second promote raised {type(e).__name__}: {e}")
        fails += 1
        _ok = False
    if _ok:
        if (_home / "foo-name.key").read_text().strip() != _k3.hex():
            print("FAIL: second promote did not install the third key")
            fails += 1
        if (_home / "foo-name.key.prev").read_text().strip() != _k2.hex():
            print("FAIL: second promote .prev does not hold the second key")
            fails += 1
        if _stat.S_IMODE(os.stat(_home / "foo-name.key.prev").st_mode) != 0o600:
            print("FAIL: second promote .prev is not 0600")
            fails += 1
        if (_home / "foo-name.key.next").exists():
            print("FAIL: second promote left .next unconsumed")
            fails += 1

if fails:
    print(f"test_rotate_name: {fails} FAIL")
    sys.exit(1)
print("test_rotate_name: OK")
