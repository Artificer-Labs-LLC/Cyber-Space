#!/usr/bin/env python3
"""mint_name shape predicates belt: _valid_mirror/_valid_label are bool
predicates — every refused input must come back False, never a
TypeError/AttributeError from iterating or measuring a non-string
(main() always passes argv strings, but the library seat is the
anyone-can-mint surface of primitives 1 naming + 6 client daemon).
Valid shapes must keep their exact verdicts.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mint_name  # noqa: E402

fails = 0


def _check(fn, arg, want, why):
    global fails
    try:
        got = fn(arg)
    except Exception as e:  # noqa: BLE001
        print(f"FAIL: {why} raised {type(e).__name__}: {e}")
        fails += 1
        return
    if got is not want:
        print(f"FAIL: {why} -> {got!r}, want {want!r}")
        fails += 1


for bad in (123, 1.5, True, None, b"http://x:8471", ["http://x"], []):
    _check(mint_name._valid_mirror, bad, False, f"_valid_mirror({bad!r})")
for good in ("http://127.0.0.1:8471", "https://node.example",
             "http://x:65535"):
    _check(mint_name._valid_mirror, good, True, f"_valid_mirror({good!r})")
for bad in ("", "ftp://x", "http://", "http://x:0", "http://x:65536",
            "http://x:abc", " http://x", "http://x/\nEVIL=1"):
    _check(mint_name._valid_mirror, bad, False, f"_valid_mirror({bad!r})")

for bad in (123, 1.5, True, b"foo", ["foo"], None):
    _check(mint_name._valid_label, bad, False, f"_valid_label({bad!r})")
_check(mint_name._valid_label, "foo-bar1", True, "_valid_label('foo-bar1')")
for bad in ("", "Foo", "a.b", "-a", "a-", "a" * 64):
    _check(mint_name._valid_label, bad, False, f"_valid_label({bad!r})")

# _hostd_env_text: a non-string in any position must refuse as
# ValueError, never an AttributeError from .rstrip() and never a
# stringified literal (CYBERNET_NAME_PRIVKEY=None) written into the
# key-bearing env body. Valid text keeps its exact active lines.
_good_env = mint_name._hostd_env_text("foo", "ab" * 32, "http://x:8471/")
for _line in ("CYBERNET_HOSTED_NAME=foo\n",
              "CYBERNET_NAME_PRIVKEY=" + "ab" * 32 + "\n",
              "CYBERNET_MIRROR_URL=http://x:8471\n"):
    if _line not in _good_env:
        print(f"FAIL: valid _hostd_env_text missing {_line!r}")
        fails += 1
for _args in ((123, "ab" * 32, "http://x"), ("foo", None, "http://x"),
              ("foo", 123, "http://x"), ("foo", "ab" * 32, None),
              ("foo", "ab" * 32, 123), (None, "ab" * 32, "http://x")):
    try:
        mint_name._hostd_env_text(*_args)
        print(f"FAIL: _hostd_env_text{_args!r} did not refuse")
        fails += 1
    except ValueError:
        pass
    except Exception as e:  # noqa: BLE001
        print(f"FAIL: _hostd_env_text{_args!r} raised "
              f"{type(e).__name__}, want ValueError")
        fails += 1

# _ensure_dir: dirs mint_name creates to hold the name key / hostd
# env are born 0700 (the files are 0600; a 0755 dir leaked their
# names); a pre-existing dir is left exactly as found.
import stat
import tempfile

with tempfile.TemporaryDirectory() as _td:
    _base = os.path.join(_td, "a", "b")
    mint_name._ensure_dir(_base)
    for _p in (os.path.join(_td, "a"), _base):
        _m = stat.S_IMODE(os.stat(_p).st_mode)
        if _m != 0o700:
            print(f"FAIL: _ensure_dir created {_p} at {oct(_m)}, want 0o700")
            fails += 1
    _pre = os.path.join(_td, "pre")
    os.mkdir(_pre)
    os.chmod(_pre, 0o755)
    mint_name._ensure_dir(_pre)
    _m = stat.S_IMODE(os.stat(_pre).st_mode)
    if _m != 0o755:
        print(f"FAIL: _ensure_dir tightened pre-existing dir to {oct(_m)}")
        fails += 1
    mint_name._ensure_dir(_base)  # idempotent on its own dirs
    _m = stat.S_IMODE(os.stat(_base).st_mode)
    if _m != 0o700:
        print(f"FAIL: _ensure_dir re-run changed mode to {oct(_m)}")
        fails += 1

# _write_secret(overwrite=True): a stale fixed "<path>.tmp" left by a
# crashed overwrite must not strand every later overwrite — the write
# uses a unique temp sibling, lands atomically at 0600, and leaves the
# stale file untouched (never deleted sight-unseen).
with tempfile.TemporaryDirectory() as _td:
    _p = os.path.join(_td, "k")
    mint_name._write_secret(_p, "old")
    with open(_p + ".tmp", "w") as _f:
        _f.write("stale")
    try:
        mint_name._write_secret(_p, "new", overwrite=True)
    except Exception as e:  # noqa: BLE001
        print(f"FAIL: overwrite with stale .tmp raised "
              f"{type(e).__name__}: {e}")
        fails += 1
    else:
        with open(_p) as _f:
            if _f.read() != "new":
                print("FAIL: overwrite with stale .tmp did not land 'new'")
                fails += 1
        _m = stat.S_IMODE(os.stat(_p).st_mode)
        if _m != 0o600:
            print(f"FAIL: overwritten secret at {oct(_m)}, want 0o600")
            fails += 1
        with open(_p + ".tmp") as _f:
            if _f.read() != "stale":
                print("FAIL: stale .tmp was touched by the overwrite")
                fails += 1
        _left = [n for n in os.listdir(_td) if n.startswith("k.tmp-")]
        if _left:
            print(f"FAIL: unique temp siblings left behind: {_left}")
            fails += 1
    # a second overwrite also succeeds (no self-stranding)
    try:
        mint_name._write_secret(_p, "third", overwrite=True)
        with open(_p) as _f:
            if _f.read() != "third":
                print("FAIL: second overwrite did not land 'third'")
                fails += 1
    except Exception as e:  # noqa: BLE001
        print(f"FAIL: second overwrite raised {type(e).__name__}: {e}")
        fails += 1

# _write_secret fsyncs before close on BOTH paths (plain O_EXCL and
# the overwrite temp sibling): a crash after a successful return must
# not leave a truncated seed the next read's shape check strands —
# the core node-key rule (e8c1c46) applied to the shared name-key
# writer (mint, Nexus keygen primary+backup, rotate .next/.prev).
with tempfile.TemporaryDirectory() as _td:
    _p = os.path.join(_td, "k")
    _fsyncs = []
    _dir_fsyncs = []
    _orig_fsync = os.fsync

    def _probe_fsync(fd):
        _fsyncs.append(fd)
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            _dir_fsyncs.append(fd)

    os.fsync = _probe_fsync
    try:
        mint_name._write_secret(_p, "seed-one")
        if not _fsyncs:
            print("FAIL: plain _write_secret did not fsync")
            fails += 1
        if not _dir_fsyncs:
            print("FAIL: plain _write_secret did not fsync the parent dir "
                  "(directory entry not durable)")
            fails += 1
        _fsyncs.clear()
        _dir_fsyncs.clear()
        mint_name._write_secret(_p, "seed-two", overwrite=True)
        if not _fsyncs:
            print("FAIL: overwrite _write_secret did not fsync")
            fails += 1
        if not _dir_fsyncs:
            print("FAIL: overwrite _write_secret did not fsync the "
                  "parent dir after os.replace")
            fails += 1
    finally:
        os.fsync = _orig_fsync
    with open(_p) as _f:
        if _f.read() != "seed-two":
            print("FAIL: fsync probe overwrite did not land 'seed-two'")
            fails += 1
    _m = stat.S_IMODE(os.stat(_p).st_mode)
    if _m != 0o600:
        print(f"FAIL: fsync probe secret at {oct(_m)}, want 0o600")
        fails += 1

# _read_seed refuses a non-regular source WITHOUT opening it:
# open() on a FIFO blocks until a writer appears, so a FIFO at the
# seed seat hung the minter forever instead of refusing (probed
# 2026-10-16). A symlink to a FIFO is the same seat (stat follows the
# link); a symlink TO a regular file and a plain regular file still
# read byte-exact.
from pathlib import Path as _Path

with tempfile.TemporaryDirectory() as _td:
    _fifo = os.path.join(_td, "seed.key")
    os.mkfifo(_fifo)
    _seed_hex = "ab" * 32
    _reg = os.path.join(_td, "real.key")
    with open(_reg, "w", encoding="utf-8") as _f:
        _f.write(_seed_hex)
    for _seat, _path in (("FIFO", _fifo),
                         ("symlink-to-FIFO", os.path.join(_td, "link.key"))):
        if _seat.startswith("symlink"):
            os.symlink(_fifo, _path)
        try:
            mint_name._read_seed(_Path(_path))
            print(f"FAIL: _read_seed {_seat} read instead of refusing")
            fails += 1
        except ValueError as _e:
            if "not a regular file" not in str(_e):
                print(f"FAIL: _read_seed {_seat} ValueError {_e!r}")
                fails += 1
        except Exception as _e:  # noqa: BLE001
            print(f"FAIL: _read_seed {_seat} raised {type(_e).__name__}: {_e}")
            fails += 1
    _good_link = os.path.join(_td, "good-link.key")
    os.symlink(_reg, _good_link)
    for _seat, _path in (("regular", _reg), ("symlink-to-regular", _good_link)):
        try:
            if mint_name._read_seed(_Path(_path)) != bytes.fromhex(_seed_hex):
                print(f"FAIL: _read_seed {_seat} read wrong bytes")
                fails += 1
        except Exception as _e:  # noqa: BLE001
            print(f"FAIL: _read_seed {_seat} raised {type(_e).__name__}: {_e}")
            fails += 1

# main() duplicate gate: a repeated value flag in space, equals or
# mixed spelling refuses by name (exit 2) before any key/network —
# it silently last-won, so --expiry-days 7 --expiry-days 9 minted a
# 9-day binding the operator believed was 7.
import contextlib
import io

for _argv in (("probe", "--expiry-days", "7", "--expiry-days", "9"),
              ("probe", "--expiry-days=7", "--expiry-days=9"),
              ("probe", "--expiry-days", "7", "--expiry-days=9"),
              ("probe", "--env-dir", "/tmp/a", "--env-dir", "/tmp/b")):
    _flag = _argv[1].split("=")[0]
    _err = io.StringIO()
    try:
        with contextlib.redirect_stderr(_err):
            _rc = mint_name.main(list(_argv))
    except Exception as _e:  # noqa: BLE001
        print(f"FAIL: main duplicate {_argv} raised {type(_e).__name__}: {_e}")
        fails += 1
        continue
    if _rc != 2 or f"{_flag} given more than once" not in _err.getvalue():
        print(f"FAIL: main duplicate {_argv} -> rc={_rc} err={_err.getvalue()!r}")
        fails += 1

if fails:
    print(f"test_mint_name: {fails} FAIL")
    sys.exit(1)
print("test_mint_name: OK")
