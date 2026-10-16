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

# CLI source seat: only a regular file may be opened — open() on a
# FIFO blocks until a writer appears, so a FIFO at the binding seat
# hung the verifier forever instead of its no-verdict exit 2.
import subprocess  # noqa: E402
import tempfile  # noqa: E402

_here = os.path.dirname(os.path.abspath(__file__))


def _run_cli(path):
    return subprocess.run(
        [sys.executable, os.path.join(_here, "verify_name.py"), path],
        capture_output=True, text=True, timeout=10)


with tempfile.TemporaryDirectory() as _td:
    _fifo = os.path.join(_td, "binding.json")
    os.mkfifo(_fifo)
    for _seat, _path in (("FIFO", _fifo),
                         ("symlink-to-FIFO", os.path.join(_td, "link.json"))):
        if _seat.startswith("symlink"):
            os.symlink(_fifo, _path)
        try:
            _r = _run_cli(_path)
        except subprocess.TimeoutExpired:
            print(f"FAIL: CLI hung on {_seat} source")
            fails += 1
            continue
        if _r.returncode != 2 or "not a regular file" not in _r.stderr:
            print(f"FAIL: CLI {_seat} -> rc={_r.returncode} { _r.stderr!r}")
            fails += 1
    # A regular file still reads: non-JSON content reaches the JSON
    # refusal (exit 2, "not JSON"), proving the gate opens real files.
    _reg = os.path.join(_td, "real.json")
    with open(_reg, "w", encoding="utf-8") as _f:
        _f.write("not json")
    _r = _run_cli(_reg)
    if _r.returncode != 2 or "not JSON" not in _r.stderr:
        print(f"FAIL: CLI regular file -> rc={_r.returncode} {_r.stderr!r}")
        fails += 1

# CLI duplicate gate: argparse silently last-wins on a repeated
# value flag, so --expect-name foo --expect-name bar verified
# against bar while the operator believed the pin was foo. A
# repeated --expect-name/--expect-pubkey in space, equals or
# mixed spelling must refuse by name, exit 2, before any verdict.
def _run_cli_args(extra):
    return subprocess.run(
        [sys.executable, os.path.join(_here, "verify_name.py"),
         "/nonexistent-binding.json"] + extra,
        capture_output=True, text=True, timeout=10)


for _flag in ("--expect-name", "--expect-pubkey"):
    for _extra in ([_flag, "a", _flag, "b"],
                   [f"{_flag}=a", f"{_flag}=b"],
                   [_flag, "a", f"{_flag}=b"],
                   [f"{_flag}=a", _flag, "b"]):
        _r = _run_cli_args(_extra)
        if _r.returncode != 2 or f"{_flag} given more than once" not in _r.stderr:
            print(f"FAIL: duplicate {_flag} {_extra} -> rc={_r.returncode} {_r.stderr!r}")
            fails += 1

# CLI abbreviation gate: argparse accepts any unambiguous prefix,
# so --expect-n silently became --expect-name and dodged the
# duplicate gate above. An abbreviated spelling in space, equals
# or paired-with-exact form must refuse by name, exit 2, before
# any verdict; a single exact flag still reaches its verdict.
for _flag, _abbr in (("--expect-name", "--expect-n"),
                     ("--expect-name", "--e"),
                     ("--expect-pubkey", "--expect-p"),
                     ("--expect-name", "--expect-")):
    for _extra in ([_abbr, "a"],
                   [f"{_abbr}=a"],
                   [_abbr, "a", _flag, "b"],
                   [_flag, "a", _abbr, "b"]):
        _r = _run_cli_args(_extra)
        if _r.returncode != 2 or f"{_abbr} is an abbreviation of {_flag}" not in _r.stderr:
            print(f"FAIL: abbreviated {_abbr} {_extra} -> rc={_r.returncode} {_r.stderr!r}")
            fails += 1
_r = _run_cli_args(["--expect-name", "foo"])
if _r.returncode != 2 or "cannot read" not in _r.stderr:
    print(f"FAIL: single exact --expect-name -> rc={_r.returncode} {_r.stderr!r}")
    fails += 1

# In-process parse seat: argparse raises SystemExit on the bad
# arguments no in-main gate can pre-empt (unknown flag, dangling
# value flag, missing/surplus positional) and on --help. main()
# must convert that exit into its own return (2 bad args, 0
# --help) so an in-process caller is never crashed; the shell
# exit is unchanged because __main__ re-raises the return.
import contextlib  # noqa: E402
import io  # noqa: E402

for _argv, _want in ((["--bogus"], 2),
                      (["--expect-name"], 2),
                      ([], 2),
                      (["a.json", "extra"], 2),
                      (["--help"], 0)):
    _err = io.StringIO()
    try:
        with contextlib.redirect_stderr(_err), \
                contextlib.redirect_stdout(io.StringIO()):
            _rc = verify_name.main(_argv)
    except SystemExit as _e:
        print(f"FAIL: main({_argv}) raised SystemExit {_e.code}, want return {_want}")
        fails += 1
        continue
    if _rc != _want:
        print(f"FAIL: main({_argv}) -> {_rc}, want {_want}")
        fails += 1

if fails:
    print(f"test_verify_name: {fails} FAIL")
    sys.exit(1)
print("test_verify_name: OK")
