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
_real_fetch = resolve_chain._fetch
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

# The terminal key compares in normalized form (twin of walk's pin and
# the live key): the same key in uppercase or padded form must agree,
# never read as a lineage break; a genuinely different key still fails.
for term in (PK_B.upper(), f"  {PK_B}  "):
    try:
        v = resolve_chain.check_live("foo", "http://x:1", term)
        if "terminal key" not in v or PK_B[:16] not in v:
            print(f"FAIL: check_live terminal={term!r} verdict {v!r}")
            fails += 1
    except Exception as e:  # noqa: BLE001
        print(f"FAIL: check_live terminal={term!r} raised {type(e).__name__}: {e}")
        fails += 1
try:
    resolve_chain.check_live("foo", "http://x:1", PK_A)
    print("FAIL: check_live different terminal key returned")
    fails += 1
except resolve_chain.ChainError as e:
    if "not the designated heir" not in str(e):
        print(f"FAIL: check_live different key -> ChainError {e!r}")
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

# CLI duplicate gate: argparse silently last-wins on a repeated
# value flag, so --expect-original-key A --expect-original-key B
# walked against pin B while the operator believed the pin was A.
# A repeated --mirror/--expect-original-key in space, equals or
# mixed spelling must refuse by name, exit 2, before any verdict.
import subprocess  # noqa: E402

_here = os.path.dirname(os.path.abspath(__file__))


def _run_cli_args(extra):
    return subprocess.run(
        [sys.executable, os.path.join(_here, "resolve_chain.py"), "-"] + extra,
        input="[]", capture_output=True, text=True, timeout=10)


for _flag in ("--mirror", "--expect-original-key"):
    for _extra in ([_flag, "a", _flag, "b"],
                   [f"{_flag}=a", f"{_flag}=b"],
                   [_flag, "a", f"{_flag}=b"],
                   [f"{_flag}=a", _flag, "b"]):
        _r = _run_cli_args(_extra)
        if _r.returncode != 2 or f"{_flag} given more than once" not in _r.stderr:
            print(f"FAIL: duplicate {_flag} {_extra} -> rc={_r.returncode} {_r.stderr!r}")
            fails += 1

# The boolean --with-live gates the same way: store_true repeats
# silently, so --with-live --with-live passed to a verdict while
# every value flag above refused its repeat by name. A repeated
# --with-live in space, equals or mixed spelling must refuse by
# name, exit 2, before any verdict; a single --with-live still
# reaches its verdict (here, the stdin-mode offline refusal).
for _extra in (["--with-live", "--with-live"],
               ["--with-live=x", "--with-live=x"],
               ["--with-live", "--with-live=x"],
               ["--with-live=x", "--with-live"]):
    _r = _run_cli_args(_extra)
    if _r.returncode != 2 or "--with-live given more than once" not in _r.stderr:
        print(f"FAIL: duplicate --with-live {_extra} -> rc={_r.returncode} {_r.stderr!r}")
        fails += 1
_r = _run_cli_args(["--with-live"])
if _r.returncode != 2 or "stdin mode is fully offline" not in _r.stderr:
    print(f"FAIL: single --with-live -> rc={_r.returncode} {_r.stderr!r}")
    fails += 1

# CLI abbreviation gate, twin of resolver client's (f184a22) and
# dial's (3328e2d): argparse accepts any unambiguous prefix, so
# --mir (even --m) silently became --mirror and dodged the duplicate
# gate above (a --mir A --mirror B pair walked against mirror B).
# An abbreviated spelling of any long option refuses by name, exit 2,
# alone or paired, in space or equals spelling, before any input is
# read or fetched.
for _abbr, _full in (("--mir", "--mirror"), ("--m", "--mirror"),
                     ("--expect-o", "--expect-original-key"),
                     ("--e", "--expect-original-key"),
                     ("--with", "--with-live"), ("--w", "--with-live"),
                     ("--h", "--help")):
    for _extra in ([_abbr, "x"], [f"{_abbr}=x"],
                   [_abbr, "a", _full, "b"], [_full, "a", _abbr, "b"]):
        _r = _run_cli_args(_extra)
        if _r.returncode != 2 or f"{_abbr} is an abbreviation of {_full}" not in _r.stderr:
            print(f"FAIL: abbreviated {_abbr} {_extra} -> rc={_r.returncode} {_r.stderr!r}")
            fails += 1

# A single exact flag still reaches its verdict: the pinned stdin
# walk walks clean, exit 0.
import json  # noqa: E402

_r = subprocess.run(
    [sys.executable, os.path.join(_here, "resolve_chain.py"), "-",
     "--expect-original-key", PK_A],
    input=json.dumps(DOC), capture_output=True, text=True, timeout=10)
if _r.returncode != 0 or "walks clean" not in _r.stdout:
    print(f"FAIL: single exact --expect-original-key -> rc={_r.returncode} {_r.stdout!r} {_r.stderr!r}")
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
                      (["--mirror"], 2),
                      ([], 2),
                      (["a", "extra"], 2),
                      (["--help"], 0)):
    _err = io.StringIO()
    try:
        with contextlib.redirect_stderr(_err), \
                contextlib.redirect_stdout(io.StringIO()):
            _rc = resolve_chain.main(_argv)
    except SystemExit as _e:
        print(f"FAIL: main({_argv}) raised SystemExit {_e.code}, want return {_want}")
        fails += 1
        continue
    if _rc != _want:
        print(f"FAIL: main({_argv}) -> {_rc}, want {_want}")
        fails += 1

# _fetch redirect belt: urllib's default opener followed a mirror
# 301/302/303 to a foreign server and accepted its document as the
# mirror's (probed 2026-10-16) — the client was also dialed to an
# address it never chose. _fetch now rides a no-redirect opener:
# a 3xx is a failed fetch (ChainError), the target is never
# contacted, and a direct 200 from the mirror itself still parses.
import threading as _threading  # noqa: E402
from http.server import BaseHTTPRequestHandler as _H, HTTPServer as _S  # noqa: E402

resolve_chain._fetch = _real_fetch
_thits = []


class _TTarget(_H):
    def do_GET(self):
        _thits.append(self.path)
        out = b'{"stolen": true}'
        self.send_response(200)
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):
        pass


class _TDirect(_H):
    def do_GET(self):
        out = b'{"name": "foo", "rotations": []}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):
        pass


_ttarget = _S(("127.0.0.1", 0), _TTarget)
_threading.Thread(target=_ttarget.serve_forever, daemon=True).start()
_tport = _ttarget.server_address[1]


def _tmirror(code):
    class _TM(_H):
        def do_GET(self):
            self.send_response(code)
            self.send_header(
                "Location", f"http://127.0.0.1:{_tport}/stolen")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *a):
            pass

    return _TM


_tservers = []
try:
    for _code in (301, 302, 303, 307, 308):
        _m = _S(("127.0.0.1", 0), _tmirror(_code))
        _tservers.append(_m)
        _threading.Thread(target=_m.serve_forever, daemon=True).start()
        _thits.clear()
        try:
            _got = resolve_chain._fetch(
                f"http://127.0.0.1:{_m.server_address[1]}/chain")
            print(f"FAIL: _fetch followed mirror redirect {_code}: {_got!r}")
            fails += 1
        except resolve_chain.ChainError:
            pass
        if _thits:
            print(f"FAIL: redirect {_code} contacted target: {_thits!r}")
            fails += 1
    _direct = _S(("127.0.0.1", 0), _TDirect)
    _tservers.append(_direct)
    _threading.Thread(target=_direct.serve_forever, daemon=True).start()
    if resolve_chain._fetch(
            f"http://127.0.0.1:{_direct.server_address[1]}/chain") != {
            "name": "foo", "rotations": []}:
        print("FAIL: direct mirror 200 no longer parses")
        fails += 1
    if resolve_chain._NoRedirect().redirect_request(
            None, None, 302, "Found", {}, "http://127.0.0.1/") is not None:
        print("FAIL: _NoRedirect.redirect_request is not None")
        fails += 1
finally:
    for _srv in _tservers:
        _srv.shutdown()
    _ttarget.shutdown()

if fails:
    print(f"test_resolve_chain: {fails} FAIL")
    sys.exit(1)
print("test_resolve_chain: OK")
