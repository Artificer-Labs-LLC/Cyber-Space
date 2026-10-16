#!/usr/bin/env python3
"""hold_open keepalive belt: hold_open_cycle() promises "Never
raises", but its keepalive gate was a raw `keepalive_every <= 0` —
a string/None interval escaped as TypeError before the loop, True
aliased to a 1-second keepalive, and NaN/inf compared False against
every elapsed time, silently disabling keepalives so the relay
would reap the hold-open (primitive 3: hosting)."""
import os
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import hold_open  # noqa: E402

fails = 0

for bad in ("240", None, True, False, float("nan"), float("inf"),
            float("-inf"), 0, -5, b"240"):
    if hold_open._keepalive_every_ok(bad):
        print(f"FAIL: _keepalive_every_ok({bad!r}) is True")
        fails += 1
    stop = threading.Event()
    stop.set()
    try:
        hold_open.hold_open_cycle("http://127.0.0.1:9", "tok",
                                  "ab" * 32, stop, keepalive_every=bad)
    except Exception as e:  # noqa: BLE001
        print(f"FAIL: hold_open_cycle(keepalive_every={bad!r}) raised "
              f"{type(e).__name__}: {e}")
        fails += 1

for good in (1, 0.5, 240.0, hold_open._KEEPALIVE_EVERY):
    if not hold_open._keepalive_every_ok(good):
        print(f"FAIL: _keepalive_every_ok({good!r}) is False")
        fails += 1

# _rendezvous_hold_maybe epoch_len belt: a bad epoch_len (out of
# bounds, non-int, bool) made epoch_for return None, so the roll
# check returned the stale point_epoch forever and the points were
# never re-registered — while _rendezvous_points_register, its
# sibling, normalizes the same bad value to the frozen default.
# A bad epoch_len must register under the default and return the
# current default epoch; a valid one is untouched.
import rendezvous as _rv  # noqa: E402
import time as _time  # noqa: E402

_PUB = "ab" * 32
_calls = []
_orig_register = hold_open._rendezvous_points_register
hold_open._rendezvous_points_register = (
    lambda *a, **k: _calls.append((a, k)) or 2)
try:
    _want_default = _rv.epoch_for(_time.time(), _rv.EPOCH_LEN_DEFAULT)
    for bad in (30, 999999, "3600", None, True, 1.5):
        _calls.clear()
        got = hold_open._rendezvous_hold_maybe(
            "http://127.0.0.1:9", "tok", _PUB, 123, bad)
        if got != _want_default or len(_calls) != 1 \
                or _calls[0][0][3] != _rv.EPOCH_LEN_DEFAULT:
            print(f"FAIL: _rendezvous_hold_maybe(epoch_len={bad!r}) "
                  f"-> {got!r} calls={_calls!r}, want epoch "
                  f"{_want_default!r} under the default")
            fails += 1
    _calls.clear()
    _want_600 = _rv.epoch_for(_time.time(), 600)
    got = hold_open._rendezvous_hold_maybe(
        "http://127.0.0.1:9", "tok", _PUB, 123, 600)
    if got != _want_600 or len(_calls) != 1 or _calls[0][0][3] != 600:
        print(f"FAIL: valid epoch_len=600 changed: {got!r} {_calls!r}")
        fails += 1
    # No-roll and no-key seats are untouched.
    _calls.clear()
    if hold_open._rendezvous_hold_maybe(
            "http://127.0.0.1:9", "tok", _PUB, _want_default) \
            != _want_default or _calls:
        print("FAIL: current-epoch hold_maybe re-registered")
        fails += 1
    if hold_open._rendezvous_hold_maybe(
            "http://127.0.0.1:9", "tok", None, 123, 30) != 123:
        print("FAIL: no-key hold_maybe passthrough changed")
        fails += 1
finally:
    hold_open._rendezvous_points_register = _orig_register

# _post redirect belt: urllib's default opener followed a relay
# 301/302/303 to a foreign server and accepted its answer as the
# relay's (probed 2026-10-16) — fake sessions from a third party
# would be signed with the name key, and a register counted a
# third party's 200. _post now rides a no-redirect opener: a 3xx
# is silence (None / False), the target is never contacted, and a
# direct 200 from the relay itself still parses.
import json as _json  # noqa: E402
import threading as _threading  # noqa: E402
from http.server import BaseHTTPRequestHandler as _H, HTTPServer as _S  # noqa: E402

_target_hits = []


class _Target(_H):
    def _answer(self):
        _target_hits.append(self.path)
        out = b'{"ok": true, "sessions": []}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    do_GET = _answer
    do_POST = _answer

    def log_message(self, *a):
        pass


class _Direct(_H):
    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(n)
        out = _json.dumps({"ok": True}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):
        pass


_target = _S(("127.0.0.1", 0), _Target)
_threading.Thread(target=_target.serve_forever, daemon=True).start()
_tport = _target.server_address[1]


def _relay_handler(code):
    class _Relay(_H):
        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0)
            self.rfile.read(n)
            self.send_response(code)
            self.send_header(
                "Location", f"http://127.0.0.1:{_tport}/stolen")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *a):
            pass

    return _Relay


_servers = []
try:
    for _code in (301, 302, 303, 307, 308):
        _relay = _S(("127.0.0.1", 0), _relay_handler(_code))
        _servers.append(_relay)
        _threading.Thread(target=_relay.serve_forever,
                          daemon=True).start()
        _rurl = f"http://127.0.0.1:{_relay.server_address[1]}"
        _target_hits.clear()
        if hold_open._post(_rurl, "/relay/wait", {"token": "tok"},
                           timeout=5.0) is not None:
            print(f"FAIL: _post followed relay redirect {_code}")
            fails += 1
        if hold_open.hold_open_register(_rurl, "tok"):
            print(f"FAIL: register accepted via redirect {_code}")
            fails += 1
        if _target_hits:
            print(f"FAIL: redirect {_code} contacted the target: "
                  f"{_target_hits!r}")
            fails += 1
    _direct = _S(("127.0.0.1", 0), _Direct)
    _servers.append(_direct)
    _threading.Thread(target=_direct.serve_forever, daemon=True).start()
    _durl = f"http://127.0.0.1:{_direct.server_address[1]}"
    if hold_open._post(_durl, "/relay/register", {"token": "tok"},
                       timeout=5.0) != {"ok": True}:
        print("FAIL: direct relay 200 no longer parses")
        fails += 1
    if hold_open._NoRedirect().redirect_request(
            None, None, 302, "Found", {}, "http://127.0.0.1/") is not None:
        print("FAIL: _NoRedirect.redirect_request is not None")
        fails += 1
finally:
    for _srv in _servers:
        _srv.shutdown()
    _target.shutdown()

if fails:
    print(f"test_hold_open: {fails} FAIL")
    sys.exit(1)
print("test_hold_open: OK")
