#!/usr/bin/env python3
"""Belt: resolver/host._mirror_post reads the mirror reply under 64KB
and refuses mirror redirects.

Every other depth POST seat (mint/rotate/hold_open/core) reads its
mirror/peer reply under the same cap and treats oversize as silence;
_mirror_post judged by status alone and never read the body, so an
oversize 200 counted as an accepted announce. It also rode urllib's
default opener, which followed a mirror 301/302/303 to a foreign
server and accepted its 200 as the mirror's verdict; _mirror_post
now rides a no-redirect opener (twin of hold_open/resolve_chain).

Run from the repo root:  python3 hidden_files/hostd-mirror-resp-size-belt-test.py
"""
import json
import os
import sys
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from resolver import host  # noqa: E402

CHECKS = 0
FAILURES = []


def check(name, cond, detail=""):
    global CHECKS
    CHECKS += 1
    if not cond:
        FAILURES.append(f"{name}: {detail}")


class FakeResp:
    def __init__(self, status, body):
        self.status = status
        self._body = body
        self.read_sizes = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self, n=-1):
        self.read_sizes.append(n)
        return self._body if n < 0 else self._body[:n]


class FakeOpener:
    def __init__(self, resp=None, exc=None):
        self._resp = resp
        self._exc = exc

    def open(self, req, timeout=None):
        if self._exc is not None:
            raise self._exc
        return self._resp


def run_case(status, body):
    resp = FakeResp(status, body)
    orig = host._OPENER
    host._OPENER = FakeOpener(resp=resp)
    try:
        return host._mirror_post("http://mirror.example", "/fed/announce",
                                 {"x": 1}), resp
    finally:
        host._OPENER = orig


# 1. 200 with a small verdict body is accepted, read under cap+1
ok, resp = run_case(200, b'{"ok": true}')
check("small-200-accepted", ok is True)
check("read-bounded", resp.read_sizes == [host._MIRROR_RESP_MAX + 1],
      repr(resp.read_sizes))

# 2. 200 with an at-cap body is accepted
ok, _ = run_case(200, b"x" * host._MIRROR_RESP_MAX)
check("at-cap-accepted", ok is True)

# 3. 200 with an oversize body is silence, not an accepted announce
ok, _ = run_case(200, b"x" * (host._MIRROR_RESP_MAX + 1))
check("oversize-200-refused", ok is False)

# 4. non-200 is refused without needing a body verdict
ok, resp = run_case(403, b"no")
check("non-200-refused", ok is False and resp.read_sizes == [])

# 5. a dead mirror (opener raises) is silence, never a crash
orig = host._OPENER
host._OPENER = FakeOpener(exc=OSError("down"))
try:
    check("unreachable-silence", host._mirror_post(
        "http://mirror.example", "/fed/announce", {}) is False)
finally:
    host._OPENER = orig

# 6. a mirror redirect is silence, never a referral: every 3xx is
# refused, the foreign target is never contacted, and a direct 200
# from the mirror itself still counts as accepted
target_hits = []


class Target(BaseHTTPRequestHandler):
    def _answer(self):
        target_hits.append(self.path)
        out = b'{"ok": true}'
        self.send_response(200)
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    do_GET = _answer
    do_POST = _answer

    def log_message(self, *a):
        pass


class Direct(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(n)
        out = json.dumps({"ok": True}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):
        pass


target = HTTPServer(("127.0.0.1", 0), Target)
threading.Thread(target=target.serve_forever, daemon=True).start()
target_url = f"http://127.0.0.1:{target.server_address[1]}"


class Redir(BaseHTTPRequestHandler):
    code = 302

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(n)
        self.send_response(self.code)
        self.send_header("Location", target_url + "/fed/announce")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *a):
        pass


try:
    for code in (301, 302, 303, 307, 308):
        Redir.code = code
        srv = HTTPServer(("127.0.0.1", 0), Redir)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            target_hits.clear()
            check(f"redirect-{code}-refused", host._mirror_post(
                f"http://127.0.0.1:{srv.server_address[1]}",
                "/fed/announce", {"x": 1}) is False)
            check(f"redirect-{code}-target-untouched", target_hits == [],
                  repr(target_hits))
        finally:
            srv.shutdown()
    direct = HTTPServer(("127.0.0.1", 0), Direct)
    threading.Thread(target=direct.serve_forever, daemon=True).start()
    try:
        check("direct-200-accepted", host._mirror_post(
            f"http://127.0.0.1:{direct.server_address[1]}",
            "/fed/announce", {"x": 1}) is True)
    finally:
        direct.shutdown()
    check("no-redirect-handler", host._NoRedirect().redirect_request(
        None, None, 302, "Found", {}, "http://127.0.0.1/") is None)
finally:
    target.shutdown()

print(f"{CHECKS - len(FAILURES)}/{CHECKS} checks passed")
for f in FAILURES:
    print("FAIL:", f)
sys.exit(1 if FAILURES else 0)
