#!/usr/bin/env python3
"""Belt: resolver/host._mirror_post reads the mirror reply under 64KB.

Every other depth POST seat (mint/rotate/hold_open/core) reads its
mirror/peer reply under the same cap and treats oversize as silence;
_mirror_post judged by status alone and never read the body, so an
oversize 200 counted as an accepted announce.

Run from the repo root:  python3 hidden_files/hostd-mirror-resp-size-belt-test.py
"""
import os
import sys
import urllib.request

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


def run_case(status, body):
    resp = FakeResp(status, body)
    orig = urllib.request.urlopen
    host.urllib.request.urlopen = lambda req, timeout=None: resp
    try:
        return host._mirror_post("http://mirror.example", "/fed/announce",
                                 {"x": 1}), resp
    finally:
        host.urllib.request.urlopen = orig


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

# 5. a dead mirror (urlopen raises) is silence, never a crash
orig = urllib.request.urlopen
host.urllib.request.urlopen = lambda req, timeout=None: (_ for _ in ()).throw(OSError("down"))
try:
    check("unreachable-silence", host._mirror_post(
        "http://mirror.example", "/fed/announce", {}) is False)
finally:
    host.urllib.request.urlopen = orig

print(f"{CHECKS - len(FAILURES)}/{CHECKS} checks passed")
for f in FAILURES:
    print("FAIL:", f)
sys.exit(1 if FAILURES else 0)
