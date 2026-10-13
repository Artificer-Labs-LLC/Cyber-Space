#!/usr/bin/env python3
"""Belt test for hold_open._post's response read bound.

_post is the hold-open daemon's only relay read: it took every relay
answer (register/wait/answer/keepalive) with resp.read() — no bound
at all. The relay is treated as untrusted for every shape this daemon
checks, yet a relay (or anything answering for it) could stream an
unbounded body straight into memory before any shape check ran.
core bounds every peer read at 64KB (_PEER_RESP_MAX) and
resolve_chain._fetch does the same (_FETCH_MAX); _post now reads
64KB+1 twin-fashion and an oversize body reads as silence (None),
never a parsed document — hold_open promises never to raise across
its boundary, and None is its word for a bad relay answer.

The fake response honors REAL read semantics — read(n) returns at
most n bytes.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/hold-open-fetch-size-belt-test.py
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import hold_open  # noqa: E402

PASSED = FAILED = 0


def check(name, cond, extra=""):
    global PASSED, FAILED
    if cond:
        PASSED += 1
        print(f"  ok: {name}")
    else:
        FAILED += 1
        print(f"  FAIL: {name} {extra}")


class FakeResp:
    """read(n) returns at most n bytes, like a real HTTP response."""

    status = 200

    def __init__(self, body: bytes):
        self.body = body
        self.asked = "never"

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self, n=-1):
        self.asked = n
        if n is None or n < 0:
            return self.body
        return self.body[:n]


def _post_with(body: bytes):
    resp = FakeResp(body)
    orig = hold_open.urllib.request.urlopen
    hold_open.urllib.request.urlopen = lambda req, timeout=None: resp
    try:
        return hold_open._post("http://relay.test", "/relay/wait",
                               {"token": "t"}, timeout=5), resp, None
    except Exception as exc:  # noqa: BLE001 - belt records the shape
        return None, resp, exc
    finally:
        hold_open.urllib.request.urlopen = orig


# 1. Oversize VALID JSON is refused as silence, never parsed.
big = json.dumps({"sessions": [], "pad": "x" * 70000}).encode()
check("crafted body is past the 64KB bound", len(big) > 65536, f"len={len(big)}")
data, resp, err = _post_with(big)
check("oversize body reads None, never raises",
      err is None and data is None, f"err={err!r} data={'parsed' if data else None}")
check("read is bounded at 64KB+1", resp.asked == 65537, f"asked={resp.asked}")

# 2. Small well-formed answer is unchanged.
small = json.dumps({"sessions": []}).encode()
data, _, err = _post_with(small)
check("small answer parses whole", err is None and data == {"sessions": []},
      f"err={err} data={data}")

# 3. Exactly at the bound still parses.
pad_len = 65536 - len(json.dumps({"pad": ""}).encode())
exact = json.dumps({"pad": "y" * pad_len}).encode()
check("boundary body is exactly 65536 bytes", len(exact) == 65536, f"len={len(exact)}")
data, _, err = _post_with(exact)
check("exactly-64KB answer parses", err is None and data is not None and len(data["pad"]) == pad_len,
      f"err={err}")

# 4. One byte past the bound reads None.
over = json.dumps({"pad": "y" * (pad_len + 1)}).encode()
check("over body is 65537 bytes", len(over) == 65537, f"len={len(over)}")
data, _, err = _post_with(over)
check("one-past-bound answer reads None", err is None and data is None,
      f"err={err} data={'parsed' if data else None}")

print(f"\nhold-open-fetch-size belt: {PASSED}/{PASSED + FAILED}")
sys.exit(1 if FAILED else 0)
