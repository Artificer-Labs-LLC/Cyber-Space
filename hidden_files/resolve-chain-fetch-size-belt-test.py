#!/usr/bin/env python3
"""Belt test for resolve_chain._fetch's response read bound.

_fetch is the chain client's only mirror read: it took the rotations
document (and, via check_live, the live binding) with resp.read() —
no bound at all. The mirror is treated as untrusted for every shape
this client checks, yet a mirror (or a middlebox answering for it)
could stream an unbounded body straight into memory before any of
those checks ran. core bounds every peer read at 64KB
(_PEER_RESP_MAX / _read_peer_bytes: legit replies are a few hundred
bytes); _fetch now reads 64KB+1 twin-fashion and an oversize body
reads as a ChainError, never a parsed document.

The fake response honors REAL read semantics — read(n) returns at
most n bytes.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/resolve-chain-fetch-size-belt-test.py
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import resolve_chain  # noqa: E402

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


def _fetch_with(body: bytes):
    resp = FakeResp(body)
    orig = resolve_chain.urllib.request.urlopen
    resolve_chain.urllib.request.urlopen = lambda req, timeout=None: resp
    try:
        return resolve_chain._fetch("http://mirror.test/x"), resp, None
    except Exception as exc:  # noqa: BLE001 - belt records the shape
        return None, resp, exc
    finally:
        resolve_chain.urllib.request.urlopen = orig


# 1. Oversize VALID JSON is refused as oversize, never parsed.
big = json.dumps({"rotations": "x" * 70000}).encode()
check("crafted body is past the 64KB bound", len(big) > 65536, f"len={len(big)}")
doc, resp, err = _fetch_with(big)
check("oversize body raises ChainError", isinstance(err, resolve_chain.ChainError),
      f"err={err!r} doc={'parsed' if doc is not None else None}")
check("oversize reason names the bound", err is not None and "oversize" in str(err),
      f"err={err}")
check("read is bounded at 64KB+1", resp.asked == 65537, f"asked={resp.asked}")

# 2. Small well-formed document is unchanged.
small = json.dumps({"name": "foo", "rotations": []}).encode()
doc, _, err = _fetch_with(small)
check("small document parses whole", err is None and doc == {"name": "foo", "rotations": []},
      f"err={err} doc={doc}")

# 3. Exactly at the bound still parses.
pad_len = 65536 - len(json.dumps({"pad": ""}).encode())
exact = json.dumps({"pad": "y" * pad_len}).encode()
check("boundary body is exactly 65536 bytes", len(exact) == 65536, f"len={len(exact)}")
doc, _, err = _fetch_with(exact)
check("exactly-64KB document parses", err is None and doc is not None and len(doc["pad"]) == pad_len,
      f"err={err}")

print(f"\n{PASSED} passed, {FAILED} failed")
sys.exit(1 if FAILED else 0)
