#!/usr/bin/env python3
"""Belt test for mint_name's mirror-response read bounds.

_get_json and _post_form are mint_name's only mirror reads: both took
every mirror answer with resp.read() — no bound at all (and the
HTTPError path in _post_form did the same). The mirror is treated as
untrusted for every shape this client checks, yet it could stream an
unbounded body straight into memory before any verdict ran.
core bounds every peer read at 64KB (_PEER_RESP_MAX) and
resolve_chain._fetch / hold_open._post do the same; mint_name now
reads 64KB+1 twin-fashion in both helpers, on success and on
HTTPError alike. An oversize body is never a parsed document:
_get_json reads it as None (its word for a bad mirror answer) and
_post_form returns an empty body, so a 200 claim answer reads as the
unparseable-response refusal the caller already gives.

The fake response honors REAL read semantics — read(n) returns at
most n bytes.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/mint-fetch-size-belt-test.py
"""
import io
import json
import sys
import urllib.error
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import mint_name  # noqa: E402

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


def _with_urlopen(resp_or_exc, fn):
    orig = mint_name.urllib.request.urlopen
    if isinstance(resp_or_exc, Exception):
        def fake(req, timeout=None):
            raise resp_or_exc
    else:
        def fake(req, timeout=None):
            return resp_or_exc
    mint_name.urllib.request.urlopen = fake
    try:
        return fn(), None
    except Exception as exc:  # noqa: BLE001 - belt records the shape
        return None, exc
    finally:
        mint_name.urllib.request.urlopen = orig


BIG = json.dumps({"node_pubkey": "ab" * 32, "pad": "x" * 70000}).encode()
check("crafted body is past the 64KB bound", len(BIG) > 65536, f"len={len(BIG)}")

# 1. _get_json: oversize VALID JSON is refused as None, never parsed.
resp = FakeResp(BIG)
data, err = _with_urlopen(resp, lambda: mint_name._get_json("http://m.test/x"))
check("_get_json oversize reads None, never raises",
      err is None and data is None, f"err={err!r} data={'parsed' if data else None}")
check("_get_json read is bounded at 64KB+1", resp.asked == 65537,
      f"asked={resp.asked}")

# 2. _get_json: small well-formed answer is unchanged.
small = json.dumps({"node_pubkey": "cd" * 32}).encode()
data, err = _with_urlopen(FakeResp(small),
                          lambda: mint_name._get_json("http://m.test/x"))
check("_get_json small answer parses whole",
      err is None and data == {"node_pubkey": "cd" * 32}, f"err={err} data={data}")

# 3. _get_json: exactly at the bound still parses; one past reads None.
pad_len = 65536 - len(json.dumps({"pad": ""}).encode())
exact = json.dumps({"pad": "y" * pad_len}).encode()
check("boundary body is exactly 65536 bytes", len(exact) == 65536,
      f"len={len(exact)}")
data, err = _with_urlopen(FakeResp(exact),
                          lambda: mint_name._get_json("http://m.test/x"))
check("_get_json exactly-64KB answer parses",
      err is None and data is not None and len(data["pad"]) == pad_len,
      f"err={err}")
over = json.dumps({"pad": "y" * (pad_len + 1)}).encode()
data, err = _with_urlopen(FakeResp(over),
                          lambda: mint_name._get_json("http://m.test/x"))
check("_get_json one-past-bound reads None",
      err is None and data is None, f"err={err} data={'parsed' if data else None}")

# 4. _post_form: oversize VALID JSON is never returned as a body.
resp = FakeResp(BIG)
out, err = _with_urlopen(resp, lambda: mint_name._post_form(
    "http://m.test/claim", {"a": "b"}))
check("_post_form oversize returns (200, ''), never raises",
      err is None and out == (200, ""), f"err={err!r} out={out!r:.80}")
check("_post_form read is bounded at 64KB+1", resp.asked == 65537,
      f"asked={resp.asked}")

# 5. _post_form: small answer is unchanged.
resp = FakeResp(b'{"status":"claimed"}')
out, err = _with_urlopen(resp, lambda: mint_name._post_form(
    "http://m.test/claim", {"a": "b"}))
check("_post_form small answer returns whole",
      err is None and out == (200, '{"status":"claimed"}'),
      f"err={err} out={out!r}")

# 6. _post_form HTTPError path: oversize error body is bounded too.
httperr = urllib.error.HTTPError("http://m.test/claim", 500, "err",
                                 None, io.BytesIO(BIG))
out, err = _with_urlopen(httperr, lambda: mint_name._post_form(
    "http://m.test/claim", {"a": "b"}))
check("_post_form HTTPError oversize returns (500, ''), never raises",
      err is None and out == (500, ""), f"err={err!r} out={out!r:.80}")

print(f"\nmint-fetch-size belt: {PASSED}/{PASSED + FAILED}")
sys.exit(1 if FAILED else 0)
