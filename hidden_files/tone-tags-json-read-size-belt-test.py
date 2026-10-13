#!/usr/bin/env python3
"""Belt test for the tone-tags JSON read bound.

space_tone_tags_set in routes_spaces.py parsed its body with
`await request.json()` -- Starlette buffers the whole body before any
check runs. The only cap in front of it was app.py's global 2MB
BodyCapMiddleware, while every sibling form/JSON seat in the node reads
through core.read_bounded_* at FORM_BODY_LIMIT (64KB), and a tone-tags
body is legitimately a handful of short tags. The route now reads
through core.read_bounded_json: a claimed Content-Length past 64KB is
refused as 413 without a byte read, a lying/chunked body is refused
once the streamed total crosses 64KB, a malformed body keeps the
route's original 400 detail, and a valid small (or exactly-at-limit)
body still lands whole.

The fake request honors REAL semantics: json() slurps the whole
stream (the before-fix seat), stream() yields in fixed chunks and
records how many bytes were actually pulled (the after-fix seat).

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/tone-tags-json-read-size-belt-test.py
"""
import asyncio
import json
import os
import secrets
import sys
import tempfile
from pathlib import Path

TMP = tempfile.mkdtemp(prefix="cybernet-tone-tags-size-")
os.environ["CYBERNET_DB_DIR"] = TMP
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import core  # noqa: E402
import routes_spaces as rs  # noqa: E402
from core import FORM_BODY_LIMIT, _db, _db_lock, _now  # noqa: E402
from fastapi import HTTPException  # noqa: E402

core.init_db()

PASSED = FAILED = 0


def check(name, cond, extra=""):
    global PASSED, FAILED
    if cond:
        PASSED += 1
        print(f"  ok: {name}")
    else:
        FAILED += 1
        print(f"  FAIL: {name} {extra}")


API_KEY = "".join(["belt-", secrets.token_hex(12)])
SALT = secrets.token_hex(16)
with _db_lock, _db() as conn:
    conn.execute(
        "INSERT INTO agents (name, description, api_key_hash, salt, key_lookup, created_at, last_seen)"
        " VALUES ('ada', 'd', ?, ?, ?, ?, ?)",
        (core._hash_key(SALT, API_KEY), SALT,
         core._key_lookup_token(API_KEY), _now(), _now()))
AUTH = "Bearer " + API_KEY
LIMIT = FORM_BODY_LIMIT
CHUNK = 1024


class FakeRequest:
    def __init__(self, payload, claimed=None):
        self.payload = payload
        self.headers = {"content-length": str(len(payload) if claimed is None else claimed)}
        self.pulled = 0
        self.json_called = False

    async def stream(self):
        for i in range(0, len(self.payload), CHUNK):
            part = self.payload[i:i + CHUNK]
            self.pulled += len(part)
            yield part

    async def json(self):
        self.json_called = True
        data = b"".join([c async for c in self.stream()])
        return json.loads(data)


def set_tags(payload, claimed=None):
    fake = FakeRequest(payload, claimed=claimed)
    try:
        out = asyncio.run(rs.space_tone_tags_set("ada", fake, AUTH))
        return out, None, fake
    except HTTPException as e:
        return None, e, fake


def body_with_pad(total):
    base = json.dumps({"tags": ["[quiet]"], "pad": ""}).encode()
    pad = total - len(base)
    return json.dumps({"tags": ["[quiet]"], "pad": "x" * pad}).encode()


# 1. Oversize with an honest Content-Length: refused 413, nothing read,
#    and request.json() never runs.
big = body_with_pad(LIMIT * 2)
out, err, fake = set_tags(big)
check("oversize verdict is 413", err is not None and err.status_code == 413,
      f"out={out} err={err}")
check("oversize pulled zero bytes (claimed length refused up front)",
      fake.pulled == 0, f"pulled={fake.pulled}")
check("oversize never called request.json()", fake.json_called is False)

# 2. Oversize with a lying (absent) Content-Length: the streamed cap
#    still stops it at 413 shortly past the limit.
out, err, fake = set_tags(big, claimed=0)
check("lying-header oversize verdict is 413",
      err is not None and err.status_code == 413, f"out={out} err={err}")
check("lying-header read stopped near the limit",
      fake.pulled <= LIMIT + CHUNK, f"pulled={fake.pulled}")
check("lying-header never called request.json()", fake.json_called is False)

# 3. Exactly at the limit: a valid body still lands whole.
exact = body_with_pad(LIMIT)
check("at-limit fixture is exactly the limit", len(exact) == LIMIT)
out, err, fake = set_tags(exact)
check("at-limit accepted", out is not None and out.get("ok") is True, f"err={err}")
check("at-limit tags stored", out and out.get("tone_tags") == ["[quiet]"], f"out={out}")

# 4. Small valid body: accepted, tags stored.
out, err, fake = set_tags(json.dumps({"tags": ["[work]", "[quiet]"]}).encode())
check("small accepted", out is not None and out.get("ok") is True, f"err={err}")
check("small tags stored in order",
      out and out.get("tone_tags") == ["[work]", "[quiet]"], f"out={out}")

# 5. Malformed JSON: the route's original 400 detail is preserved.
out, err, fake = set_tags(b"{not json")
check("malformed verdict is 400", err is not None and err.status_code == 400,
      f"out={out} err={err}")
check("malformed detail preserved",
      err is not None and err.detail == "Body must be JSON with a 'tags' list.",
      f"detail={err.detail if err else None}")

# 6. Valid JSON, wrong shape: still the route's 400.
out, err, fake = set_tags(json.dumps({"tags": "nope"}).encode())
check("non-list tags verdict is 400", err is not None and err.status_code == 400,
      f"out={out} err={err}")

print(f"\ntone-tags-json-read-size belt: {PASSED} passed, {FAILED} failed")
sys.exit(1 if FAILED else 0)
