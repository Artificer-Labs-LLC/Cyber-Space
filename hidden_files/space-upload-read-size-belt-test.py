#!/usr/bin/env python3
"""Belt test for the space upload read bound.

space_upload in routes_spaces.py checked the 1MB per-file ceiling only
AFTER `await file.read()` had slurped the entire upload into memory --
the ceiling policed the verdict, never the read, so a sender could
stream an endless body into the node's memory before the 413 ever ran.
The read now asks for _SPACE_MAX_FILE + 1 bytes, twin of the bounded
peer-read family (core._PEER_RESP_MAX and friends). Oversize still
reads as the same 413 and nothing is written; exactly-at-ceiling and
small uploads still land whole.

The fake upload honors REAL read semantics -- read(n) returns at most
n bytes, read(-1) returns everything -- and records what it was asked
for and how many bytes were actually pulled.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/space-upload-read-size-belt-test.py
"""
import asyncio
import os
import secrets
import sys
import tempfile
from pathlib import Path

TMP = tempfile.mkdtemp(prefix="cybernet-space-upload-size-")
os.environ["CYBERNET_DB_DIR"] = TMP
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import core  # noqa: E402
import routes_spaces as rs  # noqa: E402
from core import _db, _db_lock, _now  # noqa: E402
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


API_KEY = "belt-" + secrets.token_hex(12)
SALT = secrets.token_hex(16)
with _db_lock, _db() as conn:
    conn.execute(
        "INSERT INTO agents (name, description, api_key_hash, salt, key_lookup, created_at, last_seen)"
        " VALUES ('ada', 'd', ?, ?, ?, ?, ?)",
        (core._hash_key(SALT, API_KEY), SALT,
         core._key_lookup_token(API_KEY), _now(), _now()))
AUTH = "Bearer " + API_KEY
MAXF = rs._SPACE_MAX_FILE


class FakeUpload:
    def __init__(self, payload):
        self.payload = payload
        self.asked = []
        self.pulled = 0

    async def read(self, size=-1):
        self.asked.append(size)
        chunk = self.payload if size is None or size < 0 else self.payload[:size]
        self.pulled += len(chunk)
        return chunk


def upload(payload, path):
    fake = FakeUpload(payload)
    try:
        out = asyncio.run(rs.space_upload("ada", AUTH, path, fake))
        return out, None, fake
    except HTTPException as e:
        return None, e, fake


# 1. Oversize: the read is bounded at ceiling+1 and the verdict is 413.
out, err, fake = upload(b"x" * (MAXF * 2), "big.html")
check("oversize read asked ceiling+1", fake.asked == [MAXF + 1], f"asked={fake.asked}")
check("oversize pulled only ceiling+1 bytes", fake.pulled == MAXF + 1, f"pulled={fake.pulled}")
check("oversize verdict is 413", err is not None and err.status_code == 413,
      f"out={out} err={err}")
check("oversize wrote nothing",
      not os.path.exists(os.path.join(rs._SPACES_DIR, "ada", "big.html")))

# 2. Exactly at ceiling: accepted whole, bytes on disk match.
exact = b"y" * MAXF
out, err, fake = upload(exact, "exact.html")
check("at-ceiling accepted", out is not None and out.get("ok") is True, f"err={err}")
check("at-ceiling upload_bytes is the ceiling", out and out.get("upload_bytes") == MAXF)
disk = Path(rs._SPACES_DIR) / "ada" / "exact.html"
check("at-ceiling file on disk whole", disk.exists() and disk.read_bytes() == exact)

# 3. Small upload: accepted, read asked is still the bounded ask.
small = b"<p>hi</p>"
out, err, fake = upload(small, "small.html")
check("small accepted", out is not None and out.get("ok") is True, f"err={err}")
check("small read asked ceiling+1", fake.asked == [MAXF + 1], f"asked={fake.asked}")
check("small pulled only its own bytes", fake.pulled == len(small), f"pulled={fake.pulled}")

print(f"\nspace-upload-read-size belt: {PASSED} passed, {FAILED} failed")
sys.exit(1 if FAILED else 0)
