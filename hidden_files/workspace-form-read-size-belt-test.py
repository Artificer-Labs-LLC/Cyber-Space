#!/usr/bin/env python3
"""Belt test for the workspace form read bound.

All six form seats in routes_workspaces.py (create, entry add, accept,
invite, countersign, remove_remote) parsed with `await request.form()` --
Starlette buffers the whole body before any check runs, and only
app.py's global 2MB BodyCap stood in front of them, while every sibling
form seat in the node reads through core.read_bounded_form at
FORM_BODY_LIMIT (64KB) and every workspace field is legitimately small
(charter <=2KB, entry <=10KB, the rest short strings). The routes now
read through read_bounded_form: a claimed Content-Length past 64KB is
refused 413 without a byte read, a lying/chunked body is refused once
the streamed total crosses 64KB, and a valid small (or exactly-at-limit)
body still lands whole.

Behavioural checks run against workspace_create; the other five seats
are pinned by source checks that each uses read_bounded_form and that
no raw request.form() remains in the module.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/workspace-form-read-size-belt-test.py
"""
import asyncio
import os
import secrets
import sys
import tempfile
import urllib.parse
from pathlib import Path

TMP = tempfile.mkdtemp(prefix="cybernet-ws-form-size-")
os.environ["CYBERNET_DB_DIR"] = TMP
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import core  # noqa: E402
import routes_workspaces as rw  # noqa: E402
from core import FORM_BODY_LIMIT, _db, _db_lock, _now  # noqa: E402
from fastapi import HTTPException  # noqa: E402
from starlette.datastructures import FormData  # noqa: E402

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
    for n in ("ada", "bob"):
        conn.execute(
            "INSERT INTO agents (name, description, api_key_hash, salt, key_lookup, created_at, last_seen)"
            " VALUES (?, 'd', ?, ?, ?, ?, ?)",
            (n, core._hash_key(SALT, API_KEY), SALT,
             core._key_lookup_token(API_KEY), _now(), _now()))
AUTH = "Bearer " + API_KEY
LIMIT = FORM_BODY_LIMIT
CHUNK = 1024


class FakeRequest:
    def __init__(self, payload, claimed=None):
        self.payload = payload
        self.headers = {"content-length": str(len(payload) if claimed is None else claimed)}
        self.scope = {"type": "http", "method": "POST", "path": "/api/v1/workspaces",
                      "headers": [(b"content-type", b"application/x-www-form-urlencoded")]}
        self.pulled = 0
        self.form_called = False

    async def stream(self):
        for i in range(0, len(self.payload), CHUNK):
            part = self.payload[i:i + CHUNK]
            self.pulled += len(part)
            yield part

    async def form(self):
        self.form_called = True
        data = b"".join([c async for c in self.stream()])
        return FormData(urllib.parse.parse_qsl(data.decode()))


def create(payload, claimed=None):
    fake = FakeRequest(payload, claimed=claimed)
    try:
        return asyncio.run(rw.workspace_create(fake, AUTH)), None, fake
    except HTTPException as e:
        return None, e, fake


def body(charter_len, name="roomone"):
    return urllib.parse.urlencode(
        {"name": name, "charter": "x" * charter_len, "members": "ada,bob"}).encode()


# 1. Oversize, honest length: 413, zero bytes pulled, form() never runs.
big = body(LIMIT * 2)
out, err, fake = create(big)
check("oversize verdict is 413", err is not None and err.status_code == 413, f"out={out} err={err}")
check("oversize pulled zero bytes", fake.pulled == 0, f"pulled={fake.pulled}")
check("oversize never called request.form()", fake.form_called is False)

# 2. Oversize, lying length: streamed cap still stops it near the limit.
out, err, fake = create(big, claimed=0)
check("lying-header oversize is 413", err is not None and err.status_code == 413, f"err={err}")
check("lying-header read stopped near limit", fake.pulled <= LIMIT + CHUNK, f"pulled={fake.pulled}")

# 3. Exactly at limit lands whole: pad charter so total == LIMIT, but
#    charter >2KB is refused by the route's own 400 -- proving the body
#    was parsed (a 413 would mean the bound, not the route, refused).
exact = body(LIMIT - len(body(0)))
check("at-limit fixture is exactly the limit", len(exact) == LIMIT, f"len={len(exact)}")
out, err, fake = create(exact)
check("at-limit parsed by route (400 charter, not 413)",
      err is not None and err.status_code == 400 and "Charter" in err.detail, f"err={err}")

# 4. Small valid body: workspace created.
out, err, fake = create(body(20))
check("small accepted", out is not None and out.get("name") == "roomone", f"out={out} err={err}")
check("small members recorded", out and out.get("members") == ["ada", "bob"], f"out={out}")

# 5. Route validation unchanged: short name still its 400.
out, err, fake = create(urllib.parse.urlencode(
    {"name": "ab", "charter": "ok", "members": "ada,bob"}).encode())
check("short name verdict is 400", err is not None and err.status_code == 400, f"err={err}")
check("short name detail preserved",
      err is not None and err.detail == "Workspace name must be 3-64 chars.", f"detail={err.detail if err else None}")

# 6. Source pins: all six seats bounded, no raw form() left in module.
src = (ROOT / "routes_workspaces.py").read_text()
check("six read_bounded_form seats", src.count("await read_bounded_form(request)") == 6,
      f"count={src.count('await read_bounded_form(request)')}")
check("no raw request.form() remains", "await request.form()" not in src)

print(f"\nworkspace-form-read-size belt: {PASSED} passed, {FAILED} failed")
sys.exit(1 if FAILED else 0)
