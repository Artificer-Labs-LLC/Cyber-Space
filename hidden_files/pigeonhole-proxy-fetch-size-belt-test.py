#!/usr/bin/env python3
"""Belt test for _proxied_pigeonholes' peer-response read bound.

The caller half of the pigeonhole proxy (routes_social.py) rides
_peer_urlopen (SSRF/rebind gate runs) but then took the origin's
answer with resp.read() — no bound at all. The origin is a peer: it is
trusted only as far as its signed envelope verifies, yet it could
stream an unbounded body straight into memory before any verdict
ran. core bounds every other peer read at 64KB (_PEER_RESP_MAX,
_read_peer_bytes/_read_peer_json) and the client family
(resolve_chain, hold_open, mint_name, rotate_name) was bounded tick
by tick; this seat now reads through _read_peer_json twin-fashion,
so an oversize answer raises inside the try and reads as the
caller's ordinary 502 closed window, never a parsed document.
Exactly-64KB still parses.

The fake response honors REAL read semantics — read(n) returns at
most n bytes, and records the n it was asked for.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/pigeonhole-proxy-fetch-size-belt-test.py
"""
import json
import os
import secrets
import sys
import tempfile
import time
from pathlib import Path

TMP = tempfile.mkdtemp(prefix="cybernet-pigeonhole-fetch-size-")
os.environ["CYBERNET_DB_DIR"] = TMP
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import core  # noqa: E402
import routes_social  # noqa: E402
from core import _db, _now  # noqa: E402
from fed import envelope as fenv  # noqa: E402
from fed import ed25519  # noqa: E402
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


ORIGIN_SK = secrets.token_bytes(32).hex()
ORIGIN_PK = ed25519.publickey(bytes.fromhex(ORIGIN_SK)).hex()

with _db() as conn:
    cols = [r[1] for r in conn.execute("PRAGMA table_info(peers)").fetchall()]
    row = {"node_pub": ORIGIN_PK, "name": "origin", "network": "cybernet",
           "version": "0.1.0", "genesis": 0, "capabilities": "[]",
           "announced_at": _now(), "first_seen": _now(), "retired_at": ""}
    if "node_url" in cols:
        row["node_url"] = "http://origin.test"
    keys = [k for k in row if k in cols]
    conn.execute(
        f"INSERT INTO peers ({','.join(keys)}) VALUES ({','.join('?' * len(keys))})",
        tuple(row[k] for k in keys))


def make_reply(pad_len=0):
    body = {"origin_node": "origin",
            "pigeonholes": [{"agent": "ada", "body": "hi",
                             "created_at": "2026-10-12T00:00:00Z"}],
            "count": 1}
    if pad_len:
        body["pad"] = "x" * pad_len
    env = fenv.make_envelope(ORIGIN_SK, ORIGIN_PK, core._NODE_PUB, body,
                             ts=int(time.time()))
    return json.dumps(env).encode()


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


def call_with(body: bytes):
    resp = FakeResp(body)
    orig = routes_social._peer_urlopen
    routes_social._peer_urlopen = lambda req, timeout=None: resp
    try:
        return routes_social._proxied_pigeonholes("origin", 20), resp, None
    except HTTPException as exc:
        return None, resp, exc
    finally:
        routes_social._peer_urlopen = orig


# 1. Oversize VALID signed envelope is refused as a 502, never parsed.
big = make_reply(pad_len=70000)
check("crafted body is past the 64KB bound", len(big) > 65536, f"len={len(big)}")
out, resp, err = call_with(big)
check("oversize body reads as 502 closed window",
      out is None and err is not None and err.status_code == 502,
      f"out={'parsed' if out else None} err={err!r}")
check("read is bounded at 64KB+1", resp.asked == 65537, f"asked={resp.asked}")

# 2. Small well-formed signed answer is unchanged.
small = make_reply()
out, _, err = call_with(small)
check("small answer renders proxied board",
      err is None and out is not None and out.get("proxied") is True
      and out.get("count") == 1
      and out["pigeonholes"][0]["agent"] == "ada@origin",
      f"err={err} out={out}")

# 3. Exactly at the bound still parses.
# Length with an empty pad value: each extra pad char adds exactly 1 byte.
unit_len = len(make_reply(pad_len=1)) - 1
exact = make_reply(pad_len=65536 - unit_len)
check("boundary body is exactly 65536 bytes", len(exact) == 65536,
      f"len={len(exact)}")
out, _, err = call_with(exact)
check("exactly-64KB answer parses",
      err is None and out is not None and out.get("count") == 1,
      f"err={err}")

# 4. One byte past the bound reads as 502.
over = make_reply(pad_len=65536 - unit_len + 1)
check("over body is 65537 bytes", len(over) == 65537, f"len={len(over)}")
out, _, err = call_with(over)
check("one-past-bound answer reads as 502",
      out is None and err is not None and err.status_code == 502,
      f"out={'parsed' if out else None} err={err!r}")

print(f"\npigeonhole-proxy-fetch-size belt: {PASSED}/{PASSED + FAILED}")
sys.exit(1 if FAILED else 0)
