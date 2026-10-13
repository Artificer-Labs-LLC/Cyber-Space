#!/usr/bin/env python3
"""Belt test for the _push_to_peer 403 error-body read bound.

_push_to_peer's success path already reads through _read_peer_bytes
(64KB bound), but its HTTPError path took the peer's 403 body with
e.read() -- no bound at all. A peer is trusted only as far as its
signed state verifies, yet a hostile or broken peer answering a
channel push could stream an unbounded error body straight into
memory before the consent-reconcile verdict ran on it. This was the
one e.read() seat left after the resp.read() family was closed.

Oversize is never a parsed document: the 403 body reads as no
detail, so the channel_subs row is kept (the caller's ordinary
outcome for a 403 that does not carry the consent-missing detail).
A small consent-missing 403 still drops the row, a 403 with any
other detail still keeps it, and an exactly-64KB consent-missing
body still parses and drops it.

The fake fp honors REAL read semantics -- read(n) returns at most
n bytes, and records the n it was asked for.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/push-peer-error-fetch-size-belt-test.py
"""
import json
import os
import secrets
import sys
import tempfile
import urllib.error
from pathlib import Path

TMP = tempfile.mkdtemp(prefix="cybernet-push-error-fetch-size-")
os.environ["CYBERNET_DB_DIR"] = TMP
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import core  # noqa: E402
from core import _db, _db_lock  # noqa: E402
from fed import ed25519  # noqa: E402

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


PEER_PK = ed25519.publickey(secrets.token_bytes(32)).hex()
with _db_lock, _db() as conn:
    conn.execute(
        "INSERT INTO channels (name, topic, kind, created_at) VALUES (?,?, 'channel', ?)",
        ("square", "", "2026-10-09T00:00:00Z"))
    CH_ID = conn.execute(
        "SELECT id FROM channels WHERE name='square'").fetchone()["id"]


def seed_row():
    with _db_lock, _db() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO channel_subs (channel_id, node_pub, from_agent, created_at)"
            " VALUES (?,?,?,?)", (CH_ID, PEER_PK, "zoe", "2026-10-09T00:00:00Z"))


def row_count():
    with _db_lock, _db() as conn:
        return conn.execute(
            "SELECT COUNT(*) FROM channel_subs WHERE channel_id=? AND node_pub=? AND from_agent='zoe'",
            (CH_ID, PEER_PK)).fetchone()[0]


class FakeFP:
    """read(n) returns at most n bytes, like a real HTTP error body."""

    def __init__(self, body: bytes):
        self.body = body
        self.asked = "never"
        self.pos = 0

    def read(self, n=-1):
        self.asked = n
        if n is None or n < 0:
            chunk = self.body[self.pos:]
        else:
            chunk = self.body[self.pos:self.pos + n]
        self.pos += len(chunk)
        return chunk

    def close(self):
        pass

    def readline(self, limit=-1):
        return b""

    def info(self):
        return {}


def push_with_error(body: bytes, code=403):
    fp = FakeFP(body)

    def boom(req, timeout=8):
        raise urllib.error.HTTPError(
            "http://peer.test/fed/channel/push", code, "err", None, fp)

    orig = core._peer_urlopen
    core._peer_urlopen = boom
    try:
        core._push_to_peer(CH_ID, PEER_PK, "zoe", "http://peer.test", {"x": 1})
    finally:
        core._peer_urlopen = orig
    return fp


def padded(detail: str, total: int) -> bytes:
    raw = json.dumps({"detail": detail}).encode()
    assert len(raw) <= total
    return raw + b" " * (total - len(raw))


CONSENT = "no subscription: this node never asked for this feed"

# 1. Small consent-missing 403: row dropped (the reconcile still works).
seed_row()
fp = push_with_error(padded(CONSENT, 200))
check("small consent-missing 403 drops the row", row_count() == 0)
check("small body read was bounded", fp.asked == core._PEER_RESP_MAX + 1,
      f"asked={fp.asked}")

# 2. 403 with any other detail: row kept.
seed_row()
push_with_error(padded("retired node", 200))
check("other-detail 403 keeps the row", row_count() == 1)

# 3. Oversize consent-missing 403: never parsed, row kept, read bounded.
push_with_error(padded(CONSENT, core._PEER_RESP_MAX + 5000))
check("oversize consent-missing 403 keeps the row", row_count() == 1)
fp2 = push_with_error(padded(CONSENT, core._PEER_RESP_MAX + 5000))
check("oversize body read was bounded", fp2.asked == core._PEER_RESP_MAX + 1,
      f"asked={fp2.asked}")
check("oversize repeat still keeps the row", row_count() == 1)

# 4. Exactly-64KB consent-missing body: still parses, row dropped.
push_with_error(padded(CONSENT, core._PEER_RESP_MAX))
check("exactly-64KB consent-missing 403 drops the row", row_count() == 0)

print(f"\n{PASSED} passed, {FAILED} failed")
sys.exit(1 if FAILED else 0)
