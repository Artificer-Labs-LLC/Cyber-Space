#!/usr/bin/env python3
"""Belt test for workspace invite/countersign peer read bounds.

workspace_invite and workspace_invite_countersign in routes_workspaces.py
are the last two raw-urlopen seats: both took the peer's answer with
resp.read() -- no bound at all. A peer is trusted only as far as its
signed envelope verifies, yet it could stream an unbounded body straight
into memory before any verdict ran. core bounds every peer read at 64KB
(_PEER_RESP_MAX, _read_peer_json) and the bounded client/proxy/federation
family was bounded tick by tick; these seats now read through
_read_peer_json twin-fashion. Oversize is never a parsed document:
invite reads it as its ordinary 502 closed window (no pending row
recorded), countersign reads it as its ordinary 502 closed window (the
local pending row is never marked). Exactly-64KB still parses.

Gate migration (later tick): both seats now ride core._peer_urlopen
instead of raw urlopen, so the SSRF/rebind/redirect/IP-pin gate runs
at fetch time like every other peer seat -- core's own invariant is
that every peer-side urlopen rides it. The fake transport below is
therefore installed at routes_workspaces._peer_urlopen, and the final
checks pin the wiring plus the unmocked fail-closed outcome for a
loopback peer URL the gate refuses. (The fake request was also moved
to the stream-based shape read_bounded_form requires.)

The fake response honors REAL read semantics -- read(n) returns at
most n bytes, and records the n it was asked for.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/workspace-fetch-size-belt-test.py
"""
import asyncio
import hashlib
import json
import os
import secrets
import sys
import tempfile
import urllib.parse
from pathlib import Path

TMP = tempfile.mkdtemp(prefix="cybernet-ws-fetch-size-")
os.environ["CYBERNET_DB_DIR"] = TMP
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import core  # noqa: E402
import routes_workspaces as rw  # noqa: E402
from core import _db, _db_lock, _now  # noqa: E402
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


PEER_SK = secrets.token_bytes(32).hex()
PEER_PK = ed25519.publickey(bytes.fromhex(PEER_SK)).hex()
HOME_SK = secrets.token_bytes(32).hex()
HOME_PK = ed25519.publickey(bytes.fromhex(HOME_SK)).hex()

api_key = "ws" + secrets.token_hex(16)
salt = secrets.token_hex(16)
CHARTER = "build a thing together"
CHARTER_HASH = hashlib.sha256(CHARTER.encode()).hexdigest()
with _db_lock, _db() as conn:
    cur = conn.execute(
        "INSERT INTO agents (name, description, api_key_hash, salt, key_lookup, created_at, last_seen)"
        " VALUES ('ada', 'd', ?, ?, ?, ?, ?)",
        (core._hash_key(salt, api_key), salt,
         core._key_lookup_token(api_key), _now(), _now()))
    ada_id = cur.lastrowid
    cur = conn.execute(
        "INSERT INTO workspaces (name, charter, state, created_by, created_at)"
        " VALUES ('room', ?, 'live', ?, ?)", (CHARTER, ada_id, _now()))
    WID = cur.lastrowid
    conn.execute(
        "INSERT INTO workspace_members (workspace_id, agent_id, signed_at)"
        " VALUES (?,?,?)", (WID, ada_id, _now()))
    cols = [r[1] for r in conn.execute("PRAGMA table_info(peers)").fetchall()]
    for name, pk, url in (("peer", PEER_PK, "http://peer.test"),
                          ("home", HOME_PK, "http://home.test")):
        row = {"node_pub": pk, "name": name, "network": "cybernet",
               "version": "0.1.0", "genesis": 0, "capabilities": "[]",
               "announced_at": _now(), "first_seen": _now(), "retired_at": ""}
        if "node_url" in cols:
            row["node_url"] = url
        keys = [k for k in row if k in cols]
        conn.execute(
            f"INSERT INTO peers ({','.join(keys)}) VALUES ({','.join('?' * len(keys))})",
            tuple(row[k] for k in keys))
AUTH = "Bearer " + api_key


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


class FakeReq:
    """Stream-based request shape read_bounded_form requires."""

    def __init__(self, form):
        self.payload = urllib.parse.urlencode(form).encode()
        self.headers = {"content-length": str(len(self.payload))}
        self.scope = {"type": "http", "method": "POST", "path": "/x",
                      "headers": [(b"content-type",
                                   b"application/x-www-form-urlencoded")]}

    async def stream(self):
        yield self.payload


def call(coro_fn, body: bytes):
    resp = FakeResp(body)
    orig = rw._peer_urlopen
    rw._peer_urlopen = lambda req, timeout=None: resp
    try:
        return asyncio.run(coro_fn()), resp, None
    except HTTPException as exc:
        return None, resp, exc
    finally:
        rw._peer_urlopen = orig


def remote_count(key):
    with _db() as conn:
        return conn.execute(
            "SELECT COUNT(*) FROM workspace_remote_members"
            " WHERE workspace_id=? AND agent_pub=?",
            (WID, key)).fetchone()[0]


def countersigned_at(key):
    with _db() as conn:
        row = conn.execute(
            "SELECT countersigned_at FROM workspace_remote_members"
            " WHERE workspace_id=? AND agent_pub=?", (WID, key)).fetchone()
        return row[0] if row else "missing"


def sized(base: dict, total: int) -> bytes:
    pad_len = total - len(json.dumps({**base, "pad": ""}).encode())
    return json.dumps({**base, "pad": "x" * pad_len}).encode()


def invite(key):
    return lambda: rw.workspace_invite(
        WID, FakeReq({"node": "peer", "agent_key": key}), authorization=AUTH)


def countersign(key):
    return lambda: rw.workspace_invite_countersign(
        WID, FakeReq({"node": "home", "agent_key": key,
                      "charter_hash": CHARTER_HASH}), authorization=AUTH)


BIG = sized({"invited": True}, 70000)
check("crafted body is past the 64KB bound", len(BIG) > 65536, f"len={len(BIG)}")

# 1. invite: oversize VALID answer is refused as 502, never parsed, no row.
k1 = "aa" * 32
out, resp, err = call(invite(k1), BIG)
check("invite oversize reads as 502 closed window",
      out is None and err is not None and err.status_code == 502,
      f"out={'parsed' if out else None} err={err!r}")
check("invite read is bounded at 64KB+1", resp.asked == 65537, f"asked={resp.asked}")
check("invite oversize records no pending row", remote_count(k1) == 0)

# 2. invite: small well-formed answer is unchanged.
k2 = "bb" * 32
out, _, err = call(invite(k2), json.dumps({"invited": True}).encode())
check("invite small answer invites",
      err is None and out is not None and out.get("invited") is True,
      f"err={err} out={out}")
check("invite small pending row recorded", remote_count(k2) == 1)

# 3. invite: exactly at the bound still parses.
k3 = "cc" * 32
exact = sized({"invited": True}, 65536)
check("boundary body is exactly 65536 bytes", len(exact) == 65536, f"len={len(exact)}")
out, _, err = call(invite(k3), exact)
check("invite exactly-64KB answer invites",
      err is None and out is not None and out.get("invited") is True, f"err={err}")

# countersign seats: pending rows on the invitee side (node_name='home').
for key in ("dd" * 32, "ee" * 32, "ff" * 32):
    with _db_lock, _db() as conn:
        conn.execute(
            "INSERT INTO workspace_remote_members"
            " (workspace_id, agent_pub, node_name, countersigned_at, struck_at)"
            " VALUES (?,?, 'home', NULL, NULL)", (WID, key))

# 4. countersign: oversize VALID answer is refused as 502, row never marked.
k4 = "dd" * 32
out, resp, err = call(countersign(k4), sized({"countersigned": True}, 70000))
check("countersign oversize reads as 502 closed window",
      out is None and err is not None and err.status_code == 502,
      f"out={'parsed' if out else None} err={err!r}")
check("countersign read is bounded at 64KB+1", resp.asked == 65537, f"asked={resp.asked}")
check("countersign oversize row never marked", countersigned_at(k4) is None)

# 5. countersign: small well-formed answer is unchanged.
k5 = "ee" * 32
out, _, err = call(countersign(k5), json.dumps({"countersigned": True}).encode())
check("countersign small answer countersigns",
      err is None and out is not None and out.get("countersigned") is True,
      f"err={err} out={out}")
check("countersign small row marked", countersigned_at(k5) is not None)

# 6. countersign: exactly at the bound still parses.
k6 = "ff" * 32
out, _, err = call(countersign(k6), sized({"countersigned": True}, 65536))
check("countersign exactly-64KB answer countersigns",
      err is None and out is not None and out.get("countersigned") is True,
      f"err={err} out={out}")
check("countersign exactly-64KB row marked", countersigned_at(k6) is not None)

# 7. Gate wiring: both seats ride core._peer_urlopen; no raw urlopen
#    remains in routes_workspaces.py.
src = (ROOT / "routes_workspaces.py").read_text()
check("routes_workspaces._peer_urlopen is core._peer_urlopen",
      rw._peer_urlopen is core._peer_urlopen)
check("no raw urlopen seat remains in routes_workspaces.py",
      "urllib.request.urlopen" not in src and src.count("_peer_urlopen(req") == 2,
      f"count={src.count('_peer_urlopen(req')}")

# 8. Unmocked: a loopback peer URL is refused by the gate at fetch
#    time -- invite reads it as its ordinary 502 and records no row;
#    countersign reads it as its ordinary 502 and never marks its row.
LOOP_PK = ed25519.publickey(bytes.fromhex(secrets.token_bytes(32).hex())).hex()
with _db_lock, _db() as conn:
    cols = [r[1] for r in conn.execute("PRAGMA table_info(peers)").fetchall()]
    row = {"node_pub": LOOP_PK, "name": "looppeer", "network": "cybernet",
           "version": "0.1.0", "genesis": 0, "capabilities": "[]",
           "announced_at": _now(), "first_seen": _now(), "retired_at": ""}
    if "node_url" in cols:
        row["node_url"] = "http://127.0.0.1:9"
    keys = [k for k in row if k in cols]
    conn.execute(
        f"INSERT INTO peers ({','.join(keys)}) VALUES ({','.join('?' * len(keys))})",
        tuple(row[k] for k in keys))
k7 = "77" * 32
try:
    asyncio.run(rw.workspace_invite(
        WID, FakeReq({"node": "looppeer", "agent_key": k7}), authorization=AUTH))
    gate_err = None
except HTTPException as exc:
    gate_err = exc
check("unmocked loopback invite refused as 502",
      gate_err is not None and gate_err.status_code == 502, f"err={gate_err!r}")
check("gate-refused invite records no row", remote_count(k7) == 0)
k8 = "88" * 32
with _db_lock, _db() as conn:
    conn.execute(
        "INSERT INTO workspace_remote_members"
        " (workspace_id, agent_pub, node_name, countersigned_at, struck_at)"
        " VALUES (?,?, 'looppeer', NULL, NULL)", (WID, k8))
try:
    asyncio.run(rw.workspace_invite_countersign(
        WID, FakeReq({"node": "looppeer", "agent_key": k8,
                      "charter_hash": CHARTER_HASH}), authorization=AUTH))
    gate_err = None
except HTTPException as exc:
    gate_err = exc
check("unmocked loopback countersign refused as 502",
      gate_err is not None and gate_err.status_code == 502, f"err={gate_err!r}")
check("gate-refused countersign row never marked", countersigned_at(k8) is None)

print(f"\nworkspace-fetch-size belt: {PASSED}/{PASSED + FAILED}")
sys.exit(1 if FAILED else 0)
