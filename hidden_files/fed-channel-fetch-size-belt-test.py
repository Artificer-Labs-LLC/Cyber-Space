#!/usr/bin/env python3
"""Belt test for federation channel subscribe/unsubscribe peer read bounds.

fed_subscribe and fed_unsubscribe are federation.py's two outbound
peer reads: both rode raw urllib.request.urlopen and took the peer's
answer with resp.read() — no bound at all. A peer is trusted only as
far as its signed/roster state verifies, yet it could stream an
unbounded body straight into memory before any verdict ran. core
bounds every peer read at 64KB (_PEER_RESP_MAX, _read_peer_json) and
the client/proxy family was bounded tick by tick; these seats now
read through _read_peer_json twin-fashion. Oversize is never a
parsed document: subscribe reads it as its ordinary peer-join
failure (502, consent row rolled back) and unsubscribe reads it as
peer_cleaned=False (its ordinary unreachable-peer outcome).
Exactly-64KB still parses.

Gate migration (later tick): both seats now ride core._peer_urlopen
instead of raw urlopen, so the SSRF/rebind/redirect/IP-pin gate runs
at fetch time like every other peer seat — core's own invariant is
that every peer-side urlopen rides it. The fake transport below is
therefore installed at federation._peer_urlopen, and the final
checks pin the wiring plus the unmocked fail-closed outcome for a
loopback peer URL the gate refuses.

The fake response honors REAL read semantics — read(n) returns at
most n bytes, and records the n it was asked for.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/fed-channel-fetch-size-belt-test.py
"""
import json
import os
import secrets
import sys
import tempfile
from pathlib import Path

TMP = tempfile.mkdtemp(prefix="cybernet-fedchan-fetch-size-")
os.environ["CYBERNET_DB_DIR"] = TMP
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import core  # noqa: E402
import federation  # noqa: E402
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

api_key = secrets.token_hex(32)
salt = secrets.token_hex(16)
with _db_lock, _db() as conn:
    conn.execute(
        "INSERT INTO agents (name, description, api_key_hash, salt, key_lookup, created_at, last_seen)"
        " VALUES (?, 'd', ?, ?, ?, ?, ?)",
        ("ada", core._hash_key(salt, api_key), salt,
         core._key_lookup_token(api_key), _now(), _now()))
    cols = [r[1] for r in conn.execute("PRAGMA table_info(peers)").fetchall()]
    row = {"node_pub": PEER_PK, "name": "peer", "network": "cybernet",
           "version": "0.1.0", "genesis": 0, "capabilities": "[]",
           "announced_at": _now(), "first_seen": _now(), "retired_at": ""}
    if "node_url" in cols:
        row["node_url"] = "http://peer.test"
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


def call(fn, body: bytes):
    resp = FakeResp(body)
    orig = federation._peer_urlopen
    federation._peer_urlopen = lambda req, timeout=None: resp
    try:
        return fn(), resp, None
    except HTTPException as exc:
        return None, resp, exc
    finally:
        federation._peer_urlopen = orig


def subs_count(channel):
    with _db() as conn:
        return conn.execute(
            "SELECT COUNT(*) FROM outbound_subs WHERE node_pub=? AND channel=?",
            (PEER_PK, channel)).fetchone()[0]


def sized(base: dict, total: int) -> bytes:
    pad_len = total - len(json.dumps({**base, "pad": ""}).encode())
    return json.dumps({**base, "pad": "x" * pad_len}).encode()


BIG = sized({"ok": True}, 70000)
check("crafted body is past the 64KB bound", len(BIG) > 65536, f"len={len(BIG)}")

# 1. subscribe: oversize VALID answer is refused as 502, never parsed,
#    and the consent row is rolled back.
out, resp, err = call(lambda: federation.fed_subscribe(
    {"channel": "chanbig", "node_pub": PEER_PK}, AUTH), BIG)
check("subscribe oversize reads as 502 peer-join failure",
      out is None and err is not None and err.status_code == 502,
      f"out={'parsed' if out else None} err={err!r}")
check("subscribe read is bounded at 64KB+1", resp.asked == 65537,
      f"asked={resp.asked}")
check("subscribe oversize consent row rolled back", subs_count("chanbig") == 0)

# 2. subscribe: small well-formed answer is unchanged.
out, _, err = call(lambda: federation.fed_subscribe(
    {"channel": "chansmall", "node_pub": PEER_PK}, AUTH),
    json.dumps({"ok": True}).encode())
check("subscribe small answer joins",
      err is None and out is not None and out.get("ok") is True
      and out.get("joined", {}).get("ok") is True,
      f"err={err} out={out}")
check("subscribe small consent row kept", subs_count("chansmall") == 1)

# 3. subscribe: exactly at the bound still parses.
exact = sized({"ok": True}, 65536)
check("boundary body is exactly 65536 bytes", len(exact) == 65536,
      f"len={len(exact)}")
out, _, err = call(lambda: federation.fed_subscribe(
    {"channel": "chanexact", "node_pub": PEER_PK}, AUTH), exact)
check("subscribe exactly-64KB answer joins",
      err is None and out is not None and out.get("ok") is True,
      f"err={err}")

# 4. unsubscribe: oversize VALID answer reads as peer_cleaned=False.
out, resp, err = call(lambda: federation.fed_unsubscribe(
    {"channel": "chansmall", "node_pub": PEER_PK}, AUTH),
    sized({"removed": True}, 70000))
check("unsubscribe oversize reads as peer_cleaned=False",
      err is None and out is not None and out.get("peer_cleaned") is False,
      f"err={err} out={out}")
check("unsubscribe read is bounded at 64KB+1", resp.asked == 65537,
      f"asked={resp.asked}")

# 5. unsubscribe: small well-formed answer is unchanged.
out, _, err = call(lambda: federation.fed_unsubscribe(
    {"channel": "chanexact", "node_pub": PEER_PK}, AUTH),
    json.dumps({"removed": True}).encode())
check("unsubscribe small answer reports peer_cleaned=True",
      err is None and out is not None and out.get("peer_cleaned") is True,
      f"err={err} out={out}")

# 6. unsubscribe: exactly at the bound still parses.
exact = sized({"removed": True}, 65536)
out, _, err = call(lambda: federation.fed_unsubscribe(
    {"channel": "chanbig", "node_pub": PEER_PK}, AUTH), exact)
check("unsubscribe exactly-64KB answer reports peer_cleaned=True",
      err is None and out is not None and out.get("peer_cleaned") is True,
      f"err={err} out={out}")

# 7. Gate wiring: both seats ride core._peer_urlopen; no raw urlopen
#    remains in federation.py.
src = (ROOT / "federation.py").read_text()
check("federation._peer_urlopen is core._peer_urlopen",
      federation._peer_urlopen is core._peer_urlopen)
check("no raw urlopen seat remains in federation.py",
      "urllib.request.urlopen" not in src and src.count("_peer_urlopen(req") == 2,
      f"count={src.count('_peer_urlopen(req')}")

# 8. Unmocked: a loopback peer URL is refused by the gate at fetch
#    time — subscribe reads it as its ordinary 502 and rolls back.
LOOP_SK = secrets.token_bytes(32).hex()
LOOP_PK = ed25519.publickey(bytes.fromhex(LOOP_SK)).hex()
with _db_lock, _db() as conn:
    cols = [r[1] for r in conn.execute("PRAGMA table_info(peers)").fetchall()]
    row = {"node_pub": LOOP_PK, "name": "looppeer", "network": "cybernet",
           "version": "0.1.0", "genesis": 0, "capabilities": "[]",
           "announced_at": _now(), "first_seen": _now(), "retired_at": "",
           "node_url": "http://127.0.0.1:9"}
    keys = [k for k in row if k in cols]
    conn.execute(
        f"INSERT INTO peers ({','.join(keys)}) VALUES ({','.join('?' * len(keys))})",
        tuple(row[k] for k in keys))
try:
    federation.fed_subscribe({"channel": "gatechan", "node_pub": LOOP_PK}, AUTH)
    gate_err = None
except HTTPException as exc:
    gate_err = exc
check("unmocked loopback subscribe refused as 502",
      gate_err is not None and gate_err.status_code == 502,
      f"err={gate_err!r}")
with _db() as conn:
    n = conn.execute(
        "SELECT COUNT(*) FROM outbound_subs WHERE node_pub=? AND channel=?",
        (LOOP_PK, "gatechan")).fetchone()[0]
check("gate-refused subscribe consent row rolled back", n == 0)

print(f"\nfed-channel-fetch-size belt: {PASSED}/{PASSED + FAILED}")
sys.exit(1 if FAILED else 0)
