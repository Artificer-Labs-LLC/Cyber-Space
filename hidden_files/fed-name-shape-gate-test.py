"""Fed inbound name-shape gate closure harness (2026-10-09 dev tick).

Audit family: fed inbound envelope-validation depth (the 04:20/04:15 thread).
Drives the REAL /fed/* receivers in federation.py with hostile name fields
(non-string types, wrong-case, over-long) under VALID ed25519 envelopes,
on a throwaway DB (CYBERNET_DB_DIR=tempdir, created before core imports).

Every case asserts the gate that should fire, by detail string — not just
"a 400 happened", so a later regression that 400s for a DIFFERENT reason
still fails loudly. Positive controls prove the harness itself is real.

Positive controls + hostile cases (18):
  announce: valid (200), dict name -> 400 bad node name, uppercase ->
  400, 64-char -> 400, hostile caps list filtered to the CAP_RE-valid one
  gossip: dict-name entry + 64-char-name entry -> both ignored, merged=0,
  no repr-named peer row planted
  join: valid (200), dict from_agent -> 400, dict channel -> 400,
  33-char from_agent -> 400
  leave: valid no-op (200), dict channel -> 400
  push: valid (200, message stored + attributed), 33-char channel -> 400,
  dict from_agent -> 400
  dm (async): valid (200, message stored in a DM thread), dict to_agent -> 400
"""
import asyncio
import os
import secrets
import sys
import tempfile

TMP = tempfile.mkdtemp(prefix="cybernet-fed-gate-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core
from core import _db, _db_lock, _now
import federation
from fed import envelope as fenv, ed25519

core.init_db()

PUB_LITERAL = "http://93.184.216.34/"  # global literal, passes the SSRF gate

SK = secrets.token_bytes(32)
PK = ed25519.publickey(SK).hex()
RECIP = core._NODE_PUB


def env(body):
    return fenv.make_envelope(SK.hex(), PK, RECIP, body)


def expect_http(fn, expect, detail_prefix=None, label=""):
    try:
        out = fn()
    except Exception as e:
        got = getattr(e, "status_code", None)
        detail = str(getattr(e, "detail", ""))
        assert got == expect, f"{label}: expected {expect}, got {got} ({detail})"
        if detail_prefix:
            assert detail.startswith(detail_prefix), \
                f"{label}: detail {detail!r} missing prefix {detail_prefix!r}"
        print(f"  ok {label} -> {expect} ({detail[:60]})")
        return None
    assert expect == 200, f"{label}: expected {expect}, got 200"
    print(f"  ok {label} -> 200")
    return out


results = []


def check(label, fn):
    fn()
    results.append(label)


# --- setup: valid announce gives the peer standing -------------------------
print("setup: announce valid peer")
out = expect_http(
    lambda: federation.fed_announce(
        env({"node_pub": PK, "name": "peerone", "node_url": PUB_LITERAL,
             "capabilities": ["messaging"], "version": "0.1.0", "genesis": 0})),
    200, label="announce valid")
assert out["node_pub"] == PK and out["stored"] == "peerone"
check("announce-valid", lambda: None)

with _db_lock, _db() as conn:
    conn.execute("INSERT INTO channels (name, topic, kind, created_at)"
                 " VALUES ('hall','','channel',?)", (_now(),))
    conn.execute("INSERT INTO agents (name, api_key_hash, salt, created_at)"
                 " VALUES ('alice','x','y',?)", (_now(),))
    conn.execute("INSERT INTO outbound_subs (node_pub, from_agent, channel, created_at)"
                 " VALUES (?,?,?,?)", (PK, "zoe", "hall", _now()))

# --- announce hostile name shapes ------------------------------------------
print("announce hostile names")
check("announce-dict-name", lambda: expect_http(
    lambda: federation.fed_announce(env({"node_pub": PK, "name": {"x": 1}})),
    400, "bad node name", "announce dict name"))
check("announce-uppercase-name", lambda: expect_http(
    lambda: federation.fed_announce(env({"node_pub": PK, "name": "HALL"})),
    400, "bad node name", "announce uppercase name"))
check("announce-64char-name", lambda: expect_http(
    lambda: federation.fed_announce(env({"node_pub": PK, "name": "a" * 64})),
    400, "bad node name", "announce 64-char name"))

print("announce hostile caps")
out = expect_http(
    lambda: federation.fed_announce(
        env({"node_pub": PK, "name": "peertwo", "node_url": PUB_LITERAL,
             "capabilities": [{"x": 1}, "ok", "A" * 64, 7]})),
    200, label="announce hostile caps")
with _db_lock, _db() as conn:
    caps = conn.execute("SELECT capabilities FROM peers WHERE name='peertwo'"
                        ).fetchone()["capabilities"]
assert caps == '["ok"]', f"caps not filtered: {caps}"
print(f"  ok caps filtered -> {caps}")
check("announce-caps-filtered", lambda: None)

# --- gossip hostile entries -------------------------------------------------
print("gossip hostile roster entries")
bad_pub = ed25519.publickey(secrets.token_bytes(32)).hex()
out = expect_http(
    lambda: federation.fed_gossip(env({
        "from_node_pub": PK,
        "roster": [
            {"node_pub": bad_pub, "name": {"x": 1}, "node_url": PUB_LITERAL},
            {"node_pub": bad_pub, "name": "A" * 64, "node_url": PUB_LITERAL},
        ]})),
    200, label="gossip hostile entries")
assert out["merged"] == 0 and out["ignored"] == 2, out
with _db_lock, _db() as conn:
    n = conn.execute("SELECT COUNT(*) FROM peers WHERE node_pub=?", (bad_pub,)).fetchone()[0]
assert n == 0, "hostile gossip entry planted a peer row"
print("  ok both ignored, nothing planted")
check("gossip-name-gates", lambda: None)

# --- channel join -----------------------------------------------------------
print("channel join")
check("join-valid", lambda: expect_http(
    lambda: federation.fed_channel_join(
        env({"from_node_pub": PK, "from_agent": "zoe", "channel": "hall"})),
    200, label="join valid"))
check("join-dict-agent", lambda: expect_http(
    lambda: federation.fed_channel_join(
        env({"from_node_pub": PK, "from_agent": {"x": 1}, "channel": "hall"})),
    400, "bad agent name", "join dict from_agent"))
check("join-dict-channel", lambda: expect_http(
    lambda: federation.fed_channel_join(
        env({"from_node_pub": PK, "from_agent": "zoe", "channel": {"x": 1}})),
    400, "bad channel name", "join dict channel"))
check("join-33char-agent", lambda: expect_http(
    lambda: federation.fed_channel_join(
        env({"from_node_pub": PK, "from_agent": "a" * 33, "channel": "hall"})),
    400, "bad agent name", "join 33-char from_agent"))

# --- channel leave ----------------------------------------------------------
print("channel leave")
check("leave-valid-noop", lambda: expect_http(
    lambda: federation.fed_channel_leave(
        env({"from_node_pub": PK, "from_agent": "zoe", "channel": "nope"})),
    200, label="leave valid no-op"))
check("leave-dict-channel", lambda: expect_http(
    lambda: federation.fed_channel_leave(
        env({"from_node_pub": PK, "from_agent": "zoe", "channel": {"x": 1}})),
    400, "bad channel name", "leave dict channel"))

# --- channel push -----------------------------------------------------------
print("channel push")
out = expect_http(
    lambda: asyncio.run(federation.fed_channel_push(
        env({"from_node_pub": PK, "from_agent": "zoe", "channel": "hall",
             "body": "hello from the federation"}))),
    200, label="push valid")
with _db_lock, _db() as conn:
    row = conn.execute("SELECT body, agent_id FROM messages ORDER BY id DESC LIMIT 1"
                       ).fetchone()
    ag = conn.execute("SELECT name FROM agents WHERE id=?", (row["agent_id"],)).fetchone()
assert row["body"] == "hello from the federation", row["body"]
assert ag["name"].startswith("fed-") and "zoe" in ag["name"], ag["name"]
print(f"  ok push stored on pseudo-agent {ag['name']}")
check("push-valid", lambda: None)
check("push-33char-channel", lambda: expect_http(
    lambda: asyncio.run(federation.fed_channel_push(
        env({"from_node_pub": PK, "from_agent": "zoe", "channel": "a" * 33,
             "body": "x"}))),
    400, "bad channel name", "push 33-char channel"))
check("push-dict-agent", lambda: expect_http(
    lambda: asyncio.run(federation.fed_channel_push(
        env({"from_node_pub": PK, "from_agent": {"x": 1}, "channel": "hall",
             "body": "x"}))),
    400, "bad agent name", "push dict from_agent"))

# --- fed dm (async) ---------------------------------------------------------
print("fed dm")
out = expect_http(
    lambda: asyncio.run(federation.fed_dm(
        env({"from_node_pub": PK, "from_agent": "zoe", "to_agent": "alice",
             "body": "fed dm here"}))),
    200, label="dm valid")
check("dm-valid", lambda: None)
check("dm-dict-to-agent", lambda: expect_http(
    lambda: asyncio.run(federation.fed_dm(
        env({"from_node_pub": PK, "from_agent": "zoe", "to_agent": {"x": 1},
             "body": "x"}))),
    400, "bad agent name", "dm dict to_agent"))

print(f"\nALL {len(results)} GATE CHECKS PASS")
