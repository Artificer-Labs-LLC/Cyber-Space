#!/usr/bin/env python3
"""Replay-dedupe wiring check for fed_channel_leave (receiver #4 of the
fed/* wiring pass). Drives the REAL sync receiver on a throwaway DB:
first leave 200s removed=true, byte-identical replay 400s 'replay',
fresh re-sign 200s removed=false (idempotent), tampered/wrong-recipient
envelopes fail closed without poisoning the sig store. Negative control:
run on a tree with the _claim_seen_sig call stashed out — replays must
then 200 and keep removing."""
import os, sys, tempfile, secrets

tmp = tempfile.mkdtemp()
os.environ["CYBERNET_DB_DIR"] = tmp
sys.path.insert(0, "/home/hatch/workspace/cybernet")

from fastapi import HTTPException  # noqa: E402
from core import init_db, _db, _NODE_PUB  # noqa: E402
from fed import ed25519, envelope as env_mod  # noqa: E402
import federation as fed  # noqa: E402

init_db()
PASS = 0


def check(name, cond):
    global PASS
    assert cond, f"FAIL: {name}"
    PASS += 1
    print(f"ok {PASS}: {name}")


sk = secrets.token_hex(32)
pk = ed25519.publickey(bytes.fromhex(sk)).hex()
with _db() as conn:
    conn.execute(
        "INSERT INTO peers (node_pub, name, network, version, genesis, capabilities, announced_at, first_seen)"
        " VALUES (?,?,?,?,?,?,?,?)",
        (pk, "peerone", "cybernet", "0.1.0", 0, "[]", "2026-10-09T00:00:00Z", "2026-10-09T00:00:00Z"))
    conn.execute(
        "INSERT INTO channels (name, topic, kind, created_at) VALUES (?,?, 'channel', ?)",
        ("square", "", "2026-10-09T00:00:00Z"))
    row = conn.execute("SELECT id FROM channels WHERE name='square'").fetchone()
    conn.execute(
        "INSERT INTO channel_subs (channel_id, node_pub, from_agent, created_at)"
        " VALUES (?,?,?,?)",
        (row["id"], pk, "zoe", "2026-10-09T00:00:00Z"))


def make(body, sk_=sk, pk_=pk, recipient=_NODE_PUB, ts=None):
    return env_mod.make_envelope(sk_, pk_, recipient, body, ts=ts)


def subs_count():
    with _db() as conn:
        return conn.execute("SELECT COUNT(*) FROM channel_subs").fetchone()[0]


def seen_count():
    with _db() as conn:
        return conn.execute("SELECT COUNT(*) FROM fed_seen_sigs").fetchone()[0]


body = {"from_node_pub": pk, "from_agent": "zoe", "channel": "square"}

# 1. First leave 200s removed=true, row gone, sig claimed.
env = make(body)
res = fed.fed_channel_leave(env)
check("first leave 200s", res["ok"] is True and res["removed"] is True)
check("consent row deleted", subs_count() == 0)
check("sig claimed on first leave", seen_count() == 1)

# 2. Byte-identical replay 400s 'replay', no new sig row.
try:
    fed.fed_channel_leave(env)
    check("replay rejected", False)
except HTTPException as e:
    check("replay 400s", e.status_code == 400)
    check("replay detail names replay", e.detail == "replay")
check("replay never re-claims", seen_count() == 1)

# 3. Fresh re-sign (new ts -> new sig) 200s as idempotent leave,
#    removed=false, new sig claimed.
env2 = make(body, ts=env["ts"] + 1)
res2 = fed.fed_channel_leave(env2)
check("re-signed resend 200s", res2["ok"] is True)
check("re-signed leave idempotent removed=false", res2["removed"] is False)
check("fresh sig claimed", seen_count() == 2)
try:
    fed.fed_channel_leave(env2)
    check("env2 replay rejected", False)
except HTTPException as e:
    check("env2 replay 400s 'replay'", e.status_code == 400 and e.detail == "replay")

# 4. Tampered body fails closed and never touches the sig store.
bad = dict(make(body))
bad["body"] = {"from_node_pub": pk, "from_agent": "zoe", "channel": "square!"}
try:
    fed.fed_channel_leave(bad)
    check("tampered rejected", False)
except HTTPException as e:
    check("tampered 400s", e.status_code == 400)
check("tamper never claims", seen_count() == 2)

# 5. Wrong-recipient envelope 400s and never claims.
try:
    fed.fed_channel_leave(make(body, recipient="some-other-node"))
    check("wrong-recipient rejected", False)
except HTTPException as e:
    check("wrong-recipient 400s", e.status_code == 400)
check("wrong-recipient never claims", seen_count() == 2)

print(f"ALL PASS: {PASS}/14")
