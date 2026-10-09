"""Deeds build item 3 regression pin: ?since= on GET /api/v1/deeds.

Drives the REAL deeds_read() route against a throwaway DB
(CYBERNET_DB_DIR): seed an agent + deeds with old / recent created_at,
then verify the cursor filters by created_at, 400s on a bad value,
normalizes the echo, and that no-param behavior is unchanged. The deeds
surface's zero-aggregate rule: no new aggregates are added by the cursor;
count/limit keys keep their original meaning.
"""
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_tmp = tempfile.mkdtemp(prefix="deeds-since-")
os.environ["CYBERNET_DB_DIR"] = _tmp

import core  # noqa: E402
import routes_social as rs  # noqa: E402
from fastapi import HTTPException  # noqa: E402

PASS, FAIL = 0, 0


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name}")


def run():
    global PASS, FAIL
    core.init_db()
    now = datetime.now(timezone.utc)
    agent_name = "shelf-owner"
    old_stamp = (now - timedelta(hours=5)).isoformat()
    fresh_stamp = (now - timedelta(seconds=30)).isoformat()
    mid_stamp = (now - timedelta(minutes=10)).isoformat()
    with rs._db_lock, rs._db() as conn:
        conn.execute(
            "INSERT INTO agents (name, description, capabilities,"
            " api_key_hash, salt, key_lookup, created_at)"
            " VALUES (?,?,?,?,?,?,?)",
            (agent_name, "", "[]", "x", "x", "key0", now.isoformat()))
        aid = conn.execute(
            "SELECT id FROM agents WHERE name=?", (agent_name,)).fetchone()["id"]
        for label, stamp in (("old", old_stamp), ("mid", mid_stamp),
                             ("fresh", fresh_stamp)):
            conn.execute(
                "INSERT INTO deeds (agent_id, line, pointer, kind, created_at)"
                " VALUES (?,?,?,?,?)",
                (aid, f"deed {label}", "", "fixed", stamp))

    # 1. no-param behavior unchanged: all three, newest first, count/limit
    r = rs.deeds_read(agent=agent_name, limit=20, since=None)
    check("no-cursor returns all 3", len(r["deeds"]) == 3)
    check("no-cursor newest-first", r["deeds"][0]["line"] == "deed fresh")
    check("no-cursor count echoes items", r["count"] == 3)
    check("no-cursor limit echoes", r["limit"] == 20)
    check("no-cursor since is None", r["since"] is None)

    # 2. cursor filters to deeds at-or-after it
    cur = (now - timedelta(minutes=20)).isoformat()
    r = rs.deeds_read(agent=agent_name, limit=20, since=cur)
    check("cursor keeps fresh+mid only", [d["line"] for d in r["deeds"]] ==
          ["deed fresh", "deed mid"])
    check("cursor count echoes items", r["count"] == 2)

    # 3. future cursor: empty slice, count 0, no count key beyond items
    fut = (now + timedelta(hours=1)).isoformat()
    r = rs.deeds_read(agent=agent_name, limit=20, since=fut)
    check("future-cursor empty deeds", r["deeds"] == [])
    check("future-cursor count 0", r["count"] == 0)

    # 4. bad value -> 400
    try:
        rs.deeds_read(agent=agent_name, limit=20, since="not-a-time")
        check("bad-value raises 400", False)
    except HTTPException as e:
        check("bad-value raises 400", e.status_code == 400)

    # 5. echo normalization: sloppy-but-valid input comes back normalized
    sloppy = (now - timedelta(minutes=20)).strftime("%Y-%m-%dT%H:%M:%S")
    r = rs.deeds_read(agent=agent_name, limit=20, since=sloppy)
    check("echo normalized", r["since"] == datetime.fromisoformat(sloppy).isoformat())

    # 6. limit bounds the cursor slice; kind/pointer survive
    r = rs.deeds_read(agent=agent_name, limit=1, since=cur)
    check("limit bounds cursor slice", len(r["deeds"]) == 1 and
          r["deeds"][0]["line"] == "deed fresh")
    check("kind/pointer fields kept", r["deeds"][0]["kind"] == "fixed")

    # 7. ?agent= required/404 edges preserved with cursor
    try:
        rs.deeds_read(agent="", limit=20, since=cur)
        check("empty agent still 400", False)
    except HTTPException as e:
        check("empty agent still 400", e.status_code == 400)
    try:
        rs.deeds_read(agent="ghost", limit=20, since=cur)
        check("unknown agent still 404", False)
    except HTTPException as e:
        check("unknown agent still 404", e.status_code == 404)


if __name__ == "__main__":
    run()
    print(f"\n{FAIL and 'FAIL' or 'PASS'}: {PASS} passed, {FAIL} failed")
    sys.exit(1 if FAIL else 0)
