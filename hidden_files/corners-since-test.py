"""Presence build item 24 regression pin: ?since= on GET /api/v1/corners.

Drives the REAL corners_walk() route against a throwaway DB
(CYBERNET_DB_DIR): seed three agents each claiming one corner with
old / mid / fresh claimed_at, then verify the cursor filters
at-or-after, 400s on a bad value, normalizes the echo, no-param
behavior is unchanged (keys exactly corners/count/limit/since,
since=None without the param), limit still honored, the ?name=
point-read path is untouched (no cursor, single shape, 404 still
404), and the no-aggregate rule holds (no new keys — the block is
still a directory, never a leaderboard).

Harness note — FastAPI 0.142 route called directly needs
name=/limit=/since= passed explicitly (Query-object defaults),
mirroring the waymarks/fieldnotes harnesses.
"""
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_tmp = tempfile.mkdtemp(prefix="corners-since-")
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
    old = (now - timedelta(days=3)).isoformat()
    mid = (now - timedelta(hours=5)).isoformat()
    fresh = now.isoformat()

    with rs._db_lock, rs._db() as conn:
        for i, (ag, corner, ca) in enumerate(
                [("walker", "oldcorner", old),
                 ("talker", "midcorner", mid),
                 ("stayer", "freshcorner", fresh)]):
            conn.execute(
                "INSERT INTO agents (name, description, api_key_hash, salt, created_at)"
                " VALUES (?, 'd', 'h', 's', ?)", (ag, now.isoformat()))
            aid = conn.execute(
                "SELECT id FROM agents WHERE name=?", (ag,)).fetchone()["id"]
            conn.execute(
                "INSERT INTO corners (agent_id, name, plaque, pointer, claimed_at)"
                " VALUES (?, ?, ?, ?, ?)", (aid, corner, f"plaque{i}", f"ptr{i}", ca))

    # 1. no-param behavior: three rows, newest-first, count/limit echoes
    r = rs.corners_walk(name="", limit=20, since=None)
    check("no-param: three corners, newest-first", r["count"] == 3 and
          r["corners"][0]["name"] == "freshcorner" and
          r["corners"][2]["name"] == "oldcorner")
    check("no-param: keys exactly corners/count/limit/since=None",
          set(r.keys()) == {"corners", "count", "limit", "since"} and r["since"] is None)
    check("no-param: limit echoed", r["limit"] == 20)

    # 2. cursor filters at-or-after mid boundary
    r = rs.corners_walk(name="", limit=20, since=mid)
    check("cursor: mid+fresh returned, old excluded",
          r["count"] == 2 and {c["name"] for c in r["corners"]}
          == {"midcorner", "freshcorner"})
    check("cursor: echo normalized to ISO", r["since"] == datetime.fromisoformat(mid).isoformat())

    # 3. cursor after everything -> empty slice
    r = rs.corners_walk(name="", limit=20,
                        since=(now + timedelta(seconds=1)).isoformat())
    check("future cursor: empty slice, keys unchanged",
          r["count"] == 0 and r["corners"] == [] and
          set(r.keys()) == {"corners", "count", "limit", "since"})

    # 4. bad ISO -> 400
    try:
        rs.corners_walk(name="", limit=20, since="not-a-timestamp")
        check("bad since: 400 raised", False)
    except HTTPException as e:
        check("bad since: 400 raised", e.status_code == 400 and "ISO" in e.detail)

    # 5. limit still honored with cursor
    r = rs.corners_walk(name="", limit=1, since=mid)
    check("limit+cursor: one corner, the freshest",
          r["count"] == 1 and r["limit"] == 1 and r["corners"][0]["name"] == "freshcorner")

    # 6. ?name= point read untouched: single shape, no cursor keys, 404 kept
    r = rs.corners_walk(name="midcorner", limit=20, since=None)
    check("point read: single-corner shape, no since key",
          set(r.keys()) == {"agent", "name", "plaque", "pointer", "claimed_at"} and
          r["name"] == "midcorner" and r["agent"] == "talker")
    try:
        rs.corners_walk(name="nocorner", limit=20, since=None)
        check("point read: 404 on unknown corner", False)
    except HTTPException as e:
        check("point read: 404 on unknown corner", e.status_code == 404)

    # 7. point read with a bad since still 400s (house discipline)
    try:
        rs.corners_walk(name="midcorner", limit=20, since="junk")
        check("point read + bad since: 400 raised", False)
    except HTTPException as e:
        check("point read + bad since: 400 raised", e.status_code == 400)

    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(run())
