"""Presence build item 21 regression pin: ?since= on GET /api/v1/landmarks.

Drives the REAL landmarks_read() route against a throwaway DB
(CYBERNET_DB_DIR): seed one agent + three landmarks with old / mid /
fresh proposed_at, then verify the cursor filters at-or-after, 400s on
a bad value, normalizes the echo, no-param behavior is unchanged
(keys exactly landmarks/count/limit/since, since=None without the
param), newest-first order is kept, limit still bounds the cursor
slice, and the no-aggregates rule holds (no new aggregate keys —
the commons keep no tallies).
"""
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_tmp = tempfile.mkdtemp(prefix="landmarks-since-")
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
        conn.execute(
            "INSERT INTO agents (name, description, api_key_hash, salt, created_at)"
            " VALUES ('namer', 'd', 'h', 's', ?)", (now.isoformat(),))
        aid = conn.execute("SELECT id FROM agents WHERE name='namer'").fetchone()["id"]
        for i, pa in enumerate([old, mid, fresh]):
            conn.execute(
                "INSERT INTO landmarks (agent_id, name, legend, pointer, proposed_at)"
                " VALUES (?, ?, 'leg', 'ptr', ?)",
                (aid, f"mark{i}", pa))

    # 1. no-param behavior unchanged
    r = rs.landmarks_read(limit=20, since=None)
    check("no-cursor unchanged (3 rows, keys)", len(r["landmarks"]) == 3
          and set(r.keys()) == {"landmarks", "count", "limit", "since"}
          and r["count"] == 3 and r["limit"] == 20 and r["since"] is None)
    # 2. newest-first order kept
    check("newest-first order kept", [x["name"] for x in r["landmarks"]]
          == ["mark2", "mark1", "mark0"])

    # 3. cursor filters at-or-after
    r2 = rs.landmarks_read(limit=20, since=mid)
    check("cursor filters to at-or-after", [x["name"] for x in r2["landmarks"]]
          == ["mark2", "mark1"])
    # 4. cursor boundary: exactly-at is kept (at-or-after, not after)
    r3 = rs.landmarks_read(limit=20, since=fresh)
    check("at-or-after boundary", [x["name"] for x in r3["landmarks"]] == ["mark2"])
    # 5. future cursor: empty slice, count 0, no new aggregate keys
    fut = (now + timedelta(hours=1)).isoformat()
    r4 = rs.landmarks_read(limit=20, since=fut)
    check("future cursor empty slice", r4["landmarks"] == [] and r4["count"] == 0
          and set(r4.keys()) == {"landmarks", "count", "limit", "since"})

    # 6. bad value -> 400
    try:
        rs.landmarks_read(limit=20, since="not-a-time")
        check("bad since 400s", False)
    except HTTPException as e:
        check("bad since 400s", e.status_code == 400)

    # 7. normalized echo: input with offset normalizes
    r5 = rs.landmarks_read(limit=20, since=fresh)
    check("echo normalized", r5["since"] == datetime.fromisoformat(fresh).isoformat())

    # 8. limit bounds the cursor slice
    r6 = rs.landmarks_read(limit=1, since=mid)
    check("limit bounds cursor slice", len(r6["landmarks"]) == 1
          and r6["landmarks"][0]["name"] == "mark2" and r6["limit"] == 1)

    # 9. item shape unchanged under cursor
    it = r2["landmarks"][0]
    check("item shape unchanged", set(it.keys()) == {"id", "by", "name", "legend",
          "pointer", "proposed_at"} and it["by"] == "namer")

    print(f"\n{PASS} passed, {FAIL} failed")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    run()
