"""Gratitude build item 3 regression pin: ?since= on GET /api/v1/gratitude.

Drives the REAL gratitude_read() route against a throwaway DB
(CYBERNET_DB_DIR): seed two agents + thanks with old / recent created_at,
then verify the cursor filters by created_at, 400s on a bad value,
normalizes the echo, and that no-param behavior is unchanged. The
gratitude surface's zero-aggregate rule: no new aggregates are added by
the cursor; to/from/count/limit keys keep their original meaning.
"""
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_tmp = tempfile.mkdtemp(prefix="gratitude-since-")
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
    giver, taker = "giver", "taker"
    old_stamp = (now - timedelta(hours=5)).isoformat()
    fresh_stamp = (now - timedelta(seconds=30)).isoformat()
    mid_stamp = (now - timedelta(minutes=10)).isoformat()
    with rs._db_lock, rs._db() as conn:
        for i, nm in enumerate((giver, taker)):
            conn.execute(
                "INSERT INTO agents (name, description, capabilities,"
                " api_key_hash, salt, key_lookup, created_at)"
                " VALUES (?,?,?,?,?,?,?)",
                (nm, "", "[]", "x", "x", f"key{i}", now.isoformat()))
        gid = conn.execute(
            "SELECT id FROM agents WHERE name=?", (giver,)).fetchone()["id"]
        tid = conn.execute(
            "SELECT id FROM agents WHERE name=?", (taker,)).fetchone()["id"]
        for label, stamp in (("old", old_stamp), ("mid", mid_stamp),
                             ("fresh", fresh_stamp)):
            conn.execute(
                "INSERT INTO gratitude (from_agent, to_agent, line, for_ref,"
                " created_at) VALUES (?,?,?,?,?)",
                (gid, tid, f"thanks {label}", "", stamp))

    # 1. no-param behavior unchanged: all three, newest first, key/count/limit
    r = rs.gratitude_read(to=taker, frm="", limit=20, since=None)
    check("no-cursor returns all 3", len(r["gratitude"]) == 3)
    check("no-cursor newest-first", r["gratitude"][0]["line"] == "thanks fresh")
    check("no-cursor to-key echoes", r["to"] == taker)
    check("no-cursor count echoes items", r["count"] == 3)
    check("no-cursor limit echoes", r["limit"] == 20)
    check("no-cursor since is None", r["since"] is None)
    r2 = rs.gratitude_read(to="", frm=giver, limit=20, since=None)
    check("from-variant works", len(r2["gratitude"]) == 3 and r2["from"] == giver)

    # 2. cursor filters to thanks at-or-after it
    cur = (now - timedelta(minutes=20)).isoformat()
    r = rs.gratitude_read(to=taker, frm="", limit=20, since=cur)
    check("cursor keeps fresh+mid only", [g["line"] for g in r["gratitude"]] ==
          ["thanks fresh", "thanks mid"])
    check("cursor count echoes items", r["count"] == 2)
    r = rs.gratitude_read(to="", frm=giver, limit=20, since=cur)
    check("cursor applies on from-variant", len(r["gratitude"]) == 2)

    # 3. future cursor: empty slice, count 0
    fut = (now + timedelta(hours=1)).isoformat()
    r = rs.gratitude_read(to=taker, frm="", limit=20, since=fut)
    check("future-cursor empty gratitude", r["gratitude"] == [])
    check("future-cursor count 0", r["count"] == 0)

    # 4. bad value -> 400
    try:
        rs.gratitude_read(to=taker, frm="", limit=20, since="not-a-time")
        check("bad-value raises 400", False)
    except HTTPException as e:
        check("bad-value raises 400", e.status_code == 400)

    # 5. echo normalization: sloppy-but-valid input comes back normalized
    sloppy = (now - timedelta(minutes=20)).strftime("%Y-%m-%dT%H:%M:%S")
    r = rs.gratitude_read(to=taker, frm="", limit=20, since=sloppy)
    check("echo normalized", r["since"] == datetime.fromisoformat(sloppy).isoformat())

    # 6. limit bounds the cursor slice; line/for fields kept
    r = rs.gratitude_read(to=taker, frm="", limit=1, since=cur)
    check("limit bounds cursor slice", len(r["gratitude"]) == 1 and
          r["gratitude"][0]["line"] == "thanks fresh")
    check("line/for fields kept",
          r["gratitude"][0]["for"] == "" and "fresh" in r["gratitude"][0]["line"])

    # 7. ?to=/?from= edges preserved with cursor
    try:
        rs.gratitude_read(to="", frm="", limit=20, since=cur)
        check("neither param still 400", False)
    except HTTPException as e:
        check("neither param still 400", e.status_code == 400)
    try:
        rs.gratitude_read(to=taker, frm=giver, limit=20, since=cur)
        check("both params still 400", False)
    except HTTPException as e:
        check("both params still 400", e.status_code == 400)
    try:
        rs.gratitude_read(to="ghost", frm="", limit=20, since=cur)
        check("unknown agent still 404", False)
    except HTTPException as e:
        check("unknown agent still 404", e.status_code == 404)


if __name__ == "__main__":
    run()
    print(f"\n{FAIL and 'FAIL' or 'PASS'}: {PASS} passed, {FAIL} failed")
    sys.exit(1 if FAIL else 0)
