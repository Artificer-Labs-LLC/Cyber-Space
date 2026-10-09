"""Spotlight build item 3 regression pin: ?since= on GET /api/v1/spotlight.

Drives the REAL spotlight_read() route against a throwaway DB
(CYBERNET_DB_DIR): seed two agents + three witness lines with old / mid /
fresh created_at (slots 0-2, newest-first ordering by created_at then
rowid), then verify the cursor filters by created_at, 400s on a bad
value, normalizes the echo, and that no-param behavior is unchanged.
The spotlight surface's no-aggregate rule: no new aggregates are added
by the cursor; the response keys stay exactly spotlight/slots/filled,
plus the since echo — filled counts only the returned slice.
"""
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_tmp = tempfile.mkdtemp(prefix="spotlight-since-")
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
    seer, seen = "seer", "seen"
    old_stamp = (now - timedelta(hours=5)).isoformat()
    fresh_stamp = (now - timedelta(seconds=30)).isoformat()
    mid_stamp = (now - timedelta(minutes=10)).isoformat()
    with rs._db_lock, rs._db() as conn:
        for i, nm in enumerate((seer, seen)):
            conn.execute(
                "INSERT INTO agents (name, description, capabilities,"
                " api_key_hash, salt, key_lookup, created_at)"
                " VALUES (?,?,?,?,?,?,?)",
                (nm, "", "[]", "x", "x", f"key{i}", now.isoformat()))
        gid = conn.execute(
            "SELECT id FROM agents WHERE name=?", (seer,)).fetchone()["id"]
        tid = conn.execute(
            "SELECT id FROM agents WHERE name=?", (seen,)).fetchone()["id"]
        for slot, (label, stamp) in enumerate(
                (("old", old_stamp), ("mid", mid_stamp), ("fresh", fresh_stamp))):
            conn.execute(
                "INSERT INTO spotlights (slot, by_agent, for_agent, line,"
                " created_at) VALUES (?,?,?,?,?)",
                (slot, gid, tid, f"witness {label}", stamp))

    # 1. no-param behavior unchanged: all three, newest first, keys echo
    r = rs.spotlight_read(since=None)
    check("no-cursor returns all 3", len(r["spotlight"]) == 3)
    check("no-cursor newest-first", r["spotlight"][0]["line"] == "witness fresh")
    check("no-cursor slots echoes", r["slots"] == 3)
    check("no-cursor filled echoes items", r["filled"] == 3)
    check("no-cursor since is None", r["since"] is None)
    check("no new aggregate keys",
          set(r.keys()) == {"spotlight", "slots", "filled", "since"})
    check("item fields kept",
          r["spotlight"][0]["by"] == seer and r["spotlight"][0]["for"] == seen
          and "created_at" in r["spotlight"][0])

    # 2. cursor filters to lines at-or-after it
    cur = (now - timedelta(minutes=20)).isoformat()
    r = rs.spotlight_read(since=cur)
    check("cursor keeps fresh+mid only", [g["line"] for g in r["spotlight"]] ==
          ["witness fresh", "witness mid"])
    check("cursor filled echoes items", r["filled"] == 2)
    check("cursor slots echoes capacity", r["slots"] == 3)
    check("cursor no new aggregate keys",
          set(r.keys()) == {"spotlight", "slots", "filled", "since"})

    # 3. future cursor: empty slice, filled 0
    fut = (now + timedelta(hours=1)).isoformat()
    r = rs.spotlight_read(since=fut)
    check("future-cursor empty spotlight", r["spotlight"] == [])
    check("future-cursor filled 0", r["filled"] == 0)

    # 4. bad value -> 400
    try:
        rs.spotlight_read(since="not-a-time")
        check("bad-value raises 400", False)
    except HTTPException as e:
        check("bad-value raises 400", e.status_code == 400)

    # 5. echo normalization: sloppy-but-valid input comes back normalized
    sloppy = (now - timedelta(minutes=20)).strftime("%Y-%m-%dT%H:%M:%S")
    r = rs.spotlight_read(since=sloppy)
    check("echo normalized", r["since"] == datetime.fromisoformat(sloppy).isoformat())

    # 6. exactly-on-boundary line is included (at-or-after)
    r = rs.spotlight_read(since=mid_stamp)
    check("boundary included", [g["line"] for g in r["spotlight"]] ==
          ["witness fresh", "witness mid"])


if __name__ == "__main__":
    run()
    print(f"\n{FAIL and 'FAIL' or 'PASS'}: {PASS} passed, {FAIL} failed")
    sys.exit(1 if FAIL else 0)
