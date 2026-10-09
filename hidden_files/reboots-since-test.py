"""Presence build item 20 regression pin: ?since= on GET /api/v1/reboots.

Drives the REAL reboots_read() route against a throwaway DB
(CYBERNET_DB_DIR): seed one agent + three reboot_log rows with old /
mid / fresh created_at, then verify the cursor filters at-or-after,
400s on a bad value, normalizes the echo, no-param behavior is
unchanged (keys exactly agent/reboots/count/limit/since, since=None
without the param), ?agent=/404 edges preserved, limit still honored,
item shape unchanged, and the no-aggregate rule holds.
"""
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_tmp = tempfile.mkdtemp(prefix="reboots-since-")
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
            " VALUES ('crasher', 'd', 'h', 's', ?)", (now.isoformat(),))
        aid = conn.execute("SELECT id FROM agents WHERE name='crasher'").fetchone()["id"]
        for i, ca in enumerate([old, mid, fresh]):
            conn.execute(
                "INSERT INTO reboot_log (agent_id, back_at, crashed_at, note, created_at)"
                " VALUES (?, ?, ?, ?, ?)",
                (aid, ca, ca, f"note{i}", ca))

    # 1. no-param behavior unchanged (agent scoping intact)
    r = rs.reboots_read(agent="crasher", limit=20, since=None)
    check("no-param: three rows, newest-first",
          r["count"] == 3 and r["reboots"][0]["note"] == "note2" and
          r["reboots"][2]["note"] == "note0")
    check("no-param: keys exactly agent/reboots/count/limit/since=None",
          set(r.keys()) == {"agent", "reboots", "count", "limit", "since"} and
          r["since"] is None and r["agent"] == "crasher")
    check("no-param: limit echoed", r["limit"] == 20)

    # 2. cursor filters at-or-after mid boundary
    r = rs.reboots_read(agent="crasher", limit=20, since=mid)
    check("cursor: mid+fresh returned, old excluded",
          r["count"] == 2 and {b["note"] for b in r["reboots"]} == {"note1", "note2"})
    check("cursor: echo normalized to ISO", r["since"] == datetime.fromisoformat(mid).isoformat())

    # 3. cursor after everything -> empty slice
    r = rs.reboots_read(agent="crasher", limit=20, since=(now + timedelta(seconds=1)).isoformat())
    check("future cursor: empty slice, keys unchanged",
          r["count"] == 0 and r["reboots"] == [] and
          set(r.keys()) == {"agent", "reboots", "count", "limit", "since"})

    # 4. bad ISO -> 400
    try:
        rs.reboots_read(agent="crasher", limit=20, since="not-a-timestamp")
        check("bad since: 400 raised", False)
    except HTTPException as e:
        check("bad since: 400 raised", e.status_code == 400 and "ISO" in e.detail)

    # 5. limit still honored with cursor
    r = rs.reboots_read(agent="crasher", limit=1, since=mid)
    check("limit+cursor: one row, the freshest",
          r["count"] == 1 and r["limit"] == 1 and r["reboots"][0]["note"] == "note2")

    # 6. ?agent=/404 edges preserved
    try:
        rs.reboots_read(agent="", limit=20, since=None)
        check("empty agent: 400 raised", False)
    except HTTPException as e:
        check("empty agent: 400 raised", e.status_code == 400)
    try:
        rs.reboots_read(agent="ghost", limit=20, since=None)
        check("ghost agent: 404 raised", False)
    except HTTPException as e:
        check("ghost agent: 404 raised", e.status_code == 404)

    # 7. shape of one item unchanged
    r = rs.reboots_read(agent="crasher", limit=20, since=None)
    item = r["reboots"][0]
    check("item shape unchanged (id/back_at/crashed_at/note/created_at)",
          set(item.keys()) == {"id", "back_at", "crashed_at", "note", "created_at"})

    # 8. no aggregates anywhere on the response
    check("no aggregates",
          all(k in ("agent", "reboots", "count", "limit", "since") for k in r.keys()))


if __name__ == "__main__":
    run()
    print(f"\n{PASS} passed, {FAIL} failed")
    sys.exit(1 if FAIL else 0)
