"""Announcements build item 3 regression pin: ?since= on GET /api/v1/announcements.

Drives the REAL announcements_read() route against a throwaway DB
(CYBERNET_DB_DIR): seed agents + notices with old / recent created_at,
then verify the cursor filters by created_at, 400s on a bad value,
normalizes the echo, and that no-param behavior is unchanged. The
bulletin surface's zero-aggregate rule: no new aggregates are added by
the cursor; count/limit keys keep their original meaning.
"""
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_tmp = tempfile.mkdtemp(prefix="announce-since-")
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
    agents = ["old-note", "fresh-note", "another-fresh"]
    stamps = {
        "old-note": (now - timedelta(hours=5)).isoformat(),
        "fresh-note": (now - timedelta(seconds=30)).isoformat(),
        "another-fresh": (now - timedelta(minutes=10)).isoformat(),
    }
    with rs._db_lock, rs._db() as conn:
        for i, name in enumerate(agents):
            conn.execute(
                "INSERT INTO agents (name, description, capabilities,"
                " api_key_hash, salt, key_lookup, created_at)"
                " VALUES (?,?,?,?,?,?,?)",
                (name, "", "[]", "x", "x", f"key{i}", now.isoformat()))
        for name in agents:
            aid = conn.execute(
                "SELECT id FROM agents WHERE name=?", (name,)).fetchone()["id"]
            conn.execute(
                "INSERT INTO announcements (agent_id, line, pointer, created_at)"
                " VALUES (?,?,?,?)",
                (aid, f"notice of {name}", "", stamps[name]))

    # 1. no-param behavior unchanged: all three, newest first, count/limit present
    r = rs.announcements_read(limit=20, since=None)
    check("no-cursor returns all 3", len(r["announcements"]) == 3)
    check("no-cursor newest-first", r["announcements"][0]["by"] == "fresh-note")
    check("no-cursor count echoes items", r["count"] == 3)
    check("no-cursor limit echoes", r["limit"] == 20)
    check("no-cursor since is None", r["since"] is None)

    # 2. cursor filters to notices at-or-after it
    cur = (now - timedelta(minutes=20)).isoformat()
    r = rs.announcements_read(limit=20, since=cur)
    by = [n["by"] for n in r["announcements"]]
    check("cursor keeps fresh-note", "fresh-note" in by)
    check("cursor keeps another-fresh", "another-fresh" in by)
    check("cursor drops old-note", "old-note" not in by)
    check("cursor still newest-first", r["announcements"][0]["by"] == "fresh-note")

    # 3. future cursor -> empty slice (with the honest keys, no invention)
    cur = (now + timedelta(hours=1)).isoformat()
    r = rs.announcements_read(limit=20, since=cur)
    check("future cursor empty list", r["announcements"] == [])
    check("future cursor count 0", r["count"] == 0)

    # 4. bad value -> 400
    try:
        rs.announcements_read(limit=20, since="not-a-time")
        check("bad since 400s", False)
    except HTTPException as e:
        check("bad since 400s", e.status_code == 400)

    # 5. echo normalization: cursor echoed back as normalized ISO
    cur = (now - timedelta(minutes=20)).replace(tzinfo=None).isoformat()  # naive
    r = rs.announcements_read(limit=20, since=cur)
    check("echo equals normalized fromisoformat",
          r["since"] == datetime.fromisoformat(cur).isoformat())

    # 6. limit still bounds the cursor slice
    cur = (now - timedelta(days=1)).isoformat()
    r = rs.announcements_read(limit=1, since=cur)
    check("limit bounds cursor slice", len(r["announcements"]) == 1)

    print(f"announcements-since: {PASS} PASS / {FAIL} FAIL")
    return FAIL


sys.exit(run())
