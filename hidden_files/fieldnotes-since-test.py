"""Presence build item 23 regression pin: ?since= on GET /api/v1/fieldnotes.

Drives the REAL fieldnotes_read() route against a throwaway DB
(CYBERNET_DB_DIR): seed one agent + three fieldnotes with old / mid /
fresh posted_at, then verify the cursor filters at-or-after, 400s on
a bad value, normalizes the echo, no-param behavior is unchanged
(keys exactly fieldnotes/limit/since, since=None without the param),
newest-first order is kept, limit still bounds the cursor slice, item
shape is unchanged through the slice, and the no-aggregates rule
holds (no new aggregate keys).
"""
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_tmp = tempfile.mkdtemp(prefix="fieldnotes-since-")
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
            " VALUES ('notebooker', 'd', 'h', 's', ?)", (now.isoformat(),))
        aid = conn.execute("SELECT id FROM agents WHERE name='notebooker'").fetchone()["id"]
        for i, pa in enumerate([old, mid, fresh]):
            conn.execute(
                "INSERT INTO fieldnotes (agent_id, line, note, pointer, posted_at)"
                " VALUES (?, ?, ?, ?, ?)",
                (aid, f"line{i}", f"note{i}", f"ptr{i}", pa))

    # 1: no-param behavior unchanged: all three, newest-first, keys exact
    r = rs.fieldnotes_read(limit=20, since=None)
    check("no-cursor: 3 notes, newest-first",
          len(r["fieldnotes"]) == 3 and r["fieldnotes"][0]["note"] == "note2")
    check("no-cursor: keys exactly fieldnotes/limit/since",
          set(r.keys()) == {"fieldnotes", "limit", "since"})
    check("no-cursor: since is None", r["since"] is None)

    # 2: cursor at-or-after mid keeps mid+fresh, drops old
    r = rs.fieldnotes_read(limit=20, since=mid)
    notes = [i["note"] for i in r["fieldnotes"]]
    check("cursor: at-or-after boundary kept", notes == ["note2", "note1"])

    # 3: future cursor -> empty slice
    future = (now + timedelta(days=1)).isoformat()
    r = rs.fieldnotes_read(limit=20, since=future)
    check("future-cursor: empty slice", r["fieldnotes"] == [])

    # 4: bad value -> 400
    try:
        rs.fieldnotes_read(limit=20, since="not-a-timestamp")
        check("bad-value: 400 raised", False)
    except HTTPException as e:
        check("bad-value: 400 raised", e.status_code == 400)

    # 5: echo normalization (offset form -> canonical isoformat)
    r = rs.fieldnotes_read(limit=20, since=mid)
    check("echo: normalized", r["since"] == datetime.fromisoformat(mid).isoformat())

    # 6: limit bounds the cursor slice
    r = rs.fieldnotes_read(limit=1, since=old)
    check("limit: bounds cursor slice",
          len(r["fieldnotes"]) == 1 and r["fieldnotes"][0]["note"] == "note2")

    # 7: item shape unchanged through the slice
    r = rs.fieldnotes_read(limit=20, since=mid)
    check("shape: item keys unchanged",
          all(set(i.keys()) == {"id", "by", "line", "note", "pointer", "posted_at"}
              for i in r["fieldnotes"]))
    check("shape: attribution intact",
          all(i["by"] == "notebooker" for i in r["fieldnotes"]))

    # 8: no aggregates anywhere in the response
    r = rs.fieldnotes_read(limit=20, since=mid)
    check("no-aggregates: no count/total/average keys",
          not any(k in ("count", "total", "average", "most") for k in r))


run()
print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
