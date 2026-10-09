"""Presence build item 19 regression pin: ?since= on GET /api/v1/waymarks.

Drives the REAL waymarks_read() route against a throwaway DB
(CYBERNET_DB_DIR): seed one agent + three waymarks with old / mid /
fresh vouched_at, then verify the cursor filters at-or-after, 400s on
a bad value, normalizes the echo, no-param behavior is unchanged
(keys exactly waymarks/count/limit/since, since=None without the
param), limit still honored, and the no-aggregate rule holds (no new
keys — the square still watches nothing).
"""
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_tmp = tempfile.mkdtemp(prefix="waymarks-since-")
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
            " VALUES ('walker', 'd', 'h', 's', ?)", (now.isoformat(),))
        aid = conn.execute("SELECT id FROM agents WHERE name='walker'").fetchone()["id"]
        for i, (va, frm, to) in enumerate(
                [(old, "oldstreet", "oldcorner"),
                 (mid, "midstreet", "midcorner"),
                 (fresh, "freshstreet", "freshcorner")]):
            conn.execute(
                "INSERT INTO waymarks (agent_id, from_kind, from_name, to_kind, to_name, sign, vouched_at)"
                " VALUES (?, 'street', ?, 'corner', ?, ?, ?)",
                (aid, frm, to, f"sign{i}", va))

    # 1. no-param behavior unchanged
    r = rs.waymarks_read(limit=20, since=None)
    check("no-param: three rows, newest-first", r["count"] == 3 and
          r["waymarks"][0]["from"]["name"] == "freshstreet" and
          r["waymarks"][2]["from"]["name"] == "oldstreet")
    check("no-param: keys exactly waymarks/count/limit/since=None",
          set(r.keys()) == {"waymarks", "count", "limit", "since"} and r["since"] is None)
    check("no-param: limit echoed", r["limit"] == 20)

    # 2. cursor filters at-or-after mid boundary
    r = rs.waymarks_read(limit=20, since=mid)
    check("cursor: mid+fresh returned, old excluded",
          r["count"] == 2 and {w["from"]["name"] for w in r["waymarks"]}
          == {"midstreet", "freshstreet"})
    check("cursor: echo normalized to ISO", r["since"] == datetime.fromisoformat(mid).isoformat())

    # 3. cursor after everything -> empty slice
    r = rs.waymarks_read(limit=20, since=(now + timedelta(seconds=1)).isoformat())
    check("future cursor: empty slice, keys unchanged",
          r["count"] == 0 and r["waymarks"] == [] and set(r.keys()) == {"waymarks", "count", "limit", "since"})

    # 4. bad ISO -> 400
    try:
        rs.waymarks_read(limit=20, since="not-a-timestamp")
        check("bad since: 400 raised", False)
    except HTTPException as e:
        check("bad since: 400 raised", e.status_code == 400 and "ISO" in e.detail)

    # 5. limit still honored with cursor
    r = rs.waymarks_read(limit=1, since=mid)
    check("limit+cursor: one row, the freshest",
          r["count"] == 1 and r["limit"] == 1 and r["waymarks"][0]["from"]["name"] == "freshstreet")

    # 6. shape of one item unchanged
    r = rs.waymarks_read(limit=20, since=None)
    item = r["waymarks"][0]
    check("item shape unchanged (id/by/from/to/sign/vouched_at)",
          set(item.keys()) == {"id", "by", "from", "to", "sign", "vouched_at"} and
          item["by"] == "walker" and item["from"]["kind"] == "street")

    # 7. no aggregates anywhere on the response
    check("no aggregates", all(k in ("waymarks", "count", "limit", "since") for k in r.keys()))


if __name__ == "__main__":
    run()
    print(f"\n{PASS} passed, {FAIL} failed")
    sys.exit(1 if FAIL else 0)
