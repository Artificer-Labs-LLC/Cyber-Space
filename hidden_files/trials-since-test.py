"""Presence build item 22 regression pin: ?since= on GET /api/v1/trials.

Drives the REAL trials_read() route against a throwaway DB
(CYBERNET_DB_DIR): seed one agent + three trials with old / mid /
fresh posted_at (the fresh one carries two tries and an
acknowledgment), then verify the cursor filters at-or-after, 400s on
a bad value, normalizes the echo, no-param behavior is unchanged
(keys exactly trials/limit/since, since=None without the param),
newest-first order is kept, limit still bounds the cursor slice,
the ack/tries shapes ride through the cursor slice intact, and the
no-aggregates rule holds (no new aggregate keys — rank stays
uncomputable).
"""
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_tmp = tempfile.mkdtemp(prefix="trials-since-")
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
            " VALUES ('poster', 'd', 'h', 's', ?)", (now.isoformat(),))
        aid = conn.execute("SELECT id FROM agents WHERE name='poster'").fetchone()["id"]
        tids = []
        for i, pa in enumerate([old, mid, fresh]):
            cur = conn.execute(
                "INSERT INTO trials (agent_id, puzzle, hint, posted_at)"
                " VALUES (?, ?, 'hint', ?)", (aid, f"puzzle{i}", pa))
            tids.append(cur.lastrowid)
        # fresh trial gets two tries + acknowledgment of the first
        conn.execute("INSERT INTO tries (trial_id, agent_id, body, tried_at)"
                     " VALUES (?, ?, 'first try', ?)", (tids[2], aid, fresh))
        ty1 = conn.execute("SELECT id FROM tries WHERE trial_id=? AND body='first try'",
                           (tids[2],)).fetchone()["id"]
        conn.execute("INSERT INTO tries (trial_id, agent_id, body, tried_at)"
                     " VALUES (?, ?, 'second try', ?)", (tids[2], aid, fresh))
        conn.execute("UPDATE trials SET acknowledged_try_id=? WHERE id=?",
                     (ty1, tids[2]))

    # 1. no-param behavior unchanged
    r = rs.trials_read(limit=20, since=None)
    check("no-cursor unchanged (3 trials, keys)", len(r["trials"]) == 3
          and set(r.keys()) == {"trials", "limit", "since"}
          and r["limit"] == 20 and r["since"] is None)
    # 2. newest-first order kept
    check("newest-first order kept",
          [x["puzzle"] for x in r["trials"]] == ["puzzle2", "puzzle1", "puzzle0"])
    # 3. fresh trial's ack + tries ride along intact
    fr = r["trials"][0]
    check("ack/tries shapes intact",
          fr["acknowledged"] is not None and fr["acknowledged"]["body"] == "first try"
          and [t["body"] for t in fr["tries"]] == ["second try", "first try"])

    # 4. cursor filters at-or-after
    r2 = rs.trials_read(limit=20, since=mid)
    check("cursor filters to at-or-after",
          [x["puzzle"] for x in r2["trials"]] == ["puzzle2", "puzzle1"]
          and r2["since"] is not None)
    # 5. cursor boundary: exactly-at is kept (at-or-after, not after)
    r3 = rs.trials_read(limit=20, since=fresh)
    check("at-or-after boundary", [x["puzzle"] for x in r3["trials"]] == ["puzzle2"])
    # 6. future cursor: empty slice, no new aggregate keys
    fut = (now + timedelta(hours=1)).isoformat()
    r4 = rs.trials_read(limit=20, since=fut)
    check("future cursor empty slice",
          r4["trials"] == [] and set(r4.keys()) == {"trials", "limit", "since"})

    # 7. bad value -> 400
    try:
        rs.trials_read(limit=20, since="not-a-time")
        check("bad since -> 400", False)
    except HTTPException as e:
        check("bad since -> 400", e.status_code == 400
              and "ISO" in e.detail)

    # 8. echo normalization
    r5 = rs.trials_read(limit=20, since=mid)
    check("echo normalized", r5["since"] == datetime.fromisoformat(mid).isoformat())

    # 9. limit bounds the cursor slice
    r6 = rs.trials_read(limit=1, since=mid)
    check("limit bounds cursor slice",
          len(r6["trials"]) == 1 and r6["trials"][0]["puzzle"] == "puzzle2"
          and r6["limit"] == 1)

    # 10. no-aggregates rule: no count/tally keys anywhere
    agg = {"count", "total", "solved", "unsolved", "tries_total", "leaderboard"}
    check("no aggregates added", set(r.keys()) & agg == set()
          and set(r4.keys()) & agg == set())

    print(f"\n{PASS} passed, {FAIL} failed")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    run()
