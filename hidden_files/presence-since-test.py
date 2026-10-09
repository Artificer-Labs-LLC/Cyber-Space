"""Presence build item 11 regression pin: ?since= on GET /api/v1/presence.

Drives the REAL presence() route against a throwaway DB (CYBERNET_DB_DIR):
seed agents with old / recent / future-skewed last_seen, then verify the
cursor filters by last_seen, 400s on a bad value, normalizes the echo, and
composes honestly with ?status=.
"""
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_tmp = tempfile.mkdtemp(prefix="presence-since-")
os.environ["CYBERNET_DB_DIR"] = _tmp

import core  # noqa: E402
import routes_agents as ra  # noqa: E402
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
    seeds = [
        ("old-one", now - timedelta(hours=5)),
        ("fresh-one", now - timedelta(seconds=30)),
        ("skewed-one", now + timedelta(minutes=10)),  # beyond FUTURE_SLOP -> away
        ("never-one", ""),
    ]
    with ra._db_lock, ra._db() as conn:
        for name, seen in seeds:
            conn.execute(
                "INSERT INTO agents (name, description, capabilities, last_seen,"
                " api_key_hash, salt, key_lookup, created_at)"
                " VALUES (?,?,?,?,?,?,?,?)",
                (name, "", "[]",
                 seen.isoformat() if isinstance(seen, datetime) else seen,
                 "x", "x", "x", now.isoformat()))

    # 1. no cursor: everyone back (no behavior change)
    r = ra.presence(status=None, limit=50, since=None)
    check("no-since returns all 4", r["returned"] == 4 and r["since"] is None)

    # 2. cursor at now-1h: old-one + never-one drop out, fresh + skewed stay
    r = ra.presence(status=None, limit=50, since=(now - timedelta(hours=1)).isoformat())
    names = {a["name"] for a in r["agents"]}
    check("since filters stale beats",
          names == {"fresh-one", "skewed-one"})

    # 3. cursor in the future: honest empty slice
    r = ra.presence(status=None, limit=50, since=(now + timedelta(hours=1)).isoformat())
    check("future since -> empty, count 0",
          r["returned"] == 0 and r["count"] == 0 and r["here_count"] == 0)

    # 4. bad value: 400
    try:
        ra.presence(status=None, limit=50, since="not-a-time")
        check("bad since -> 400", False)
    except HTTPException as e:
        check("bad since -> 400", e.status_code == 400)

    # 5. since echoes back normalized ISO
    raw = "2026-10-09T07:20:40"
    r = ra.presence(status=None, limit=50, since=raw)
    check("since echoed normalized", r["since"] == "2026-10-09T07:20:40")

    # 6. since composes with ?status=here (fresh-one here, skewed-one away)
    r = ra.presence(status="here", limit=50, since=(now - timedelta(hours=1)).isoformat())
    names = {a["name"] for a in r["agents"]}
    check("since+status=here -> only fresh-one", names == {"fresh-one"})

    # 7. limit still bounds the cursor slice
    r = ra.presence(status=None, limit=1, since=(now - timedelta(hours=1)).isoformat())
    check("limit bounds cursor slice",
          r["returned"] == 1 and r["limit"] == 1)

    # 8. roster row contents intact (note fields present)
    r = ra.presence(status=None, limit=50, since=(now - timedelta(hours=1)).isoformat())
    a = next(x for x in r["agents"] if x["name"] == "fresh-one")
    check("status computed on cursor rows",
          a["status"] == "here" and "last_note" in a)

    print(f"presence-since: {PASS} passed, {FAIL} failed")
    return FAIL == 0


if __name__ == "__main__":
    raise SystemExit(0 if run() else 1)
