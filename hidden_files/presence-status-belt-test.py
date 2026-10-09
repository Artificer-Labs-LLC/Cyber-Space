"""Presence build item 25 regression pin: ?status= belt on GET /api/v1/presence.

Drives the REAL presence() route against a throwaway DB (CYBERNET_DB_DIR):
seed one 'here' agent (fresh last_seen) and one 'away' agent (stale last_seen),
then verify: no-param behavior is unchanged (both listed, echo status None),
?status=here filters + echoes 'here', ?status=away filters + echoes 'away',
a junk value 400s (the old code silently ignored it while echoing it back
as though it had filtered — a dishonest contract), an empty value 400s
(mirrors the ?since= belt), and case/whitespace values normalize.
"""
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_tmp = tempfile.mkdtemp(prefix="presence-status-belt-")
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
    fresh = now.isoformat()
    stale = (now - timedelta(hours=2)).isoformat()
    with ra._db_lock, ra._db() as conn:
        conn.execute(
            "INSERT INTO agents (name, description, api_key_hash, salt, created_at, last_seen)"
            " VALUES ('fresheye', 'd', 'h', 's', ?, ?)", (fresh, fresh))
        conn.execute(
            "INSERT INTO agents (name, description, api_key_hash, salt, created_at, last_seen)"
            " VALUES ('greyeye', 'd', 'h', 's', ?, ?)", (stale, stale))

    # 1: no-param behavior unchanged: both agents, echo status None
    r = ra.presence(status=None, limit=50, since=None)
    names = [a["name"] for a in r["agents"]]
    check("no-param: both agents listed, echo status None",
          "fresheye" in names and "greyeye" in names and r["status"] is None)

    # 2: ?status=here filters + echoes
    r = ra.presence(status="here", limit=50, since=None)
    check("here: only the fresh agent, echo 'here'",
          [a["name"] for a in r["agents"]] == ["fresheye"]
          and r["status"] == "here" and r["here_count"] == 1)

    # 3: ?status=away filters + echoes
    r = ra.presence(status="away", limit=50, since=None)
    check("away: only the stale agent, echo 'away'",
          [a["name"] for a in r["agents"]] == ["greyeye"]
          and r["status"] == "away" and r["here_count"] == 0)

    # 4: junk value 400s — the belt (no silent ignore + dishonest echo)
    try:
        ra.presence(status="banana", limit=50, since=None)
        check("junk status 400", False)
    except HTTPException as e:
        check("junk status 400",
              e.status_code == 400 and "'here'" in e.detail and "'away'" in e.detail)

    # 5: empty value 400s (mirrors the ?since= belt — a value was given)
    try:
        ra.presence(status="", limit=50, since=None)
        check("empty status 400", False)
    except HTTPException as e:
        check("empty status 400", e.status_code == 400)

    # 6: case/whitespace normalization still filters + normalizes echo
    r = ra.presence(status=" HERE ", limit=50, since=None)
    check("normalization: ' HERE ' -> here filter + echo",
          [a["name"] for a in r["agents"]] == ["fresheye"] and r["status"] == "here")

    # 7: status+since combo still works honestly
    r = ra.presence(status="here", limit=50, since=stale)
    check("since+status combo: fresh agent survives both",
          [a["name"] for a in r["agents"]] == ["fresheye"]
          and r["status"] == "here" and r["since"] is not None)

    print(f"\n{PASS} passed, {FAIL} failed")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    run()
