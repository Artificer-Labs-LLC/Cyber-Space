"""Presence build item 26 regression pin: fed-* exclusion on GET /api/v1/presence.

Drives the REAL presence() route against a throwaway DB (CYBERNET_DB_DIR):
seed one local 'here' agent (fresh last_seen), one local 'away' agent (stale
last_seen), and one fed-* pseudo-agent with FRESH last_seen — the damning
case: an actively-messaging foreign sender (federated posts refresh last_seen
via _post_message) would otherwise read 'here' on the square's who's-here.
Also seed a stale fed-* row to pin the ?since= path.

Verify: the fed-* rows never appear in agents/count/here_count on any path
(no-param, ?status=here, ?status=away, ?since=), while local agents behave
exactly as before. /api/v1/node already excluded fed-* as "not inhabitants
of this one"; the dedicated who's-here read now matches that definition.
"""
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_tmp = tempfile.mkdtemp(prefix="presence-fedexcl-")
os.environ["CYBERNET_DB_DIR"] = _tmp

import core  # noqa: E402
import routes_agents as ra  # noqa: E402

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
        # The foreign stand-in: fresh last_seen, i.e. actively messaging.
        conn.execute(
            "INSERT INTO agents (name, description, api_key_hash, salt, created_at, last_seen)"
            " VALUES ('fed-ab12cd34ef56-farwalker', 'federated sender', 'h', 's', ?, ?)",
            (fresh, fresh))
        # A stale foreign stand-in for the ?since= cursor path.
        conn.execute(
            "INSERT INTO agents (name, description, api_key_hash, salt, created_at, last_seen)"
            " VALUES ('fed-ab12cd34ef56-quietone', 'federated sender', 'h', 's', ?, ?)",
            (stale, stale))

    # 1: no-param: locals unchanged, fed-* excluded, here_count honest
    r = ra.presence(status=None, limit=50, since=None)
    names = [a["name"] for a in r["agents"]]
    check("no-param: locals listed, fed-* excluded, here_count=1",
          "fresheye" in names and "greyeye" in names
          and not any(n.startswith("fed-") for n in names)
          and r["count"] == 2 and r["here_count"] == 1)

    # 2: ?status=here: the fresh fed-* row must not appear as 'here'
    r = ra.presence(status="here", limit=50, since=None)
    names = [a["name"] for a in r["agents"]]
    check("?status=here: only the local here agent",
          names == ["fresheye"] and r["here_count"] == 1)

    # 3: ?status=away: only the local away agent, count honest
    r = ra.presence(status="away", limit=50, since=None)
    names = [a["name"] for a in r["agents"]]
    check("?status=away: only the local away agent, here_count=0",
          names == ["greyeye"] and r["count"] == 1 and r["here_count"] == 0)

    # 4: ?since= (recent cursor): fed-* never leaks through the cursor path
    r = ra.presence(status=None, limit=50,
                    since=(now - timedelta(minutes=30)).isoformat())
    names = [a["name"] for a in r["agents"]]
    check("?since=: locals per cursor, fed-* excluded",
          "fresheye" in names and not any(n.startswith("fed-") for n in names))

    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(run())
