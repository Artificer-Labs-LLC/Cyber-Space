"""Fresh audit thread (unbounded unauthenticated reads) regression pin: per-IP
read belts on GET /api/v1/node and GET /api/v1/agents.

Drives the REAL node_info() and list_agents() routes against a throwaway DB
(CYBERNET_DB_DIR) with a real Starlette Request (scope client IP set).

Verify:
  1. node: 60 reads pass, 61st 429s with the house detail, before any DB work.
  2. agents: 60 reads pass, 61st 429s, other-IP isolation (bucket is per-IP).
  3. Shape unchanged: node response carries its usual keys (agent_surface
     still lists inhabitants, no fed-* rows seeded here), agents read still
     honors q search + limit.
"""
import os
import sys
import tempfile
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_tmp = tempfile.mkdtemp(prefix="node-read-rate-")
os.environ["CYBERNET_DB_DIR"] = _tmp

from starlette.requests import Request  # noqa: E402
from fastapi import HTTPException  # noqa: E402

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


def _req(ip: str) -> Request:
    return Request({"type": "http", "method": "GET", "headers": [],
                    "client": (ip, 51234)})


def _gate_runs(fn, route_label, ip):
    """Fire (limit+1) reads; return (reads_ok, detail_of_61st_or_None)."""
    ok = 0
    detail = None
    for _ in range(ra.NODE_READ_LIMIT + 1):
        try:
            fn()
        except HTTPException as e:
            if e.status_code == 429:
                detail = e.detail
                break
            raise
        else:
            ok += 1
    return ok, detail


def run():
    global PASS, FAIL
    core.init_db()
    now = datetime.now(timezone.utc).isoformat()
    with ra._db_lock, ra._db() as conn:
        conn.execute(
            "INSERT INTO agents (name, description, api_key_hash, salt, created_at, last_seen)"
            " VALUES ('scout-one', 'watches the square', 'h', 's', ?, ?)", (now, now))
        conn.execute(
            "INSERT INTO agents (name, description, api_key_hash, salt, created_at, last_seen)"
            " VALUES ('scout-two', 'watches the square', 'h', 's', ?, ?)", (now, now))

    ip_a, ip_b = "10.1.1.7", "10.1.1.8"

    # 1. node: 60 pass, 61st 429s with the house detail
    ok, detail = _gate_runs(lambda: ra.node_info(_req(ip_a)), "node", ip_a)
    check("node: 60 reads pass, 61st is 429",
          ok == ra.NODE_READ_LIMIT and detail is not None)
    check("node: 429 carries the house detail",
          detail == f"Rate limit exceeded: {ra.NODE_READ_LIMIT} requests/{int(ra.NODE_READ_WINDOW)}s.")

    # 2. agents: same belt, per-IP isolation
    ok, detail = _gate_runs(lambda: ra.list_agents(_req(ip_a), q=None, limit=50), "agents", ip_a)
    check("agents: 60 reads pass, 61st is 429", ok == ra.NODE_READ_LIMIT and detail is not None)
    try:
        ra.list_agents(_req(ip_b), q=None, limit=50)
        other_ok = True
    except HTTPException:
        other_ok = False
    check("agents: other IP unaffected by first IP's saturation", other_ok)

    # 3. shape unchanged on a fresh IP
    r = ra.node_info(_req("10.1.1.9"))
    here = r.get("inhabitants", {}).get("here", [])
    check("node: surface shape intact, inhabitants still shown",
          "scout-one" in here and "scout-two" in here
          and r["inhabitants"]["here_count"] == 2
          and isinstance(r.get("directory", {}).get("known_peers"), int)
          and isinstance(r.get("deeds", {}).get("recent"), list))
    r = ra.list_agents(_req("10.1.1.9"), q="scout-one", limit=50)
    check("agents: q search + shape intact",
          r["query"] == "scout-one" and len(r["agents"]) == 1
          and r["agents"][0]["name"] == "scout-one" and r["returned"] == 1)
    r = ra.list_agents(_req("10.1.1.9"), q=None, limit=50)
    check("agents: no-param unchanged (both rows, limit echo)",
          r["returned"] == 2 and r["limit"] == 50)


if __name__ == "__main__":
    run()
    print(f"\n{PASS} passed, {FAIL} failed")
    sys.exit(1 if FAIL else 0)
