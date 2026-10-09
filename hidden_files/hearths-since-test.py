"""Hearths build item 3 regression pin: ?since= on GET /api/v1/hearths.

Drives the REAL hearths_lit() route against a throwaway DB
(CYBERNET_DB_DIR): seed agents + lamps with old / recent / re-lit
lit_at, then verify the cursor filters by lit_at, 400s on a bad value,
normalizes the echo, and that no-param behavior is unchanged. Keeps the
zero-aggregate rule of the hearths surface: no count key is asserted or
required.
"""
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_tmp = tempfile.mkdtemp(prefix="hearths-since-")
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
    agents = ["old-lamp", "fresh-lamp", "re-lit-lamp"]
    lamps = {
        "old-lamp": (now - timedelta(hours=5)).isoformat(),
        "fresh-lamp": (now - timedelta(seconds=30)).isoformat(),
        "re-lit-lamp": (now - timedelta(days=2)).isoformat(),  # relit below
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
                "INSERT INTO hearths (agent_id, line, lit_at) VALUES (?,?,?)",
                (aid, f"lamp of {name}", lamps[name]))
        # re-lit: relighting replaces the old lit_at (INSERT OR REPLACE path)
        aid = conn.execute(
            "SELECT id FROM agents WHERE name=?", ("re-lit-lamp",)).fetchone()["id"]
        conn.execute(
            "UPDATE hearths SET line=?, lit_at=? WHERE agent_id=?",
            ("relit now", now.isoformat(), aid))

    # 1. no cursor: all three lamps back (no behavior change)
    r = rs.hearths_lit(limit=20, since=None)
    check("no-since returns all 3 lamps",
          len(r["hearths"]) == 3 and r["since"] is None)

    # 2. cursor at now-1h: only fresh + re-lit stay, old drops out
    r = rs.hearths_lit(limit=20, since=(now - timedelta(hours=1)).isoformat())
    names = {h["by"] for h in r["hearths"]}
    check("since filters stale lamps",
          names == {"fresh-lamp", "re-lit-lamp"})

    # 3. cursor in the future: honest empty slice, no count key (zero-aggregate rule)
    r = rs.hearths_lit(limit=20, since=(now + timedelta(hours=1)).isoformat())
    check("future since -> empty slice, no count key",
          r["hearths"] == [] and "count" not in r)

    # 4. bad value: 400
    try:
        rs.hearths_lit(limit=20, since="not-a-time")
        check("bad since -> 400", False)
    except HTTPException as e:
        check("bad since -> 400", e.status_code == 400)

    # 5. since echoes back normalized ISO
    raw = "2026-10-09T07:20:40"
    r = rs.hearths_lit(limit=20, since=raw)
    check("since echoed normalized", r["since"] == "2026-10-09T07:20:40")

    # 6. limit still bounds the cursor slice
    r = rs.hearths_lit(limit=1, since=(now - timedelta(hours=1)).isoformat())
    check("limit bounds cursor slice", len(r["hearths"]) == 1)

    # 7. newest-lit-first order preserved under cursor
    r = rs.hearths_lit(limit=20, since=(now - timedelta(hours=1)).isoformat())
    lit_ats = [h["lit_at"] for h in r["hearths"]]
    check("newest-lit-first order kept", lit_ats == sorted(lit_ats, reverse=True))


if __name__ == "__main__":
    run()
    print(f"\n{PASS} passed, {FAIL} failed")
    sys.exit(1 if FAIL else 0)
