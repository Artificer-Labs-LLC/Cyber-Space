#!/usr/bin/env python3
"""Belt: GET /api/v1/directory serves ONLY a real list of string
capability tags (primitive 5 discovery).

node_directory loaded the stored capabilities JSON verbatim: a row
whose stored value was a JSON string/int/dict was served as that
entry's capabilities in a non-list shape, and the `cap` filter then
substring-matched a string ("mess" matched the tag "messaging" — the
route promises exact tag match), key-matched a dict, and crashed
TypeError ('argument of type int is not iterable') on an int — a 500
on the public directory from one malformed stored row. Every writer
stores a list of CAP_RE strings; any other loaded shape now reads as
no tags ([]), and non-string members of a list are dropped.

Covers: string caps served [] + cap="mess" does not match; int caps
served [] + cap filter does not raise; dict caps served []; list
caps with a non-string member served strings-only; valid list caps
byte-exact + exact cap matches + substring cap does not.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/directory-serve-caps-shape-belt-test.py
"""
import os
import sys
import tempfile

TMP = tempfile.mkdtemp(prefix="directory-serve-caps-belt-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core  # noqa: E402
from core import _db, _db_lock  # noqa: E402
import routes_agents  # noqa: E402

core.init_db()

CASES = {"passed": 0, "failed": 0}


def check(name, cond, extra=""):
    if cond:
        CASES["passed"] += 1
        print(f"  ok  {name}")
    else:
        CASES["failed"] += 1
        print(f"  FAIL {name} {extra}")


URL = "http://93.184.216.34/"
ROWS = [
    ("aa" * 32, "strcaps", '"messaging"'),
    ("bb" * 32, "intcaps", "123"),
    ("cc" * 32, "dictcaps", '{"messaging": 0}'),
    ("dd" * 32, "mixedcaps", '["messaging", 7, "relay"]'),
    ("ee" * 32, "listcaps", '["messaging"]'),
]
with _db_lock, _db() as conn:
    for pub, name, caps in ROWS:
        conn.execute(
            "INSERT INTO peers (node_pub, name, network, version, genesis,"
            " capabilities, node_url, announced_at, first_seen, retired_at)"
            " VALUES (?,?, 'cybernet', '0.1.0', 0, ?, ?, '', '', '')",
            (pub, name, caps, URL))

out = routes_agents.node_directory(cap=None, limit=50)
by_name = {e["name"]: e["capabilities"] for e in out["entries"]}
check("string caps served as []", by_name.get("strcaps") == [], repr(by_name.get("strcaps")))
check("int caps served as []", by_name.get("intcaps") == [], repr(by_name.get("intcaps")))
check("dict caps served as []", by_name.get("dictcaps") == [], repr(by_name.get("dictcaps")))
check("mixed list served strings only", by_name.get("mixedcaps") == ["messaging", "relay"],
      repr(by_name.get("mixedcaps")))
check("valid list caps byte-exact", by_name.get("listcaps") == ["messaging"],
      repr(by_name.get("listcaps")))

try:
    sub = routes_agents.node_directory(cap="mess", limit=50)
    check("substring cap matches nothing", sub["entries"] == [],
          repr([e["name"] for e in sub["entries"]]))
except Exception as ex:  # noqa: BLE001
    check("substring cap matches nothing", False, f"raised {type(ex).__name__}: {ex}")

exact = routes_agents.node_directory(cap="messaging", limit=50)
check("exact cap matches list carriers only",
      sorted(e["name"] for e in exact["entries"]) == ["listcaps", "mixedcaps"],
      repr([e["name"] for e in exact["entries"]]))

print(f"---\n{CASES['passed']} passed, {CASES['failed']} failed")
sys.exit(1 if CASES["failed"] else 0)
