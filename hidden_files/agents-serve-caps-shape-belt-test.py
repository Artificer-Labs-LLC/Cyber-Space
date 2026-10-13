#!/usr/bin/env python3
"""Belt: GET /api/v1/agents (list_agents) and the presence roster
(_presence_summary) serve ONLY a real list of string capability tags
(primitive 5 discovery).

Both seats loaded the stored capabilities JSON verbatim (bare
json.loads, only a parse failure read as []): a row whose stored value
was a JSON string/int/dict was served as that agent's capabilities in
a non-list shape, and a list kept its non-string members — the same
flaw node_directory's serve gate and _gossip_out's _stored_caps gate
already refuse on sight (their agent-roster twins were left ungated).
Every writer stores a list of CAP_RE strings; any other loaded shape
now reads as no tags ([]), and non-string members of a list are
dropped, via core._stored_caps at both seats.

Covers (each seat): string caps served []; int caps []; dict caps [];
malformed JSON []; mixed list served strings only; valid list caps
byte-exact.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/agents-serve-caps-shape-belt-test.py
"""
import os
import sys
import tempfile

TMP = tempfile.mkdtemp(prefix="agents-serve-caps-belt-")
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


ROWS = [
    ("strcaps", '"messaging"'),
    ("intcaps", "123"),
    ("dictcaps", '{"messaging": 0}'),
    ("badjson", "not json"),
    ("mixedcaps", '["messaging", 7, "relay"]'),
    ("listcaps", '["messaging"]'),
]
with _db_lock, _db() as conn:
    for name, caps in ROWS:
        conn.execute(
            "INSERT INTO agents (name, description, capabilities,"
            " api_key_hash, salt, key_lookup, created_at)"
            " VALUES (?, '', ?, 'h', 's', 'k', '')",
            (name, caps))

EXPECT = {
    "strcaps": [], "intcaps": [], "dictcaps": [], "badjson": [],
    "mixedcaps": ["messaging", "relay"], "listcaps": ["messaging"],
}

out = routes_agents.list_agents(q=None, limit=50)
by_name = {a["name"]: a["capabilities"] for a in out["agents"]}
for name, want in EXPECT.items():
    check(f"list_agents {name} served {want!r}", by_name.get(name) == want,
          repr(by_name.get(name)))

agents, _here, _window = routes_agents._presence_summary()
by_name = {a["name"]: a["capabilities"] for a in agents}
for name, want in EXPECT.items():
    check(f"presence {name} served {want!r}", by_name.get(name) == want,
          repr(by_name.get(name)))

print(f"---\n{CASES['passed']} passed, {CASES['failed']} failed")
sys.exit(1 if CASES["failed"] else 0)
