#!/usr/bin/env python3
"""Belt: _gossip_out gossips ONLY a real list of string capability
tags (primitive 5 discovery).

_gossip_out loaded stored capabilities JSON verbatim into the roster
entries it signs and sends to every announced peer: a row whose
stored value was a JSON string/int/dict was gossiped in that shape,
so this node propagated a tag set nobody stored as a list (receivers
gate it to [], but the sender is the seat that puts it on the wire).
Every writer stores a list of CAP_RE strings; any other loaded shape
now reads as no tags ([]), and non-string members of a list are
dropped. Malformed stored JSON reads as [] instead of killing the
gossip cycle.

Covers: string/int/dict caps gossiped []; mixed list gossiped
strings-only; valid list byte-exact; malformed JSON gossiped [] and
the cycle still returns its recipient count.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/gossip-out-caps-shape-belt-test.py
"""
import os
import sys
import tempfile

TMP = tempfile.mkdtemp(prefix="gossip-out-caps-belt-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core  # noqa: E402
from core import _db, _db_lock  # noqa: E402

core.init_db()

CASES = {"passed": 0, "failed": 0}


def check(name, cond, extra=""):
    if cond:
        CASES["passed"] += 1
        print(f"  ok  {name}")
    else:
        CASES["failed"] += 1
        print(f"  FAIL {name} {extra}")


SENT = []


class FakeThread:
    def __init__(self, target=None, args=(), daemon=None):
        self.args = args

    def start(self):
        SENT.append(self.args[2])


core.threading.Thread = FakeThread

URL = "http://93.184.216.34/"
ROWS = [
    ("aa" * 32, "strcaps", '"messaging"'),
    ("bb" * 32, "intcaps", "123"),
    ("cc" * 32, "dictcaps", '{"messaging": 0}'),
    ("dd" * 32, "mixedcaps", '["messaging", 7, "relay"]'),
    ("ee" * 32, "listcaps", '["messaging"]'),
    ("ff" * 32, "badjson", "not-json{"),
]
with _db_lock, _db() as conn:
    for pub, name, caps in ROWS:
        conn.execute(
            "INSERT INTO peers (node_pub, name, network, version, genesis,"
            " capabilities, node_url, announced_at, first_seen, retired_at)"
            " VALUES (?,?, 'cybernet', '0.1.0', 0, ?, ?, '2026-01-01', '', '')",
            (pub, name, caps, URL))

try:
    sent = core._gossip_out()
    check("gossip cycle completes", sent == len(ROWS), f"sent={sent}")
except Exception as ex:  # noqa: BLE001
    check("gossip cycle completes", False, f"raised {type(ex).__name__}: {ex}")
    sent = 0

by_name = {}
for env in SENT:
    for e in env["body"]["roster"]:
        by_name[e["name"]] = e["capabilities"]
check("string caps gossiped as []", by_name.get("strcaps") == [], repr(by_name.get("strcaps")))
check("int caps gossiped as []", by_name.get("intcaps") == [], repr(by_name.get("intcaps")))
check("dict caps gossiped as []", by_name.get("dictcaps") == [], repr(by_name.get("dictcaps")))
check("mixed list gossiped strings only", by_name.get("mixedcaps") == ["messaging", "relay"],
      repr(by_name.get("mixedcaps")))
check("valid list caps byte-exact", by_name.get("listcaps") == ["messaging"],
      repr(by_name.get("listcaps")))
check("malformed JSON gossiped as []", by_name.get("badjson") == [], repr(by_name.get("badjson")))

print(f"---\n{CASES['passed']} passed, {CASES['failed']} failed")
sys.exit(1 if CASES["failed"] else 0)
