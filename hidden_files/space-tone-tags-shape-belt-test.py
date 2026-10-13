#!/usr/bin/env python3
"""Belt: _space_tone_tags serves ONLY a real list of string tone tags
(primitive 3 hosting / space door).

The loader gated the loaded shape as a list (non-list reads as []) but
kept a list's members verbatim: a stored row holding a mixed list was
served on the public street/door with its non-string members (ints,
nulls, dicts, nested lists) as the space's room conventions — the same
flaw core._stored_caps already refuses on sight for capabilities.
Every writer (space_tone_tags_set) stores a list of vocabulary strings;
non-string members of a stored list are not tags and are dropped.

Covers: string tags []; int tags []; dict tags []; malformed JSON [];
mixed list served strings only; valid list byte-exact; empty list [].

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/space-tone-tags-shape-belt-test.py
"""
import os
import sys
import tempfile

TMP = tempfile.mkdtemp(prefix="tone-tags-shape-belt-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core  # noqa: E402
from core import _db, _db_lock  # noqa: E402
import routes_spaces  # noqa: E402

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
    ("strtags", '"quiet"'),
    ("inttags", "123"),
    ("dicttags", '{"quiet": 0}'),
    ("badjson", "not json"),
    ("mixedtags", '["quiet", 7, "calm", null, {"x": 1}, ["nested"]]'),
    ("listtags", '["quiet", "calm"]'),
    ("emptytags", "[]"),
]
with _db_lock, _db() as conn:
    for name, tags in ROWS:
        conn.execute(
            "INSERT INTO space_tone_tags (space_name, tone_tags, updated_at)"
            " VALUES (?, ?, '')",
            (name, tags))

EXPECT = {
    "strtags": [], "inttags": [], "dicttags": [], "badjson": [],
    "mixedtags": ["quiet", "calm"], "listtags": ["quiet", "calm"],
    "emptytags": [],
}

with _db_lock, _db() as conn:
    for name, want in EXPECT.items():
        got = routes_spaces._space_tone_tags(conn, name)
        check(f"_space_tone_tags {name} served {want!r}", got == want,
              repr(got))
    check("_space_tone_tags missing space served []",
          routes_spaces._space_tone_tags(conn, "nosuchspace") == [])

print(f"---\n{CASES['passed']} passed, {CASES['failed']} failed")
sys.exit(1 if CASES["failed"] else 0)
