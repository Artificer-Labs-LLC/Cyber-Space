#!/usr/bin/env python3
"""Belt: /api/v1/names/{name}/reach serves ONLY a real list reach
(primitives 1 naming + 2 resolution + 3 hosting).

names_reach loaded the stored reach JSON verbatim and served it in
whatever shape it was stored in: a JSON string/int/dict/null row was
served 200 as the descriptor's reach, a descriptor every consumer
refuses on sight — _reach_descriptor_verify requires a list (any
other shape verifies False at resolve step 5, dial step 4, and the
ingest merge). The route's own contract says a mirror never
advertises a descriptor the dialer could not use (its expiry seat);
the shape seat was left ungated. Every writer (ingest_reach_descriptor,
the only writer) stores json.dumps of a verify-proved list.

Covers: string reach 404; int reach 404; dict reach 404; null reach
404; malformed JSON 404; valid list 200 byte-exact + self-verifies;
empty list 200 (a list is a list — verify's shape gate passes it).

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/reach-serve-shape-belt-test.py
"""
import json
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone

TMP = tempfile.mkdtemp(prefix="reach-serve-shape-belt-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core  # noqa: E402
import app as cyber  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from fed import ed25519 as _ed  # noqa: E402

CASES = {"passed": 0, "failed": 0}


def check(name, cond, extra=""):
    if cond:
        CASES["passed"] += 1
        print(f"  ok  {name}")
    else:
        CASES["failed"] += 1
        print(f"  FAIL {name} {extra}")


def _iso(dt):
    return dt.isoformat(timespec="seconds")


now = datetime.now(timezone.utc)
ISSUED = _iso(now - timedelta(days=1))
LIVE = _iso(now + timedelta(days=6))

_seed = os.urandom(32)
_pub = _ed.publickey(_seed).hex()
REACH = [{"kind": "direct", "url": "http://93.184.216.36:18799/"}]

LABELS = {
    "reachshapeStr": '"direct"',
    "reachshapeInt": "123",
    "reachshapeDict": '{"kind": "direct"}',
    "reachshapeNull": "null",
    "reachshapeBad": "not json",
    "reachshapeList": json.dumps(REACH, sort_keys=True, separators=(",", ":")),
    "reachshapeEmpty": "[]",
}

core.init_db()
with core._db_lock, core._db() as conn:
    for label, reach_json in LABELS.items():
        lab = label.lower()
        sig = _ed.sign(core._name_claim_payload(lab, _pub, ISSUED, LIVE),
                       _seed, bytes.fromhex(_pub)).hex()
        conn.execute(
            "INSERT INTO name_bindings (name, node_pubkey, issued_at,"
            " expires_at, signature) VALUES (?,?,?,?,?)",
            (lab, _pub, ISSUED, LIVE, sig))
        # Descriptor signature is the minted one for the valid case;
        # the shape cases are seeded directly (ingest's fail-closed
        # verify would drop them) with the same signature string.
        desc = core._reach_mint(_seed.hex(), _pub, lab, REACH, ISSUED, LIVE)
        conn.execute(
            "INSERT INTO reach_descriptors (name, node_pubkey, reach,"
            " issued_at, expires_at, signature) VALUES (?,?,?,?,?,?)",
            (lab, _pub, reach_json, ISSUED, LIVE, desc["signature"]))

with TestClient(cyber.app) as c:
    for label in ("reachshapestr", "reachshapeint", "reachshapedict",
                  "reachshapenull", "reachshapebad"):
        r = c.get(f"/api/v1/names/{label}/reach")
        check(f"{label} non-list reach -> 404", r.status_code == 404,
              f"{r.status_code} {r.text[:120]}")
    r = c.get("/api/v1/names/reachshapelist/reach")
    check("valid list reach -> 200", r.status_code == 200, r.status_code)
    if r.status_code == 200:
        payload = r.json()
        check("valid list reach byte-exact", payload.get("reach") == REACH,
              repr(payload.get("reach")))
        check("valid descriptor self-verifies",
              core._reach_descriptor_verify(payload))
    r = c.get("/api/v1/names/reachshapeempty/reach")
    check("empty list reach -> 200", r.status_code == 200, r.status_code)
    if r.status_code == 200:
        check("empty list reach served []", r.json().get("reach") == [],
              repr(r.json().get("reach")))

print(f"---\n{CASES['passed']} passed, {CASES['failed']} failed")
sys.exit(1 if CASES["failed"] else 0)
