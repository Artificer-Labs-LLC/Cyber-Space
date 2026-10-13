#!/usr/bin/env python3
"""Belt: /api/v1/names/{name}/reach refuses a stored descriptor whose
sig/pubkey STRING length is not 128/64 even when its decode is the
right byte count (primitives 1 naming + 2 resolution + 3 hosting).

names_reach served the stored reach_descriptors row VERBATIM with no
string-length gate: a legacy/pre-gate row with a 129-char inserted-
space sig (or outer-padded spelling, or a 65-char spaced pubkey)
decoded to the TRUE bytes yet was served in a non-canonical spelling
every consumer refuses on sight (_reach_descriptor_verify gates
len(signature) != 128 / len(node_pubkey) != 64). The serve seat is
the seat that puts it on the wire; only exact 128/64 spellings are
served, anything else reads as absent (404), twin of
_names_gossip_out's sender gate (008dfd2). Case is left alone
(uppercase served before and still does).

Covers: valid 200 byte-exact + self-verifies; uppercase sig+pub 200;
inserted-space sig 404; outer-padded sig 404; inserted-space pubkey
404; outer-padded pubkey 404 (pub cases seed the binding with the
same spelling so the binding-match seat passes and only the length
gate can refuse).

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/reach-serve-stringlen-belt-test.py
"""
import json
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone

TMP = tempfile.mkdtemp(prefix="reach-serve-strlen-belt-")
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
REACH_JSON = json.dumps(REACH, sort_keys=True, separators=(",", ":"))


def _spaced(s):
    return s[:32] + " " + s[32:]


def _padded(s):
    return " " + s


core.init_db()

with core._db_lock, core._db() as conn:
    for lab, pub_spell, sig_spell in (
            ("valid", "clean", "clean"), ("upper", "upper", "upper"),
            ("sigs", "clean", "spaced"), ("sigp", "clean", "padded"),
            ("pubs", "spaced", "clean"), ("pubp", "padded", "clean")):
        lab = "reachstrlen" + lab
        good = core._reach_mint(
            _seed.hex(), _pub, lab, REACH, ISSUED, LIVE)["signature"]
        dpub = {"clean": _pub, "upper": _pub.upper(),
                "spaced": _spaced(_pub), "padded": _padded(_pub)}[pub_spell]
        dsig = {"clean": good, "upper": good.upper(),
                "spaced": _spaced(good), "padded": _padded(good)}[sig_spell]
        sig = _ed.sign(core._name_claim_payload(lab, _pub, ISSUED, LIVE),
                       _seed, bytes.fromhex(_pub)).hex()
        conn.execute(
            "INSERT INTO name_bindings (name, node_pubkey, issued_at,"
            " expires_at, signature) VALUES (?,?,?,?,?)",
            (lab, dpub, ISSUED, LIVE, sig))
        conn.execute(
            "INSERT INTO reach_descriptors (name, node_pubkey, reach,"
            " issued_at, expires_at, signature) VALUES (?,?,?,?,?,?)",
            (lab, dpub, REACH_JSON, ISSUED, LIVE, dsig))

with TestClient(cyber.app) as c:
    r = c.get("/api/v1/names/reachstrlenvalid/reach")
    check("valid -> 200", r.status_code == 200, r.status_code)
    if r.status_code == 200:
        payload = r.json()
        want = core._reach_mint(_seed.hex(), _pub, "reachstrlenvalid",
                                REACH, ISSUED, LIVE)["signature"]
        check("valid byte-exact", payload.get("signature") == want
              and payload.get("node_pubkey") == _pub, repr(payload)[:160])
        check("valid self-verifies", core._reach_descriptor_verify(payload))
    r = c.get("/api/v1/names/reachstrlenupper/reach")
    check("uppercase sig+pub -> 200", r.status_code == 200, r.status_code)
    for lab in ("reachstrlensigs", "reachstrlensigp",
                "reachstrlenpubs", "reachstrlenpubp"):
        r = c.get(f"/api/v1/names/{lab}/reach")
        check(f"{lab} -> 404", r.status_code == 404,
              f"{r.status_code} {r.text[:120]}")

print(f"---\n{CASES['passed']} passed, {CASES['failed']} failed")
sys.exit(1 if CASES["failed"] else 0)
