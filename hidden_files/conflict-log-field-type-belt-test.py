#!/usr/bin/env python3
"""Belt: _log_name_conflict refuses a NON-STRING challenger field
instead of str()-aliasing it into the audit trail (primitive 1 naming).

_log_name_conflict (core.py) writes the rejected challenger to
name_conflicts for operators, and it str()-coerced signature and the
payload fields while storing the rest raw: an int node_pubkey (12345)
was stored as the text "12345", an int issued_at as "20261013", and an
int signature as "999" (verified before the fix) — an audit row for a
claim nobody ever made in that form, the SAME alias the binding seats
refuse on sight. Both production callers pass already-gated bindings,
but the logger was not self-contained. isinstance gate at the source:
name a string, challenger a dict, node_pubkey/issued_at/expires_at
real strings, signature a string when present (absent keeps the ""
default). A refused log is a silent skip — the never-raises contract
(a logging failure must not break the claim path) stands.

Covers: int node_pubkey / int issued_at / int signature challengers
store NO row; non-dict challenger stores no row and does not raise;
valid string challenger stored byte-exact with the canonical payload
(control); absent signature keeps the "" default (control).

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/conflict-log-field-type-belt-test.py
"""
import os
import sys
import tempfile

TMP = tempfile.mkdtemp(prefix="conflict-log-belt-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core  # noqa: E402

core.init_db()

CASES = {"passed": 0, "failed": 0}


def check(name, cond, extra=""):
    if cond:
        CASES["passed"] += 1
        print(f"  ok  {name}")
    else:
        CASES["failed"] += 1
        print(f"  FAIL {name} {extra}")


ISSUED = "2026-10-13T00:00:00Z"
EXPIRES = "2027-01-01T00:00:00Z"
INC = {"node_pubkey": "aa" * 32, "issued_at": ISSUED}
GOOD = {"node_pubkey": "bb" * 32, "issued_at": ISSUED,
        "expires_at": EXPIRES, "signature": "cc" * 64}


def log(name, challenger):
    with core._db_lock, core._db() as conn:
        core._log_name_conflict(conn, name, INC, challenger,
                                "live-foreign-incumbent")


def rows(name):
    with core._db_lock, core._db() as conn:
        return [tuple(r) for r in conn.execute(
            "SELECT challenger_pubkey, challenger_issued_at,"
            " challenger_signature, signed_payload FROM name_conflicts"
            " WHERE name=?", (name,)).fetchall()]


log("intpub", {**GOOD, "node_pubkey": 12345})
check("int node_pubkey stores no row", rows("intpub") == [])
log("intissued", {**GOOD, "issued_at": 20261013})
check("int issued_at stores no row", rows("intissued") == [])
log("intsig", {**GOOD, "signature": 999})
check("int signature stores no row", rows("intsig") == [])
log("nondict", None)
check("non-dict challenger stores no row, no raise", rows("nondict") == [])

log("goodname", GOOD)
kept = rows("goodname")
check("valid challenger stored byte-exact",
      kept == [("bb" * 32, ISSUED, "cc" * 64,
                core._name_claim_payload("goodname", "bb" * 32,
                                         ISSUED, EXPIRES))],
      f"got {kept!r}")
log("nosig", {k: v for k, v in GOOD.items() if k != "signature"})
check("absent signature keeps empty default",
      [r[:3] for r in rows("nosig")] == [("bb" * 32, ISSUED, "")])

print(f"{CASES['passed']} passed, {CASES['failed']} failed")
sys.exit(1 if CASES["failed"] else 0)
