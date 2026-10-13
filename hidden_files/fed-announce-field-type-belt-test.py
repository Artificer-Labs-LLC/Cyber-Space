#!/usr/bin/env python3
"""Belt: fed_announce refuses a NON-STRING body field instead of
str()-aliasing it (primitives 1 naming + 5 discovery).

fed_announce (federation.py) read the roster body through str():
an announce-carried numeric name (12345) stringified to the valid
label "12345" and was STORED as that peer name, and int
network/version were stored as their digit strings -- the same
alias the binding/roster/delta seats refuse on sight. Only real
strings are announce roster fields; absent fields keep defaults.

Covers: int name refused (400, no row); int network refused
(400, no row); int version refused (400, no row);
valid string announce stored exact (control).

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/fed-announce-field-type-belt-test.py
"""
import os
import secrets
import sys
import tempfile

TMP = tempfile.mkdtemp(prefix="fed-announce-field-type-belt-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core  # noqa: E402
from core import _db, _db_lock  # noqa: E402
import federation  # noqa: E402
from fed import envelope as fenv, ed25519  # noqa: E402
from fastapi import HTTPException  # noqa: E402

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


def attempt(body_extra):
    sk = secrets.token_bytes(32)
    pk = ed25519.publickey(sk).hex()
    body = {"node_pub": pk, "name": "validnode", "node_url": URL,
            "network": "cybernet", "version": "0.1.0"}
    body.update(body_extra)
    # body_extra may override node_pub mismatch; keep node_pub == pk
    body["node_pub"] = pk
    env = fenv.make_envelope(sk.hex(), pk, core._NODE_PUB, body)
    try:
        out = federation.fed_announce(env)
        status, detail = 200, ""
    except HTTPException as e:
        out, status, detail = None, e.status_code, str(e.detail)
    with _db_lock, _db() as conn:
        row = conn.execute(
            "SELECT name, network, version FROM peers WHERE node_pub=?",
            (pk,)).fetchone()
    return status, detail, out, row


# 1. int name: str() alias is a valid label, must be refused.
status, detail, out, row = attempt({"name": 12345})
check("int name refused 400 bad node name, no row",
      status == 400 and detail == "bad node name" and row is None,
      f"{status} {detail} row={row}")

# 2. int network: must be refused, not stored as digit string.
status, detail, out, row = attempt({"network": 12345})
check("int network refused 400, no row",
      status == 400 and row is None, f"{status} {detail} row={row}")

# 3. int version: must be refused, not stored as digit string.
status, detail, out, row = attempt({"version": 1})
check("int version refused 400, no row",
      status == 400 and row is None, f"{status} {detail} row={row}")

# 4. valid string control: stored byte-exact.
status, detail, out, row = attempt({})
check("valid string announce stored exact",
      status == 200 and row is not None and row["name"] == "validnode"
      and row["network"] == "cybernet" and row["version"] == "0.1.0",
      f"{status} {detail} row={row}")

print(f"{CASES['passed']} passed, {CASES['failed']} failed")
sys.exit(1 if CASES["failed"] else 0)
