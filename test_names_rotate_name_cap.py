#!/usr/bin/env python3
"""ART-42 392140b7: per-NAME rotation cap at /api/v1/names/rotate.

Rows (each with a mutant that must fail it):
1. Name A rotates CAP times (200); rotation CAP+1 on A is 429 and writes
   no row. Mutant: the cap check is a no-op.
2. Exhausting A does not affect B: B still rotates (200). Mutant: the cap
   counts name_rotations across ALL names (one global total).
3. Default is conservative: under window_open.SNAPSHOT_PER_NAME.
Scratch DB only.
"""
import os
import sys
import tempfile

os.environ["CYBERNET_DB_DIR"] = tempfile.mkdtemp(prefix="art42-rotcap-")
os.environ["CYBERNET_NAME_CLAIM_RATE_LIMIT"] = "1000"
os.environ["CYBERNET_NAME_ROTATE_PER_NAME_CAP"] = "3"
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient  # noqa: E402
import core  # noqa: E402
core.init_db()
import core_serve  # noqa: E402
from fed import ed25519 as _ed  # noqa: E402
import app as appmod  # noqa: E402
import routes_social_serve as rss  # noqa: E402
import window_open as wo  # noqa: E402
from rotate_name import _rotate_payload  # noqa: E402

client = TestClient(appmod.app)
PASS = FAIL = 0
MUTANTS = []
ISSUED = "2026-01-01T00:00:00+00:00"
EXPIRES = "2099-01-01T00:00:00+00:00"
CAP = 3


def check(label, cond, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok  {label}")
    else:
        FAIL += 1
        print(f"  FAIL {label} {extra}")


def record_mutant(name, row, real_ok, mutant_fails):
    MUTANTS.append((name, row, real_ok, mutant_fails))
    check(f"MUTANT {name}: real passes and mutant fails the row", real_ok and mutant_fails,
          (real_ok, mutant_fails))


PRIVS = [bytes([0x30 + i]) * 32 for i in range(12)]
PUBS = [_ed.publickey(p).hex() for p in PRIVS]


def claim_sig(name, i):
    return _ed.sign(core._name_claim_payload(name, PUBS[i], ISSUED, EXPIRES), PRIVS[i],
                    bytes.fromhex(PUBS[i])).hex()


def reset(names):
    with core._db_lock:
        core_serve._hits.clear()
    with core._db_lock, core._db() as conn:
        for n in names:
            conn.execute("DELETE FROM name_rotations WHERE name=?", (n,))
            conn.execute("INSERT OR REPLACE INTO name_bindings (name,node_pubkey,issued_at,expires_at,signature) "
                         "VALUES (?,?,?,?,?)", (n, PUBS[0], ISSUED, EXPIRES, claim_sig(n, 0)))


def rotate(name, i):
    """Rotate name from PUBS[i] to PUBS[i+1]."""
    rsig = _ed.sign(_rotate_payload(name, PUBS[i], PUBS[i + 1], ISSUED), PRIVS[i],
                    bytes.fromhex(PUBS[i])).hex()
    return client.post("/api/v1/names/rotate", data={
        "name": name, "old_pubkey": PUBS[i], "new_pubkey": PUBS[i + 1],
        "rotation_issued_at": ISSUED, "rotation_signature": rsig,
        "binding_issued_at": ISSUED, "binding_expires_at": EXPIRES,
        "binding_signature": claim_sig(name, i + 1)}).status_code


def rows(name):
    with core._db_lock, core._db() as conn:
        return conn.execute("SELECT COUNT(*) FROM name_rotations WHERE name=?", (name,)).fetchone()[0]


def scenario():
    reset(("rca", "rcb"))
    a = [rotate("rca", i) for i in range(CAP + 1)]
    a_rows = rows("rca")
    b = rotate("rcb", 0)
    row1 = a[:CAP] == [200] * CAP and a[CAP] == 429 and a_rows == CAP
    row2 = b == 200 and rows("rcb") == 1
    return row1, row2, (a, a_rows, b)


check("cap is configurable from CYBERNET_NAME_ROTATE_PER_NAME_CAP", rss.NAME_ROTATE_PER_NAME_CAP == CAP)
src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "routes_social_serve.py")).read()
check("default cap (16) is conservative: below the window per-name admission cap",
      '"CYBERNET_NAME_ROTATE_PER_NAME_CAP", "16"' in src and 16 < wo.SNAPSHOT_PER_NAME)

r1, r2, info = scenario()
check("(1) name A: CAP rotations accepted, CAP+1 is 429 and writes no row", r1, info)
check("(2) exhausting A leaves B able to rotate", r2, info)

real_check = rss._rotate_name_cap_check
rss._rotate_name_cap_check = lambda conn, name: None
try:
    m1, _m2, _i = scenario()
finally:
    rss._rotate_name_cap_check = real_check
record_mutant("per-name cap check is a no-op", "(1) CAP+1 on A is 429", r1, not m1)

real_count = rss._rotate_name_cap_count
rss._rotate_name_cap_count = lambda conn, name: conn.execute(
    "SELECT COUNT(*) FROM name_rotations").fetchone()[0]
try:
    _m1, m2, _i = scenario()
finally:
    rss._rotate_name_cap_count = real_count
record_mutant("cap is one global total across names", "(2) B still rotates after A is exhausted",
              r2, not m2)

print("mutant table:")
for name, row, real_ok, mf in MUTANTS:
    print(f"  {name:<44} {row:<44} {real_ok} {mf}")
print(f"{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
