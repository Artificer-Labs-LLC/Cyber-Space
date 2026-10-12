#!/usr/bin/env python3
"""Belt for r3 (ART-29): names/claim route gates.

Proves the route enforces, in order:
  - fresh claim -> 200 (claimed)
  - stale claim (>24h old issued_at) -> 400
  - over-cap claim (>365d lifetime) -> 400
  - future issued_at -> 400
  - expired on arrival -> 400
  - duplicate claim by same key (renewal) -> 200
  - foreign challenger vs live incumbent -> 409 + conflict logged
  - T-1s steal attempt -> 409 (incumbent kept)

Runs against a SCRATCH DB (CYBERNET_DB_DIR=tempdir set before import);
the repo's live cybernet.db is never touched.
"""
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone

TMP = tempfile.mkdtemp(prefix="route-claim-belt-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient  # noqa: E402
import core  # noqa: E402
core.init_db()
from fed import ed25519 as _ed  # noqa: E402

# Import the app after DB dir is set
import app as appmod  # noqa: E402
client = TestClient(appmod.app)

PASS = FAIL = 0


def check(label, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1
    else:
        FAIL += 1
        print(f"FAIL {label}: got {got!r}, want {want!r}")


def mint_claim(name, priv_hex, issued_at, expires_at):
    pub = _ed.publickey(bytes.fromhex(priv_hex)).hex()
    sig = _ed.sign(
        core._name_claim_payload(name, pub, issued_at, expires_at),
        bytes.fromhex(priv_hex), bytes.fromhex(pub)).hex()
    return {"name": name, "node_pubkey": pub, "issued_at": issued_at,
            "expires_at": expires_at, "signature": sig}


def iso_z(dt):
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


NOW = datetime.now(timezone.utc)
live_issued = iso_z(NOW - timedelta(minutes=5))
live_expires = iso_z(NOW + timedelta(days=30))

# --- 1: fresh claim -> 200 ---
k1 = os.urandom(32).hex()
r = client.post("/api/v1/names/claim",
                data=mint_claim("belt-r1", k1, live_issued, live_expires))
check("fresh claim -> 200", r.status_code, 200)

# --- 2: stale claim (>24h) -> 400 ---
k2 = os.urandom(32).hex()
stale_issued = iso_z(NOW - timedelta(hours=25))
r = client.post("/api/v1/names/claim",
                data=mint_claim("belt-r2", k2, stale_issued, live_expires))
check("stale claim -> 400", r.status_code, 400)

# --- 3: over-cap claim (>365d) -> 400 ---
k3 = os.urandom(32).hex()
over_expires = iso_z(datetime.fromisoformat(live_issued) + timedelta(days=400))
r = client.post("/api/v1/names/claim",
                data=mint_claim("belt-r3", k3, live_issued, over_expires))
check("over-cap claim -> 400", r.status_code, 400)

# --- 4: future issued_at -> 400 ---
k4 = os.urandom(32).hex()
fut_issued = iso_z(NOW + timedelta(hours=1))
r = client.post("/api/v1/names/claim",
                data=mint_claim("belt-r4", k4, fut_issued, live_expires))
check("future issued_at -> 400", r.status_code, 400)

# --- 5: expired on arrival -> 400 ---
k5 = os.urandom(32).hex()
dead_expires = iso_z(NOW - timedelta(hours=1))
r = client.post("/api/v1/names/claim",
                data=mint_claim("belt-r5", k5, live_issued, dead_expires))
check("expired on arrival -> 400", r.status_code, 400)

# --- 6: same-key renewal -> 200 ---
k6 = os.urandom(32).hex()
r = client.post("/api/v1/names/claim",
                data=mint_claim("belt-r6", k6, live_issued, live_expires))
check("initial claim -> 200", r.status_code, 200)
r = client.post("/api/v1/names/claim",
                data=mint_claim("belt-r6", k6, iso_z(NOW), live_expires))
check("same-key renewal -> 200", r.status_code, 200)

# --- 7: foreign challenger vs live incumbent -> 409 + conflict logged ---
k7a = os.urandom(32).hex()
r = client.post("/api/v1/names/claim",
                data=mint_claim("belt-r7", k7a, live_issued, live_expires))
check("incumbent claims -> 200", r.status_code, 200)
k7b = os.urandom(32).hex()
r = client.post("/api/v1/names/claim",
                data=mint_claim("belt-r7", k7b, iso_z(NOW), live_expires))
check("foreign challenger -> 409", r.status_code, 409)
# Conflict logged
with core._db_lock, core._db() as conn:
    crow = conn.execute(
        "SELECT reason FROM name_conflicts WHERE name=?",
        ("belt-r7",)).fetchone()
check("conflict logged on route", crow[0] if crow else None,
      "live-foreign-incumbent")
# Incumbent still holds it
with core._db_lock, core._db() as conn:
    row = conn.execute(
        "SELECT node_pubkey FROM name_bindings WHERE name=?",
        ("belt-r7",)).fetchone()
check("incumbent kept on route",
      row[0], _ed.publickey(bytes.fromhex(k7a)).hex())

# --- 8: T-1s steal attempt via route -> 409 ---
k8a = os.urandom(32).hex()
inc8_issued = iso_z(NOW - timedelta(minutes=5))
r = client.post("/api/v1/names/claim",
                data=mint_claim("belt-r8", k8a, inc8_issued, live_expires))
check("t-1s incumbent -> 200", r.status_code, 200)
k8b = os.urandom(32).hex()
atk8_issued = iso_z(datetime.fromisoformat(inc8_issued) - timedelta(seconds=1))
r = client.post("/api/v1/names/claim",
                data=mint_claim("belt-r8", k8b, atk8_issued, live_expires))
check("T-1s steal -> 409", r.status_code, 409)

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
