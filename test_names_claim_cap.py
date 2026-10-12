#!/usr/bin/env python3
"""ART-38 (window-open precondition 1): names/claim caps, local belt.

1. Per-IP rate gate runs FIRST: probes 1..LIMIT with an all-zero signature
   get 400 (validation), probe LIMIT+1 gets 429 — the same shape Bulwark's
   live script (research-board/bulwark/art38-live-limit-check.py) expects.
2. The limit is configurable (CYBERNET_NAME_CLAIM_RATE_LIMIT).
3. Registry fill: with name_bindings at NAME_REGISTRY_CAP (1024) live rows,
   a genuinely-new claim is refused and a renewal of a known name merges.

Scratch DB only (CYBERNET_DB_DIR tempdir set before import).
"""
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone

os.environ["CYBERNET_DB_DIR"] = tempfile.mkdtemp(prefix="art38-cap-")
os.environ["CYBERNET_NAME_CLAIM_RATE_LIMIT"] = "7"
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient  # noqa: E402
import core  # noqa: E402
core.init_db()
import core_serve  # noqa: E402
from fed import ed25519 as _ed  # noqa: E402
import app as appmod  # noqa: E402
import routes_social_serve as rss  # noqa: E402

client = TestClient(appmod.app)
PASS = FAIL = 0


def check(label, cond, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok  {label}")
    else:
        FAIL += 1
        print(f"  FAIL {label} {extra}")


def iso(dt):
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


NOW = datetime.now(timezone.utc)
ISSUED = iso(NOW - timedelta(minutes=1))
EXPIRES = iso(NOW + timedelta(days=30))


def mint(name, priv_hex, issued=ISSUED, expires=EXPIRES):
    pub = _ed.publickey(bytes.fromhex(priv_hex)).hex()
    sig = _ed.sign(core._name_claim_payload(name, pub, issued, expires),
                   bytes.fromhex(priv_hex), bytes.fromhex(pub)).hex()
    return {"name": name, "node_pubkey": pub, "issued_at": issued,
            "expires_at": expires, "signature": sig}


def reset_rate():
    with core._db_lock:
        core_serve._hits.clear()


# 1. configurable limit picked up from env
check("limit configurable from env", rss.NAME_CLAIM_RATE_LIMIT == 7, rss.NAME_CLAIM_RATE_LIMIT)

# 2. limit-hit: zero-signature probes, Bulwark's live shape
reset_rate()
LIMIT = rss.NAME_CLAIM_RATE_LIMIT
# NOTE: probes use a REAL (full-order) pubkey with a zero signature. An
# all-zero pubkey is small-order and a zero signature verifies against it
# for ~1 in 4 names (core._name_binding_verify has no small-order check) —
# reported separately; not fixed here (core.py is a Q1 file).
PROBE_PUB = _ed.publickey(bytes.fromhex("33" * 32)).hex()
codes = []
for i in range(LIMIT + 2):
    r = client.post("/api/v1/names/claim", data={
        "name": f"art38probe{i}", "node_pubkey": PROBE_PUB, "issued_at": ISSUED,
        "expires_at": EXPIRES, "signature": "00" * 64})
    codes.append(r.status_code)
check("probes 1..LIMIT -> 400", all(c == 400 for c in codes[:LIMIT]), codes)
check("probe LIMIT+1 and beyond -> 429", all(c == 429 for c in codes[LIMIT:]), codes)
with core._db_lock, core._db() as conn:
    n = conn.execute("SELECT COUNT(*) FROM name_bindings WHERE name LIKE 'art38probe%'").fetchone()[0]
check("zero probes stored", n == 0, n)

# 3. gate runs before the form parse: an empty body is rate-limited too
reset_rate()
for _ in range(LIMIT):
    client.post("/api/v1/names/claim", data={})
r = client.post("/api/v1/names/claim", data={})
check("gate precedes parse (empty body -> 429 at LIMIT+1)", r.status_code == 429, r.status_code)

# 4. registry fill to NAME_REGISTRY_CAP; renewal still merges
rss.NAME_CLAIM_RATE_LIMIT = 10_000
reset_rate()
priv = "11" * 32
r = client.post("/api/v1/names/claim", data=mint("keeper", priv))
check("seed claim keeper -> 200", r.status_code == 200, r.text)
cap = core.NAME_REGISTRY_CAP
check("registry cap is 1024", cap == 1024, cap)
with core._db_lock, core._db() as conn:
    have = conn.execute("SELECT COUNT(*) FROM name_bindings").fetchone()[0]
    conn.executemany(
        "INSERT INTO name_bindings (name, node_pubkey, issued_at, expires_at, signature) VALUES (?,?,?,?,?)",
        [(f"fill{i}", f"{i:064x}", ISSUED, EXPIRES, "00" * 64) for i in range(cap - have)])
    full = conn.execute("SELECT COUNT(*) FROM name_bindings").fetchone()[0]
check("table filled to 1024", full == cap, full)
r = client.post("/api/v1/names/claim", data=mint("newcomer", "22" * 32))
check("new name at cap refused (400, registry full)",
      r.status_code == 400 and "registry is full" in r.text, r.text)
renew = mint("keeper", priv, issued=iso(NOW), expires=iso(NOW + timedelta(days=60)))
r = client.post("/api/v1/names/claim", data=renew)
check("renewal at cap merges (200)", r.status_code == 200, r.text)
with core._db_lock, core._db() as conn:
    row = conn.execute("SELECT expires_at FROM name_bindings WHERE name='keeper'").fetchone()
    full = conn.execute("SELECT COUNT(*) FROM name_bindings").fetchone()[0]
check("renewal updated expiry", row and row[0] == renew["expires_at"], row)
check("still exactly 1024 rows", full == cap, full)

print(f"{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
