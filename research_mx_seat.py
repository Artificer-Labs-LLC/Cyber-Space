#!/usr/bin/env python3
"""MX-SEAT (Cipher, ART-42) - STATUS: DOCUMENTS CURRENT BEHAVIOUR.
NOT wired into run_tests.sh: rows that are expected to refuse but are
accepted today are known gaps, not regressions. Exit code is always 0;
read the per-row status (last run: research_mx_seat.status.txt).

A mixed-order key A' = A + T8 (honest scalar known, so A' signs) is
presented at each seat with a signature that strict checkvalid ACCEPTS
(h % 8 == 0), so only a subgroup precheck can refuse it.

Rows (expected = refusal at every seat):
  MX-CLAIM        POST /api/v1/names/claim, node_pubkey = A'
  MX-ROTATE-NEW   POST /api/v1/names/rotate, honest old -> new = A'
  MX-ROTATE-OLD   POST /api/v1/names/rotate, old = A' (binding seeded directly)
  MX-ANNOUNCE     POST /fed/announce, envelope sender_pub = A' (fed/envelope.py:72)
  MX-DIRSYNC      POST /fed/directory/delta from a known honest peer, relayed
                  retire delta whose row.node_pub = A' (federation.py:331 -> :354)
Owned elsewhere (not duplicated): MX-SEAT-G (core.ingest_gossiped_binding
:1708) and MX-SEAT-R (resolve_cyberspace step 3, :1453) - Lodestar.
"""
import hashlib
import json
import os
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone

os.environ["CYBERNET_DB_DIR"] = tempfile.mkdtemp(prefix="mx-seat-")
os.environ["CYBERNET_NAME_CLAIM_RATE_LIMIT"] = "10000"
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import nacl.bindings as nb  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
import core  # noqa: E402
core.init_db()
import app as appmod  # noqa: E402
from fed import ed25519 as E, envelope as ENV  # noqa: E402
from rotate_name import _rotate_payload  # noqa: E402
import window_open  # noqa: E402

client = TestClient(appmod.app)
L = E._L
T8 = bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05")


def keypair(label):
    seed = hashlib.sha256(label).digest()
    pk, sk = nb.crypto_sign_seed_keypair(seed)
    hh = hashlib.sha512(seed).digest()
    a = int.from_bytes(hh[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, pk, sk


a, PK, SK = keypair(b"mx-seat-A")
AP = nb.crypto_core_ed25519_add(PK, T8)
APH = AP.hex()
assert window_open.weak_reason(APH) == "mixed-order"


def mx_sign(msg_for):
    """First i whose message gives h % 8 == 0 (strict checkvalid accepts)."""
    R = nb.crypto_scalarmult_ed25519_base_noclamp((7).to_bytes(32, "little"))
    for i in range(4096):
        m = msg_for(i)
        h = int.from_bytes(hashlib.sha512(R + AP + m).digest(), "little")
        if h % 8 == 0:
            sig = R + ((7 + h * a) % L).to_bytes(32, "little")
            assert E.checkvalid(sig, m, AP)
            return i, m, sig.hex()
    raise RuntimeError("grind")


def hsign(m, sk):
    return nb.crypto_sign(m, sk)[:64].hex()


rows = []


def record(row, expected_refused, refused, detail):
    status = "OK (refused)" if (refused == expected_refused) else "GAP (accepted today)"
    rows.append((row, status, detail))
    print(f"{row:15s} expected={'REFUSE' if expected_refused else 'ACCEPT'} "
          f"actual={'REFUSE' if refused else 'ACCEPT'}  -> {status}  [{detail}]")


now = datetime.now(timezone.utc).replace(microsecond=0)
EXP = (now + timedelta(days=30)).isoformat()


def iss(i):
    return (now - timedelta(seconds=i)).isoformat()


# MX-CLAIM
i, m, sg = mx_sign(lambda i: core._name_claim_payload("mxclaim", APH, iss(i), EXP))
r = client.post("/api/v1/names/claim", data={"name": "mxclaim", "node_pubkey": APH, "issued_at": iss(i),
                                             "expires_at": EXP, "signature": sg})
with core._db() as c:
    stored = c.execute("SELECT 1 FROM name_bindings WHERE name='mxclaim'").fetchone() is not None
record("MX-CLAIM", True, r.status_code >= 400 and not stored, f"HTTP {r.status_code}; stored={stored}; {r.text[:80]}")

# MX-ROTATE-NEW: honest old key holds 'mxrot', rotates to A'
_, OPK, OSK = keypair(b"mx-seat-old")
B_ISS = iss(6000)
with core._db() as c:
    c.execute("INSERT INTO name_bindings VALUES (?,?,?,?,?)",
              ("mxrot", OPK.hex(), B_ISS, EXP, hsign(core._name_claim_payload("mxrot", OPK.hex(), B_ISS, EXP), OSK)))
ROT_ISS = iss(5000)
i, m, bsig = mx_sign(lambda i: core._name_claim_payload("mxrot", APH, iss(1 + i), EXP))
b_iss = iss(1 + i)
r = client.post("/api/v1/names/rotate", data={
    "name": "mxrot", "old_pubkey": OPK.hex(), "new_pubkey": APH, "rotation_issued_at": ROT_ISS,
    "rotation_signature": hsign(_rotate_payload("mxrot", OPK.hex(), APH, ROT_ISS), OSK),
    "binding_issued_at": b_iss, "binding_expires_at": EXP, "binding_signature": bsig})
with core._db() as c:
    holder = c.execute("SELECT node_pubkey FROM name_bindings WHERE name='mxrot'").fetchone()[0]
record("MX-ROTATE-NEW", True, r.status_code >= 400 and holder == OPK.hex(),
       f"HTTP {r.status_code}; holder_is_mixed={holder == APH}; {r.text[:80]}")

# MX-ROTATE-OLD: A' holds 'mxold' (seeded directly), rotates to an honest key
_, NPK, NSK = keypair(b"mx-seat-new")
with core._db() as c:
    i, m, s0 = mx_sign(lambda i: core._name_claim_payload("mxold", APH, iss(20000 + i), EXP))
    c.execute("INSERT INTO name_bindings VALUES (?,?,?,?,?)", ("mxold", APH, iss(20000 + i), EXP, s0))
j, m, rsig = mx_sign(lambda i: _rotate_payload("mxold", APH, NPK.hex(), iss(5000 + i)))
rot_iss = iss(5000 + j)
b_iss = iss(1)
r = client.post("/api/v1/names/rotate", data={
    "name": "mxold", "old_pubkey": APH, "new_pubkey": NPK.hex(), "rotation_issued_at": rot_iss,
    "rotation_signature": rsig, "binding_issued_at": b_iss, "binding_expires_at": EXP,
    "binding_signature": hsign(core._name_claim_payload("mxold", NPK.hex(), b_iss, EXP), NSK)})
with core._db() as c:
    holder = c.execute("SELECT node_pubkey FROM name_bindings WHERE name='mxold'").fetchone()[0]
record("MX-ROTATE-OLD", True, r.status_code >= 400 and holder == APH,
       f"HTTP {r.status_code}; moved={holder != APH}; {r.text[:80]}")

# MX-ANNOUNCE
body = {"name": "mxnode", "node_pub": APH, "network": "cybernet", "version": "0.1.0", "capabilities": []}
bh = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).digest()
t0 = int(time.time())
i, m, sg = mx_sign(lambda i: ENV._canonical(t0 - i, "federation", bh))
env = {"v": ENV.VERSION, "sender_pub": APH, "ts": t0 - i, "recipient": "federation",
       "body_hash": bh.hex(), "body": body, "sig": sg}
r = client.post("/fed/announce", json=env)
with core._db() as c:
    stored = c.execute("SELECT 1 FROM peers WHERE node_pub=?", (APH,)).fetchone() is not None
record("MX-ANNOUNCE", True, r.status_code >= 400 and not stored, f"HTTP {r.status_code}; peers row stored={stored}")

# MX-DIRSYNC: honest peer P (announced) relays a retire delta for A'
_, PPK, PSK = keypair(b"mx-seat-peer")
pbody = {"name": "honestpeer", "node_pub": PPK.hex(), "network": "cybernet", "version": "0.1.0", "capabilities": []}
r0 = client.post("/fed/announce", json=ENV.make_envelope(PSK[:32].hex(), PPK.hex(), "federation", pbody))
row = {"node_pub": APH, "name": "mxrelay", "node_url": "", "capabilities": [], "network": "cybernet",
       "version": "0.1.0", "genesis": False}
i, m, dsig = mx_sign(lambda i: core._delta_payload(dict(row, name=f"mxrelay{i}"), 1, True))
row["name"] = f"mxrelay{i}"
denv = ENV.make_envelope(PSK[:32].hex(), PPK.hex(), core._NODE_PUB,
                         {"from_node_pub": PPK.hex(), "deltas": [{"row": row, "seq": 1, "sig": dsig, "retire": True}]})
r = client.post("/fed/directory/delta", json=denv)
with core._db() as c:
    stored = c.execute("SELECT 1 FROM peers WHERE node_pub=?", (APH,)).fetchone() is not None
record("MX-DIRSYNC", True, not stored, f"announce(P) HTTP {r0.status_code}; delta HTTP {r.status_code} "
       f"{r.text[:90]}; A' row stored={stored}")

print("\nSUMMARY " + "; ".join(f"{n}={s}" for n, s, _ in rows))
print("MX-SEAT-G / MX-SEAT-R: owned by Lodestar, not run here.")
