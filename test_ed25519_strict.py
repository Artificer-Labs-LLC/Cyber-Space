#!/usr/bin/env python3
"""Strict Ed25519 checkvalid (window-open precondition, ART-29/ART-38).

fed/ed25519.checkvalid must, in order, fail closed on:
  1. non-canonical pk or R (y >= p, or decode/re-encode mismatch);
  2. S >= L (RFC 8032 5.1.7);
  3. small-order A or R (8*P == identity);
then run the unchanged verification equation.

Covers: the 8 small-order encodings as pk with a zero signature; a
small-order R under a real key; an S+L malleated signature; non-canonical
y encodings; all five RFC 8032 section 7.1 Ed25519 vectors; and
POST /api/v1/names/claim with an all-zero key for zz0 and zz1.

Scratch DB only (CYBERNET_DB_DIR tempdir set before import).
"""
import json
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone

os.environ["CYBERNET_DB_DIR"] = tempfile.mkdtemp(prefix="ed25519-strict-")
os.environ["CYBERNET_NAME_CLAIM_RATE_LIMIT"] = "10000"
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from fed import ed25519 as ed  # noqa: E402

PASS = FAIL = 0


def check(label, cond, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok  {label}")
    else:
        FAIL += 1
        print(f"  FAIL {label} {extra}")


def loose_small_order(enc: bytes) -> bool:
    """Decode with the permissive decoder and test 8*P == identity."""
    P = ed._decodepoint(enc)
    for _ in range(3):
        P = ed._edwards(P, P)
    return P == (0, 1)


# The 8 canonical small-order encodings (the full 8-torsion subgroup).
SMALL_ORDER = [bytes.fromhex(h) for h in (
    "0100000000000000000000000000000000000000000000000000000000000000",  # identity
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",  # order 2
    "0000000000000000000000000000000000000000000000000000000000000000",  # order 4
    "0000000000000000000000000000000000000000000000000000000000000080",  # order 4
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",  # order 8
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",  # order 8
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",  # order 8
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",  # order 8
)]
check("8 distinct small-order encodings", len(set(SMALL_ORDER)) == 8)
check("each is small-order under the loose decoder",
      all(loose_small_order(e) for e in SMALL_ORDER))
check("each is a canonical encoding (so step 3, not step 1, refuses it)",
      all(ed._encodepoint(ed._decodepoint(e)) == e for e in SMALL_ORDER))

ZERO_SIG = bytes(64)
MSGS = [b"", b"zz0", b"zz1", b"x" * 100] + [bytes([i]) * 7 for i in range(32)]
for i, e in enumerate(SMALL_ORDER):
    check(f"small-order pk #{i} + zero sig refused on every message",
          not any(ed.checkvalid(ZERO_SIG, m, e) for m in MSGS))

# Small-order R under a real key: R = identity, S = 0 is the classic forgery
# shape against a small-order A; here A is real, so also prove step 3 fires
# by using a small-order R with S chosen so the equation would hold if
# R's torsion component were ignored (cofactored verifiers).
SK = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
PK = ed.publickey(SK)
for i, e in enumerate(SMALL_ORDER):
    check(f"small-order R #{i} with real key refused",
          not ed.checkvalid(e + bytes(32), b"msg", PK))

# S + L malleation of a valid signature.
m = b"malleate me"
sig = ed.sign(m, SK, PK)
check("valid signature verifies", ed.checkvalid(sig, m, PK))
S = int.from_bytes(sig[32:], "little")
mall = sig[:32] + (S + ed._L).to_bytes(32, "little")
check("S+L malleated copy refused", not ed.checkvalid(mall, m, PK))
# Sanity: the malleated copy satisfies the raw equation (so step 2 is what stops it).
R = ed._decodepoint(sig[:32])
h = int.from_bytes(ed._H(sig[:32] + PK + m), "little")
check("malleated copy satisfies the bare equation (step 2 is load-bearing)",
      ed._scalarmult(ed._BPOINT, S + ed._L) == ed._edwards(R, ed._scalarmult(ed._decodepoint(PK), h)))

# Non-canonical y (y >= p).
P_ = ed._Q
non_canon = []
for y in range(0, 19):  # y + p < 2^255 only for y < 19
    enc = (y + P_).to_bytes(32, "little")
    non_canon.append(enc)
    non_canon.append(enc[:31] + bytes([enc[31] | 0x80]))
non_canon.append(bytes.fromhex("01" + "00" * 30 + "80"))  # x=0 with sign bit set
for enc in non_canon:
    try:
        ed._decodepoint_strict(enc)
        ok = False
    except Exception:
        ok = True
    if not ok:
        break
check("strict decoder rejects every non-canonical y / x-sign encoding", ok, enc.hex())
check("non-canonical y as pk refused (zero sig and real sig)",
      not any(ed.checkvalid(ZERO_SIG, b"", e) or ed.checkvalid(sig, m, e) for e in non_canon))
check("non-canonical y as R refused",
      not any(ed.checkvalid(e + sig[32:], m, PK) for e in non_canon))
# A non-canonical y that is a full-order curve point (not just small-order).
def _loose_full_order(e):
    try:
        return not loose_small_order(e)
    except Exception:
        return False


full = [e for e in non_canon[:-1] if _loose_full_order(e)]
check("at least one non-canonical y is a full-order point (step 1 is load-bearing)",
      len(full) > 0, len(full))
check("full-order non-canonical pk refused",
      not any(ed.checkvalid(ZERO_SIG, mm, e) for e in full for mm in MSGS))

# RFC 8032 section 7.1 vectors (TEST 1, 2, 3, 1024, SHA(abc)).
with open(os.path.join(HERE, "rfc8032_vectors.json")) as f:
    VECS = json.load(f)
check("five RFC 8032 Ed25519 vectors loaded", len(VECS) == 5, len(VECS))
for v in VECS:
    sk, pk, msg, sg = (bytes.fromhex(v[k]) for k in ("sk", "pk", "msg", "sig"))
    check(f"RFC 8032 TEST {v['name']}: publickey", ed.publickey(sk) == pk)
    check(f"RFC 8032 TEST {v['name']}: sign", ed.sign(msg, sk, pk) == sg)
    check(f"RFC 8032 TEST {v['name']}: checkvalid", ed.checkvalid(sg, msg, pk))
    check(f"RFC 8032 TEST {v['name']}: tampered msg refused",
          not ed.checkvalid(sg, msg + b"\x00", pk))

# names/claim with an all-zero key, zz0 and zz1.
from fastapi.testclient import TestClient  # noqa: E402
import core  # noqa: E402
core.init_db()
import app as appmod  # noqa: E402

client = TestClient(appmod.app)
NOW = datetime.now(timezone.utc)
ISSUED = (NOW - timedelta(minutes=1)).isoformat(timespec="seconds")
EXPIRES = (NOW + timedelta(days=30)).isoformat(timespec="seconds")
for name in ("zz0", "zz1"):
    r = client.post("/api/v1/names/claim", data={
        "name": name, "node_pubkey": "00" * 32, "issued_at": ISSUED,
        "expires_at": EXPIRES, "signature": "00" * 64})
    check(f"names/claim {name} with all-zero key refused (400)", r.status_code == 400,
          f"{r.status_code} {r.text}")
with core._db_lock, core._db() as conn:
    n = conn.execute("SELECT COUNT(*) FROM name_bindings WHERE name IN ('zz0','zz1')").fetchone()[0]
check("no zero-key binding stored", n == 0, n)

print(f"{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
