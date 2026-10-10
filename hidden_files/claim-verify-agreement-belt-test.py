#!/usr/bin/env python3
"""Claim/verify agreement belt (primitive 1: naming).

The offline verifier's promise: anyone can trust a name without trusting
the mirror. That promise holds only if the verifier's accept set EQUALS
the mirror's accept set. This belt drives the REAL /api/v1/names/claim
route on the REAL app (scratch DB, loopback uvicorn) and the REAL
verify_name.verify on the same bindings, asserting agreement case by
case: mirror-accepts => verifier-accepts (checked against the STORED
form from GET /api/v1/names/{name}, which is what the network vouches
for), and mirror-rejects => verifier-rejects.

The interesting cases are the normalization edges: the mirror strips
and lowercases name/pubkey/signature before validating, reads naive
timestamps as UTC (core_serve._parse_claim_time house convention), and
verifies the signature against the NORMALIZED values. The verifier must
do exactly the same, or mirror-accepted bindings fail offline
verification and the primitive-1 promise breaks.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/claim-verify-agreement-belt-test.py
"""

import json
import os
import secrets
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

TMP = tempfile.mkdtemp(prefix="claim-verify-belt-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import core  # noqa: E402
import uvicorn  # noqa: E402
from app import app  # noqa: E402
from fed import ed25519 as _fed_ed25519  # noqa: E402
import verify_name  # noqa: E402

PASSED = FAILED = 0


def check(desc, cond, extra=""):
    global PASSED, FAILED
    if cond:
        PASSED += 1
        print(f"  ok  {desc}")
    else:
        FAILED += 1
        print(f"  FAIL {desc} {extra}")


MIRROR_PORT = 18377
MIRROR = f"http://127.0.0.1:{MIRROR_PORT}"

config = uvicorn.Config(app, host="127.0.0.1", port=MIRROR_PORT, log_level="error")
server = uvicorn.Server(config)
threading.Thread(target=server.run, daemon=True).start()
for _ in range(100):
    try:
        urllib.request.urlopen(MIRROR + "/fed/ping", timeout=1)
        break
    except Exception:
        time.sleep(0.1)
else:
    check("mirror up", False)
    sys.exit(1)
check("mirror up", True)


def _keypair():
    seed = secrets.token_hex(32)
    return seed, _fed_ed25519.publickey(bytes.fromhex(seed)).hex()


def _sig(sk, name, pub, issued, expires):
    return _fed_ed25519.sign(
        core._name_claim_payload(name, pub, issued, expires),
        bytes.fromhex(sk), bytes.fromhex(pub)).hex()


def _claim(fields):
    """POST the real claim route; return (status, body-or-None)."""
    body = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(MIRROR + "/api/v1/names/claim", data=body,
                                 method="POST")
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, None


def _stored(label):
    """The binding as the mirror stores and serves it (the vouched form)."""
    try:
        with urllib.request.urlopen(
                MIRROR + "/api/v1/names/" + label, timeout=8) as r:
            return json.loads(r.read())
    except Exception:
        return None


NOW = datetime.now(timezone.utc)


def _iso(dt, naive=False, zulu=False, offset=None):
    if naive:
        return dt.replace(tzinfo=None).strftime("%Y-%m-%dT%H:%M:%S")
    if zulu:
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if offset is not None:
        tz = timezone(timedelta(hours=offset))
        return dt.astimezone(tz).isoformat(timespec="seconds")
    return dt.isoformat(timespec="seconds")


def _live():
    return _iso(NOW - timedelta(hours=1)), _iso(NOW + timedelta(days=30))


# --- case 1: plain valid binding -------------------------------------------
sk, pk = _keypair()
issued, expires = _live()
sig = _sig(sk, "agreevalid", pk, issued, expires)
st, _ = _claim({"name": "agreevalid", "node_pubkey": pk, "issued_at": issued,
                "expires_at": expires, "signature": sig})
stored = _stored("agreevalid")
check("valid: mirror accepts", st == 200 and stored is not None, f"st={st}")
check("valid: verifier accepts the stored form",
      stored is not None and verify_name.verify(stored) is None,
      repr(verify_name.verify(stored) if stored else None))

# --- case 2: naive timestamps (no offset) -----------------------------------
sk, pk = _keypair()
issued, expires = _iso(NOW - timedelta(hours=1), naive=True), _iso(
    NOW + timedelta(days=30), naive=True)
sig = _sig(sk, "agreenaive", pk, issued, expires)
st, _ = _claim({"name": "agreenaive", "node_pubkey": pk, "issued_at": issued,
                "expires_at": expires, "signature": sig})
stored = _stored("agreenaive")
check("naive-ts: mirror accepts (naive reads as UTC)",
      st == 200 and stored is not None, f"st={st}")
check("naive-ts: verifier accepts the stored form",
      stored is not None and verify_name.verify(stored) is None,
      repr(verify_name.verify(stored) if stored else None))

# --- case 3: mixed-case name in the claim form -------------------------------
sk, pk = _keypair()
issued, expires = _live()
sig = _sig(sk, "agreeupper", pk, issued, expires)  # signed over normalized
st, _ = _claim({"name": "AgreeUpper", "node_pubkey": pk, "issued_at": issued,
                "expires_at": expires, "signature": sig})
stored = _stored("agreeupper")
check("upper-name: mirror accepts and stores lowercase",
      st == 200 and stored is not None and stored["name"] == "agreeupper",
      f"st={st}")
check("upper-name: verifier accepts the stored form",
      stored is not None and verify_name.verify(stored) is None,
      repr(verify_name.verify(stored) if stored else None))
check("upper-name: verifier accepts the submitted form too",
      verify_name.verify({"name": "AgreeUpper", "node_pubkey": pk,
                          "issued_at": issued, "expires_at": expires,
                          "signature": sig}) is None)

# --- case 4: uppercase pubkey hex in the form --------------------------------
sk, pk = _keypair()
issued, expires = _live()
sig = _sig(sk, "agreeupub", pk, issued, expires)
st, _ = _claim({"name": "agreeupub", "node_pubkey": pk.upper(),
                "issued_at": issued, "expires_at": expires, "signature": sig})
stored = _stored("agreeupub")
check("upper-pub: mirror accepts (lowercases before verify)",
      st == 200 and stored is not None, f"st={st}")
check("upper-pub: verifier accepts the stored form",
      stored is not None and verify_name.verify(stored) is None,
      repr(verify_name.verify(stored) if stored else None))
check("upper-pub: verifier accepts the submitted form too",
      verify_name.verify({"name": "agreeupub", "node_pubkey": pk.upper(),
                          "issued_at": issued, "expires_at": expires,
                          "signature": sig}) is None)

# --- case 5: expired binding --------------------------------------------------
sk, pk = _keypair()
issued = _iso(NOW - timedelta(hours=2))
expires = _iso(NOW - timedelta(hours=1))
sig = _sig(sk, "agreeexpired", pk, issued, expires)
st, _ = _claim({"name": "agreeexpired", "node_pubkey": pk, "issued_at": issued,
                "expires_at": expires, "signature": sig})
form = {"name": "agreeexpired", "node_pubkey": pk, "issued_at": issued,
        "expires_at": expires, "signature": sig}
check("expired: mirror rejects", st == 400, f"st={st}")
check("expired: verifier rejects",
      verify_name.verify(form) is not None)

# --- case 6: issued in the future ----------------------------------------------
sk, pk = _keypair()
issued = _iso(NOW + timedelta(hours=1))
expires = _iso(NOW + timedelta(days=30))
sig = _sig(sk, "agreefuture", pk, issued, expires)
st, _ = _claim({"name": "agreefuture", "node_pubkey": pk, "issued_at": issued,
                "expires_at": expires, "signature": sig})
form = {"name": "agreefuture", "node_pubkey": pk, "issued_at": issued,
        "expires_at": expires, "signature": sig}
check("future-issued: mirror rejects", st == 400, f"st={st}")
check("future-issued: verifier rejects",
      verify_name.verify(form) is not None)

# --- case 7: tampered signature -------------------------------------------------
sk, pk = _keypair()
issued, expires = _live()
sig = _sig(sk, "agreebadsig", pk, issued, expires)
bad = ("00" if not sig.startswith("00") else "ff") + sig[2:]
st, _ = _claim({"name": "agreebadsig", "node_pubkey": pk, "issued_at": issued,
                "expires_at": expires, "signature": bad})
form = {"name": "agreebadsig", "node_pubkey": pk, "issued_at": issued,
        "expires_at": expires, "signature": bad}
check("bad-sig: mirror rejects", st == 400, f"st={st}")
check("bad-sig: verifier rejects",
      verify_name.verify(form) is not None)

# --- case 8: bad label ------------------------------------------------------------
sk, pk = _keypair()
issued, expires = _live()
sig = _sig(sk, "-bad", pk, issued, expires)
st, _ = _claim({"name": "-bad", "node_pubkey": pk, "issued_at": issued,
                "expires_at": expires, "signature": sig})
form = {"name": "-bad", "node_pubkey": pk, "issued_at": issued,
        "expires_at": expires, "signature": sig}
check("bad-label: mirror rejects", st == 400, f"st={st}")
check("bad-label: verifier rejects",
      verify_name.verify(form) is not None)

# --- case 9: Zulu timestamps -------------------------------------------------------
sk, pk = _keypair()
issued = _iso(NOW - timedelta(hours=1), zulu=True)
expires = _iso(NOW + timedelta(days=30), zulu=True)
sig = _sig(sk, "agreezulu", pk, issued, expires)
st, _ = _claim({"name": "agreezulu", "node_pubkey": pk, "issued_at": issued,
                "expires_at": expires, "signature": sig})
stored = _stored("agreezulu")
check("zulu-ts: mirror accepts", st == 200 and stored is not None, f"st={st}")
check("zulu-ts: verifier accepts the stored form",
      stored is not None and verify_name.verify(stored) is None,
      repr(verify_name.verify(stored) if stored else None))

# --- case 10: non-UTC offset, live -----------------------------------------------
sk, pk = _keypair()
issued = _iso(NOW - timedelta(hours=1), offset=5)
expires = _iso(NOW + timedelta(days=30), offset=5)
sig = _sig(sk, "agreeoffset", pk, issued, expires)
st, _ = _claim({"name": "agreeoffset", "node_pubkey": pk, "issued_at": issued,
                "expires_at": expires, "signature": sig})
stored = _stored("agreeoffset")
check("offset-ts: mirror accepts (chronological, not lexicographic)",
      st == 200 and stored is not None, f"st={st}")
check("offset-ts: verifier accepts the stored form",
      stored is not None and verify_name.verify(stored) is None,
      repr(verify_name.verify(stored) if stored else None))

# --- case 11: born dead (issued == expires) ------------------------------------------
sk, pk = _keypair()
issued = expires = _iso(NOW - timedelta(hours=1))
sig = _sig(sk, "agreedead", pk, issued, expires)
st, _ = _claim({"name": "agreedead", "node_pubkey": pk, "issued_at": issued,
                "expires_at": expires, "signature": sig})
form = {"name": "agreedead", "node_pubkey": pk, "issued_at": issued,
        "expires_at": expires, "signature": sig}
check("born-dead: mirror rejects", st == 400, f"st={st}")
check("born-dead: verifier rejects",
      verify_name.verify(form) is not None)

# --- case 12: non-hex pubkey ------------------------------------------------------------
sk, pk = _keypair()
issued, expires = _live()
sig = _sig(sk, "agreenonhex", pk, issued, expires)
form = {"name": "agreenonhex", "node_pubkey": "zz" * 32, "issued_at": issued,
        "expires_at": expires, "signature": sig}
st, _ = _claim(form)
check("nonhex-pub: mirror rejects", st == 400, f"st={st}")
check("nonhex-pub: verifier rejects",
      verify_name.verify(dict(form)) is not None)

# --- case 13: name/payload mismatch (sign X, submit Y) -------------------------------------
sk, pk = _keypair()
issued, expires = _live()
sig = _sig(sk, "agreemismx", pk, issued, expires)
form = {"name": "agreemismy", "node_pubkey": pk, "issued_at": issued,
        "expires_at": expires, "signature": sig}
st, _ = _claim(form)
check("name-mismatch: mirror rejects", st == 400, f"st={st}")
check("name-mismatch: verifier rejects",
      verify_name.verify(dict(form)) is not None)

print(f"\n{PASSED} passed, {FAILED} failed")
sys.exit(1 if FAILED else 0)
