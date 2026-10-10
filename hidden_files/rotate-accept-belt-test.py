"""Rotate-accept belt (primitive 4, identity): the mirror-side half of rotation.

Drives the REAL /api/v1/names/rotate route on the REAL app (scratch DB,
loopback uvicorn) against REAL Ed25519 keys:

  claim under old key -> mint rotation via the REAL rotate_name.mint_rotation
  (record signed by OLD key) -> mint new binding via the REAL
  core._name_claim_payload signed by the NEW key -> POST rotate.

The mirror must move the binding ONLY when the whole chain verifies:
rotation signed by old key, old key actually holds the live name, new
binding names the designated new key and moves forward in time. Every
forgery or out-of-order shape must be refused, never stored. The genesis
name is never touched; every key here is fresh and dies with the run.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/rotate-accept-belt-test.py
"""

import datetime
import json
import os
import secrets
import sqlite3
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

TMP = tempfile.mkdtemp(prefix="rotate-accept-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

MIRROR_PORT = 18361
MIRROR = f"http://127.0.0.1:{MIRROR_PORT}"

import core  # noqa: E402
import uvicorn  # noqa: E402
from app import app  # noqa: E402
from fed import ed25519 as _fed_ed25519  # noqa: E402
import rotate_name  # noqa: E402

CASES = {"passed": 0, "failed": 0}


def check(name, cond, extra=""):
    if cond:
        CASES["passed"] += 1
        print(f"  ok  {name}")
    else:
        CASES["failed"] += 1
        print(f"  FAIL {name} {extra}")


_real_gate = core._reject_nonpublic_node_url


def _test_gate(url):
    if url.startswith(MIRROR):
        return "127.0.0.1"
    return _real_gate(url)


core._reject_nonpublic_node_url = _test_gate

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

DB = os.path.join(TMP, "cybernet.db")


def _keypair():
    seed = secrets.token_hex(32)
    return bytes.fromhex(seed), _fed_ed25519.publickey(bytes.fromhex(seed)).hex().lower()


def _iso(dt):
    return dt.isoformat()


def _fresh_iso():
    """A fresh timestamp taken at call time — never a stale fixture. New
    bindings must be minted AFTER the rotation they follow, or the mirror's
    chain-order gate (correctly) refuses them as pre-dated."""
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _mint_binding(label, priv, pub, issued_s, expires_s):
    sig = _fed_ed25519.sign(
        core._name_claim_payload(label, pub, issued_s, expires_s),
        priv, bytes.fromhex(pub)).hex().lower()
    return {"node_pubkey": pub, "issued_at": issued_s,
            "expires_at": expires_s, "signature": sig}


def _post(path, fields):
    body = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(MIRROR + path, data=body, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read())
        except Exception:
            return e.code, {"detail": str(e)}


def _claim(label, binding):
    return _post("/api/v1/names/claim",
                 {"name": label, **binding})


def _rotate(label, record, binding):
    return _post("/api/v1/names/rotate", {
        "name": label,
        "old_pubkey": record["old_pubkey"],
        "new_pubkey": record["new_pubkey"],
        "rotation_issued_at": record["issued_at"],
        "rotation_signature": record["signature"],
        "binding_issued_at": binding["issued_at"],
        "binding_expires_at": binding["expires_at"],
        "binding_signature": binding["signature"],
    })


def _stored_binding(label):
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT node_pubkey, issued_at, expires_at, signature FROM name_bindings WHERE name=?",
        (label,)).fetchone()
    conn.close()
    return dict(row) if row else None


def _stored_rotations(label):
    conn = sqlite3.connect(DB)
    rows = conn.execute(
        "SELECT old_pubkey, new_pubkey FROM name_rotations WHERE name=?",
        (label,)).fetchall()
    conn.close()
    return [tuple(r) for r in rows]


NOW = datetime.datetime.now(datetime.timezone.utc)
LATER = NOW + datetime.timedelta(days=30)

# --- the happy path: claim -> rotate -> stored binding moves ---------------
SK1, PK1 = _keypair()
SK2, PK2 = _keypair()
LABEL = "rotbelt"
st, claimed = _claim(LABEL, _mint_binding(LABEL, SK1, PK1, _iso(NOW), _iso(LATER)))
check("claim under old key", st == 200 and claimed.get("status") == "claimed",
      f"{st} {claimed}")

rec = rotate_name.mint_rotation(LABEL, SK1, PK2)
check("rotation minted by real minter",
      rotate_name.verify_rotation(rec) is None, str(rec))
new_binding = _mint_binding(LABEL, SK2, PK2, _fresh_iso(), _iso(LATER))
st, out = _rotate(LABEL, rec, new_binding)
check("rotate accepted", st == 200 and out.get("status") == "rotated"
      and out.get("old_pubkey") == PK1 and out.get("new_pubkey") == PK2,
      f"{st} {out}")
stored = _stored_binding(LABEL)
check("stored binding now names the new key",
      stored is not None and stored["node_pubkey"] == PK2
      and stored["signature"] == new_binding["signature"], repr(stored))
check("rotation record kept in name_rotations",
      _stored_rotations(LABEL) == [(PK1, PK2)], _stored_rotations(LABEL))

# the old key's claim against the rotated name is refused by the deterministic
# conflict rule: a different key with a later issued_at cannot beat the
# stored earlier binding, so the holder change stands.
st, out = _claim(LABEL, _mint_binding(LABEL, SK1, PK1, _fresh_iso(), _iso(LATER)))
check("old key with later issued_at refused (holder changed)",
      st == 409, f"{st} {out}")
st, out = _claim(LABEL, _mint_binding(LABEL, SK2, PK2, _fresh_iso(), _iso(LATER)))
check("new key can renew via normal claim", st == 200 and out.get("node_pubkey") == PK2,
      f"{st} {out}")

# --- a stranger's rotation (old_pubkey holds nothing) is refused -----------
SK4, PK4 = _keypair()
SK5, PK5 = _keypair()
SK6B, PK6B = _keypair()
LABEL2 = "rotbelt-two"
st, _ = _claim(LABEL2, _mint_binding(LABEL2, SK4, PK4, _iso(NOW), _iso(LATER)))
check("second name claimed", st == 200, st)
# attacker holds SK5 but the name is held by PK4: a VALID rotation record
# (SK5's own signature designating PK6B) must still fail — the rotation's
# old key does not hold the name.
stranger_rec = rotate_name.mint_rotation(LABEL2, SK5, PK6B)
st, out = _rotate(LABEL2, stranger_rec,
                  _mint_binding(LABEL2, SK6B, PK6B, _iso(NOW), _iso(LATER)))
check("stranger rotation refused (does not hold the name)", st == 400,
      f"{st} {out}")
stored2 = _stored_binding(LABEL2)
check("binding untouched after stranger attempt",
      stored2 is not None and stored2["node_pubkey"] == PK4, repr(stored2))
check("no rotation row written for stranger attempt",
      _stored_rotations(LABEL2) == [], _stored_rotations(LABEL2))

# --- tampered rotation signature refused -----------------------------------
rec3 = rotate_name.mint_rotation(LABEL2, SK4, PK5)
rec3["signature"] = ("0" if rec3["signature"][0] != "0" else "1") + rec3["signature"][1:]
st, out = _rotate(LABEL2, rec3,
                  _mint_binding(LABEL2, SK5, PK5, _fresh_iso(), _iso(LATER)))
check("tampered rotation signature refused", st == 400, f"{st} {out}")

# --- future-dated rotation (not yet in force) refused ----------------------
fut = NOW + datetime.timedelta(hours=1)
rec4 = rotate_name.mint_rotation(LABEL2, SK4, PK5, issued_at=_iso(fut))
st, out = _rotate(LABEL2, rec4,
                  _mint_binding(LABEL2, SK5, PK5, _fresh_iso(), _iso(LATER)))
check("future-dated rotation refused", st == 400, f"{st} {out}")

# --- new binding signed by the OLD key (not the new one) refused -----------
rec5 = rotate_name.mint_rotation(LABEL2, SK4, PK5)
wrong_b = _mint_binding(LABEL2, SK4, PK5, _fresh_iso(), _iso(LATER))  # signed by SK4
st, out = _rotate(LABEL2, rec5, wrong_b)
check("binding signed by old key refused", st == 400, f"{st} {out}")

# --- new binding naming a different key than the rotation designates ------
SK6, PK6 = _keypair()
rec6 = rotate_name.mint_rotation(LABEL2, SK4, PK5)
other_b = _mint_binding(LABEL2, SK6, PK6, _fresh_iso(), _iso(LATER))
st, out = _rotate(LABEL2, rec6, other_b)
check("binding naming undesignated key refused", st == 400, f"{st} {out}")

# --- binding issued before the rotation (chain must move forward) ---------
early = NOW - datetime.timedelta(hours=1)
rec7 = rotate_name.mint_rotation(LABEL2, SK4, PK5)
past_b = _mint_binding(LABEL2, SK5, PK5, _iso(early), _iso(LATER))
st, out = _rotate(LABEL2, rec7, past_b)
check("pre-dated new binding refused", st == 400, f"{st} {out}")

# --- rotate an unclaimed name: 404, not a guess ---------------------------
SK7, PK7 = _keypair()
SK8, PK8 = _keypair()
rec8 = rotate_name.mint_rotation("rotbelt-ghost", SK7, PK8)
st, out = _rotate("rotbelt-ghost", rec8,
                  _mint_binding("rotbelt-ghost", SK8, PK8, _fresh_iso(), _iso(LATER)))
check("rotate of unclaimed name -> 404", st == 404, f"{st} {out}")

# --- rotate an expired binding: dead names read as absent ----------------
SK9, PK9 = _keypair()
SKA, PKA = _keypair()
LABEL3 = "rotbelt-dead"
st, _ = _claim(LABEL3, _mint_binding(LABEL3, SK9, PK9, _iso(NOW), _iso(LATER)))
check("third name claimed", st == 200, st)
conn = sqlite3.connect(DB)
conn.execute("UPDATE name_bindings SET expires_at=? WHERE name=?",
             (_iso(NOW - datetime.timedelta(seconds=1)), LABEL3))
conn.commit(); conn.close()
rec9 = rotate_name.mint_rotation(LABEL3, SK9, PKA)
st, out = _rotate(LABEL3, rec9,
                  _mint_binding(LABEL3, SKA, PKA, _fresh_iso(), _iso(LATER)))
check("rotate of expired binding -> 404 (dead name absent)", st == 404,
      f"{st} {out}")

# --- self-rotation refused at mint and at the mirror ----------------------
SKB, PKB = _keypair()
try:
    rotate_name.mint_rotation(LABEL3, SKB, PKB)
    check("self-rotation refused by minter", False)
except ValueError:
    check("self-rotation refused by minter", True)
self_rec = {"name": LABEL3, "old_pubkey": PKB, "new_pubkey": PKB,
            "issued_at": _iso(NOW), "signature": "0" * 128}
st, out = _rotate(LABEL3, self_rec,
                  _mint_binding(LABEL3, SKB, PKB, _iso(NOW), _iso(LATER)))
check("self-rotation refused by mirror", st == 400, f"{st} {out}")

print(f"\n{CASES['passed']} passed, {CASES['failed']} failed")
sys.exit(1 if CASES["failed"] else 0)
