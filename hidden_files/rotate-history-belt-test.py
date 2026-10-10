"""Rotate-history belt (primitive 4, identity): the mirror's read side of
rotation.

Drives the REAL /api/v1/names/{name}/rotations route on the REAL app
(scratch DB, loopback uvicorn) against REAL Ed25519 keys:

  claim under key A -> rotate A->B -> rotate B->C ->
  GET rotations must return the two designation rows, oldest first,
  each offline-verifiable against the OLD key that signed it (a third
  party who never saw the mint can follow the chain from the mirror
  alone).

Also: 404 for a name that was never rotated (absence, not emptiness),
404 for a name with no rows at all, 400 for a bad label, and label
normalization on the path. The genesis name is never touched; every
key here is fresh and dies with the run.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/rotate-history-belt-test.py
"""

import datetime
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

TMP = tempfile.mkdtemp(prefix="rotate-history-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

MIRROR_PORT = 18371
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


def _keypair():
    seed = secrets.token_hex(32)
    return bytes.fromhex(seed), _fed_ed25519.publickey(bytes.fromhex(seed)).hex().lower()


def _fresh_iso():
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


def _get(path):
    try:
        with urllib.request.urlopen(MIRROR + path, timeout=8) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read())
        except Exception:
            return e.code, {"detail": str(e)}


# --- build a two-link chain: claim A -> rotate A->B -> rotate B->C ---------
SK_A, PK_A = _keypair()
SK_B, PK_B = _keypair()
SK_C, PK_C = _keypair()
LABEL = "chainhist"
LATER = _fresh_iso() and (datetime.datetime.now(datetime.timezone.utc)
                          + datetime.timedelta(days=30)).isoformat()

st, _ = _post("/api/v1/names/claim",
              {"name": LABEL,
               **_mint_binding(LABEL, SK_A, PK_A, _fresh_iso(), LATER)})
check("claim under A", st == 200, st)

rec_ab = rotate_name.mint_rotation(LABEL, SK_A, PK_B)
binding_b = _mint_binding(LABEL, SK_B, PK_B, _fresh_iso(), LATER)
st, out = _post("/api/v1/names/rotate", {
    "name": LABEL, "old_pubkey": rec_ab["old_pubkey"], "new_pubkey": rec_ab["new_pubkey"],
    "rotation_issued_at": rec_ab["issued_at"], "rotation_signature": rec_ab["signature"],
    "binding_issued_at": binding_b["issued_at"], "binding_expires_at": binding_b["expires_at"],
    "binding_signature": binding_b["signature"]})
check("rotate A->B accepted", st == 200, f"{st} {out}")

rec_bc = rotate_name.mint_rotation(LABEL, SK_B, PK_C)
binding_c = _mint_binding(LABEL, SK_C, PK_C, _fresh_iso(), LATER)
st, out = _post("/api/v1/names/rotate", {
    "name": LABEL, "old_pubkey": rec_bc["old_pubkey"], "new_pubkey": rec_bc["new_pubkey"],
    "rotation_issued_at": rec_bc["issued_at"], "rotation_signature": rec_bc["signature"],
    "binding_issued_at": binding_c["issued_at"], "binding_expires_at": binding_c["expires_at"],
    "binding_signature": binding_c["signature"]})
check("rotate B->C accepted", st == 200, f"{st} {out}")

# --- the history endpoint: the mirror's view of the chain ------------------
st, body = _get(f"/api/v1/names/{LABEL}/rotations")
check("GET rotations 200", st == 200, f"{st} {body}")
rows = body.get("rotations", []) if isinstance(body, dict) else []
check("two rows oldest first",
      len(rows) == 2
      and rows[0]["old_pubkey"] == PK_A and rows[0]["new_pubkey"] == PK_B
      and rows[1]["old_pubkey"] == PK_B and rows[1]["new_pubkey"] == PK_C,
      rows)
check("row fields complete",
      all(set(r) == {"old_pubkey", "new_pubkey", "issued_at", "signature", "accepted_at"}
          for r in rows), rows)
check("served issued_at matches the minted records",
      rows[0]["issued_at"] == rec_ab["issued_at"]
      and rows[1]["issued_at"] == rec_bc["issued_at"], rows)

# a third party who never saw the mint can verify every designation
# signature against the OLD key that signed it, straight from the GET.
def _payload(label, old, new, issued):
    return f"name-rotate|{label}|{old}|{new}|{issued}".encode()


ok_chain = True
for row, pub_of_old in ((rows[0], PK_A), (rows[1], PK_B)):
    sig = bytes.fromhex(row["signature"])
    try:
        ok_chain &= _fed_ed25519.checkvalid(
            sig, _payload(LABEL, row["old_pubkey"], row["new_pubkey"], row["issued_at"]),
            bytes.fromhex(pub_of_old))
    except Exception:
        ok_chain = False
check("every served designation verifies under its old key (third-party chain walk)",
      ok_chain, rows)

# --- absence and grammar ----------------------------------------------------
st, _ = _get(f"/api/v1/names/{LABEL.upper()}/rotations")
check("label normalized on the path", st == 200, st)

SK_Z, PK_Z = _keypair()
st, _ = _post("/api/v1/names/claim",
              {"name": "norotations", **_mint_binding("norotations", SK_Z, PK_Z, _fresh_iso(), LATER)})
check("second name claimed without rotating", st == 200, st)
st, body = _get("/api/v1/names/norotations/rotations")
check("rotated-never name reads 404 (absence, not emptiness)", st == 404, f"{st} {body}")

st, body = _get("/api/v1/names/no-such-name-xyz/rotations")
check("unknown name reads 404", st == 404, f"{st} {body}")

st, body = _get("/api/v1/names/-bad-/rotations")
check("bad label reads 400", st == 400, f"{st} {body}")

print(f"\n{CASES['passed']} passed, {CASES['failed']} failed")
sys.exit(1 if CASES["failed"] else 0)
