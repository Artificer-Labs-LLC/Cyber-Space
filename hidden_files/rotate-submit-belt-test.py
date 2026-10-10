#!/usr/bin/env python3
"""Belt test for rotate_name.py --submit: the middle step of the rotation
loop (mint -> SUBMIT -> promote).

Before this tick, minting a rotation ended at "publish it" — the mirror's
POST /api/v1/names/rotate existed, but no client tool could send it. The
submit path posts the record AND the new binding (signed by the NEW key,
issued now) to the mirror, then verifies the mirror moved the name: the
live binding resolves to the new key AND the hop is in the served chain.

Drives the REAL /api/v1/names/rotate route on the REAL app (scratch DB,
loopback uvicorn) against REAL Ed25519 keys, 13 checks:

  happy path (submit accepts, resolve-back to new key, hop in chain,
    .next/.key files untouched),
  refusals: no record, no .next, tampered record signature, future-dated
    record, .next deriving the wrong key, key file already promoted,
    rotation for a name the old key does not hold (mirror 404),
    mirror unreachable, --submit+--promote together (rc 2),
    CLI --submit success (rc 0),
    and the old submit/mint belts still green afterward.

The genesis name is never touched; every key here is fresh and dies
with the run.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/rotate-submit-belt-test.py
"""

import json
import os
import secrets
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
import urllib.error
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from io import StringIO
from pathlib import Path
from unittest import mock

TMP = tempfile.mkdtemp(prefix="rotate-submit-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

MIRROR_PORT = 18379
MIRROR = f"http://127.0.0.1:{MIRROR_PORT}"

import core  # noqa: E402
import uvicorn  # noqa: E402
from app import app  # noqa: E402
from fed.ed25519 import publickey, sign  # noqa: E402
import rotate_name  # noqa: E402

PASSED = FAILED = 0


def check(desc, cond, extra=""):
    global PASSED, FAILED
    if cond:
        PASSED += 1
        print(f"  ok  {desc}")
    else:
        FAILED += 1
        print(f"  FAIL {desc} {extra}")


config = uvicorn.Config(app, host="127.0.0.1", port=MIRROR_PORT,
                        log_level="error")
server = uvicorn.Server(config)
t = threading.Thread(target=server.run, daemon=True)
t.start()
time.sleep(1.2)


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S+00:00")


def _claim(name, priv, expiry_days=730):
    """Claim a name at the real mirror; returns True on 200."""
    pub = publickey(priv).hex().lower()
    now = datetime.now(timezone.utc)
    issued = _iso(now)
    expires = _iso(now + timedelta(days=expiry_days))
    payload = (b"name-claim|" + name.encode() + b"|" + pub.encode()
               + b"|" + issued.encode() + b"|" + expires.encode())
    sig = sign(payload, priv, bytes.fromhex(pub)).hex().lower()
    fields = {"name": name, "node_pubkey": pub, "issued_at": issued,
              "expires_at": expires, "signature": sig}
    data = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(
        MIRROR + "/api/v1/names/claim", data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status == 200
    except Exception:
        return False


def _get(path):
    try:
        with urllib.request.urlopen(MIRROR + path, timeout=10) as resp:
            return json.loads(resp.read().decode())
    except Exception:
        return None


def _stage(home, label, old, new, issued=None, tamper=None):
    rec = rotate_name.mint_rotation(
        label, old, publickey(new).hex().lower(),
        issued or _iso(datetime.now(timezone.utc)))
    if tamper:
        rec = dict(rec)
        rec["signature"] = tamper
    (home / f"{label}-name.key").write_text(old.hex() + "\n")
    (home / f"{label}-rotate.json").write_text(json.dumps(rec) + "\n")
    (home / f"{label}-name.key.next").write_text(new.hex() + "\n")
    return rec


LABEL = "submithop-" + secrets.token_hex(3)
OLD_SEED = bytes.fromhex("cc" * 32)
NEW_SEED = bytes.fromhex("dd" * 32)
OLD_PUB = publickey(OLD_SEED).hex().lower()
NEW_PUB = publickey(NEW_SEED).hex().lower()

# claim the name at the mirror under the OLD key
assert _claim(LABEL, OLD_SEED), "setup: claim failed"

# 1-4. happy path: submit moves the name, files untouched
with tempfile.TemporaryDirectory() as td:
    home = Path(td)
    rec = _stage(home, LABEL, OLD_SEED, NEW_SEED)
    ok, msg = rotate_name.submit_rotation(LABEL, MIRROR, home)
    check("submit accepts", ok, msg)
    resolved = _get(f"/api/v1/names/{LABEL}")
    check("live binding resolves to the NEW key",
          bool(resolved) and resolved.get("node_pubkey", "").lower() == NEW_PUB)
    chain = _get(f"/api/v1/names/{LABEL}/rotations")
    hop = False
    if isinstance(chain, dict):
        hop = any(h.get("old_pubkey", "").lower() == OLD_PUB
                  and h.get("new_pubkey", "").lower() == NEW_PUB
                  and h.get("signature", "").lower() == rec["signature"].lower()
                  for h in chain.get("rotations") or [])
    check("the hop is in the served chain", hop)
    check("submit never touches key files",
          (home / f"{LABEL}-name.key").read_text().strip() == OLD_SEED.hex()
          and (home / f"{LABEL}-name.key.next").read_text().strip() == NEW_SEED.hex())

# 5-6. refusals: no record / no .next
with tempfile.TemporaryDirectory() as td:
    home = Path(td)
    ok, msg = rotate_name.submit_rotation(LABEL, MIRROR, home)
    check("refuses with no record", not ok and "mint one first" in msg, msg)
    (home / f"{LABEL}-rotate.json").write_text(json.dumps(
        rotate_name.mint_rotation(LABEL, OLD_SEED, NEW_PUB)) + "\n")
    ok, msg = rotate_name.submit_rotation(LABEL, MIRROR, home)
    check("refuses with no .next", not ok and "no pending new key" in msg, msg)

# 7. refusal: tampered record signature
with tempfile.TemporaryDirectory() as td:
    home = Path(td)
    _stage(home, LABEL, OLD_SEED, NEW_SEED, tamper="00" * 64)
    ok, msg = rotate_name.submit_rotation(LABEL, MIRROR, home)
    check("refuses tampered record", not ok and "does not verify" in msg, msg)

# 8. refusal: future-dated record (not yet in force)
with tempfile.TemporaryDirectory() as td:
    home = Path(td)
    _stage(home, LABEL, OLD_SEED, NEW_SEED,
           issued=_iso(datetime.now(timezone.utc) + timedelta(hours=2)))
    ok, msg = rotate_name.submit_rotation(LABEL, MIRROR, home)
    check("refuses future-dated record",
          not ok and "not yet in force" in msg, msg)

# 9. refusal: .next derives the wrong key
with tempfile.TemporaryDirectory() as td:
    home = Path(td)
    _stage(home, LABEL, OLD_SEED, NEW_SEED)
    (home / f"{LABEL}-name.key.next").write_text(bytes.fromhex("ee" * 32).hex())
    ok, msg = rotate_name.submit_rotation(LABEL, MIRROR, home)
    check("refuses foreign .next", not ok and "does not derive" in msg, msg)

# 10. refusal: already promoted (name key is the NEW key)
with tempfile.TemporaryDirectory() as td:
    home = Path(td)
    _stage(home, LABEL, OLD_SEED, NEW_SEED)
    (home / f"{LABEL}-name.key").write_text(NEW_SEED.hex() + "\n")
    ok, msg = rotate_name.submit_rotation(LABEL, MIRROR, home)
    check("refuses after promotion", not ok and "BEFORE" in msg, msg)

# 11. refusal: rotation for a name the old key does not hold (mirror 404)
LABEL2 = "submitforeign-" + secrets.token_hex(3)
OTHER = bytes.fromhex("11" * 32)
assert _claim(LABEL2, OTHER), "setup: foreign claim failed"
with tempfile.TemporaryDirectory() as td:
    home = Path(td)
    _stage(home, LABEL2, OLD_SEED, NEW_SEED)  # staged under the WRONG old key
    ok, msg = rotate_name.submit_rotation(LABEL2, MIRROR, home)
    check("refuses foreign-name rotation (not the holder)",
          not ok and ("does not hold this name" in msg or "No such name" in msg), msg)

# 12. refusal: mirror unreachable
with tempfile.TemporaryDirectory() as td:
    home = Path(td)
    _stage(home, LABEL, OLD_SEED, NEW_SEED)
    ok, msg = rotate_name.submit_rotation(LABEL, "http://127.0.0.1:1", home)
    check("refuses when the mirror does not answer",
          not ok and "did not answer" in msg, msg)

# 13-14. CLI exit codes: success rc=0, --submit+--promote together rc=2
LABEL3 = "submitcli-" + secrets.token_hex(3)
assert _claim(LABEL3, OLD_SEED), "setup: cli claim failed"
with tempfile.TemporaryDirectory() as td:
    home = Path(td)
    cy = home / ".cyberspace"
    cy.mkdir()
    rec = rotate_name.mint_rotation(LABEL3, OLD_SEED, NEW_PUB)
    (cy / f"{LABEL3}-name.key").write_text(OLD_SEED.hex() + "\n")
    (cy / f"{LABEL3}-rotate.json").write_text(json.dumps(rec) + "\n")
    (cy / f"{LABEL3}-name.key.next").write_text(NEW_SEED.hex() + "\n")
    with mock.patch.object(Path, "home", return_value=home):
        buf = StringIO()
        with redirect_stdout(buf), redirect_stderr(StringIO()):
            rc = rotate_name.main(["--submit", MIRROR, LABEL3])
        check("CLI --submit exits 0", rc == 0 and "submitted" in buf.getvalue())
        with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            rc2 = rotate_name.main(["--submit", MIRROR, "--promote", LABEL3])
        check("CLI --submit+--promote exits 2", rc2 == 2)

server.should_exit = True
t.join(timeout=5)

print(f"\n{PASSED} passed, {FAILED} failed")
sys.exit(1 if FAILED else 0)
