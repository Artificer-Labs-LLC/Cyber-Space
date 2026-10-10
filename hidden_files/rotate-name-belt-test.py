#!/usr/bin/env python3
"""Belt test for rotate_name.py: the identity half of primitive 4.

15 checks against real Ed25519 rotation records:
valid rotation verifies, tampered new/old pub fail, signature by the NEW
key fails (wrong side vouches), garbage sig fails, bad label fails,
self-rotation refused at mint AND verify, uppercase keys normalize,
future-dated rotation not yet in force, bad timestamp fails, a name-claim
payload can't pass as rotation (prefix confusion), the rotation record
fails closed in verify_name (it is not a binding), mint CLI roundtrip
with a temp HOME, CLI refuses with no existing key.
"""
import io
import json
import os
import sys
import tempfile
from contextlib import redirect_stdout, redirect_stderr
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import rotate_name  # noqa: E402
import verify_name  # noqa: E402
from fed.ed25519 import publickey, sign  # noqa: E402

PASSED = FAILED = 0


def check(desc, cond):
    global PASSED, FAILED
    if cond:
        PASSED += 1
        print(f"  ok: {desc}")
    else:
        FAILED += 1
        print(f"  FAIL: {desc}")


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S+00:00")


def _mint(old_priv=None, label="rotbind", new_priv=None, issued=None):
    old_priv = old_priv or os.urandom(32)
    new_priv = new_priv or os.urandom(32)
    new_pub = publickey(new_priv).hex().lower()
    rec = rotate_name.mint_rotation(label, old_priv, new_pub,
                                    issued or _iso(datetime.now(timezone.utc)))
    return rec, old_priv, new_priv


# 1. valid rotation verifies
rec, old_priv, new_priv = _mint()
check("valid rotation verifies", rotate_name.verify_rotation(rec) is None)

# 2-3. tampered pubs fail
r2 = dict(rec); r2["new_pubkey"] = publickey(os.urandom(32)).hex()
check("tampered new_pubkey fails",
      rotate_name.verify_rotation(r2) is not None)
r3 = dict(rec); r3["old_pubkey"] = publickey(os.urandom(32)).hex()
check("tampered old_pubkey fails",
      rotate_name.verify_rotation(r3) is not None)

# 4. signature by the NEW key (wrong side) fails — continuity means OLD vouches
old_pub = publickey(old_priv).hex().lower()
new_pub = publickey(new_priv).hex().lower()
iss = _iso(datetime.now(timezone.utc))
payload = rotate_name._rotate_payload("rotbind", old_pub, new_pub, iss)
wrong_sig = sign(payload, new_priv, bytes.fromhex(new_pub)).hex().lower()
r4 = {"name": "rotbind", "old_pubkey": old_pub, "new_pubkey": new_pub,
      "issued_at": iss, "signature": wrong_sig}
check("new-key signature (wrong side) fails",
      rotate_name.verify_rotation(r4) is not None)

# 5. garbage signature fails
r5 = dict(rec); r5["signature"] = "00" * 64
check("garbage signature fails",
      rotate_name.verify_rotation(r5) is not None)

# 6. bad label fails
bad_label_refused = False
try:
    rotate_name.mint_rotation("BAD LABEL!", os.urandom(32),
                              publickey(os.urandom(32)).hex().lower())
except ValueError:
    bad_label_refused = True
check("bad label fails at mint", bad_label_refused)

# 7. self-rotation refused at mint and verify
op = os.urandom(32)
spub = publickey(op).hex().lower()
mint_refused = False
try:
    rotate_name.mint_rotation("rotbind", op, spub)
except ValueError:
    mint_refused = True
check("self-rotation refused at mint", mint_refused)
r7 = {"name": "rotbind", "old_pubkey": spub, "new_pubkey": spub,
      "issued_at": iss, "signature": "00" * 64}
check("self-rotation refused at verify",
      rotate_name.verify_rotation(r7) is not None)

# 8. uppercase keys normalize (mirror twin rule)
r8 = dict(rec)
r8["old_pubkey"] = r8["old_pubkey"].upper()
r8["new_pubkey"] = "  " + r8["new_pubkey"] + "  "
check("uppercase/padded keys normalize",
      rotate_name.verify_rotation(r8) is None)

# 9. future-dated rotation not yet in force
rf, _, _ = _mint(issued=_iso(datetime.now(timezone.utc) + timedelta(days=1)))
reason = rotate_name.verify_rotation(rf)
check("future-dated rotation not yet in force",
      reason is not None and "future" in reason)

# 10. unparseable issued_at fails
r10 = dict(rec); r10["issued_at"] = "not-a-time"
check("unparseable issued_at fails",
      rotate_name.verify_rotation(r10) is not None)

# 11. name-claim payload cannot pass as rotation (prefix confusion)
op2 = os.urandom(32)
pub2 = publickey(op2).hex().lower()
claim_payload = (b"name-claim|rotbind|" + pub2.encode() + b"|" + iss.encode()
                 + b"|" + _iso(datetime.now(timezone.utc)
                               + timedelta(days=730)).encode())
claim_sig = sign(claim_payload, op2, bytes.fromhex(pub2)).hex().lower()
r11 = {"name": "rotbind", "old_pubkey": pub2, "new_pubkey": pub2,
       "issued_at": iss, "signature": claim_sig}
check("claim-shaped signature rejected as rotation",
      rotate_name.verify_rotation(r11) is not None)

# 12. rotation record fails closed inside verify_name (it is not a binding)
check("rotation record rejected by the binding verifier",
      verify_name.verify(rec) is not None)

# 13. CLI roundtrip with a temp HOME
tmpd = tempfile.mkdtemp()
os.environ["HOME"] = tmpd
try:
    seed = os.urandom(32)
    (os.path.join(tmpd, ".cyberspace"))
    cyd = os.path.join(tmpd, ".cyberspace")
    os.makedirs(cyd, exist_ok=True)
    with open(os.path.join(cyd, "clibind-name.key"), "w") as f:
        f.write(seed.hex())
    buf_out, buf_err = io.StringIO(), io.StringIO()
    with redirect_stdout(buf_out), redirect_stderr(buf_err):
        rc = rotate_name.main(["clibind"])
    rec_path = os.path.join(cyd, "clibind-rotate.json")
    next_path = os.path.join(cyd, "clibind-name.key.next")
    rec_back = json.load(open(rec_path)) if os.path.exists(rec_path) else None
    check("CLI mints, self-verifies, writes record + .next key (old key untouched)",
          rc == 0 and rec_back is not None
          and rotate_name.verify_rotation(rec_back) is None
          and os.path.exists(next_path)
          and open(os.path.join(cyd, "clibind-name.key")).read().strip() == seed.hex())
finally:
    os.environ["HOME"] = os.path.expanduser("~")

# 14. CLI refuses with no existing key
tmpd2 = tempfile.mkdtemp()
os.environ["HOME"] = tmpd2
try:
    with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
        rc2 = rotate_name.main(["ghostbind"])
    check("CLI refuses with no existing key", rc2 != 0)
finally:
    os.environ["HOME"] = os.path.expanduser("~")

print(f"\n{PASSED} passed, {FAILED} failed")
sys.exit(1 if FAILED else 0)
