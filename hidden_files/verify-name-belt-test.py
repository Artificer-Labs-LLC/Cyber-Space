#!/usr/bin/env python3
"""Belt test for verify_name.py: offline self-authentication of name bindings.

12 checks against real Ed25519 bindings minted the same way mint_name.py
does (the byte-canonical payload from core._name_claim_payload):
valid-and-live, expired, not-yet-issued, tampered name/pub/issued/expires/sig,
bad label, missing field, non-hex pub, stdin path.
"""
import io
import json
import os
import sys
import tempfile
from contextlib import redirect_stdout, redirect_stderr
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
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


def _mint(name="testbind", pub=None, issued=None, expires=None):
    priv = os.urandom(32)
    pub = publickey(priv) if pub is None else pub
    now = datetime.now(timezone.utc)
    issued = issued or _iso(now - timedelta(hours=1))
    expires = expires or _iso(now + timedelta(days=365))
    pub_hex = pub.hex().lower()
    payload = (b"name-claim|" + name.encode() + b"|" + pub_hex.encode()
               + b"|" + issued.encode() + b"|" + expires.encode())
    sig = sign(payload, priv, pub).hex().lower()
    return {"name": name, "node_pubkey": pub_hex, "issued_at": issued,
            "expires_at": expires, "signature": sig}


def _run_cli(binding, via_stdin=False):
    """Run verify_name.main capturing stdout/stderr; return (rc, out, err)."""
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        if via_stdin:
            old = sys.stdin
            sys.stdin = io.StringIO(json.dumps(binding))
            try:
                rc = verify_name.main(["-"])
            finally:
                sys.stdin = old
        else:
            with tempfile.NamedTemporaryFile("w", suffix=".json",
                                             delete=False) as f:
                json.dump(binding, f)
                path = f.name
            try:
                rc = verify_name.main([path])
            finally:
                os.unlink(path)
    return rc, out.getvalue(), err.getvalue()


now = datetime.now(timezone.utc)

rc, out, err = _run_cli(_mint())
check("valid live binding -> exit 0 and names the binding", rc == 0 and "testbind.cyberspace" in out)

b = _mint()
check("verify() returns None on a good binding", verify_name.verify(b) is None)

b = _mint(issued=_iso(now - timedelta(hours=2)),
          expires=_iso(now - timedelta(hours=1)))
check("expired binding -> exit 1 saying expired", verify_name.verify(b) is not None and "expired" in verify_name.verify(b))

b = _mint(issued=_iso(now + timedelta(hours=1)),
          expires=_iso(now + timedelta(days=365)))
check("not-yet-issued binding -> exit 1 saying not yet issued",
      (lambda r: r is not None and "not yet issued" in r)(verify_name.verify(b)))

b = _mint(); b["name"] = "tampered"
check("tampered name -> exit 1, signature does not verify",
      (lambda r: r is not None and "does not verify" in r)(verify_name.verify(b)))

b = _mint(); b["node_pubkey"] = "ab" * 32
check("wrong pubkey -> exit 1, signature does not verify",
      (lambda r: r is not None and "does not verify" in r)(verify_name.verify(b)))

b = _mint(); b["issued_at"] = _iso(now - timedelta(hours=2))
check("tampered issued_at -> exit 1, signature does not verify",
      (lambda r: r is not None and "does not verify" in r)(verify_name.verify(b)))

b = _mint(); b["signature"] = ("ab" * 64).lower()
check("replaced signature -> exit 1, signature does not verify",
      (lambda r: r is not None and "does not verify" in r)(verify_name.verify(b)))

b = _mint(); b["name"] = "Bad.Name"
check("bad label -> exit 1 before touching crypto",
      (lambda r: r is not None and "not a valid" in r)(verify_name.verify(b)))

b = _mint(); del b["signature"]
check("missing field -> exit 1 naming the field",
      (lambda r: r is not None and "missing field" in r)(verify_name.verify(b)))

b = _mint(); b["node_pubkey"] = "zz" * 32
check("non-hex pubkey -> exit 1 saying not hex",
      (lambda r: r is not None and "not hex" in r)(verify_name.verify(b)))

rc, out, err = _run_cli(_mint(), via_stdin=True)
check("stdin path (-) verifies a good binding, exit 0", rc == 0)

print(f"\n{PASSED} passed, {FAILED} failed")
sys.exit(1 if FAILED else 0)
