#!/usr/bin/env python3
"""Belt: core._name_binding_verify itself refuses a signature /
node_pubkey whose STRING length is not 128/64 even when its decode
is the right byte count (primitives 1 naming + 4 identity).

Every caller seat gates the spelling before calling (resolve step 2,
the merge, the claim/rotate routes, dial.plan), but the helper -- the
one fail-closed seat every binding verdict funnels through, imported
across modules -- carried NO length gate before checkvalid, and
bytes.fromhex ignores embedded spaces: a 129-char signature with an
inserted space (or an outer-padded spelling) decoded to the TRUE 64
bytes and VERIFIED, and a binding signed over a payload built from a
spaced 65-char pubkey string verified too. Any present or future
direct caller inherits the false accept. Only the exact 128/64-char
spellings verify at the helper; case is left alone.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/name-binding-verify-stringlen-belt-test.py
"""
import os
import secrets
import sys
import tempfile
from datetime import datetime, timedelta, timezone

TMP = tempfile.mkdtemp(prefix="nbv-strlen-belt-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core  # noqa: E402

core.init_db()
CASES = {"passed": 0, "failed": 0}


def check(name, cond, extra=""):
    if cond:
        CASES["passed"] += 1
        print(f"  ok  {name}")
    else:
        CASES["failed"] += 1
        print(f"  FAIL {name} {extra}")


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S+00:00")


def _signed(label, pub_spelling=None):
    now = datetime.now(timezone.utc)
    issued, expires = _iso(now - timedelta(hours=1)), _iso(now + timedelta(days=364))
    priv = secrets.token_hex(32)
    pub = core._fed_ed25519.publickey(bytes.fromhex(priv)).hex()
    payload_pub = pub_spelling(pub) if pub_spelling else pub
    sig = core._fed_ed25519.sign(
        core._name_claim_payload(label, payload_pub, issued, expires),
        bytes.fromhex(priv), bytes.fromhex(pub)).hex()
    return label, pub, issued, expires, sig


def verify(label, pub, issued, expires, sig):
    return core._name_binding_verify(label, pub, issued, expires, sig)


def spaced(s):
    return s[:32] + " " + s[32:]  # one inserted space, true decode


label, pub, issued, expires, sig = _signed("nbvok")
check("valid binding verifies (control)",
      verify(label, pub, issued, expires, sig) is True)

label, pub, issued, expires, sig = _signed("nbvupper")
check("uppercase sig verifies (control)",
      verify(label, pub, issued, expires, sig.upper()) is True)

label, pub, issued, expires, sig = _signed("nbvspace")
check("inserted-space 129-char sig refused",
      verify(label, pub, issued, expires, spaced(sig)) is False)

label, pub, issued, expires, sig = _signed("nbvpad")
check("outer-padded 130-char sig refused",
      verify(label, pub, issued, expires, " " + sig + " ") is False)

label, pub, issued, expires, sig = _signed("nbvpubsp", spaced)
check("spaced 65-char pubkey refused (sig signed over spaced payload)",
      verify(label, spaced(pub), issued, expires, sig) is False)

label, pub, issued, expires, sig = _signed("nbvpubpad", lambda p: " " + p + " ")
check("padded 66-char pubkey refused (sig signed over padded payload)",
      verify(label, " " + pub + " ", issued, expires, sig) is False)

label, pub, issued, expires, sig = _signed("nbvtamp")
bad = ("0" if sig[0] != "0" else "1") + sig[1:]
check("tampered clean sig refused (control)",
      verify(label, pub, issued, expires, bad) is False)

label, pub, issued, expires, sig = _signed("nbvshort")
check("truncated 64-char sig refused (control)",
      verify(label, pub, issued, expires, sig[:64]) is False)

label, pub, issued, expires, sig = _signed("nbvtype")
check("non-string sig refused (control)",
      verify(label, pub, issued, expires, 123) is False)

print(f"\n{CASES['passed']} passed, {CASES['failed']} failed")
sys.exit(1 if CASES["failed"] else 0)
