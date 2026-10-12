#!/usr/bin/env python3
"""Label-grammar agreement belt (primitive 1: naming).

The label grammar is enforced in FOUR places and only one of them is the
mirror: core._valid_name_label (server), mint_name._valid_label (client
fast check), verify_name._valid_label (offline verifier),
rotate_name._valid_label (rotation client). The promise that
breaks if they drift: mint's refusal must never surprise the operator (a
label mint refuses but the mirror would accept is an ugly false negative),
and verify's accept set must stay a twin of the mirror's.

The subtlety this belt pins: the claim route normalizes (strip+lowercase)
BEFORE validating, so the mirror's accept set is wider than the raw
checkers' — e.g. the mirror accepts "UPPER" as "upper". verify_name
normalizes identically first, so its accept set equals the mirror's.
mint_name's fast check is deliberately conservative on the raw form
(docstring: "server decides") — it refuses raw uppercase, and the belt
documents that as contract, not a bug.

Agreement assertions:
  1. all three checkers agree on every raw label in the corpus (True-set
     and False-set identical);
  2. claim route on raw label L: all-True => 200 stored under L;
     all-False => 400 (name refusal, never another code);
  3. uppercase label: checkers False, claim 200 (stored lowercased),
     verify_name.verify accepts the submitted binding (normalize-first
     twin), mint CLI refuses client-side (documented conservatism);
  4. occupied-label conflict: claiming the same label with a stranger key
     is not 200.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/label-grammar-agreement-belt-test.py
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

TMP = tempfile.mkdtemp(prefix="label-grammar-belt-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import core  # noqa: E402
import uvicorn  # noqa: E402
from app import app  # noqa: E402
from fed import ed25519 as _fed_ed25519  # noqa: E402
import mint_name  # noqa: E402
import verify_name  # noqa: E402
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


MIRROR_PORT = 18378
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


def _claim(fields):
    body = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(MIRROR + "/api/v1/names/claim", data=body,
                                 method="POST")
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, None


def _stored(label):
    try:
        with urllib.request.urlopen(
                MIRROR + "/api/v1/names/" + label, timeout=8) as r:
            return json.loads(r.read())
    except Exception:
        return None


NOW = datetime.now(timezone.utc)


def _live():
    return ((NOW - timedelta(hours=1)).isoformat(timespec="seconds"),
            (NOW + timedelta(days=30)).isoformat(timespec="seconds"))


def _bind_fields(label, sk, pk, issued, expires):
    return {
        "name": label, "node_pubkey": pk, "issued_at": issued,
        "expires_at": expires,
        "signature": _fed_ed25519.sign(
            core._name_claim_payload(label.strip().lower(), pk.lower(),
                                     issued.strip(), expires.strip()),
            bytes.fromhex(sk), bytes.fromhex(pk)).hex(),
    }


# --- corpus: checker agreement on the raw form -------------------------------
valid = ["a", "ab", "ab-cd", "x1", "0", "a" * 63, "grammar-one-9"]
# Spec question settled 2026-10-12: str.isalnum() used to accept unicode
# letters, so all checkers agreed True on 'oké' — but the resolver's DNS
# wire face decodes labels as ASCII and refuses them, making such names
# claimable yet never resolvable. Ruled: ASCII-only grammar; unicode
# labels now sit in the invalid corpus and pin the refusal.
invalid = ["", "A", "UPPER", "a b", "a.b", "-a", "a-", "ab_cd", "a" * 64,
           "a/b", "x:y", "-", "a.-b", "  ", "oké", "génèrïs"]

for label in valid:
    g = (mint_name._valid_label(label), verify_name._valid_label(label),
         core._valid_name_label(label), rotate_name._valid_label(label))
    check(f"all-true: {label!r}" if len(label) < 63 else "all-true: 63-char label",
          g == (True, True, True, True), repr(g))
for label in invalid:
    g = (mint_name._valid_label(label), verify_name._valid_label(label),
         core._valid_name_label(label), rotate_name._valid_label(label))
    check(f"all-false: {label!r}", g == (False, False, False, False), repr(g))

# --- claim route honors the grammar ------------------------------------------
sk, pk = _keypair()
issued, expires = _live()
sk2, pk2 = _keypair()

for i, label in enumerate(["grammar-a1", "g2-ok", "x9"]):
    f = _bind_fields(label, sk, pk, issued, expires)
    st, _ = _claim(f)
    check(f"claim accepts checker-true label {label!r}", st == 200, f"st={st}")
    check(f"stored under the raw label {label!r}",
          _stored(label) is not None)

for label in ["-bad1", "bad.gram2"]:
    f = _bind_fields(label, sk, pk, issued, expires)
    st, _ = _claim(f)
    check(f"claim 400-refuses raw-invalid label {label!r}", st == 400,
          f"st={st}")

# Raw-uppercase is NOT refused: the mirror normalizes (strip+lowercase)
# before validating, so "UP1" is accepted as "up1" — the twin of the
# normalized-path case below. It does not belong in the 400 list.
check("claim 200-accepts raw-uppercase label (normalize-first)",
      _claim(_bind_fields("UP1", sk, pk, issued, expires))[0] == 200)

# --- normalized path: mirror accepts what the raw checkers refuse ------------
sk3, pk3 = _keypair()
label_upper = "GRAMMAR-UP-3"
f = _bind_fields(label_upper, sk3, pk3, issued, expires)
st, _ = _claim(f)
check("claim accepts raw-uppercase label (mirror normalizes)", st == 200,
      f"st={st}")
check("mirror stores it lowercased", _stored("grammar-up-3") is not None)
check("verify_name.verify accepts the submitted binding (normalize-first twin)",
      verify_name.verify(f) is None,
      repr(verify_name.verify(f)))
check("mint_name._valid_label refuses the raw uppercase form (contract: server decides)",
      mint_name._valid_label(label_upper) is False)

# --- occupied-label conflict: stranger key is not 200 -------------------------
# The deterministic rule: different keys, earlier issued_at wins. The
# incumbent ("grammar-a1") was issued 1h ago, so a stranger issued 30min
# ago loses — must come back 409. (Earlier issued_at == NOW-1h for both
# would be a pubkey tie-break; the belt asserts the real rule, not a coin.)
_later_issued = (NOW - timedelta(minutes=30)).isoformat(timespec="seconds")
f = _bind_fields("grammar-a1", sk2, pk2, _later_issued, expires)
st, _ = _claim(f)
check("claim conflict: stranger key issued LATER on a live name gets 409",
      st == 409, f"st={st}")
check("incumbent binding unchanged by the refused claim",
      (_stored("grammar-a1") or {}).get("node_pubkey") == pk)

print(f"\n{PASSED} passed, {FAILED} failed")
sys.exit(1 if FAILED else 0)
