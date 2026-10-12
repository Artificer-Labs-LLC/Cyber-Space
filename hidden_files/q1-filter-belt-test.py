#!/usr/bin/env python3
"""Belt test for Q1 fixes #2/#3/#4 (Lodestar B1/B2/B3, ART-29):
refused_bindings.classify_binding.

B1: grammar checked BEFORE length (spec §7.3.9 order:
    grammar -> length -> expiry-cap -> not-in-manifest).
B2: missing or malformed issued_at -> refused (expiry-cap).
B3: (expires - issued) > 365 days -> refused (expiry-cap);
    year-9999 stamps must not 500 (subtraction form, no OverflowError).
"""
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import refused_bindings as rb  # noqa: E402

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


now = datetime.now(timezone.utc)
MANIFEST = {"goodname", "another"}


def _row(name="goodname", issued=None, expires=None):
    issued = issued if issued is not None else _iso(now - timedelta(hours=1))
    expires = expires if expires is not None else _iso(now + timedelta(days=30))
    return {"name": name, "node_pubkey": "aa" * 32,
            "issued_at": issued, "expires_at": expires}


# --- B1: grammar before length ---
# A label that fails BOTH grammar and length must report "grammar".
# "ab" is 2 bytes (length-refused) but also... "ab" passes grammar.
# Use a label that is both bad-grammar AND bad-length: e.g. "a!" is 2 bytes
# (length-refused: 1-2) and fails grammar (has "!").
r = _row(name="a!")
check("B1: label failing both grammar and length -> 'grammar' (not 'length')",
      rb.classify_binding(r, MANIFEST) == "grammar")

# Pure length failure still reports length.
r = _row(name="ab")  # 2 bytes, grammar-ok
check("B1: pure length failure (2-byte label) -> 'length'",
      rb.classify_binding(r, MANIFEST) == "length")

# Pure grammar failure still reports grammar.
r = _row(name="Bad_Name")  # uppercase + underscore
check("B1: pure grammar failure -> 'grammar'",
      rb.classify_binding(r, MANIFEST) == "grammar")

# --- B2: issued_at validation ---
r = _row()
del r["issued_at"]
check("B2: missing issued_at -> 'expiry-cap'",
      rb.classify_binding(r, MANIFEST) == "expiry-cap")

r = _row(issued="not-a-timestamp")
check("B2: malformed issued_at -> 'expiry-cap'",
      rb.classify_binding(r, MANIFEST) == "expiry-cap")

r = _row(issued="2026-10-12")  # date-only, not canonical
check("B2: date-only issued_at -> 'expiry-cap'",
      rb.classify_binding(r, MANIFEST) == "expiry-cap")

r = _row(issued="")
check("B2: empty issued_at -> 'expiry-cap'",
      rb.classify_binding(r, MANIFEST) == "expiry-cap")

# --- B3: 365-day cap ---
r = _row(issued=_iso(now - timedelta(hours=1)),
         expires=_iso(now + timedelta(days=366)))
check("B3: 366-day lifetime -> 'expiry-cap'",
      rb.classify_binding(r, MANIFEST) == "expiry-cap")

r = _row(issued=_iso(now),
         expires=_iso(now + timedelta(days=365)))
check("B3: exactly 365-day lifetime -> hold-eligible (None)",
      rb.classify_binding(r, MANIFEST) is None)

r = _row(issued=_iso(now - timedelta(hours=1)),
         expires=_iso(now + timedelta(days=730)))
check("B3: 730-day lifetime -> 'expiry-cap'",
      rb.classify_binding(r, MANIFEST) == "expiry-cap")

# Year-9999 must not raise (no OverflowError -> no 500).
# Jan 1 -> Dec 31 9999 is 364 days: under the cap, hold-eligible.
r = _row(issued="9999-01-01T00:00:00Z",
         expires="9999-12-31T23:59:59Z")
try:
    result = rb.classify_binding(r, MANIFEST)
    check("B3: year-9999 364-day span -> hold-eligible (None), no raise",
          result is None)
except Exception as e:
    check(f"B3: year-9999 stamps do not raise (got {type(e).__name__})", False)

# Year-9999 with > 365 day span.
r = _row(issued="9998-01-01T00:00:00Z",
         expires="9999-12-31T23:59:59Z")
try:
    result = rb.classify_binding(r, MANIFEST)
    check("B3: year-9999 2-year span -> 'expiry-cap', no raise",
          result == "expiry-cap")
except Exception as e:
    check(f"B3: year-9999 2-year span no raise (got {type(e).__name__})", False)

# --- Sanity: good row still passes ---
r = _row()
check("sanity: well-formed row in manifest -> hold-eligible (None)",
      rb.classify_binding(r, MANIFEST) is None)

r = _row(name="notlisted")
check("sanity: well-formed row NOT in manifest -> 'not-in-manifest'",
      rb.classify_binding(r, MANIFEST) == "not-in-manifest")

print(f"\n{PASSED} passed, {FAILED} failed")
sys.exit(1 if FAILED else 0)
