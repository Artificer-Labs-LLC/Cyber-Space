#!/usr/bin/env python3
"""Belt test for Q1 fix #1 (Examiner's block, ART-29): _old_binding_beaten.

An unparseable stored row must NOT be beaten by a foreign key — only the
same node_pubkey may re-claim it. A different key attempting to overwrite
gets refused (the route raises 409), not a silent replacement.

Legs:
- no old row -> beaten (fresh claim lands)
- old row expired -> beaten (free to any valid claim)
- old row live, same key, later issued_at -> beaten (renewal)
- old row live, different key, earlier issued_at wins -> NOT beaten (409)
- old row unparseable issued_at, SAME key -> beaten (owner re-claims)
- old row unparseable expires_at, SAME key -> beaten (owner re-claims)
- old row unparseable issued_at, DIFFERENT key -> NOT beaten (Examiner's block)
- old row unparseable expires_at, DIFFERENT key -> NOT beaten (Examiner's block)
- old row fully garbage timestamps, different key -> NOT beaten
"""
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core import _old_binding_beaten  # noqa: E402

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
KEY_A = "aa" * 32
KEY_B = "bb" * 32


def _binding(key=KEY_A, issued=None, expires=None):
    issued = issued or _iso(now - timedelta(hours=1))
    expires = expires or _iso(now + timedelta(days=30))
    return {"name": "testname", "node_pubkey": key,
            "issued_at": issued, "expires_at": expires,
            "signature": "cc" * 64}


def _old(key=KEY_A, issued=None, expires=None):
    return _binding(key=key, issued=issued, expires=expires)


# 1. No old row -> beaten
check("no old row -> beaten (fresh claim lands)",
      _old_binding_beaten(None, _binding(), KEY_A, now) is True)

# 2. Old row expired -> beaten by any valid claim
old = _old(key=KEY_B,
           issued=_iso(now - timedelta(days=60)),
           expires=_iso(now - timedelta(days=30)))
check("expired old row -> beaten by a different key",
      _old_binding_beaten(old, _binding(key=KEY_A), KEY_A, now) is True)

# 3. Old row live, same key, later issued_at -> beaten (renewal)
old = _old(key=KEY_A,
           issued=_iso(now - timedelta(hours=2)),
           expires=_iso(now + timedelta(days=30)))
new = _binding(key=KEY_A,
               issued=_iso(now - timedelta(hours=1)),
               expires=_iso(now + timedelta(days=60)))
check("live old row, same key, later issued_at -> beaten (renewal)",
      _old_binding_beaten(old, new, KEY_A, now) is True)

# 4. Old row live, different key, old has earlier issued_at -> NOT beaten
old = _old(key=KEY_B,
           issued=_iso(now - timedelta(hours=3)),
           expires=_iso(now + timedelta(days=30)))
new = _binding(key=KEY_A,
               issued=_iso(now - timedelta(hours=1)),
               expires=_iso(now + timedelta(days=30)))
check("live old row, different key, earlier issued_at wins -> NOT beaten (409)",
      _old_binding_beaten(old, new, KEY_A, now) is False)

# 5. Unparseable issued_at, SAME key -> beaten (owner re-claims)
old = _old(key=KEY_A, issued="not-a-timestamp",
           expires=_iso(now + timedelta(days=30)))
check("unparseable issued_at, same key -> beaten (owner re-claims)",
      _old_binding_beaten(old, _binding(key=KEY_A), KEY_A, now) is True)

# 6. Unparseable expires_at, SAME key -> beaten (owner re-claims)
old = _old(key=KEY_A,
           issued=_iso(now - timedelta(hours=1)),
           expires="2026/10/12")  # date-only, not canonical
check("unparseable expires_at, same key -> beaten (owner re-claims)",
      _old_binding_beaten(old, _binding(key=KEY_A), KEY_A, now) is True)

# 7. Unparseable issued_at, DIFFERENT key -> NOT beaten (Examiner's block)
old = _old(key=KEY_B, issued="not-a-timestamp",
           expires=_iso(now + timedelta(days=30)))
check("unparseable issued_at, different key -> NOT beaten (Examiner's block)",
      _old_binding_beaten(old, _binding(key=KEY_B), KEY_A, now) is False)

# 8. Unparseable expires_at, DIFFERENT key -> NOT beaten (Examiner's block)
old = _old(key=KEY_B,
           issued=_iso(now - timedelta(hours=1)),
           expires="2026/10/12")
check("unparseable expires_at, different key -> NOT beaten (Examiner's block)",
      _old_binding_beaten(old, _binding(key=KEY_B), KEY_A, now) is False)

# 9. Fully garbage timestamps, different key -> NOT beaten
old = _old(key=KEY_B, issued="garbage", expires="also garbage")
check("fully garbage timestamps, different key -> NOT beaten",
      _old_binding_beaten(old, _binding(key=KEY_B), KEY_A, now) is False)

# 10. Fully garbage timestamps, same key -> beaten (owner re-claims)
old = _old(key=KEY_A, issued="garbage", expires="also garbage")
check("fully garbage timestamps, same key -> beaten (owner re-claims)",
      _old_binding_beaten(old, _binding(key=KEY_A), KEY_A, now) is True)

print(f"\n{PASSED} passed, {FAILED} failed")
sys.exit(1 if FAILED else 0)
