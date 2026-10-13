#!/usr/bin/env python3
"""Belt: routes_relay.relay_answer refuses a name-key sig whose DECODE
is not 64 bytes (primitive 3 hosting).

relay_answer shape-checks the hoster's answer sig on STRING length
only (128 chars + bytes.fromhex parses), but bytes.fromhex ignores
embedded spaces: a spaced 128-char sig decodes to 63 bytes and was
stored as the session's answer. The answer slot is one-shot — a
second answer gets 404 "session already answered" — so the malformed
answer burned the session's only slot with bytes no dialer can ever
verify (core._relay_open_session's checkvalid refuses a non-64-byte
sig decode): the live-proof dies even though the real hoster signed
correctly. The seat's own contract says it shape-checks "128 hex";
a string with spaces is not 128 hex chars. Decoded-length gate at
the seat (twin of hold_open 17387df / rendezvous 5f37a3e).

Covers: valid sig -> stored (control); uppercase sig -> stored
(control); spaced sig -> 400 + slot untouched + a later valid answer
still lands; short sig -> 400 (existing); non-hex sig -> 400
(existing).

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/relay-answer-decode-length-belt-test.py
"""
import asyncio
import os
import sys
import time
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import HTTPException  # noqa: E402
import routes_relay as rr  # noqa: E402

CASES = {"passed": 0, "failed": 0}


def check(name, cond, extra=""):
    if cond:
        CASES["passed"] += 1
        print(f"  ok  {name}")
    else:
        CASES["failed"] += 1
        print(f"  FAIL {name} {extra}")


REQ = SimpleNamespace(client=None)


def _seed(sid):
    with rr._relay_lock:
        rr._relay_sessions[sid] = {"token": "tok", "challenge": "ab" * 32,
                                   "created": time.monotonic(),
                                   "answer": None}


def _answer(sid):
    with rr._relay_lock:
        rec = rr._relay_sessions.get(sid)
        return None if rec is None else rec.get("answer")


def _post(sid, sig):
    try:
        out = asyncio.run(rr.relay_answer(
            REQ, {"session_id": sid, "name_key_sig": sig}))
        return out.get("ok") is True, None
    except HTTPException as e:
        return False, e.status_code


SIG = "cd" * 64
SPACED = SIG[:10] + "  " + SIG[12:]  # 128 chars, 63-byte decode
assert len(SIG) == 128 and len(SPACED) == 128
assert len(bytes.fromhex(SPACED)) == 63

_seed("s-valid")
ok, _ = _post("s-valid", SIG)
check("valid sig -> accepted (control)", ok)
check("valid sig -> stored (control)", _answer("s-valid") == SIG)

_seed("s-upper")
ok, _ = _post("s-upper", SIG.upper())
check("uppercase sig -> accepted (control)", ok)
check("uppercase sig -> stored (control)", _answer("s-upper") == SIG.upper())

_seed("s-spaced")
ok, code = _post("s-spaced", SPACED)
check("spaced sig -> refused 400", not ok and code == 400,
      f"got ok={ok} code={code}")
check("spaced sig -> answer slot untouched", _answer("s-spaced") is None,
      f"got {_answer('s-spaced')!r}")
ok, _ = _post("s-spaced", SIG)
check("spaced sig -> later valid answer still lands", ok
      and _answer("s-spaced") == SIG)

_seed("s-short")
ok, code = _post("s-short", "cd" * 32)
check("short sig -> refused 400 (existing)", not ok and code == 400)

_seed("s-nonhex")
ok, code = _post("s-nonhex", "zz" * 64)
check("non-hex sig -> refused 400 (existing)", not ok and code == 400)
check("non-hex sig -> answer slot untouched", _answer("s-nonhex") is None)

print(f"\n{CASES['passed']} passed, {CASES['failed']} failed")
sys.exit(1 if CASES["failed"] else 0)
