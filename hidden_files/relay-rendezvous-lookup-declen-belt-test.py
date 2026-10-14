#!/usr/bin/env python3
"""Belt: routes_relay rendezvous LOOKUP seats refuse a point whose
DECODE is not 32 bytes (primitives 2 resolution + 3 hosting).

_resolve_rendezvous_token and relay_hold_query shape-checked the
point on STRING length only (64 chars + bytes.fromhex parses), but
bytes.fromhex ignores embedded spaces: a spaced 64-char point
decoded to 31 bytes, passed both seats' shape gates, and was only
refused downstream (index miss / epoch string-compare). Their own
contracts (malformed -> None / held:false) must hold at the seat
whatever writer populated the index. Decoded-length gate at both
seats, twin of _valid_rendezvous / relay_answer in the same file.

Isolation: point_is_current is stubbed True and the index is seeded
directly, so the ONLY thing that can refuse the spaced point is
each seat's own shape gate. Valid + uppercase points still resolve.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/relay-rendezvous-lookup-declen-belt-test.py
"""
import asyncio
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import rendezvous  # noqa: E402
import routes_relay as rr  # noqa: E402

CASES = {"passed": 0, "failed": 0}


def check(name, cond, extra=""):
    if cond:
        CASES["passed"] += 1
        print(f"  ok  {name}")
    else:
        CASES["failed"] += 1
        print(f"  FAIL {name} {extra}")


PUB = "ab" * 32
NOW = time.time()
CUR, _PREV = rendezvous.derive_points(NOW, PUB)
SPACED = CUR[:10] + "  " + CUR[12:]  # 64 chars, 31-byte decode
assert len(SPACED) == 64 and len(bytes.fromhex(SPACED)) == 31

rr._relay_belt = lambda request, surface: None  # noqa: E731
rendezvous.point_is_current = lambda *a, **k: True
rr.rendezvous.point_is_current = lambda *a, **k: True

TOK = "tok-belt"
now_mono = time.monotonic()
for point in (CUR, CUR.upper(), SPACED):
    rr._relay_rendezvous[point] = {
        "token": TOK, "name_pub": PUB,
        "epoch_len": rendezvous.EPOCH_LEN_DEFAULT, "seen": now_mono}
rr._relay_hold_opens[TOK] = {"registered": now_mono, "seen": now_mono}


class Req:
    client = None


check("valid point -> token (control)",
      rr._resolve_rendezvous_token(CUR) == TOK)
check("uppercase point -> token (control)",
      rr._resolve_rendezvous_token(CUR.upper()) == TOK)
check("spaced point (31-byte decode) -> None at the seat",
      rr._resolve_rendezvous_token(SPACED) is None)
check("valid point -> held:true (control)",
      asyncio.run(rr.relay_hold_query(Req(), CUR)) == {"held": True})
check("spaced point (31-byte decode) -> held:false at the seat",
      asyncio.run(rr.relay_hold_query(Req(), SPACED)) == {"held": False})
check("non-hex 64-char point -> None (existing)",
      rr._resolve_rendezvous_token("zz" * 32) is None)
check("short point -> held:false (existing)",
      asyncio.run(rr.relay_hold_query(Req(), CUR[:32])) == {"held": False})

print(f"{CASES['passed']}/{CASES['passed'] + CASES['failed']} passed")
sys.exit(1 if CASES["failed"] else 0)
