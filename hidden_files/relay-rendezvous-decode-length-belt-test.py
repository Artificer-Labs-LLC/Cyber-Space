#!/usr/bin/env python3
"""Belt: routes_relay._valid_rendezvous refuses a rendezvous point /
name_pub whose DECODE is not 32 bytes as malformed (primitive 3 hosting).

_valid_rendezvous shape-checked point_id and name_pub on STRING
length only (64 chars + bytes.fromhex parses), but bytes.fromhex
ignores embedded spaces: a spaced 64-char value decoded to 31 bytes,
passed the shape gate, and point_is_current read it as merely "not
in a willing epoch" — a malformed binding misreported as a stale
one, so a hoster that miscomputed its point got told to wait for
an epoch its point could never join instead of being told the
value itself was not 64 hex. Decoded-length gate at the seat (twin
of rendezvous._name_pub_bytes, which already gates the same decode
downstream). Both refusal seats answer the same 400; only the
detail distinguishes malformed from unwilling, and the contract of
this seat (see its docstring: malformed -> told so) is the detail.

Covers: valid current point + valid pub -> tuple (control);
uppercase point/pub -> tuple (control); spaced pub -> 400 malformed
detail; spaced point -> 400 malformed detail; stale clean point ->
400 unwilling detail (existing, unchanged); short/non-hex -> 400
malformed (existing).

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/relay-rendezvous-decode-length-belt-test.py
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import HTTPException  # noqa: E402
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


MALFORMED = "rendezvous_point and name_pub must be 64 hex."
UNWILLING = "rendezvous point is not in a willing epoch."

PUB = "ab" * 32
NOW = time.time()
CUR, _PREV = rendezvous.derive_points(NOW, PUB)
STALE = rendezvous.derive_point_id(PUB, rendezvous.epoch_for(NOW) - 5)
SPACED_PUB = "ab" * 31 + "  "              # 64 chars, 31-byte decode
SPACED_POINT = CUR[:10] + "  " + CUR[12:]   # 64 chars, 31-byte decode
assert len(SPACED_PUB) == 64 and len(bytes.fromhex(SPACED_PUB)) == 31
assert len(SPACED_POINT) == 64 and len(bytes.fromhex(SPACED_POINT)) == 31


def probe(point, pub):
    try:
        return ("ok", rr._valid_rendezvous(point, pub))
    except HTTPException as e:
        return (e.status_code, e.detail)


kind, out = probe(CUR, PUB)
check("valid point+pub -> binding tuple (control)",
      kind == "ok" and out == (CUR, PUB, rendezvous.EPOCH_LEN_DEFAULT),
      f"got {kind} {out!r}")
kind, out = probe(CUR, PUB.upper())
check("uppercase pub -> binding tuple (control; pub derives from bytes)",
      kind == "ok" and out[0] == CUR and out[1] == PUB.upper(),
      f"got {kind} {out!r}")

for label, point, pub in (("spaced pub", CUR, SPACED_PUB),
                          ("spaced point", SPACED_POINT, PUB)):
    kind, detail = probe(point, pub)
    check(f"{label} -> 400 malformed detail (not unwilling)",
          kind == 400 and detail == MALFORMED, f"got {kind} {detail!r}")

kind, detail = probe(STALE, PUB)
check("stale clean point -> 400 unwilling detail (existing)",
      kind == 400 and detail == UNWILLING, f"got {kind} {detail!r}")
for label, point, pub in (("short pub", CUR, "ab" * 16),
                          ("non-hex point", "zz" * 32, PUB)):
    kind, detail = probe(point, pub)
    check(f"{label} -> 400 malformed detail (existing)",
          kind == 400 and detail == MALFORMED, f"got {kind} {detail!r}")

print(f"\n{CASES['passed']} passed, {CASES['failed']} failed")
sys.exit(1 if CASES["failed"] else 0)
