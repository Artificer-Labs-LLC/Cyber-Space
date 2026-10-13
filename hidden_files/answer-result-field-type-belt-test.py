#!/usr/bin/env python3
"""Belt: handle_query refuses a NON-STRING result field instead of
str()-aliasing it (primitives 2 resolution + 6 client daemon).

handle_query (resolver/answer.py) read the resolver result's
node_url/expires_at through str() before handing them to
_family_addresses/_ttl_for — both helpers already isinstance-gate on
their own, and the str() defeated them: a non-string node_url whose
string form is a valid URL was answered as that URL, an address for a
value nobody served in that form, the SAME alias the binding seats
refuse on sight. Fields now pass raw: a non-string node_url has no
addresses (NODATA, ancount 0), a non-string expires_at floors the TTL
at 0 (the answer still serves, with TTL 0), and valid string fields
are byte-exact. The resolver is stubbed at answer.resolve_cyberspace
(the collaborator-word seat the non-dict gate already guards); the
node host is a global IP literal, so no DNS leaves the process.

Covers: string control -> 1 answer, TTL > 0; exotic-str node_url ->
NODATA, no answer (alias); int node_url -> NODATA; exotic-str
expires_at (str() spells a future canonical stamp) -> answer with
TTL 0, not the aliased TTL; missing fields -> NODATA.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/answer-result-field-type-belt-test.py
"""
import os
import struct
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from resolver import answer  # noqa: E402

CASES = {"passed": 0, "failed": 0}


def check(name, cond, extra=""):
    if cond:
        CASES["passed"] += 1
        print(f"  ok  {name}")
    else:
        CASES["failed"] += 1
        print(f"  FAIL {name} {extra}")


def _pkt(qname, qtype=1):
    labels = b"".join(bytes([len(p)]) + p.encode() for p in qname.split("."))
    return (struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
            + labels + b"\x00" + struct.pack(">HH", qtype, 1))


def _ttl(resp):
    # header 12 + question (wire name + 4) -> answer TTL at fixed offset
    qend = 12
    while resp[qend] != 0:
        qend += resp[qend] + 1
    aoff = qend + 5  # root terminator + qtype + qclass; answer starts here
    return int.from_bytes(resp[aoff + 6:aoff + 10], "big")


URL = "http://93.184.216.34/"
FUTURE = (datetime.now(timezone.utc) + timedelta(days=1)).strftime(
    "%Y-%m-%dT%H:%M:%SZ")


class _UrlAlias:
    def __str__(self):
        return URL


class _StampAlias:
    def __str__(self):
        return FUTURE


def _run(result):
    real = answer.resolve_cyberspace
    answer.resolve_cyberspace = lambda _n, _u: result
    try:
        return answer.handle_query(_pkt("vill.cyberspace"),
                                   mirror_url="http://mirror.invalid",
                                   upstream=("8.8.8.8", 53))
    finally:
        answer.resolve_cyberspace = real


# Control: valid string fields answer byte-exact, TTL from the stamp.
resp = _run({"node_url": URL, "expires_at": FUTURE})
check("string control -> rcode 0, 1 answer, TTL > 0",
      (resp[3] & 0x0F) == 0 and int.from_bytes(resp[6:8], "big") == 1
      and resp[-4:] == b"\x5d\xb8\xd8\x22" and _ttl(resp) > 0,
      f"rcode={resp[3] & 0x0F} an={int.from_bytes(resp[6:8], 'big')}")

# The alias: a non-string node_url whose str() is a valid URL.
resp = _run({"node_url": _UrlAlias(), "expires_at": FUTURE})
check("exotic-str node_url -> NODATA, no answer (alias)",
      (resp[3] & 0x0F) == 0 and int.from_bytes(resp[6:8], "big") == 0,
      f"rcode={resp[3] & 0x0F} an={int.from_bytes(resp[6:8], 'big')}")

resp = _run({"node_url": 2130706433, "expires_at": FUTURE})
check("int node_url -> NODATA, no answer",
      (resp[3] & 0x0F) == 0 and int.from_bytes(resp[6:8], "big") == 0,
      f"rcode={resp[3] & 0x0F} an={int.from_bytes(resp[6:8], 'big')}")

# A non-string expires_at floors at TTL 0 — never the aliased stamp.
resp = _run({"node_url": URL, "expires_at": _StampAlias()})
check("exotic-str expires_at -> answer with TTL 0, not aliased TTL",
      (resp[3] & 0x0F) == 0 and int.from_bytes(resp[6:8], "big") == 1
      and _ttl(resp) == 0,
      f"an={int.from_bytes(resp[6:8], 'big')} ttl={_ttl(resp) if int.from_bytes(resp[6:8], 'big') else '-'}")

resp = _run({"node_url": URL, "expires_at": 20261014})
check("int expires_at -> answer with TTL 0",
      int.from_bytes(resp[6:8], "big") == 1 and _ttl(resp) == 0)

# Absent fields keep the "" default: NODATA, untouched.
resp = _run({})
check("absent fields -> NODATA, no answer",
      (resp[3] & 0x0F) == 0 and int.from_bytes(resp[6:8], "big") == 0)

print(f"\n{CASES['passed']} passed, {CASES['failed']} failed")
sys.exit(1 if CASES["failed"] else 0)
