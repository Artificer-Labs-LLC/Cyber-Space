"""Unit tests for the resolver's two untested design points (see docs/RESOLVER.md):

  1. Forwarding: anything outside .cyberspace is relayed to the upstream
     resolver untouched; any failure answers SERVFAIL — the daemon forwards
     or admits failure, never invents. The sandbox blocks UDP sends, so the
     real wire path is monkeypatched: a canned-reply socket for passthrough
     and a raising socket for the SERVFAIL case.
  2. TTL: the zone answers with min(seconds-to-expiry, cap); a far-future
     binding gets the cap (300s), a soon-expiring one gets its remaining
     life, floor 0.
  3. NODATA for unhandled qtypes in our zone (MX): NOERROR, zero answers —
     decided before the mirror is ever asked.

Run: cd ~/workspace/cybernet && ./venv/bin/python resolver/test_forward_ttl.py
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


def _query_packet(qname, qtype=1, qid=0x4321):
    labels = b"".join(bytes([len(p)]) + p.encode() for p in qname.split("."))
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    return header + labels + b"\x00" + struct.pack(">HH", qtype, 1)


def _rcode(resp):
    return resp[3] & 0x0F


def _ancount(resp):
    return int.from_bytes(resp[6:8], "big")


# --- 1. forwarding ---------------------------------------------------------

class _CannedSocket:
    """sendto/recvfrom are a fixed round trip; anything else is an error."""

    def __init__(self, reply: bytes):
        self.reply = reply
        self.sent_to = None

    def settimeout(self, _):
        pass

    def sendto(self, data, addr):
        self.sent_to = (bytes(data), addr)

    def recvfrom(self, _n):
        return self.reply, ("upstream", 53)

    def close(self):
        pass


class _DeafSocket:
    """The sandbox's shape: UDP sends die."""

    def settimeout(self, _):
        pass

    def sendto(self, _data, _addr):
        raise PermissionError("sandbox blocks UDP sends")

    def recvfrom(self, _n):
        raise AssertionError("never reached")

    def close(self):
        pass


def _with_socket_factory(factory, fn):
    real = answer.socket.socket
    answer.socket.socket = lambda *a, **k: factory()
    try:
        return fn()
    finally:
        answer.socket.socket = real


def test_forward_passthrough():
    """The query leaves byte-for-byte and the reply returns byte-for-byte."""
    raw = _query_packet("example.com")
    canned = b"\x00" * 12 + b"upstream says hi"
    resp = _with_socket_factory(
        lambda: _CannedSocket(canned),
        lambda: answer.handle_query(
            raw, mirror_url="http://mirror.invalid", upstream=("8.8.8.8", 53)))
    check("forward: reply is the upstream's bytes untouched", resp == canned,
          f"got {resp!r}")


def test_forward_failure_servfail():
    """A dead upstream is a SERVFAIL, never an invented answer."""
    raw = _query_packet("example.com")
    resp = _with_socket_factory(
        lambda: _DeafSocket(),
        lambda: answer.handle_query(
            raw, mirror_url="http://mirror.invalid", upstream=("8.8.8.8", 53)))
    check("forward: dead upstream -> SERVFAIL (rcode 2)", _rcode(resp) == 2,
          f"got {_rcode(resp)}")
    check("forward: SERVFAIL echoes the query id",
          resp[:2] == raw[:2], resp[:2].hex())


# --- 2. TTL ----------------------------------------------------------------

def _iso(dt):
    return dt.isoformat(timespec="seconds")


def test_ttl_cap():
    far = _iso(datetime.now(timezone.utc) + timedelta(days=6))
    check("ttl: far-future binding gets the 300s cap",
          answer._ttl_for(far) == 300, f"got {answer._ttl_for(far)}")


def test_ttl_remaining():
    soon = _iso(datetime.now(timezone.utc) + timedelta(seconds=100))
    ttl = answer._ttl_for(soon)
    check("ttl: soon-expiring binding gets its remaining life",
          95 <= ttl <= 100, f"got {ttl}")


def test_ttl_floor():
    check("ttl: unparseable expiry floors at 0, never negative",
          answer._ttl_for("not-a-date") == 0)
    past = _iso(datetime.now(timezone.utc) - timedelta(hours=1))
    check("ttl: already-dead expiry floors at 0",
          answer._ttl_for(past) == 0)


# --- 3. NODATA for unhandled qtypes -----------------------------------------

def test_mx_nodata():
    """An MX question for our zone answers NOERROR with no answers —
    the mirror is never consulted (watch the wire: no socket touched)."""
    def explode(*a, **k):
        raise AssertionError("mirror must not be asked for qtype MX")

    real_forward = answer._forward
    answer._forward = explode
    try:
        resp = answer.handle_query(
            _query_packet("vill.cyberspace", qtype=15),
            mirror_url="http://mirror.invalid", upstream=("8.8.8.8", 53))
    finally:
        answer._forward = real_forward
    check("mx: rcode 0 (NODATA, not NXDOMAIN)", _rcode(resp) == 0,
          f"got {_rcode(resp)}")
    check("mx: zero answers", _ancount(resp) == 0)


def main():
    print("forward + ttl unit tests (resolver/answer.py):")
    test_forward_passthrough()
    test_forward_failure_servfail()
    test_ttl_cap()
    test_ttl_remaining()
    test_ttl_floor()
    test_mx_nodata()
    print(f"  {CASES['passed']} passed, {CASES['failed']} failed")
    sys.exit(1 if CASES["failed"] else 0)


if __name__ == "__main__":
    main()
