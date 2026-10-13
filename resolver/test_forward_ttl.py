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

    def __init__(self, reply: bytes, source=("8.8.8.8", 53)):
        self.reply = reply
        self.source = source
        self.sent_to = None

    def settimeout(self, _):
        pass

    def sendto(self, data, addr):
        self.sent_to = (bytes(data), addr)

    def recvfrom(self, _n):
        return self.reply, self.source

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


def test_forward_v6_upstream_uses_inet6():
    """An IPv6-literal upstream is dialed on an AF_INET6 socket (an
    AF_INET sendto to it would raise and SERVFAIL every forward)."""
    raw = _query_packet("example.com")
    canned = b"\x00" * 12 + b"v6 upstream says hi"
    seen = {}

    def factory(family, *a, **k):
        seen["family"] = family
        return _CannedSocket(canned, source=("::1", 5353))

    real = answer.socket.socket
    answer.socket.socket = factory
    try:
        resp = answer.handle_query(
            raw, mirror_url="http://mirror.invalid", upstream=("::1", 5353))
    finally:
        answer.socket.socket = real
    check("forward: v6 upstream -> AF_INET6 socket",
          seen.get("family") == answer.socket.AF_INET6,
          f"got {seen.get('family')}")
    check("forward: v6 reply passthrough", resp == canned, f"got {resp!r}")


def test_forward_hostname_upstream_resolves_family():
    """A v6-only hostname upstream: before, _forward guessed AF_INET
    from the string, sent to the unresolved hostname, so the forward
    was never reached and SERVFAILed. Now dials _upstream_target via
    getaddrinfo AF_UNSPEC: AF_INET6 socket to the resolved sockaddr."""
    raw = _query_packet("example.com")
    canned = b"\x00" * 12 + b"v6-host upstream says hi"
    seen = {}
    sock_inst = _CannedSocket(canned, source=("::1", 53))

    def factory(family, *a, **k):
        seen["family"] = family
        return sock_inst

    def fake_gai(host, port, family=0, type=0, proto=0, flags=0):
        seen["gai"] = (host, port)
        return [(answer.socket.AF_INET6, answer.socket.SOCK_DGRAM, 17, "",
                 ("::1", port, 0, 0))]

    real_sock, real_gai = answer.socket.socket, answer.socket.getaddrinfo
    answer.socket.socket, answer.socket.getaddrinfo = factory, fake_gai
    try:
        resp = answer.handle_query(
            raw, mirror_url="http://mirror.invalid",
            upstream=("v6only.example", 53))
        lit_v4 = answer._upstream_target(("8.8.8.8", 53))
        lit_v6 = answer._upstream_target(("::1", 5353))
    finally:
        answer.socket.socket, answer.socket.getaddrinfo = real_sock, real_gai
    check("forward: v6-only hostname -> AF_INET6 socket",
          seen.get("family") == answer.socket.AF_INET6,
          f"got {seen.get('family')}")
    check("forward: v6-only hostname -> resolved sockaddr target",
          sock_inst.sent_to is not None
          and sock_inst.sent_to[1] == ("::1", 53, 0, 0),
          f"got {sock_inst.sent_to}")
    check("forward: v6-host reply passthrough", resp == canned)
    check("forward: literals keep exact family+target+expected source",
          lit_v4 == (answer.socket.AF_INET, ("8.8.8.8", 53), "8.8.8.8")
          and lit_v6 == (answer.socket.AF_INET6, ("::1", 5353), "::1"),
          f"got {lit_v4} {lit_v6}")


def test_forward_wrong_source_servfail():
    """A reply from an unexpected source is not the upstream's word:
    before, _forward discarded recvfrom's source and relayed any
    packet that reached the ephemeral port byte-for-byte. Wrong IP
    and wrong port both SERVFAIL; the exact source (the passthrough
    test above) is the control."""
    raw = _query_packet("example.com")
    canned = b"\x00" * 12 + b"stranger says hi"
    for label, source in [("wrong IP", ("10.0.0.99", 53)),
                          ("wrong port", ("8.8.8.8", 12345))]:
        resp = _with_socket_factory(
            lambda src=source: _CannedSocket(canned, source=src),
            lambda: answer.handle_query(
                raw, mirror_url="http://mirror.invalid",
                upstream=("8.8.8.8", 53)))
        check(f"forward: {label} -> SERVFAIL (rcode 2), not relayed",
              _rcode(resp) == 2 and resp != canned,
              f"got rcode {_rcode(resp)} resp={resp!r}")


def test_forward_unresolvable_hostname_servfail():
    """An unresolvable hostname upstream raises gaierror in
    _upstream_target, which _forward already reads as SERVFAIL."""
    raw = _query_packet("example.com")

    def fake_gai(*a, **k):
        raise answer.socket.gaierror("no such host")

    real_gai = answer.socket.getaddrinfo
    answer.socket.getaddrinfo = fake_gai
    try:
        resp = _with_socket_factory(
            lambda: _CannedSocket(b"never"),
            lambda: answer.handle_query(
                raw, mirror_url="http://mirror.invalid",
                upstream=("nope.example", 53)))
    finally:
        answer.socket.getaddrinfo = real_gai
    check("forward: unresolvable hostname -> SERVFAIL (rcode 2)",
          _rcode(resp) == 2, f"got {_rcode(resp)}")


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


def test_ttl_noncanonical():
    """Non-canonical spellings floor at 0 even when live and future —
    the TTL belt uses the same strict parser as every claim-time seat."""
    future = datetime.now(timezone.utc) + timedelta(hours=2)
    spellings = [
        future.strftime("%Y-%m-%d"),                       # date-only
        future.isoformat(timespec="microseconds"),        # fractional
        future.strftime("%Y-%m-%d %H:%M:%S+00:00"),        # space sep
        future.astimezone(timezone(timedelta(hours=5))).isoformat(timespec="seconds"),  # +05:00
        future.replace(tzinfo=None).isoformat(timespec="seconds"),  # naive
    ]
    for s in spellings:
        check(f"ttl: non-canonical expiry {s!r} floors at 0",
              answer._ttl_for(s) == 0, f"got {answer._ttl_for(s)}")
    zulu = future.isoformat(timespec="seconds").replace("+00:00", "Z")
    check("ttl: canonical Z expiry still gets the cap",
          answer._ttl_for(zulu) == 300, f"got {answer._ttl_for(zulu)}")


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
    test_forward_v6_upstream_uses_inet6()
    test_forward_hostname_upstream_resolves_family()
    test_forward_wrong_source_servfail()
    test_forward_unresolvable_hostname_servfail()
    test_forward_failure_servfail()
    test_ttl_cap()
    test_ttl_remaining()
    test_ttl_floor()
    test_ttl_noncanonical()
    test_mx_nodata()
    print(f"  {CASES['passed']} passed, {CASES['failed']} failed")
    sys.exit(1 if CASES["failed"] else 0)


if __name__ == "__main__":
    main()
