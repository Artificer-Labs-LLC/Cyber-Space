"""Unit tests for the resolver's TCP connection path (RFC 7766).

Drives the REAL _serve_tcp_conn() over real socketpair() sockets — actual
length-prefixed frames on a real (loopback-local) transport, a monkeypatched
handle_query for the transport layer's own contract. sandbox blocks UDP,
not TCP, so this is the wire the daemon can prove in-sandbox; the full
end-to-end (real handler, real claim) lives in
hidden_files/resolver-tcp-wire-loopback-test.py.

Coverage:
  1. two sequential queries on one connection -> both answered, txids echoed
  2. handle_query raising -> SERVFAIL on that frame, connection stays open
  3. garbage bytes -> SERVFAIL with the txid echoed, never silence
  4. zero-length frame skipped, next query still answered
  5. client dies mid-packet -> connection ends, function returns, never raises
  6. clean EOF with no queries -> returns 0, never raises

Run: cd ~/workspace/cybernet && ./venv/bin/python resolver/test_daemon_tcp.py
"""

import os
import socket
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from resolver import daemon  # noqa: E402

CASES = {"passed": 0, "failed": 0}


def check(name, cond, extra=""):
    if cond:
        CASES["passed"] += 1
        print(f"  ok  {name}")
    else:
        CASES["failed"] += 1
        print(f"  FAIL {name} {extra}")


def _query_packet(qid=0x6001):
    hdr = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    qname = b"\x04test\x09cyberspace\x00"
    return hdr + qname + struct.pack(">HH", 1, 1)


def _frame(payload):
    return struct.pack(">H", len(payload)) + payload


def _read_reply(client):
    head = b""
    while len(head) < 2:
        chunk = client.recv(2 - len(head))
        if not chunk:
            raise AssertionError("EOF waiting for reply length")
        head += chunk
    (n,) = struct.unpack(">H", head)
    body = b""
    while len(body) < n:
        chunk = client.recv(n - len(body))
        if not chunk:
            raise AssertionError("EOF waiting for reply body")
        body += chunk
    return body


def _rcode_qid(reply):
    qid = struct.unpack(">H", reply[:2])[0]
    flags = struct.unpack(">H", reply[2:4])[0]
    return qid, (flags >> 15) & 1, flags & 0xF


def _echo_handler(raw, **kw):
    # transport-layer stand-in: a real query shape echoes as NOERROR,
    # anything else SERVFAILs — the real six-step runs in the wire harness.
    if len(raw) >= 12 and struct.unpack(">H", raw[4:6])[0] == 1:
        return raw[:2] + b"\x81\x80" + raw[4:]
    return daemon.error_response(raw, 2)


def _raising_handler(raw, **kw):
    raise RuntimeError("handler exploded")


def _pair():
    a, b = socket.socketpair()
    return a, b


def main():
    real_handle = daemon.handle_query

    # Phase 1: sequential queries on one connection.
    daemon.handle_query = _echo_handler
    client, server = _pair()
    try:
        sent = []
        for qid in (0x6001, 0x6002):
            pkt = _query_packet(qid)
            client.sendall(_frame(pkt))
        client.shutdown(socket.SHUT_WR)  # EOF after the frames
        served = daemon._serve_tcp_conn(server, "m", ("1.1.1.1", 53), 300)
        r1 = _read_reply(client)
        r2 = _read_reply(client)
    finally:
        client.close()
        server.close()
    qid1, qr1, rc1 = _rcode_qid(r1)
    qid2, qr2, rc2 = _rcode_qid(r2)
    check("two frames on one connection -> served == 2", served == 2,
          f"served={served}")
    check("first reply NOERROR with txid echoed",
          qid1 == 0x6001 and qr1 == 1 and rc1 == 0, f"qid={qid1:#x} rc={rc1}")
    check("second reply NOERROR with txid echoed",
          qid2 == 0x6002 and qr2 == 1 and rc2 == 0, f"qid={qid2:#x} rc={rc2}")

    # Phase 2: handler raising mid-connection -> SERVFAIL, connection survives.
    daemon.handle_query = _raising_handler
    client, server = _pair()
    try:
        client.sendall(_frame(_query_packet(0x6003)))
        client.shutdown(socket.SHUT_WR)
        served = daemon._serve_tcp_conn(server, "m", ("1.1.1.1", 53), 300)
        r = _read_reply(client)
    finally:
        client.close()
        server.close()
    qid, qr, rc = _rcode_qid(r)
    check("raising handler -> SERVFAIL, never silence",
          qid == 0x6003 and qr == 1 and rc == 2, f"qid={qid:#x} rc={rc}")
    check("SERVFAIL still counts as served", served == 1, f"served={served}")

    # Phase 3: garbage bytes -> SERVFAIL with txid echo.
    daemon.handle_query = _echo_handler
    client, server = _pair()
    try:
        client.sendall(_frame(b"\x12\x34junk-bytes-not-dns"))
        client.shutdown(socket.SHUT_WR)
        served = daemon._serve_tcp_conn(server, "m", ("1.1.1.1", 53), 300)
        r = _read_reply(client)
    finally:
        client.close()
        server.close()
    qid, qr, rc = _rcode_qid(r)
    check("garbage frame -> SERVFAIL with txid echo",
          qid == 0x1234 and qr == 1 and rc == 2, f"qid={qid:#x} rc={rc}")

    # Phase 4: zero-length frame skipped, next query answered.
    client, server = _pair()
    try:
        client.sendall(struct.pack(">H", 0) + _frame(_query_packet(0x6004)))
        client.shutdown(socket.SHUT_WR)
        served = daemon._serve_tcp_conn(server, "m", ("1.1.1.1", 53), 300)
        r = _read_reply(client)
    finally:
        client.close()
        server.close()
    qid, qr, rc = _rcode_qid(r)
    check("zero-length frame skipped, query answered",
          served == 1 and qid == 0x6004 and rc == 0,
          f"served={served} qid={qid:#x} rc={rc}")

    # Phase 5: client dies mid-packet -> ends cleanly, never raises.
    client, server = _pair()
    try:
        client.sendall(struct.pack(">H", 100) + b"short")
        client.close()  # EOF mid-frame
        served = daemon._serve_tcp_conn(server, "m", ("1.1.1.1", 53), 300)
    finally:
        server.close()
    check("mid-packet EOF -> returns, never raises", served == 0,
          f"served={served}")

    # Phase 6: clean EOF, no queries -> returns 0.
    client, server = _pair()
    try:
        client.close()
        served = daemon._serve_tcp_conn(server, "m", ("1.1.1.1", 53), 300)
    finally:
        server.close()
    check("clean EOF with no frames -> 0 served", served == 0,
          f"served={served}")

    # Phase 7: _read_exact refuses a malformed length instead of raising
    # or aliasing it — its contract is None on a read that cannot happen.
    class _StubConn:
        def __init__(self):
            self.calls = 0

        def recv(self, n):
            self.calls += 1
            return b"x" * n

    for bad in ("2", None, 2.5, True, -1, [2]):
        stub = _StubConn()
        try:
            got = daemon._read_exact(stub, bad)
            raised = False
        except Exception:
            got, raised = "raised", True
        check(f"_read_exact({bad!r}) -> None, never raises, never reads",
              got is None and not raised and stub.calls == 0,
              f"got={got!r} raised={raised} calls={stub.calls}")
    stub = _StubConn()
    check("_read_exact valid length still reads exactly",
          daemon._read_exact(stub, 3) == b"xxx", f"calls={stub.calls}")
    check("_read_exact zero length still returns b''",
          daemon._read_exact(_StubConn(), 0) == b"")

    daemon.handle_query = real_handle
    print(f"\n{CASES['passed']} passed, {CASES['failed']} failed")
    return 1 if CASES["failed"] else 0


if __name__ == "__main__":
    sys.exit(main())
