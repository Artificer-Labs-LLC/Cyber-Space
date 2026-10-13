#!/usr/bin/env python3
"""Belt test for resolver.answer._forward's reply buffer.

_forward promises the upstream reply byte-for-byte, but read it with
recvfrom(512): a forwarded query is relayed untouched, so a query
carrying EDNS legitimately draws a reply far past the classic 512,
and the 512 read silently amputated it mid-record — the header
counts still claimed bytes that were never delivered. The read is
now a whole datagram (65535, the UDP maximum — twin of
daemon._serve_udp's read buffer).

The fake socket honors REAL UDP semantics — recvfrom(n) returns at
most n bytes and discards the rest of the datagram — which the
canned socket in resolver/test_forward_ttl.py does not model (it
returns its reply whole whatever n it is handed), so that suite
could never see the truncation.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/forward-reply-size-belt-test.py
"""
import os
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from resolver import answer  # noqa: E402

PASSED = FAILED = 0


def check(name, cond, extra=""):
    global PASSED, FAILED
    if cond:
        PASSED += 1
        print(f"  ok: {name}")
    else:
        FAILED += 1
        print(f"  FAIL: {name} {extra}")


class RealSemanticsSocket:
    """A UDP round trip as the kernel performs it: recvfrom(n)
    returns at most n bytes of the datagram and discards the rest."""

    def __init__(self, reply):
        self.reply = reply
        self.asked = None

    def settimeout(self, _):
        pass

    def sendto(self, data, addr):
        self.sent = (bytes(data), addr)

    def recvfrom(self, n):
        self.asked = n
        return self.reply[:n], ("1.1.1.1", 53)

    def close(self):
        pass


def _with_reply(reply, fn):
    sock = RealSemanticsSocket(reply)
    real = answer.socket.socket
    answer.socket.socket = lambda *a, **k: sock
    try:
        return fn(), sock
    finally:
        answer.socket.socket = real


QUERY = struct.pack(">HHHHHH", 0x4321, 0x0100, 1, 0, 0, 0) + b"\x07example\x03com\x00" + struct.pack(">HH", 1, 1)

# 1. A reply past 512 (an EDNS-sized answer) passes through whole.
big = struct.pack(">HHHHHH", 0x4321, 0x8180, 1, 1, 0, 0) + bytes(888)
out, sock = _with_reply(big, lambda: answer._forward(QUERY, ("1.1.1.1", 53)))
check("900-byte upstream reply returns byte-for-byte", out == big,
      f"len={len(out)}")
check("read buffer is the datagram maximum", sock.asked == 65535,
      f"asked={sock.asked}")
check("query forwarded untouched", sock.sent[0] == QUERY)

# 2. A classic small reply is unchanged.
small = struct.pack(">HHHHHH", 0x4321, 0x8180, 1, 1, 0, 0) + bytes(40)
out, _ = _with_reply(small, lambda: answer._forward(QUERY, ("1.1.1.1", 53)))
check("small upstream reply returns byte-for-byte", out == small,
      f"len={len(out)}")

# 3. A near-maximum datagram (65507 payload bytes on the wire) survives.
huge = struct.pack(">HHHHHH", 0x4321, 0x8180, 1, 1, 0, 0) + bytes(60000)
out, _ = _with_reply(huge, lambda: answer._forward(QUERY, ("1.1.1.1", 53)))
check("60012-byte upstream reply returns byte-for-byte", out == huge,
      f"len={len(out)}")

print(f"\n{PASSED} passed, {FAILED} failed")
sys.exit(1 if FAILED else 0)
