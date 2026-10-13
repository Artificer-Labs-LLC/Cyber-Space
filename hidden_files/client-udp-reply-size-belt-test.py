#!/usr/bin/env python3
"""Belt test for resolver.client._query_udp's reply buffer.

The daemon's replies are whole on the UDP wire (neither response
builder ever sets TC), and since the forward fix its forwarded
upstream replies can run to a whole datagram — but the client read
its UDP answer with recvfrom(4096), so a well-formed reply past
4096 was silently amputated mid-record and then misread by
_parse_response as a malformed packet: a perfect answer became a
spurious TCP retry, or an outright failure where TCP is blocked.
The read is now a whole datagram (65535, the UDP maximum — twin of
daemon._serve_udp's and answer._forward's buffers).

The fake socket honors REAL UDP semantics — recvfrom(n) returns at
most n bytes and discards the rest of the datagram.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/client-udp-reply-size-belt-test.py
"""
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from resolver import client  # noqa: E402

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
    """recvfrom(n) returns at most n bytes, discarding the rest."""

    def __init__(self, reply, source=("127.0.0.1", 5353)):
        self.reply = reply
        self.source = source
        self.asked = None

    def settimeout(self, _):
        pass

    def sendto(self, data, addr):
        self.sent = (bytes(data), addr)

    def recvfrom(self, n):
        self.asked = n
        return self.reply[:n], self.source

    def close(self):
        pass


QNAME = "host.cyberspace"
TXID = 0x4321
QUESTION = b"\x04host\x0acyberspace\x00" + struct.pack(">HH", 1, 1)
PACKET = struct.pack(">HHHHHH", TXID, 0x0100, 1, 0, 0, 0) + QUESTION


def _response(n_answers):
    flags = 0x8000 | 0x0400 | 0x0100  # QR | AA | RD echo, rcode 0
    out = struct.pack(">HHHHHH", TXID, flags, 1, n_answers, 0, 0) + QUESTION
    for i in range(n_answers):
        rdata = bytes([10, 0, (i >> 8) & 0xFF, i & 0xFF])
        out += struct.pack(">HHHIH", 0xC00C, 1, 1, 60, 4) + rdata
    return out


def _query(reply):
    sock = RealSemanticsSocket(reply)
    try:
        result = client._query_udp(
            TXID, PACKET, "127.0.0.1", 5353, 1.0,
            sock=sock, qname=QNAME, qtype=1,
        )
        return result, sock, None
    except Exception as exc:  # noqa: BLE001 - belt records the shape
        return None, sock, exc


# 1. A well-formed reply past 4096 bytes parses whole.
big = _response(300)
check("crafted big reply is past the old buffer", len(big) > 4096,
      f"len={len(big)}")
result, sock, err = _query(big)
check("300-answer reply (>4096B) parses over UDP", result is not None,
      f"err={err}")
if result is not None:
    flags, answers = result
    check("all 300 answers returned", len(answers) == 300,
          f"n={len(answers)}")
check("read buffer is the datagram maximum", sock.asked == 65535,
      f"asked={sock.asked}")

# 2. A classic small reply is unchanged.
small = _response(1)
result, _, err = _query(small)
check("single-answer reply still parses",
      result is not None and len(result[1]) == 1, f"err={err}")

# 3. A near-maximum datagram survives.
huge = _response(4000)
check("crafted huge reply is near the datagram maximum", len(huge) > 60000,
      f"len={len(huge)}")
result, _, err = _query(huge)
check("4000-answer reply (>60000B) parses over UDP",
      result is not None and len(result[1]) == 4000, f"err={err}")

print(f"\n{PASSED} passed, {FAILED} failed")
sys.exit(1 if FAILED else 0)
