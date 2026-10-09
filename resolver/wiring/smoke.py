#!/usr/bin/env python3
"""smoke.py — one-minute smoke test for the cybernet-resolver daemon.

Assumes the daemon is already running (resolver/daemon.py, default
127.0.0.1:5353) and that one of the three wiring units is in place.
Uses only the stdlib: builds one DNS query by hand, reads the rcode.

Checks:
  1. genesis.cyberspace (or --name) resolves -> NOERROR with >=1 A/AAAA
  2. a random never-registered label -> NXDOMAIN (fail-closed check)
  3. (with --tcp) the same two checks over DNS-over-TCP (RFC 7766), the
     daemon's second wire path — same port, same fail-closed zone

Exit 0 if all run checks pass, 1 otherwise. Prints what it saw.

Usage:
  python resolver/wiring/smoke.py [--name genesis.cyberspace]
                                  [--server 127.0.0.1] [--port 5353]
                                  [--tcp]
"""

import argparse
import random
import socket
import struct
import string
import sys

_QTYPE_A = 1
_QTYPE_AAAA = 28
_QCLASS_IN = 1


def _build_query(name: str, qtype: int) -> tuple[bytes, int]:
    txid = random.getrandbits(16)
    flags = 0x0100  # RD set
    header = struct.pack(">HHHHHH", txid, flags, 1, 0, 0, 0)
    qname = b"".join(
        bytes([len(part)]) + part.encode("ascii") for part in name.split(".")
    ) + b"\x00"
    question = qname + struct.pack(">HH", qtype, _QCLASS_IN)
    return header + question, txid


def _query(name: str, qtype: int, server: str, port: int,
           timeout: float = 3.0) -> tuple[int, int, int]:
    """Return (rcode, ancount, txid_echoed). Raises on transport failure."""
    packet, txid = _build_query(name, qtype)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(packet, (server, port))
        resp, _ = sock.recvfrom(512)
    if len(resp) < 12:
        raise ValueError("truncated DNS response")
    (rtxid, flags, qd, an, ns, ar) = struct.unpack(">HHHHHH", resp[:12])
    if rtxid != txid:
        raise ValueError("txid mismatch — response is not ours")
    return flags & 0x000F, an, rtxid


def _read_exact(sock, n: int, timeout: float) -> bytes:
    """Read exactly n bytes from a blocking socket with a deadline."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError("peer closed before the answer arrived")
        buf += chunk
    return buf


def _query_tcp(name: str, qtype: int, server: str, port: int,
               timeout: float = 3.0) -> tuple[int, int, int]:
    """Same contract as _query, over DNS-over-TCP (RFC 7766).

    Two-byte big-endian length prefix, one query per connection, the
    connection closes after the answer. Return (rcode, ancount,
    txid_echoed). Raises on transport failure.
    """
    packet, txid = _build_query(name, qtype)
    frame = struct.pack(">H", len(packet)) + packet
    with socket.create_connection((server, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(frame)
        (rlen,) = struct.unpack(">H", _read_exact(sock, 2, timeout))
        resp = _read_exact(sock, rlen, timeout)
    if len(resp) < 12:
        raise ValueError("truncated DNS response")
    (rtxid, flags, qd, an, ns, ar) = struct.unpack(">HHHHHH", resp[:12])
    if rtxid != txid:
        raise ValueError("txid mismatch — response is not ours")
    return flags & 0x000F, an, rtxid


def main() -> int:
    ap = argparse.ArgumentParser(description="smoke-test the .cyberspace daemon")
    ap.add_argument("--name", default="genesis.cyberspace",
                    help="registered name to resolve (default: genesis.cyberspace)")
    ap.add_argument("--server", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5353)
    ap.add_argument("--tcp", action="store_true",
                    help="run the same checks over DNS-over-TCP (RFC 7766)")
    args = ap.parse_args()

    query_fn = _query_tcp if args.tcp else _query
    wire = "tcp" if args.tcp else "udp"
    ok = True

    try:
        rcode, an, _ = query_fn(args.name, _QTYPE_A, args.server, args.port)
    except Exception as exc:  # transport down — say so, fail closed
        print(f"FAIL[{wire}]: {args.server}:{args.port} unreachable ({exc})")
        return 1
    print(f"[{wire}] {args.name}: rcode={rcode} answers={an}")
    if rcode == 0 and an >= 1:
        print(f"PASS[{wire}]: registered name resolves")
    else:
        print(f"FAIL[{wire}]: registered name did not resolve")
        ok = False

    junk = "zz-" + "".join(random.choice(string.ascii_lowercase)
                           for _ in range(12)) + ".cyberspace"
    try:
        rcode, an, _ = query_fn(junk, _QTYPE_A, args.server, args.port)
    except Exception as exc:
        print(f"FAIL[{wire}]: junk query raised ({exc})")
        return 1
    print(f"[{wire}] {junk}: rcode={rcode} answers={an}")
    if rcode == 3 and an == 0:
        print(f"PASS[{wire}]: junk name -> NXDOMAIN (fail-closed)")
    else:
        print(f"FAIL[{wire}]: junk name did not NXDOMAIN — daemon is not fail-closed")
        ok = False

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
