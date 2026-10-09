#!/usr/bin/env python3
"""smoke.py — one-minute smoke test for the cybernet-resolver daemon.

Assumes the daemon is already running (resolver/daemon.py, default
127.0.0.1:5353) and that one of the three wiring units is in place.
Uses only the stdlib: builds one DNS query by hand, reads the rcode.

Checks:
  1. genesis.cyberspace (or --name) resolves -> NOERROR with >=1 A/AAAA
  2. a random never-registered label -> NXDOMAIN (fail-closed check)

Exit 0 if both pass, 1 otherwise. Prints what it saw.

Usage:
  python resolver/wiring/smoke.py [--name genesis.cyberspace]
                                  [--server 127.0.0.1] [--port 5353]
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


def main() -> int:
    ap = argparse.ArgumentParser(description="smoke-test the .cyberspace daemon")
    ap.add_argument("--name", default="genesis.cyberspace",
                    help="registered name to resolve (default: genesis.cyberspace)")
    ap.add_argument("--server", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5353)
    args = ap.parse_args()

    ok = True

    try:
        rcode, an, _ = _query(args.name, _QTYPE_A, args.server, args.port)
    except Exception as exc:  # transport down — say so, fail closed
        print(f"FAIL: {args.server}:{args.port} unreachable ({exc})")
        return 1
    print(f"{args.name}: rcode={rcode} answers={an}")
    if rcode == 0 and an >= 1:
        print("PASS: registered name resolves")
    else:
        print("FAIL: registered name did not resolve")
        ok = False

    junk = "zz-" + "".join(random.choice(string.ascii_lowercase)
                           for _ in range(12)) + ".cyberspace"
    try:
        rcode, an, _ = _query(junk, _QTYPE_A, args.server, args.port)
    except Exception as exc:
        print(f"FAIL: junk query raised ({exc})")
        return 1
    print(f"{junk}: rcode={rcode} answers={an}")
    if rcode == 3 and an == 0:
        print("PASS: junk name -> NXDOMAIN (fail-closed)")
    else:
        print("FAIL: junk name did not NXDOMAIN — daemon is not fail-closed")
        ok = False

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
