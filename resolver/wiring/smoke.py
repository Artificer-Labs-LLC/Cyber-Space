#!/usr/bin/env python3
"""smoke.py — one-minute smoke test for the cybernet-resolver daemon.

Assumes the daemon is already running (resolver/daemon.py, default
127.0.0.1:5353) and that one of the three wiring units is in place.
Uses only the stdlib: builds one DNS query by hand, reads the rcode.

Checks:
  1. genesis.cyberspace (or --name) resolves -> NOERROR with >=1 A
     answer, or (A is NODATA) >=1 AAAA answer — a v6-only node answers
     A with NOERROR/0, so the A leg alone would fail a healthy name
  2. a random never-registered label -> NXDOMAIN (fail-closed check)
  3. (with --tcp) the same two checks over DNS-over-TCP (RFC 7766), the
     daemon's second wire path — same port, same fail-closed zone

Exit 0 if all run checks pass, 1 otherwise. Prints what it saw.

Usage:
  python resolver/wiring/smoke.py [--name genesis.cyberspace]
                                  [--server 127.0.0.1] [--port N]
                                  [--tcp]

--server may be an IPv6 literal, bare ("::1") or bracketed ("[::1]",
the form copied out of a URL) — the same forms the daemon binds and
the resolver client dials; see _server_host/_server_family. A hostname
is dialed at its resolved family on the UDP wire too (a v6-only
hostname reaches a ::1 daemon), via _server_target.
"""

import argparse
import ipaddress
import os
import random
import socket
import struct
import string
import sys

_QTYPE_A = 1
_QTYPE_AAAA = 28
_QCLASS_IN = 1


def _default_port() -> int:
    """Port when --port is not given: CYBERNET_RESOLVER_PORT, else 5353.

    Mirrors daemon._env_int("CYBERNET_RESOLVER_PORT", 5353, floor=1)
    and client._default_port exactly, so all three seats derive the
    same port from the same environment. The literal 5353 default
    disagreed: a daemon bound on the env port was smoked on 5353 and
    read as "unreachable" — a verdict on the daemon — when the smoke
    simply never asked the port the operator configured. An explicit
    --port still wins; the resolved value passes the 1..65535 gate in
    main() like any other port."""


    try:
        return max(1, int(os.environ.get("CYBERNET_RESOLVER_PORT", "").strip()))
    except (ValueError, TypeError):
        return 5353


def _port_warnings() -> list[str]:
    """Loud env-port mistakes, or []. Twin of client._client_port_warnings
    and daemon._daemon_config_warnings: unset/empty means the documented
    default (silent, a choice). Set-but-ineffective cases _default_port
    otherwise hides: not an integer (5353 will be smoked instead of the
    port the operator named — and the result then reads as a verdict on
    the daemon), below 1 (clamped to 1), or above 65535 (honored, so the
    1..65535 gate in main() refuses it). Never prints the value."""
    raw = os.environ.get("CYBERNET_RESOLVER_PORT", "").strip()
    if not raw:
        return []
    try:
        port = int(raw)
    except (ValueError, TypeError):
        return [
            "CYBERNET_RESOLVER_PORT is not an integer — the 5353 "
            "default will be smoked instead"]
    if port < 1:
        return [
            "CYBERNET_RESOLVER_PORT is below the 1 floor — 1 will be "
            "smoked instead"]
    if port > 65535:
        return [
            "CYBERNET_RESOLVER_PORT is above 65535 — no valid port "
            "can be derived from it"]
    return []


def _build_query(name: str, qtype: int) -> tuple[bytes, int]:
    txid = random.getrandbits(16)
    flags = 0x0100  # RD set
    header = struct.pack(">HHHHHH", txid, flags, 1, 0, 0, 0)
    qname = b"".join(
        bytes([len(part)]) + part.encode("ascii") for part in name.split(".")
    ) + b"\x00"
    question = qname + struct.pack(">HH", qtype, _QCLASS_IN)
    return header + question, txid


def _server_host(server: str) -> str:
    """Host to dial for a --server value, brackets stripped.

    Mirrors resolver/client._server_host and daemon._bind_family
    exactly: an operator who bound the daemon with the bracketed form
    copied out of a URL ("[::1]") will naturally pass that same form
    here, but sendto and create_connection both want the bare literal
    — the bracketed form died in transport (gaierror) for a daemon
    that was listening fine. Brackets are stripped when they wrap the
    whole value; anything else is returned unchanged."""
    host = server.strip()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1].strip()
    return host


def _server_family(host: str) -> int:
    """Socket family for a (bare) server host: AF_INET6 for an IPv6
    literal, AF_INET otherwise. The UDP wire hardcoded AF_INET, so a
    daemon bound to ::1 — a bind the daemon itself now accepts — could
    never be smoked at all, however the address was written."""
    try:
        if ipaddress.ip_address(host).version == 6:
            return socket.AF_INET6
    except ValueError:
        pass
    return socket.AF_INET


def _server_target(host: str, port: int):
    """(family, sockaddr) the UDP wire dials for a bare server host.

    A literal keeps _server_family + the literal itself, exactly as
    before. A HOSTNAME is resolved first (getaddrinfo, AF_UNSPEC) and
    the socket is created from the answer's family, dialing the
    resolved sockaddr — the family can no longer be guessed from the
    string's shape. Before, every hostname picked AF_INET and sendto
    carried the unresolved string, so a daemon bound to ::1 and smoked
    by a v6-only hostname (the natural --server a operator types) was
    never reached on its own wire and read as "unreachable", while the
    TCP leg — create_connection resolves the same way — passed. First
    getaddrinfo result wins, as create_connection tries them in order.
    An unresolvable hostname raises gaierror here, which main() already
    reads as unreachable, honestly."""
    try:
        ipaddress.ip_address(host)
        return _server_family(host), (host, port)
    except ValueError:
        pass
    infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC,
                               socket.SOCK_DGRAM)
    family, _kind, _proto, _canon, sockaddr = infos[0]
    return family, sockaddr


def _query(name: str, qtype: int, server: str, port: int,
           timeout: float = 3.0) -> tuple[int, int, int]:
    """Return (rcode, ancount, txid_echoed). Raises on transport failure."""
    packet, txid = _build_query(name, qtype)
    host = _server_host(server)
    family, target = _server_target(host, port)
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(packet, target)
        # Read a whole datagram (65535, the UDP maximum — twin of
        # daemon._serve_udp, client._query_udp and answer._forward):
        # recvfrom discards whatever it is not handed room for, so the
        # classic 512 silently amputated a multi-answer reply
        # mid-record and the header counts below still claimed the
        # answers that were never delivered.
        resp, _ = sock.recvfrom(65535)
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
    with socket.create_connection((_server_host(server), port),
                                  timeout=timeout) as sock:
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
    ap.add_argument("--port", type=int, default=None,
                    help="daemon port (default: CYBERNET_RESOLVER_PORT "
                         "or 5353, as the daemon and client derive it)")
    ap.add_argument("--tcp", action="store_true",
                    help="run the same checks over DNS-over-TCP (RFC 7766)")
    args = ap.parse_args()
    if args.port is None:
        # --port wins over the env derivation, and the env warnings
        # (which describe the port the env WOULD have derived) stay
        # silent when an explicit --port is given: that port is not
        # the one about to be smoked (client.main's exact rule).
        for warn in _port_warnings():
            print(f"smoke: config: {warn}", file=sys.stderr)
        args.port = _default_port()

    # The port is part of the argument shape: a port outside 1..65535
    # can never be dialed (sendto raises OverflowError, create_connection
    # fails likewise), so without this check it read as "unreachable" —
    # a healthy daemon merely down — when it is really a bad argument,
    # exactly as dial.plan and the daemon mirror warning ruled.
    if not 1 <= args.port <= 65535:
        print(f"FAIL: --port {args.port} is not a dialable port "
              f"(must be 1..65535) — bad argument, no query attempted")
        return 1

    # The server is part of the argument shape too: a value that is
    # not an IP literal or a syntactically valid hostname can never
    # be dialed (sendto/create_connection die in name resolution),
    # so without this check it read as "unreachable" — a verdict on
    # the daemon — when the argument itself was at fault, exactly as
    # the --port gate above ruled. Shape only, offline (twin of the
    # daemon's BIND shape check): an IPv4/IPv6 literal (bracketed v6
    # unwrapped by _server_host) or a valid hostname passes; a dotted
    # all-numeric value that is not an IPv4 literal can never resolve
    # as written. A valid-but-unresolvable hostname is beyond what an
    # offline check can prove and still reads as unreachable, honestly.
    host = _server_host(args.server)
    server_ok = bool(host)
    if server_ok:
        try:
            ipaddress.ip_address(host)
        except ValueError:
            labels = host.split(".")
            server_ok = (
                not all(p.isdigit() for p in labels)
                and len(host) <= 253
                and all(
                    1 <= len(p) <= 63
                    and not p.startswith("-") and not p.endswith("-")
                    and all((c.isascii() and c.isalnum()) or c == "-"
                            for c in p)
                    for p in labels)
            )
    if not server_ok:
        print("FAIL: --server is not a dialable address (an IP literal "
              "or a valid hostname) — bad argument, no query attempted")
        return 1

    # The name is part of the argument shape too: a name that is not
    # exactly one valid label under .cyberspace can never be claimed
    # (the resolver client's label grammar), so querying it could only
    # read back NXDOMAIN — "registered name did not resolve", a verdict
    # on the daemon — or die in _build_query's ascii encode and read
    # as "unreachable", when the argument itself was at fault. Gate
    # the normalized name (strip, one FQDN root dot, lowercase — the
    # client's normalization) before any wire use, as a bad argument.
    asked = args.name.strip()
    if asked.endswith("."):
        asked = asked[:-1]
    asked = asked.lower()
    label = asked[: -len(".cyberspace")] if asked.endswith(".cyberspace") else ""
    if (
        not label
        or len(label) > 63
        or "." in label
        or label.startswith("-")
        or label.endswith("-")
        or not all((c.isascii() and c.isalnum()) or c == "-" for c in label)
    ):
        print(f"FAIL: --name {args.name!r} is not a valid .cyberspace name "
              f"(one label of ASCII letters/digits/hyphens under "
              f".cyberspace) — bad argument, no query attempted")
        return 1
    args.name = asked

    query_fn = _query_tcp if args.tcp else _query
    wire = "tcp" if args.tcp else "udp"
    ok = True

    try:
        rcode, an, _ = query_fn(args.name, _QTYPE_A, args.server, args.port)
    except Exception as exc:  # transport down — say so, fail closed
        print(f"FAIL[{wire}]: {args.server}:{args.port} unreachable ({exc})")
        return 1
    print(f"[{wire}] {args.name} A: rcode={rcode} answers={an}")
    resolved = rcode == 0 and an >= 1
    if rcode == 0 and an == 0:
        # NODATA on A: the name may live on a v6-only node — ask AAAA
        # before calling it unresolved (answer.py's family split).
        try:
            rcode6, an6, _ = query_fn(args.name, _QTYPE_AAAA,
                                      args.server, args.port)
        except Exception as exc:
            print(f"FAIL[{wire}]: AAAA query raised ({exc})")
            return 1
        print(f"[{wire}] {args.name} AAAA: rcode={rcode6} answers={an6}")
        resolved = rcode6 == 0 and an6 >= 1
    if resolved:
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
