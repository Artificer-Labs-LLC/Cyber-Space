"""Client-side resolver for .cyberspace — primitive 2 from the agent's seat.

The daemon (resolver/daemon.py) is the local DNS face of the zone. This
module is how an agent talks to it from code, without touching system DNS
configuration: a dependency-free query builder + response parser speaking
the same hand-rolled wire codec as resolver/dns.py. UDP first, with a
DNS-over-TCP (RFC 7766) fallback when UDP is down or silent — mirroring
the daemon's own two wire paths.

Fail-closed semantics mirror the daemon's: NXDOMAIN raises NameNotFound,
and anything malformed, mistransacted, truncated-without-TCP, or SERVFAIL
raises ResolveError. The client adds no trust of its own — it only reads
what the daemon answers, and the daemon only answers what the six-step
verifier proved.

Env (mirrors daemon defaults):
  CYBERNET_RESOLVER_PORT  listen port the client queries (default 5353)
                         — parsed exactly as the daemon parses it
                         (strip, int, floor 1, fallback 5353); the old
                         isdigit() check disagreed with the daemon on
                         " 5354 " (client 5353, daemon 5354), "0"
                         (client 0, daemon 1) and "-5" (client 5353,
                         daemon 1), so the client queried a port no
                         daemon was listening on, in silence. main()
                         warns on set-but-ineffective values (see
                         _client_port_warnings)
"""

import os
import random
import socket
import struct
import sys

from . import dns
from .dns import _read_name

QTYPE_A = 1
QTYPE_AAAA = 28
_QTYPES = {"A": QTYPE_A, "AAAA": QTYPE_AAAA}

DEFAULT_SERVER = "127.0.0.1"
DEFAULT_TIMEOUT = 2.0


def _default_port() -> int:
    """Mirror daemon._env_int("CYBERNET_RESOLVER_PORT", 5353, floor=1)
    exactly, so client and daemon derive the same port from the same
    environment — agreement, not a second parser that drifts."""
    try:
        return max(1, int(os.environ.get("CYBERNET_RESOLVER_PORT", "").strip()))
    except (ValueError, TypeError):
        return 5353


def _client_port_warnings() -> list[str]:
    """Loud port mistakes, or []. Unset/empty means the documented
    default (silent, a choice). Set-but-ineffective cases _default_port
    otherwise hides: not an integer (5353 will be queried instead of
    the port the operator named), below 1 (clamped to 1), or above
    65535 (honored, so every query fails against an invalid port).
    Never prints the value."""
    raw = os.environ.get("CYBERNET_RESOLVER_PORT", "").strip()
    if not raw:
        return []
    try:
        port = int(raw)
    except (ValueError, TypeError):
        return [
            "CYBERNET_RESOLVER_PORT is not an integer — the 5353 "
            "default will be queried instead"]
    if port < 1:
        return [
            "CYBERNET_RESOLVER_PORT is below the 1 floor — 1 will be "
            "queried instead"]
    if port > 65535:
        return [
            "CYBERNET_RESOLVER_PORT is above 65535 — no valid port "
            "can be derived from it, so queries will fail"]
    return []


class NameNotFound(NameError):
    """The daemon answered NXDOMAIN: the name does not resolve."""


class ResolveError(OSError):
    """Transport failure, mistransaction, or a daemon SERVFAIL."""


def _build_query(txid: int, qname: str, qtype: int) -> bytes:
    """One-question standard query, the smallest the daemon will parse."""
    qname = qname.rstrip(".").lower()
    labels = b"".join(
        bytes([len(p)]) + p.encode("ascii") for p in qname.split(".") if p
    ) + b"\x00"
    header = struct.pack(">HHHHHH", txid & 0xFFFF, 0x0100, 1, 0, 0, 0)  # RD
    return header + labels + struct.pack(">HH", qtype, 1)


def _parse_response(data: bytes, txid: int) -> tuple[int, list[tuple[int, bytes]]]:
    """Return (flags, [(rtype, rdata), ...]). Mistransaction -> ResolveError.

    Only the records the daemon ever emits are extracted (A/AAAA, class
    IN); anything else in the section is skipped, never trusted.
    """
    if len(data) < 12:
        raise ResolveError("short response")
    resp_id, flags, qdcount, ancount, _, _ = struct.unpack(">HHHHHH", data[:12])
    if resp_id != (txid & 0xFFFF):
        raise ResolveError("transaction id mismatch")
    off = 12
    for _ in range(qdcount):
        _, off = _read_name(data, off)
        off += 4  # qtype + qclass
    answers: list[tuple[int, bytes]] = []
    for _ in range(ancount):
        _, off = _read_name(data, off)
        rtype, rclass, _ttl, rdlen = struct.unpack_from(">HHIH", data, off)
        off += 10
        rdata = data[off : off + rdlen]
        off += rdlen
        if rclass == 1 and rtype in (QTYPE_A, QTYPE_AAAA):
            answers.append((rtype, rdata))
    return flags, answers


def _read_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly n bytes or raise ResolveError (EOF is a failure)."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ResolveError("truncated TCP response")
        buf += chunk
    return buf


def _query_udp(
    txid: int,
    packet: bytes,
    server: str,
    port: int,
    timeout: float,
    sock: socket.socket | None = None,
) -> tuple[int, list[tuple[int, bytes]]]:
    """One UDP round trip. Raises ResolveError on failure or truncation."""
    s = sock
    try:
        if s is None:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(packet, (server, port))
        data, _ = s.recvfrom(4096)
    except OSError as exc:
        raise ResolveError(f"udp transport failed: {exc}") from exc
    finally:
        if sock is None and s is not None:
            s.close()
    flags, answers = _parse_response(data, txid)
    if flags & 0x0200:  # TC — answer was truncated; retry on the TCP wire
        raise ResolveError("udp response truncated (TC)")
    return flags, answers


def _query_tcp(
    txid: int,
    packet: bytes,
    server: str,
    port: int,
    timeout: float,
    sock: socket.socket | None = None,
) -> tuple[int, list[tuple[int, bytes]]]:
    """One DNS-over-TCP round trip (RFC 7766): length-prefixed frames."""
    s = sock
    try:
        if s is None:
            s = socket.create_connection((server, port), timeout)
        s.settimeout(timeout)
        s.sendall(struct.pack(">H", len(packet)) + packet)
        (body_len,) = struct.unpack(">H", _read_exact(s, 2))
        data = _read_exact(s, body_len)
    except OSError as exc:
        raise ResolveError(f"tcp transport failed: {exc}") from exc
    finally:
        if sock is None and s is not None:
            s.close()
    return _parse_response(data, txid)


def _textify(qtype: int, rdata: bytes) -> str:
    """rdata bytes -> printable IP, strictly per the asked family."""
    if qtype == QTYPE_A and len(rdata) == 4:
        return socket.inet_ntoa(rdata)
    if qtype == QTYPE_AAAA and len(rdata) == 16:
        return socket.inet_ntop(socket.AF_INET6, rdata)
    raise ResolveError("answer rdata does not match the asked family")


def resolve(
    name: str,
    qtype: str = "A",
    server: str = DEFAULT_SERVER,
    port: int | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    tcp_only: bool = False,
    _udp_sock: socket.socket | None = None,
    _tcp_sock: socket.socket | None = None,
) -> list[str]:
    """Resolve a .cyberspace name through the local daemon face.

    Returns the answer addresses as text, fail-closed: NameNotFound on
    NXDOMAIN (the name is not bound), ResolveError on SERVFAIL, transport
    failure, mistransaction, or any malformed response. UDP is tried
    first; any UDP failure falls back to the TCP wire (unless tcp_only).
    ``_udp_sock`` / ``_tcp_sock`` are test hooks, not public API.
    """
    qtype_n = _QTYPES.get(qtype.upper())
    if qtype_n is None:
        raise ValueError(f"unsupported qtype {qtype!r}")
    if port is None:
        port = _default_port()
    txid = random.getrandbits(16)
    packet = _build_query(txid, name, qtype_n)
    try:
        if tcp_only:
            flags, answers = _query_tcp(txid, packet, server, port, timeout, _tcp_sock)
        else:
            try:
                flags, answers = _query_udp(
                    txid, packet, server, port, timeout, _udp_sock
                )
            except ResolveError:
                flags, answers = _query_tcp(
                    txid, packet, server, port, timeout, _tcp_sock
                )
    except ResolveError as exc:
        raise ResolveError(f"could not resolve {name}: {exc}") from exc
    rcode = flags & 0x000F
    if rcode == 3:
        raise NameNotFound(f"{name} does not resolve")
    if rcode != 0:
        raise ResolveError(f"daemon answered rcode {rcode} for {name}")
    return [_textify(qtype_n, rdata) for rtype, rdata in answers if rtype == qtype_n]


def main(argv: list[str] | None = None) -> int:
    """CLI front door for the resolver client.

    ``python -m resolver.client alice.cyberspace [--qtype AAAA] [--tcp-only]``

    Prints one address per line on success. Exit codes: 0 resolved,
    1 name does not resolve (NXDOMAIN), 2 everything else (usage,
    transport, daemon SERVFAIL, malformed answer) — so a shell script
    can tell "no such name" apart from "resolution broke".
    """
    import argparse

    parser = argparse.ArgumentParser(
        prog="resolver.client",
        description="Resolve a .cyberspace name through the local daemon face.",
    )
    parser.add_argument("name", help="name to resolve, e.g. alice.cyberspace")
    parser.add_argument(
        "--qtype", default="A", choices=sorted(_QTYPES), help="record family (default A)"
    )
    parser.add_argument(
        "--server", default=DEFAULT_SERVER, help="daemon host (default 127.0.0.1)"
    )
    parser.add_argument(
        "--tcp-only", action="store_true", help="skip UDP, speak DNS-over-TCP only"
    )
    args = parser.parse_args(argv)

    for warn in _client_port_warnings():
        print(f"resolver-client: config: {warn}", file=sys.stderr)
    port = _default_port()
    try:
        answers = resolve(
            args.name, qtype=args.qtype, server=args.server, port=port,
            tcp_only=args.tcp_only,
        )
    except NameNotFound as exc:
        print(f"error: {exc}", flush=True)
        return 1
    except (ResolveError, ValueError) as exc:
        print(f"error: {exc}", flush=True)
        return 2
    for addr in answers:
        print(addr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
