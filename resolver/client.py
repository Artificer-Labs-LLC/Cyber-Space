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

import ipaddress
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
    """One-question standard query, the smallest the daemon will parse.

    Labels are validated before encoding: a label over 63 bytes would
    write a length byte whose top bits the daemon's parser reads as a
    compression pointer, so the query came back as a confusing
    mistransaction instead of a clear local error; a non-ASCII label
    died as codec gibberish. Both now raise ValueError here, at the
    source (main() already maps ValueError to exit 2).

    Empty labels raise too: the old skip-empty loop silently queried a
    DIFFERENT name than the caller wrote — "alice..cyberspace" went on
    the wire as "alice.cyberspace", ".cyberspace" as bare "cyberspace",
    and "" / "." as a root query the daemon does not treat as its zone
    and forwards upstream. One trailing dot (the FQDN root marker) is
    still accepted; any other empty label is a malformed name, refused
    here rather than canonicalized into a neighbour's name.
    """
    if qname.endswith("."):
        qname = qname[:-1]  # a single FQDN root dot; a second leaves an empty label
    qname = qname.lower()
    encoded: list[bytes] = []
    for part in qname.split("."):
        if not part:
            raise ValueError(f"name has an empty label: {qname!r}")
        try:
            raw = part.encode("ascii")
        except UnicodeEncodeError:
            raise ValueError(f"name label is not ASCII: {part!r}") from None
        if len(raw) > 63:
            raise ValueError("name label exceeds the 63-byte DNS limit")
        encoded.append(raw)
    labels = b"".join(bytes([len(r)]) + r for r in encoded) + b"\x00"
    if len(labels) > 255:
        raise ValueError("name exceeds the 255-byte DNS wire limit")
    header = struct.pack(">HHHHHH", txid & 0xFFFF, 0x0100, 1, 0, 0, 0)  # RD
    return header + labels + struct.pack(">HH", qtype, 1)


def _parse_response(
    data: bytes,
    txid: int,
    qname: str | None = None,
    qtype: int | None = None,
) -> tuple[int, list[tuple[int, bytes]]]:
    """Return (flags, [(rtype, rdata), ...]). Mistransaction -> ResolveError.

    Only the records the daemon ever emits are extracted (A/AAAA, class
    IN); anything else in the answer section is refused, never skipped
    (see below).

    A matching txid alone never sufficed: a packet with the QR bit
    clear is a query, not an answer, a packet with the AA bit clear
    is not the daemon's authoritative answer for this zone (every
    reply the daemon builds — answers, NXDOMAIN, SERVFAIL — sets AA;
    an AA-clear packet is some other responder's word), a packet
    with a nonzero opcode is not a reply to a standard query at all
    (the daemon only ever answers opcode 0, and both its response
    builders emit opcode 0), a packet with the RD bit clear is not
    the daemon's reply to THIS query (the client always sends RD,
    and build_response echoes RD on every zone reply it builds), a packet
    with the TC bit set claims its own answer was truncated (neither
    daemon response builder ever sets TC — its replies are whole on
    both wires, so a TC-set packet over TCP was contradicting itself
    yet still trusted until now; over UDP the TC refusal was already
    the retry-on-TCP signal), a packet with the RA bit set claims
    recursion was available (the daemon is authoritative-only for the
    zone and neither response builder ever sets RA — an RA-set packet
    is a recursive resolver's answer, not the daemon's), a packet
    with the Z bit set uses a header bit reserved for future use
    that neither daemon response builder ever sets (its replies are
    QR | AA | RD echo | rcode only — a Z-set packet is not one of
    them), a packet with the AD or CD bit set reports DNSSEC
    checking states the client never asked for (its query sends RD
    only, no AD/CD) and neither daemon response builder ever sets
    (an AD/CD-set packet carries a recursive checker's marks, not
    the daemon's), a packet carrying authority or additional
    section records (neither daemon response builder ever emits
    any — build_response sends header counts 0/0 for those sections
    and error_response sends 0/0/0/0; records the parser would only
    skip, never read, can carry nothing the daemon meant), a packet
    with bytes left over after its counted sections are consumed
    (neither daemon response builder ever emits any — build_response
    ends exactly at its last answer's rdata and error_response is a
    bare 12-byte header; trailing bytes the parser would only ignore
    can carry nothing the daemon meant), an answer whose rdata
    length does not match its type (an A record is exactly 4 bytes
    and an AAAA record exactly 16 in every reply the daemon builds;
    a different length was until now caught only downstream, in
    _textify, and only for the asked family — at parse time it is
    refused for any collected record), an answer record of a type
    or class the daemon never emits (its handler answers only the
    asked A or AAAA family — every other qtype gets an empty NODATA
    reply — and build_response hard-codes class IN on every answer
    it builds; a TXT/CNAME or non-IN record in the section was
    until now skipped silently, so a packet carrying records the
    daemon never sends was still trusted for the records beside
    them), and an echoed
    question naming a DIFFERENT name (or family) than the one asked
    is a mistransaction even with the right txid — its answers belong
    to another question.

    The answer TTL is deliberately NOT bounded, and this is a settled
    question, not an unchecked gap: the daemon emits
    min(seconds-until-the-binding-expires, its TTL cap), the cap is
    daemon-local config (CYBERNET_TTL_CAP: default 300, floored at 0,
    no ceiling — an operator may raise it), and a verified binding's
    remaining life can run to the 365-day admission cap, so no bound
    tighter than the wire's uint32 is provable from the client's
    seat. The TTL also carries no trust here: this client never
    caches — it discards the TTL and returns only the addresses — so
    a large TTL cannot extend anything. Bounding it would only
    refuse replies from a legitimately raised-cap daemon.
    When qname/qtype are given (resolve() always gives both), the
    echoed question must match them exactly (name compared in the
    client's normalized lower-case form).

    The same binding applies to each answer that would be trusted
    (class IN, A/AAAA): its owner name must be the asked name. The
    daemon builds every answer with a pointer back to the question
    name, so a collected record owned by another name never came
    from the daemon's verified answer for this question — trusting
    it would let a correct question carry a stranger's address.
    """
    if len(data) < 12:
        raise ResolveError("short response")
    resp_id, flags, qdcount, ancount, nscount, arcount = struct.unpack(
        ">HHHHHH", data[:12]
    )
    if resp_id != (txid & 0xFFFF):
        raise ResolveError("transaction id mismatch")
    if not flags & 0x8000:
        raise ResolveError("not a response (QR bit clear)")
    if not flags & 0x0400:
        raise ResolveError("not authoritative (AA bit clear)")
    if flags & 0x7800:
        raise ResolveError("not a standard-query response (opcode set)")
    if not flags & 0x0100:
        raise ResolveError("response does not echo RD")
    if flags & 0x0200:
        raise ResolveError("response claims truncation (TC set)")
    if flags & 0x0080:
        raise ResolveError("response claims recursion available (RA set)")
    if flags & 0x0040:
        raise ResolveError("response sets the reserved Z bit")
    if flags & 0x0030:
        raise ResolveError("response sets AD/CD bits the daemon never sets")
    if nscount or arcount:
        raise ResolveError(
            "response carries authority/additional sections the daemon never sends"
        )
    if qname is not None and qdcount != 1:
        raise ResolveError("response does not echo exactly one question")
    # Everything past the header is peer-controlled: a truncated or
    # garbled question/answer section must surface as ResolveError
    # (this module's documented malformed-response contract), never as
    # a leaked ValueError/struct.error from the codec, and an rdata
    # claiming more bytes than the packet holds must never be sliced
    # short and trusted downstream.
    try:
        off = 12
        for _ in range(qdcount):
            seen_name, off = _read_name(data, off)
            if off + 4 > len(data):
                raise ResolveError("truncated question")
            seen_qtype, seen_qclass = struct.unpack_from(">HH", data, off)
            off += 4  # qtype + qclass
            if qname is not None and (
                seen_name.lower() != qname
                or (qtype is not None and seen_qtype != qtype)
                or seen_qclass != 1
            ):
                raise ResolveError("response answers a different question")
        answers: list[tuple[int, bytes]] = []
        for _ in range(ancount):
            owner, off = _read_name(data, off)
            if off + 10 > len(data):
                raise ResolveError("truncated answer")
            rtype, rclass, _ttl, rdlen = struct.unpack_from(">HHIH", data, off)
            off += 10
            if off + rdlen > len(data):
                raise ResolveError("truncated rdata")
            rdata = data[off : off + rdlen]
            off += rdlen
            if rclass != 1 or rtype not in (QTYPE_A, QTYPE_AAAA):
                raise ResolveError(
                    "answer record of a type or class the daemon never sends"
                )
            if rclass == 1 and rtype in (QTYPE_A, QTYPE_AAAA):
                if len(rdata) != (4 if rtype == QTYPE_A else 16):
                    raise ResolveError(
                        "answer rdata length does not match its type"
                    )
                if qname is not None and owner.lower() != qname:
                    raise ResolveError(
                        "response answer owned by a different name"
                    )
                answers.append((rtype, rdata))
        if off != len(data):
            raise ResolveError("response carries trailing bytes")
    except (ValueError, struct.error) as exc:
        raise ResolveError(f"malformed response: {exc}") from exc
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
    qname: str | None = None,
    qtype: int | None = None,
) -> tuple[int, list[tuple[int, bytes]]]:
    """One UDP round trip. Raises ResolveError on failure or truncation.

    The datagram's SOURCE is part of the transaction: UDP has no
    connection, so a reply is only the daemon's if it arrives from the
    exact (address, port) the query was sent to. Anything else — even
    a perfectly formed packet with the right txid, question, and
    owner — came from a stranger who reached the ephemeral port, and
    is refused rather than parsed.
    """
    s = sock
    try:
        if s is None:
            # A v6-literal server (a daemon bound to ::1, say) needs an
            # AF_INET6 socket; gethostbyname below is v4-only, so the
            # expected source for a literal is the literal itself.
            try:
                is_v6 = ipaddress.ip_address(server).version == 6
            except ValueError:
                is_v6 = False
            family = socket.AF_INET6 if is_v6 else socket.AF_INET
            s = socket.socket(family, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(packet, (server, port))
        data, source = s.recvfrom(4096)
        try:
            expected = str(ipaddress.ip_address(server))
        except ValueError:
            expected = socket.gethostbyname(server)
        if (source[0], source[1]) != (expected, port):
            raise ResolveError("udp response from an unexpected source")
    except ResolveError:
        raise
    except OSError as exc:
        raise ResolveError(f"udp transport failed: {exc}") from exc
    finally:
        if sock is None and s is not None:
            s.close()
    # TC is refused inside _parse_response (both wires) — resolve()
    # turns that ResolveError into the retry on the TCP wire.
    return _parse_response(data, txid, qname, qtype)


def _query_tcp(
    txid: int,
    packet: bytes,
    server: str,
    port: int,
    timeout: float,
    sock: socket.socket | None = None,
    qname: str | None = None,
    qtype: int | None = None,
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
    return _parse_response(data, txid, qname, qtype)


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
    failure, mistransaction, any malformed response, or a NOERROR answer
    holding no record of the asked family (NODATA / wrong-family only) —
    an empty list is never a success, or the CLI would print nothing and
    exit 0 for a name that gave it no address to go to. UDP is tried
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
    asked = name[:-1] if name.endswith(".") else name
    asked = asked.lower()
    try:
        if tcp_only:
            flags, answers = _query_tcp(
                txid, packet, server, port, timeout, _tcp_sock, asked, qtype_n
            )
        else:
            try:
                flags, answers = _query_udp(
                    txid, packet, server, port, timeout, _udp_sock, asked, qtype_n
                )
            except ResolveError:
                flags, answers = _query_tcp(
                    txid, packet, server, port, timeout, _tcp_sock, asked, qtype_n
                )
    except ResolveError as exc:
        raise ResolveError(f"could not resolve {name}: {exc}") from exc
    rcode = flags & 0x000F
    if rcode == 3:
        raise NameNotFound(f"{name} does not resolve")
    if rcode != 0:
        raise ResolveError(f"daemon answered rcode {rcode} for {name}")
    matched = [_textify(qtype_n, rdata) for rtype, rdata in answers if rtype == qtype_n]
    if not matched:
        raise ResolveError(f"daemon answered no {qtype.upper()} record for {name}")
    return matched


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
