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
                         _client_port_warnings). main() also accepts
                         --port as an explicit override, gated to
                         1..65535 exactly as wiring/smoke gates its own
                         --port; without it an operator whose daemon
                         listens on a non-default port could not point
                         the CLI at it at all.
"""

import ipaddress
import math
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


def _server_host(server: str) -> str:
    """Host to dial for a --server value, brackets stripped.

    Mirrors daemon._bind_family exactly: an operator who bound the
    daemon with the bracketed form copied out of a URL ("[::1]") will
    naturally pass that same form here, but ip_address, gethostbyname,
    sendto, and create_connection all want the bare literal — the
    bracketed form picked AF_INET, then died in transport, for a
    daemon that was listening fine. Brackets are stripped when they
    wrap the whole value; anything else is returned unchanged."""
    # The server is caller-supplied at the library seats that call
    # this directly (_query_udp/_query_tcp — resolve() gates its own
    # argument, but a direct wire caller could pass anything): a
    # non-string escaped as AttributeError from .strip() (None, an
    # int, True) or TypeError from .startswith() (bytes) — neither
    # the ValueError resolve() raises for a bad server nor the
    # ResolveError the wires promise. Only a real string is a server
    # to unwrap; anything else raises ValueError here, at the source,
    # and both wires read it as a transport failure (ResolveError).
    if not isinstance(server, str):
        raise ValueError(f"bad server {server!r}")
    host = server.strip()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1].strip()
    return host


def _server_target(host: str, port: int):
    """(family, sockaddr, expected source IP) the UDP wire dials.

    A literal keeps its own family and (host, port) target, exactly as
    before. A HOSTNAME is resolved first (getaddrinfo, AF_UNSPEC) and
    the socket is created from the answer's family, dialing the
    resolved sockaddr, with that address as the expected reply source
    — the family can no longer be guessed from the string's shape.
    Before, every hostname picked AF_INET, sendto carried the
    unresolved string, and the source check used gethostbyname
    (v4-only), so a daemon bound to ::1 and reached by a v6-only
    hostname was never reached on the UDP wire and its reply could
    never pass the source check; only the TCP fallback (whose
    create_connection resolves the same way) masked it. First
    getaddrinfo result wins, as create_connection tries them in
    order. An unresolvable hostname raises gaierror here, which
    _query_udp already reads as a transport failure."""
    # The host is caller-supplied at this library seat too: ip_address()
    # ALIASED a non-string host (123 -> 0.0.0.123, True -> 0.0.0.1, a
    # 4-byte bytes host -> its dotted quad) and getaddrinfo ALIASED
    # None to localhost — a daemon nobody named was dialed and its
    # reply source-checked as expected. Only a real string is a host
    # to dial (twin of answer._upstream_target's host gate); anything
    # else raises ValueError here, which _query_udp reads as a
    # transport failure (ResolveError) like gaierror.
    if not isinstance(host, str):
        raise ValueError(f"bad server host {host!r}")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC,
                                   socket.SOCK_DGRAM)
        family, _kind, _proto, _canon, sockaddr = infos[0]
        return family, sockaddr, str(ipaddress.ip_address(sockaddr[0]))
    family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
    return family, (host, port), str(ip)


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

    The two header fields are caller-supplied too (resolve() passes a
    random 16-bit txid and a dict-validated qtype, but a direct caller
    could pass anything): the txid was masked with & 0xFFFF, so 65536
    silently ALIASED to txid 0 and -1 to 65535 — a query built under a
    different transaction id than the caller chose, whose reply this
    client would then refuse as a mistransaction — and a bool qtype
    built as A (bool is an int subclass), while an out-of-range or
    non-int qtype/txid escaped as struct.error/TypeError instead of
    the ValueError this function's callers guard. Both fields must be
    real ints (never bool) in the uint16 wire range; anything else
    raises ValueError here, at the source — the same fail-closed gate
    dns.build_response applies to its caller-supplied fields.
    """
    for _field, _value in (("txid", txid), ("qtype", qtype)):
        if not isinstance(_value, int) or isinstance(_value, bool) \
                or not 0 <= _value <= 65535:
            raise ValueError(f"bad {_field} {_value!r}")
    # The qname is caller-supplied too: resolve() gates its type, but a
    # direct caller passing a non-string (None, an int, bytes) escaped
    # as AttributeError/TypeError from .endswith() below — not the
    # ValueError this function's other malformed inputs raise and its
    # callers guard. Only a real string is a name to build.
    if not isinstance(qname, str):
        raise ValueError(f"bad qname {qname!r}")
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
    # The packet itself is caller-supplied too: a str/None/int/float/
    # list packet escaped as a raw TypeError from len()/struct.unpack
    # before this function's ResolveError contract ever ran — the twin
    # of the dns.parse_query non-bytes gate. Only a real bytes/bytearray
    # packet can be a response; anything else is a mistransaction.
    if not isinstance(data, (bytes, bytearray)):
        raise ResolveError(f"bad response packet {type(data).__name__}")
    # The expected txid is caller-supplied too (resolve() passes the
    # random 16-bit id _build_query already gated, but a direct caller
    # could pass anything): it was compared as txid & 0xFFFF, so 65536
    # and -65536 silently ALIASED to txid 0 — a packet was trusted as
    # the answer to a transaction it never belonged to — True aliased
    # to 1, and a float/str/None txid escaped as a raw TypeError from
    # the & before this function's ResolveError contract ever ran.
    # The expected id must be a real int (never bool) in the uint16
    # wire range; anything else is a mistransaction, refused here —
    # the same fail-closed gate _build_query applies at build time.
    if isinstance(txid, bool) or not isinstance(txid, int) \
            or not 0 <= txid <= 65535:
        raise ResolveError(f"bad expected transaction id {txid!r}")
    # The expected qtype is caller-supplied too, and it was compared
    # with plain !=: True and 1.0 compare equal to 1 in Python, so
    # both silently ALIASED to A — a packet was trusted as answering
    # the family the caller asked for when the caller never named a
    # real family at all (bool is an int subclass; float equality
    # crosses types). An expected qtype that is given must be a real
    # int (never bool) in the uint16 wire range, else ResolveError —
    # the same fail-closed gate _build_query applies at build time.
    # None stays valid: it means no family was asked to be checked.
    if qtype is not None and (isinstance(qtype, bool)
                              or not isinstance(qtype, int)
                              or not 0 <= qtype <= 65535):
        raise ResolveError(f"bad expected qtype {qtype!r}")
    if len(data) < 12:
        raise ResolveError("short response")
    resp_id, flags, qdcount, ancount, nscount, arcount = struct.unpack(
        ">HHHHHH", data[:12]
    )
    if resp_id != txid:
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


def _check_timeout(timeout: float) -> float:
    """Gate a caller-supplied timeout before any socket sees it.

    The timeout reaches settimeout/create_connection raw: a negative
    value escaped as a raw ValueError and a string as a raw TypeError
    (neither is the ResolveError transport contract), None meant
    BLOCK FOREVER — a silent daemon would hang the client without
    limit, the opposite of fail-closed — True aliased to 1 second
    (bool is an int subclass), and inf/NaN were blocking in disguise
    or undefined. A timeout must be a real int/float (never bool),
    finite, and positive; anything else is a transport failure,
    refused here on both wires — the same fail-closed shape
    _build_query/_parse_response apply to caller-supplied txid/qtype.
    """
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) \
            or not math.isfinite(timeout) or timeout <= 0:
        raise ResolveError(f"bad timeout {timeout!r}")
    return timeout


def _read_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly n bytes or raise ResolveError (EOF is a failure)."""
    # n is caller-supplied at this library seat (the TCP wire passes a
    # real int, but a direct caller can pass anything): a str/None/
    # float escaped as a raw TypeError from the comparison/recv, True
    # aliased to a 1-byte read, and a negative length silently
    # returned b"" as if a frame had been read — none of them the
    # ResolveError this function promises for a read that cannot
    # happen. Only a real non-negative int (bool excluded, twin of
    # daemon._read_exact's gate and dns._is_int) is a length.
    if isinstance(n, bool) or not isinstance(n, int) or n < 0:
        raise ResolveError(f"bad read length {n!r}")
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
    _check_timeout(timeout)
    s = sock
    try:
        host = _server_host(server)
        family, target, expected = _server_target(host, port)
        if s is None:
            s = socket.socket(family, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(packet, target)
        # The daemon's replies are whole on this wire (it never sets
        # TC) and can run past 4096 — a multi-answer binding, or a
        # forwarded upstream reply relayed byte-for-byte. recvfrom
        # discards whatever it is not handed room for, so a smaller
        # read silently amputated the tail mid-record and the parser
        # then misread a perfect answer as malformed. Read a whole
        # datagram: 65535, the UDP maximum, twin of daemon._serve_udp
        # and answer._forward.
        data, source = s.recvfrom(65535)
        try:
            source_ip = str(ipaddress.ip_address(source[0]))
        except ValueError:
            source_ip = source[0]
        if (source_ip, source[1]) != (expected, port):
            raise ResolveError("udp response from an unexpected source")
    except ResolveError:
        raise
    except (OSError, OverflowError, ValueError) as exc:
        # OverflowError rides along: a port above 65535 (honored from
        # CYBERNET_RESOLVER_PORT, see _client_port_warnings) makes
        # sendto raise OverflowError, NOT OSError — uncaught it would
        # escape resolve() as a raw crash instead of a ResolveError.
        # ValueError rides along for the _server_host/_server_target
        # bad-server gates above: a malformed server is a transport
        # failure on this wire, never a raw bad-argument escape.
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
    _check_timeout(timeout)
    s = sock
    try:
        if s is None:
            s = socket.create_connection((_server_host(server), port), timeout)
        s.settimeout(timeout)
        s.sendall(struct.pack(">H", len(packet)) + packet)
        (body_len,) = struct.unpack(">H", _read_exact(s, 2))
        data = _read_exact(s, body_len)
    except (OSError, OverflowError, ValueError) as exc:
        # OverflowError for parity with the UDP wire: create_connection
        # itself wraps an oversize port through getaddrinfo (OSError),
        # but a caller-supplied socket's send/recv path can still raise
        # OverflowError for one — a transport failure either way.
        # ValueError rides along for the _server_host bad-server gate:
        # a malformed server is a transport failure on this wire too.
        raise ResolveError(f"tcp transport failed: {exc}") from exc
    finally:
        if sock is None and s is not None:
            s.close()
    return _parse_response(data, txid, qname, qtype)


def _textify(qtype: int, rdata: bytes) -> str:
    """rdata bytes -> printable IP, strictly per the asked family."""
    # Both fields are caller-supplied at this library seat (resolve()
    # passes a parsed qtype and wire rdata, but a direct caller can
    # pass anything): a non-bytes rdata escaped as a raw TypeError
    # from len()/inet_ntoa, and True ALIASED to QTYPE_A (bool is an
    # int subclass, True == 1) — neither the ResolveError this
    # function raises for every other mismatch. Only a real int
    # qtype (bool excluded) and real bytes/bytearray rdata can match
    # a family; anything else is that same mismatch, refused here.
    if isinstance(qtype, bool) or not isinstance(qtype, int) \
            or not isinstance(rdata, (bytes, bytearray)):
        raise ResolveError("answer rdata does not match the asked family")
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
    # name is caller-supplied text: a non-string (None, an int, True,
    # bytes) escaped as a raw AttributeError/TypeError from .endswith()
    # inside _build_query — neither the ValueError a malformed string
    # name raises there nor anything main() maps to exit 2. Gate the
    # type first, the same fail-closed shape the qtype gate applies.
    if not isinstance(name, str):
        raise ValueError(f"bad name {name!r}")
    # qtype is caller-supplied text: a non-string (None, an int family
    # code, True) escaped as a raw AttributeError from .upper() before
    # this lookup — neither the ValueError an unsupported string raises
    # here nor anything main() maps to exit 2. Gate the type first, the
    # same fail-closed shape the txid/timeout gates apply.
    if not isinstance(qtype, str):
        raise ValueError(f"unsupported qtype {qtype!r}")
    qtype_n = _QTYPES.get(qtype.upper())
    if qtype_n is None:
        raise ValueError(f"unsupported qtype {qtype!r}")
    # server is caller-supplied text: a non-string (None, an int, bytes)
    # escaped as a raw AttributeError/TypeError from .strip() inside
    # _server_host — neither the ValueError a malformed name/qtype raises
    # here nor anything main() maps to exit 2. Gate the type first, the
    # same fail-closed shape the name/qtype gates apply.
    if not isinstance(server, str):
        raise ValueError(f"bad server {server!r}")
    # port is caller-supplied too (when given): a string/float/bytes
    # port escaped as a raw TypeError from the transport, True aliased
    # to port 1 and False to port 0 (bool is an int subclass), and 0 /
    # a negative port passed through to fail as a misleading transport
    # verdict — none of them the ValueError a malformed name/qtype/
    # server raises here, nor anything main() maps to exit 2. An
    # explicit port must be a real int (never bool) in 1..65535, the
    # same range main() gates --port to. port=None is untouched: the
    # env derivation keeps its documented semantics (an env port above
    # 65535 is honored and fails as a transport ResolveError, warned
    # by _client_port_warnings).
    if port is not None and (isinstance(port, bool)
                              or not isinstance(port, int)
                              or not 1 <= port <= 65535):
        raise ValueError(f"bad port {port!r}")
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

    ``python -m resolver.client alice.cyberspace [--qtype AAAA] [--port N] [--tcp-only]``

    Prints one address per line on success. Exit codes: 0 resolved,
    1 name does not resolve (NXDOMAIN), 2 everything else (usage,
    transport, daemon SERVFAIL, malformed answer) — so a shell script
    can tell "no such name" apart from "resolution broke".

    With no --qtype, A is asked first and AAAA is tried when A answers
    NODATA, so a v6-only hosted name resolves through the default
    invocation; an explicit --qtype asks exactly that family.
    """
    import argparse

    parser = argparse.ArgumentParser(
        prog="resolver.client",
        description="Resolve a .cyberspace name through the local daemon face.",
    )
    parser.add_argument("name", help="name to resolve, e.g. alice.cyberspace")
    parser.add_argument(
        # type=str.upper before choices: resolve() itself uppercases
        # qtype, so 'a'/'aaaa' are valid library arguments — the CLI
        # refusing them as invalid choices contradicted its own library.
        # Default None (not "A") so main() can tell an explicit family
        # from an unchosen one: an unchosen query falls back to AAAA
        # when A answers NODATA (see below); an explicit one is strict.
        "--qtype", default=None, type=str.upper, choices=sorted(_QTYPES),
        help="record family (default: A, falling back to AAAA when the "
             "name has no A record)",
    )
    parser.add_argument(
        "--server", default=DEFAULT_SERVER, help="daemon host (default 127.0.0.1)"
    )
    parser.add_argument(
        "--port", type=int, default=None,
        help="daemon port (default: CYBERNET_RESOLVER_PORT or 5353, "
             "as the daemon derives it)",
    )
    parser.add_argument(
        "--tcp-only", action="store_true", help="skip UDP, speak DNS-over-TCP only"
    )
    args = parser.parse_args(argv)

    # A name that is not exactly one valid label under .cyberspace can
    # never be claimed (core._valid_name_label's grammar), so querying
    # it could only ever read back NXDOMAIN — exit 1, a verdict on the
    # name — when the argument itself was at fault. Gate the shape here,
    # before any wire use, as a bad argument (exit 2). Normalized first
    # (strip, one FQDN root dot, lowercase — the same normalization
    # resolve()/_build_query apply), and the label check is a local
    # twin of core._valid_name_label: this module is dependency-free by
    # design and does not import core. resolve() library semantics are
    # unchanged; only the CLI front door gates.
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
        print(
            "error: not a valid .cyberspace name "
            "(one label of ASCII letters/digits/hyphens under .cyberspace)",
            flush=True,
        )
        return 2

    # The server is part of the argument shape too: a value that is
    # not an IP literal or a syntactically valid hostname can never
    # be dialed (sendto/create_connection die in name resolution), so
    # without this check it read as a transport failure — a verdict
    # on the daemon — when the argument itself was at fault, exactly
    # as wiring/smoke's --server gate ruled. Shape only, offline
    # (twin of the daemon's BIND shape check): an IPv4/IPv6 literal
    # (bracketed v6 unwrapped by _server_host) or a valid hostname
    # passes; a dotted all-numeric value that is not an IPv4 literal
    # can never resolve as written. A valid-but-unresolvable hostname
    # is beyond what an offline check can prove and still reads as a
    # transport failure, honestly. resolve() library semantics are
    # unchanged; only the CLI front door gates.
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
        print(
            "error: --server is not a dialable address "
            "(an IP literal or a valid hostname)",
            flush=True,
        )
        return 2

    # An explicit --port is part of the argument shape too: a port
    # outside 1..65535 can never be dialed (sendto/create_connection
    # die on it), so without this gate it read as a transport failure
    # — a verdict on the daemon — when the argument itself was at
    # fault, exactly as wiring/smoke's --port gate ruled. A valid
    # --port wins over the env derivation, and the env warnings (which
    # describe the port the env WOULD have derived) stay silent: that
    # port is not the one about to be queried.
    if args.port is not None and not 1 <= args.port <= 65535:
        print(
            "error: --port is not a dialable port (must be 1..65535)",
            flush=True,
        )
        return 2
    if args.port is None:
        for warn in _client_port_warnings():
            print(f"resolver-client: config: {warn}", file=sys.stderr)
        port = _default_port()
    else:
        port = args.port
    try:
        if args.qtype is not None:
            answers = resolve(
                args.name, qtype=args.qtype, server=args.server, port=port,
                tcp_only=args.tcp_only,
            )
        else:
            # No family chosen: ask A first, and fall back to AAAA only
            # on A-NODATA (NOERROR, no A record — the name lives, the
            # family is absent), exactly as wiring/smoke's registered
            # leg rules. A v6-only hosted node answers A that way
            # (answer.py), so without the fallback the front door
            # reported a live name as broken. NXDOMAIN (NameNotFound),
            # SERVFAIL, and transport failures never fall back — they
            # are verdicts on the name or the daemon, not on a family.
            try:
                answers = resolve(
                    args.name, qtype="A", server=args.server, port=port,
                    tcp_only=args.tcp_only,
                )
            except ResolveError as exc:
                if "answered no A record" not in str(exc):
                    raise
                try:
                    answers = resolve(
                        args.name, qtype="AAAA", server=args.server,
                        port=port, tcp_only=args.tcp_only,
                    )
                except ResolveError as exc6:
                    if "answered no AAAA record" in str(exc6):
                        print(
                            f"error: daemon answered no A or AAAA record "
                            f"for {args.name}",
                            flush=True,
                        )
                        return 2
                    raise
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
