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
import math
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


    raw = os.environ.get("CYBERNET_RESOLVER_PORT", "").strip()
    # Mirror daemon._env_int's ASCII gate exactly (1212c00): bare int()
    # parses Unicode decimal digits and underscore separators, so a
    # non-ASCII/underscored spelling aliased to a port the daemon
    # itself refuses -- the smoke tested a port nobody listened on.
    digits = raw[1:] if raw[:1] in ("+", "-") else raw
    if not digits or not digits.isascii() or not digits.isdigit():
        return 5353
    return max(1, int(raw))


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
    _digits = raw[1:] if raw[:1] in ("+", "-") else raw
    if not _digits or not _digits.isascii() or not _digits.isdigit():
        return [
            "CYBERNET_RESOLVER_PORT is not an integer — the 5353 "
            "default will be smoked instead"]
    port = int(raw)
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
    """Build the one-question query, refusing a malformed name/qtype.

    Twin of client._build_query's gates: both fields are caller-supplied
    (main() normalizes its --name, but a direct caller can pass
    anything). Before, a non-string name escaped as AttributeError from
    .split() (None/int) or TypeError (bytes), a non-ASCII label died as
    codec gibberish, True ALIASED to qtype A (bool is an int subclass)
    and an out-of-range or non-int qtype escaped as struct.error —
    none of them the ValueError this module's other gates raise. An
    empty label was silently skipped into the length byte of the next,
    so "alice..cyberspace" built a DIFFERENT name than the caller
    wrote, "" built a root query, and a label over 63 bytes wrote a
    length byte whose top bits the daemon's parser reads as a
    compression pointer. Only a real string of non-empty ASCII labels
    (each <=63 bytes, the whole wire name <=255 bytes) and a real int
    qtype in the uint16 wire range (bool excluded) build a query;
    anything else raises ValueError here, at the source. main()'s
    normalized names and the A/AAAA qtypes are untouched."""
    if not isinstance(name, str):
        raise ValueError(f"bad name {name!r}")
    if isinstance(qtype, bool) or not isinstance(qtype, int) \
            or not 0 <= qtype <= 65535:
        raise ValueError(f"bad qtype {qtype!r}")
    encoded: list[bytes] = []
    for part in name.split("."):
        if not part:
            raise ValueError(f"name has an empty label: {name!r}")
        try:
            raw = part.encode("ascii")
        except UnicodeEncodeError:
            raise ValueError(f"name label is not ASCII: {part!r}") from None
        if len(raw) > 63:
            raise ValueError("name label exceeds the 63-byte DNS limit")
        encoded.append(raw)
    qname = b"".join(bytes([len(r)]) + r for r in encoded) + b"\x00"
    if len(qname) > 255:
        raise ValueError("name exceeds the 255-byte DNS wire limit")
    txid = random.getrandbits(16)
    flags = 0x0100  # RD set
    header = struct.pack(">HHHHHH", txid, flags, 1, 0, 0, 0)
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
    # Twin of client._server_host's gate: a non-string escaped as
    # AttributeError from .strip() (None/int/bool) or TypeError from
    # .startswith() (bytes), past the ValueError shape main() expects.
    if not isinstance(server, str):
        raise ValueError(f"bad server {server!r}")
    host = server.strip()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1].strip()
    return host


def _server_family(host: str) -> int:
    """Socket family for a (bare) server host: AF_INET6 for an IPv6
    literal, AF_INET otherwise. The UDP wire hardcoded AF_INET, so a
    daemon bound to ::1 — a bind the daemon itself now accepts — could
    never be smoked at all, however the address was written."""
    if not isinstance(host, str):
        raise ValueError(f"bad server host {host!r}")
    try:
        if ipaddress.ip_address(host).version == 6:
            return socket.AF_INET6
    except ValueError:
        pass
    return socket.AF_INET


def _check_port(port: int) -> int:
    """Gate a caller-supplied port before any socket sees it.

    Twin of client.resolve's port gate: only a real int (bool
    excluded) in 1..65535 is a port. Before, _server_target returned
    True/False/0/-1/65536/a string/a float/None verbatim in the
    sockaddr, so True aliased to port 1, a string was handed to the
    transport as a service name, and an out-of-range port escaped
    later as OverflowError/OSError — or, on the TCP wire, was dialed
    as a different port than the caller wrote. main() gates its
    --port, but a direct caller bypassed it. Anything else raises
    ValueError at the source."""
    if isinstance(port, bool) or not isinstance(port, int) \
            or not 1 <= port <= 65535:
        raise ValueError(f"bad port {port!r}")
    return port


def _server_target(host: str, port: int):
    """(family, sockaddr, expected source IP) the UDP wire dials.

    Twin of client._server_target. A literal keeps _server_family +
    the literal itself, exactly as before. A HOSTNAME is resolved
    first (getaddrinfo, AF_UNSPEC) and the socket is created from the
    answer's family, dialing the resolved sockaddr — the family can
    no longer be guessed from the string's shape. Before, every
    hostname picked AF_INET and sendto carried the unresolved string,
    so a daemon bound to ::1 and smoked by a v6-only hostname (the
    natural --server a operator types) was never reached on its own
    wire and read as "unreachable", while the TCP leg —
    create_connection resolves the same way — passed. First
    getaddrinfo result wins, as create_connection tries them in
    order. An unresolvable hostname raises gaierror here, which
    main() already reads as unreachable, honestly. The third value
    is the only source _query may accept a reply from (see there)."""
    # Twin of client._server_target's gate: ip_address() ALIASED a
    # non-string host (123 -> 0.0.0.123, True -> 0.0.0.1, a 4-byte
    # bytes host -> its quad) and getaddrinfo ALIASED None to ::1 —
    # a daemon nobody named was dialed and source-checked as expected.
    if not isinstance(host, str):
        raise ValueError(f"bad server host {host!r}")
    _check_port(port)
    try:
        ip = ipaddress.ip_address(host)
        return _server_family(host), (host, port), str(ip)
    except ValueError:
        pass
    infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC,
                               socket.SOCK_DGRAM)
    family, _kind, _proto, _canon, sockaddr = infos[0]
    return family, sockaddr, str(ipaddress.ip_address(sockaddr[0]))


def _check_name_read(data, off) -> None:
    """Gate a name read's packet and offset before any indexing.

    Twin of dns._read_name's gate: a non-bytes packet escaped as
    TypeError from the index/& below (str) or len() (None/int), a
    float/str/None offset as TypeError, True aliased to offset 1,
    and a NEGATIVE offset silently read from the packet's tail
    (data[-1] is its last byte) — none of them the ValueError this
    smoke's response refusals promise. Only a real bytes packet at
    a real, non-negative int offset (bool excluded) has a name."""
    if not isinstance(data, (bytes, bytearray)) \
            or not isinstance(off, int) or isinstance(off, bool) \
            or off < 0:
        raise ValueError("truncated DNS response — response is not ours")


def _skip_name(data: bytes, off: int) -> int:
    """Offset just past the name at off (labels or a pointer)."""
    _check_name_read(data, off)
    while True:
        if off >= len(data):
            raise ValueError("truncated DNS response — response is not ours")
        length = data[off]
        if length == 0:
            return off + 1
        if length & 0xC0 == 0xC0:
            if off + 2 > len(data):
                raise ValueError(
                    "truncated DNS response — response is not ours")
            return off + 2
        if length & 0xC0:
            raise ValueError("malformed name in response — response is not ours")
        off += 1 + length


def _read_name(data: bytes, off: int) -> tuple[str, int]:
    """(dotted name, offset past it) at off — twin of dns._read_name:
    labels plus compression pointers, pointer cycles bounded."""
    _check_name_read(data, off)
    labels: list[str] = []
    jumped = False
    end = off
    for _ in range(64):
        if off >= len(data):
            raise ValueError("truncated DNS response — response is not ours")
        length = data[off]
        if length & 0xC0 == 0xC0:
            if off + 1 >= len(data):
                raise ValueError(
                    "truncated DNS response — response is not ours")
            if not jumped:
                end = off + 2
            off = ((length & 0x3F) << 8) | data[off + 1]
            jumped = True
            continue
        if length & 0xC0:
            raise ValueError("malformed name in response — response is not ours")
        if length == 0:
            if not jumped:
                end = off + 1
            break
        off += 1
        if off + length > len(data):
            raise ValueError("truncated DNS response — response is not ours")
        try:
            labels.append(data[off:off + length].decode("ascii"))
        except UnicodeDecodeError:
            raise ValueError("malformed name in response — response is not ours")
        off += length
    else:
        raise ValueError("malformed name in response — response is not ours")
    return ".".join(labels), end


def _check_walk(resp, qd, an) -> None:
    """Gate a section walk's packet and counts before any loop.

    The _refuse_* walkers are caller-supplied at this library seat:
    _query passes header counts (always real uint16s), but a direct
    caller passing a string/float count escaped as TypeError from
    range(), True aliased to one section, and a NEGATIVE count made
    range() empty — the walk ended at the header and a bare packet
    was silently accepted as well-formed, the opposite of a refusal.
    _refuse_different_question likewise compared an ungated name
    (None escaped as AttributeError from .lower()) and qtype (True
    and 1.0 compare equal to A, so both aliased to it). Only a real
    bytes packet, real non-negative int counts (bool excluded), a
    real string name, and a real int qtype in the uint16 wire range
    (bool excluded) may be walked or compared; anything else raises
    ValueError at the source, twin of client._parse_response's
    txid/qtype gates and _check_name_read above."""
    if not isinstance(resp, (bytes, bytearray)):
        raise ValueError("truncated DNS response — response is not ours")
    for count in (qd, an):
        if isinstance(count, bool) or not isinstance(count, int) \
                or count < 0:
            raise ValueError(
                "bad section count — response is not ours")


def _refuse_different_question(resp: bytes, name: str, qtype: int) -> None:
    """Refuse an echoed question that is not THIS one, twin of
    client._parse_response: the daemon echoes exactly the question
    it was asked (build_response carries the parsed question bytes),
    so an echo naming a different name — or the same name under a
    different qtype or class — is a reply to another question and
    its answers belong to that question, however clean its header.
    Name compared case-insensitively (the wire form of the asked
    name is already normalized lower-case by main())."""
    _check_walk(resp, 1, 0)
    if not isinstance(name, str):
        raise ValueError(
            "response answers a different question — response is not ours")
    if isinstance(qtype, bool) or not isinstance(qtype, int) \
            or not 0 <= qtype <= 65535:
        raise ValueError(
            "response answers a different question — response is not ours")
    seen, off = _read_name(resp, 12)
    if off + 4 > len(resp):
        raise ValueError("truncated DNS response — response is not ours")
    seen_qtype, seen_qclass = struct.unpack_from(">HH", resp, off)
    if (seen.lower() != name.lower() or seen_qtype != qtype
            or seen_qclass != _QCLASS_IN):
        raise ValueError(
            "response answers a different question — response is not ours")


def _refuse_stranger_answer(resp: bytes, qd: int, an: int,
                            name: str) -> None:
    """Refuse an answer owned by a different name, twin of
    client._parse_response: the daemon builds every answer with a
    pointer back to the question name, so a collected record owned
    by another name never came from the daemon's verified answer
    for this question — trusting it would let a correct question
    carry a stranger's address. Name compared case-insensitively.
    Walks question + answer headers only; type/class/rdlen parity
    is _refuse_wrong_type_answer's, trailing is _refuse_trailing's."""
    _check_walk(resp, qd, an)
    if not isinstance(name, str):
        raise ValueError(
            "response answer owned by a different name — "
            "response is not ours")
    off = 12
    for _ in range(qd):
        off = _skip_name(resp, off)
        if off + 4 > len(resp):
            raise ValueError("truncated DNS response — response is not ours")
        off += 4  # qtype + qclass
    for _ in range(an):
        owner, off = _read_name(resp, off)
        if owner.lower() != name.lower():
            raise ValueError(
                "response answer owned by a different name — "
                "response is not ours")
        if off + 10 > len(resp):
            raise ValueError("truncated DNS response — response is not ours")
        rdlen = struct.unpack_from(">H", resp, off + 8)[0]
        off += 10
        if off + rdlen > len(resp):
            raise ValueError("truncated DNS response — response is not ours")
        off += rdlen


def _refuse_wrong_type_answer(resp: bytes, qd: int, an: int) -> None:
    """Refuse an answer record the daemon never sends, twin of
    client._parse_response: the daemon's handler answers only the
    asked A or AAAA family (every other qtype gets an empty NODATA
    reply) and build_response hard-codes class IN on every answer
    it builds, with rdata exactly 4 bytes for A and 16 for AAAA —
    so a TXT/CNAME record, a non-IN record, or a record whose rdata
    length does not match its type never came from the daemon,
    however clean its owner. Walks question + answer headers only;
    owner is _refuse_stranger_answer's, trailing is
    _refuse_trailing's."""
    _check_walk(resp, qd, an)
    off = 12
    for _ in range(qd):
        off = _skip_name(resp, off)
        if off + 4 > len(resp):
            raise ValueError("truncated DNS response — response is not ours")
        off += 4  # qtype + qclass
    for _ in range(an):
        off = _skip_name(resp, off)
        if off + 10 > len(resp):
            raise ValueError("truncated DNS response — response is not ours")
        rtype, rclass, _ttl, rdlen = struct.unpack_from(">HHIH", resp, off)
        off += 10
        if off + rdlen > len(resp):
            raise ValueError("truncated DNS response — response is not ours")
        off += rdlen
        if rclass != _QCLASS_IN or rtype not in (_QTYPE_A, _QTYPE_AAAA):
            raise ValueError(
                "response answer record of a type or class the daemon "
                "never sends — response is not ours")
        if rdlen != (4 if rtype == _QTYPE_A else 16):
            raise ValueError(
                "response answer rdata length does not match its type — "
                "response is not ours")


def _refuse_trailing(resp: bytes, qd: int, an: int) -> None:
    """Refuse bytes left over after the counted sections, twin of
    client._parse_response: neither daemon response builder ever
    emits any — build_response ends exactly at its last answer's
    rdata and error_response is a bare header plus the echoed
    question — so trailing bytes can carry nothing the daemon
    meant, however well-formed the packet before them. Walking the
    sections is the only way to know where they end; a walk that
    runs past the packet is a truncation, refused likewise."""
    _check_walk(resp, qd, an)
    off = 12
    for _ in range(qd):
        off = _skip_name(resp, off)
        if off + 4 > len(resp):
            raise ValueError("truncated DNS response — response is not ours")
        off += 4  # qtype + qclass
    for _ in range(an):
        off = _skip_name(resp, off)
        if off + 10 > len(resp):
            raise ValueError("truncated DNS response — response is not ours")
        rdlen = struct.unpack_from(">H", resp, off + 8)[0]
        off += 10
        if off + rdlen > len(resp):
            raise ValueError("truncated DNS response — response is not ours")
        off += rdlen
    if off != len(resp):
        raise ValueError("response carries trailing bytes the daemon never sends — response is not ours")


def _check_timeout(timeout: float) -> float:
    """Gate a caller-supplied timeout before any socket sees it.

    The timeout reaches settimeout/create_connection raw: None meant
    BLOCK FOREVER — a silent daemon would hang this smoke without
    limit, the opposite of a check that must fail — True aliased to
    1 second (bool is an int subclass), a string escaped as TypeError,
    and inf/NaN escaped as OverflowError/ValueError from deep inside
    settimeout. A timeout must be a real int/float (never bool),
    finite, and positive; anything else raises ValueError at the
    source (twin of client._check_timeout, whose contract is its
    ResolveError). main()'s own callers pass the 3.0 default.
    """
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) \
            or not math.isfinite(timeout) or timeout <= 0:
        raise ValueError(f"bad timeout {timeout!r}")
    return timeout


def _query(name: str, qtype: int, server: str, port: int,
           timeout: float = 3.0) -> tuple[int, int, int]:
    """Return (rcode, ancount, txid_echoed). Raises on transport failure."""
    _check_timeout(timeout)
    packet, txid = _build_query(name, qtype)
    host = _server_host(server)
    family, target, expected = _server_target(host, port)
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(packet, target)
        # Read a whole datagram (65535, the UDP maximum — twin of
        # daemon._serve_udp, client._query_udp and answer._forward):
        # recvfrom discards whatever it is not handed room for, so the
        # classic 512 silently amputated a multi-answer reply
        # mid-record and the header counts below still claimed the
        # answers that were never delivered.
        resp, source = sock.recvfrom(65535)
        # The reply's SOURCE is part of the transaction (twin of
        # client._query_udp): UDP has no connection, so a packet from
        # any other (address, port) — even a perfectly formed one with
        # the right txid — is a stranger's word, not the daemon's.
        # Discarding the source, as before, let such a packet earn
        # this smoke a PASS the daemon never gave.
        try:
            source_ip = str(ipaddress.ip_address(source[0]))
        except ValueError:
            source_ip = source[0]
        if (source_ip, source[1]) != (expected, port):
            raise ValueError(
                "response from an unexpected source — not the daemon "
                "queried")
    if len(resp) < 12:
        raise ValueError("truncated DNS response")
    (rtxid, flags, qd, an, ns, ar) = struct.unpack(">HHHHHH", resp[:12])
    if rtxid != txid:
        raise ValueError("txid mismatch — response is not ours")
    # A matching txid alone never sufficed (twin of client._parse_response):
    # a packet with the QR bit clear is a query, not an answer — the daemon
    # builds every reply with QR set (dns.build_response/error_response),
    # so a QR-clear packet claiming answers is not its word, however
    # well-formed, and must not earn this smoke a PASS.
    if not flags & 0x8000:
        raise ValueError("not a response (QR bit clear) — response is not ours")
    # AA bit, twin of client._parse_response: the daemon is authoritative
    # for this zone and every reply it builds sets AA (answers, NXDOMAIN,
    # SERVFAIL) — an AA-clear packet is some other responder's word, not
    # the daemon's, and must not earn this smoke a PASS.
    if not flags & 0x0400:
        raise ValueError("not authoritative (AA bit clear) — response is not ours")
    # Opcode, twin of client._parse_response: a packet with a nonzero
    # opcode is not a reply to a standard query at all — the daemon
    # only ever answers opcode 0 and both its response builders emit
    # opcode 0, so an opcode-set packet is not its word.
    if flags & 0x7800:
        raise ValueError("not a standard-query response (opcode set) — response is not ours")
    # RD echo, twin of client._parse_response: this smoke always sends
    # RD and build_response echoes RD on every zone reply it builds —
    # an RD-clear packet is not the daemon's reply to THIS query.
    if not flags & 0x0100:
        raise ValueError("response does not echo RD — response is not ours")
    # TC bit, twin of client._parse_response: a packet with TC set
    # claims its own answer was truncated — neither daemon response
    # builder ever sets TC (its replies are whole on both wires), so
    # a TC-set packet is not the daemon's whole reply.
    if flags & 0x0200:
        raise ValueError("response claims truncation (TC set) — response is not ours")
    # RA bit, twin of client._parse_response: a packet with RA set
    # claims recursion was available — the daemon is authoritative-only
    # for this zone and neither response builder ever sets RA, so an
    # RA-set packet is a recursive resolver's answer, not the daemon's.
    if flags & 0x0080:
        raise ValueError("response claims recursion available (RA set) — response is not ours")
    # Z bit, twin of client._parse_response: a packet with Z set uses
    # a header bit reserved for future use — neither daemon response
    # builder ever sets Z (its replies are QR|AA|RD echo|rcode only),
    # so a Z-set packet is not one of the daemon's replies.
    if flags & 0x0040:
        raise ValueError("response sets the reserved Z bit — response is not ours")
    # AD/CD bits, twin of client._parse_response: a packet with AD
    # or CD set reports DNSSEC checking states this smoke never
    # asked for (its query sends RD only, no AD/CD) and neither
    # daemon response builder ever sets — an AD/CD-set packet
    # carries a recursive checker's marks, not the daemon's.
    if flags & 0x0030:
        raise ValueError("response sets AD/CD bits the daemon never sets — response is not ours")
    # Authority/additional counts, twin of client._parse_response:
    # a packet carrying authority or additional section records is
    # not the daemon's — neither response builder ever emits any
    # (build_response sends header counts 0/0 for those sections and
    # error_response sends 0/0/0/0), and this smoke never reads them.
    if ns or ar:
        raise ValueError("response carries authority/additional sections the daemon never sends — response is not ours")
    # Question count, twin of client._parse_response: this smoke
    # always asks exactly one question (_build_query emits QDCOUNT=1)
    # and both daemon response builders echo exactly that one — a
    # packet with qd != 1 answers no question, or a different batch,
    # and is not the daemon's reply to THIS query.
    if qd != 1:
        raise ValueError("response does not echo exactly one question — response is not ours")
    # Echoed question, twin of client._parse_response: the one
    # question must be THIS one (name, qtype, class IN) — see
    # _refuse_different_question.
    _refuse_different_question(resp, name, qtype)
    # Answer owner, twin of client._parse_response: every answer
    # must be owned by the asked name — see _refuse_stranger_answer.
    _refuse_stranger_answer(resp, qd, an, name)
    # Answer type/class/rdlen, twin of client._parse_response:
    # every answer must be a record the daemon ever sends — see
    # _refuse_wrong_type_answer.
    _refuse_wrong_type_answer(resp, qd, an)
    # Trailing bytes, twin of client._parse_response: the packet
    # must end exactly at its counted sections (see _refuse_trailing).
    _refuse_trailing(resp, qd, an)
    return flags & 0x000F, an, rtxid


def _read_exact(sock, n: int, timeout: float) -> bytes:
    """Read exactly n bytes from a blocking socket with a deadline."""
    # n is caller-supplied at this library seat (the TCP wire passes a
    # real int unpacked from the frame, but a direct caller can pass
    # anything): a str/None/float escaped as a raw TypeError from the
    # comparison/recv, True aliased to a 1-byte read, and a negative
    # length silently returned b"" as if a frame had been read — none
    # of them the refusal this smoke owes for a read that cannot
    # happen. Only a real non-negative int (bool excluded, twin of
    # client._read_exact's and daemon._read_exact's gates) is a
    # length; anything else raises ValueError before the socket is
    # touched. Valid and zero lengths are untouched.
    if isinstance(n, bool) or not isinstance(n, int) or n < 0:
        raise ValueError(f"bad read length {n!r}")
    # The timeout is caller-supplied too — and until now it was not
    # even gated, only carried: _query_tcp gates its own before
    # calling, but a direct caller passing None/"3"/True/inf/NaN/0/-1
    # got a read under a deadline this function never refused, the
    # exact shapes _check_timeout exists to refuse (None would block
    # forever on a socket without one). Gate it here, at the source,
    # before the socket is touched; the socket's own timeout (set by
    # the wire caller) still does the enforcing.
    _check_timeout(timeout)
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
    _check_timeout(timeout)
    _check_port(port)
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
    # QR bit, twin of _query above (and client._parse_response): a
    # QR-clear packet is a query, not the daemon's answer.
    if not flags & 0x8000:
        raise ValueError("not a response (QR bit clear) — response is not ours")
    # AA bit, twin of _query above: an AA-clear packet is not the
    # authoritative daemon's answer for this zone.
    if not flags & 0x0400:
        raise ValueError("not authoritative (AA bit clear) — response is not ours")
    # Opcode, twin of _query above: an opcode-set packet is not a
    # reply to a standard query, hence not the daemon's answer.
    if flags & 0x7800:
        raise ValueError("not a standard-query response (opcode set) — response is not ours")
    # RD echo, twin of _query above: an RD-clear packet is not the
    # daemon's reply to this RD-set query.
    if not flags & 0x0100:
        raise ValueError("response does not echo RD — response is not ours")
    # TC bit, twin of _query above: a TC-set packet claims its own
    # answer was truncated; the daemon's replies are whole on both
    # wires, so over TCP it is contradicting itself.
    if flags & 0x0200:
        raise ValueError("response claims truncation (TC set) — response is not ours")
    # RA bit, twin of _query above: an RA-set packet claims recursion
    # was available; the authoritative-only daemon never sets RA.
    if flags & 0x0080:
        raise ValueError("response claims recursion available (RA set) — response is not ours")
    # Z bit, twin of _query above: a Z-set packet uses a reserved
    # header bit; neither daemon response builder ever sets Z.
    if flags & 0x0040:
        raise ValueError("response sets the reserved Z bit — response is not ours")
    # AD/CD bits, twin of _query above: an AD/CD-set packet carries
    # a recursive checker's marks; neither daemon response builder
    # ever sets AD or CD and this smoke's query never asks for them.
    if flags & 0x0030:
        raise ValueError("response sets AD/CD bits the daemon never sets — response is not ours")
    # Authority/additional counts, twin of _query above: a packet
    # carrying authority or additional records is not the daemon's;
    # neither response builder ever emits any.
    if ns or ar:
        raise ValueError("response carries authority/additional sections the daemon never sends — response is not ours")
    # Question count, twin of _query above: a packet with qd != 1
    # does not echo this smoke's single question and is not the
    # daemon's reply to it.
    if qd != 1:
        raise ValueError("response does not echo exactly one question — response is not ours")
    # Echoed question, twin of _query above: the one question must
    # be THIS one (name, qtype, class IN) — see
    # _refuse_different_question.
    _refuse_different_question(resp, name, qtype)
    # Answer owner, twin of _query above: every answer must be
    # owned by the asked name — see _refuse_stranger_answer.
    _refuse_stranger_answer(resp, qd, an, name)
    # Answer type/class/rdlen, twin of _query above: every answer
    # must be a record the daemon ever sends — see
    # _refuse_wrong_type_answer.
    _refuse_wrong_type_answer(resp, qd, an)
    # Trailing bytes, twin of _query above: the packet must end
    # exactly at its counted sections (see _refuse_trailing).
    _refuse_trailing(resp, qd, an)
    return flags & 0x000F, an, rtxid


def main() -> int:
    # Duplicate gate, twin of resolver/client (434e0ae), dial,
    # resolve_chain and verify_name: argparse silently last-wins on
    # a repeated value flag, so --port 5353 --port 5354 smoked port
    # 5354 while the operator believed the daemon port was 5353, and
    # a repeated --name/--server redirected the smoke the same way
    # (probed: duplicates proceeded to the wire and read back a
    # transport verdict against the second value). main() takes no
    # argv, so scan sys.argv directly; refuse a repeated value flag
    # by name, in space, equals or mixed spelling, before argparse
    # runs — before any query is built or sent. Exit 1 is this
    # smoke's bad-argument code (see the --port gate below).
    # The boolean --tcp gates the same way: store_true repeats
    # silently too, so --tcp --tcp passed to a verdict while every
    # value flag refused its repeat by name — twin of client's
    # --tcp-only gate (49473c8) and resolve_chain's --with-live
    # gate (c466111).
    _seen: set[str] = set()
    _long_opts = ("--name", "--server", "--port", "--tcp", "--help")
    for _tok in sys.argv[1:]:
        if _tok == "--":
            break
        if not _tok.startswith("--"):
            continue
        _flag = _tok.partition("=")[0]
        if _flag not in _long_opts:
            # argparse accepts any unambiguous prefix as an
            # abbreviation, so --por (even --p) silently became
            # --port and dodged the duplicate gate below: a
            # --por A --port B pair smoked B while the operator
            # believed the daemon port was A (probed this tick).
            # Refuse the abbreviated spelling itself, by name,
            # before argparse can expand it. Twin of client/dial.
            _full = [o for o in _long_opts if o.startswith(_flag)]
            if _full:
                print(f"FAIL: {_flag} is an abbreviation of "
                      f"{_full[0]} — spell it out — "
                      f"bad argument, no query attempted")
                return 1
        if _flag in ("--name", "--server", "--port", "--tcp"):
            if _flag in _seen:
                print(f"FAIL: {_flag} given more than once — "
                      f"bad argument, no query attempted")
                return 1
            _seen.add(_flag)
    ap = argparse.ArgumentParser(description="smoke-test the .cyberspace daemon",
                                 allow_abbrev=False)
    ap.add_argument("--name", default="genesis.cyberspace",
                    help="registered name to resolve (default: genesis.cyberspace)")
    ap.add_argument("--server", default="127.0.0.1")
    # No type=int: argparse would bare-int() the value (see the gate
    # in main) -- the raw string reaches main and is gated there so
    # bad spellings refuse with return 1, not argparse's SystemExit.
    ap.add_argument("--port", default=None,
                    help="daemon port (default: CYBERNET_RESOLVER_PORT "
                         "or 5353, as the daemon and client derive it)")
    ap.add_argument("--tcp", action="store_true",
                    help="run the same checks over DNS-over-TCP (RFC 7766)")
    args = ap.parse_args()
    if args.port is not None:
        # ASCII digits only, one optional leading sign (twin of
        # client.main's --port gate / rotate_name f97a2c9): argparse
        # type=int bare-int()ed this value, and int() parses Unicode
        # decimal digits (an Arabic-Indic/fullwidth spelling of 5353
        # became 5353) and accepts underscore separators (5_353 became
        # 5353), so a non-ASCII or underscored spelling smoked a port
        # the operator never wrote in ASCII, where the env seat
        # (_default_port) refuses those spellings. The sign and
        # surrounding whitespace stay so valid spellings keep their
        # exact behaviour through the range gate below.
        _port_txt = args.port.strip()
        _port_digits = (_port_txt[1:]
                        if _port_txt[:1] in ("+", "-") else _port_txt)
        if (not _port_digits or not _port_digits.isascii()
                or not _port_digits.isdigit()):
            print(f"FAIL: --port {args.port} must be an integer — "
                  f"not a dialable port (must be 1..65535) — "
                  f"bad argument, no query attempted")
            return 1
        args.port = int(_port_txt)
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
