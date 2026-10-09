"""Minimal stdlib DNS codec for cybernet-resolver.

Deliberately narrow: parse a standard query (one question), build a
response echoing that question with A/AAAA answers, NXDOMAIN, or SERVFAIL.
Anything the daemon will never need — OPT, TSIG, AXFR, compression in
queries — is refused with SERVFAIL rather than half-parsed.

Fail-closed: malformed input raises ValueError at the boundary; the daemon
turns that into SERVFAIL. The codec never guesses.
"""

import struct

# Response flags: QR (response) | AA (authoritative for .cyberspace) + RD echo.
_RCODE_NAMES = {0: "NOERROR", 2: "SERVFAIL", 3: "NXDOMAIN"}


def _read_name(data: bytes, off: int) -> tuple[str, int]:
    """Read a DNS label sequence from off. Returns (dotted_name, new_off).

    Handles pointer compression (0xC0..) so hand-built and real-world
    queries both parse. Loops are bounded — a pointer cycle is malformed.
    """
    labels: list[str] = []
    jumped = False
    end = off
    for _ in range(64):  # hard bound: no name needs more than 64 hops
        if off >= len(data):
            raise ValueError("truncated name")
        length = data[off]
        if (length & 0xC0) == 0xC0:  # pointer
            if off + 1 >= len(data):
                raise ValueError("truncated pointer")
            if not jumped:
                end = off + 2
            off = ((length & 0x3F) << 8) | data[off + 1]
            jumped = True
            continue
        if length & 0xC0:
            raise ValueError("bad label length bits")
        if length == 0:
            if not jumped:
                end = off + 1
            break
        off += 1
        if off + length > len(data):
            raise ValueError("truncated label")
        try:
            labels.append(data[off:off + length].decode("ascii"))
        except UnicodeDecodeError:
            raise ValueError("non-ascii label")
        off += length
    else:
        raise ValueError("name too deep")
    return ".".join(labels), end


def parse_query(data: bytes) -> dict:
    """Parse a DNS query packet. Returns {"id", "qname", "qtype", "qclass",
    "rd", "question"} where question is the raw question bytes to echo.

    Raises ValueError on anything malformed or out of scope (no question,
    more than one question, truncated packet).
    """
    if len(data) < 12:
        raise ValueError("packet shorter than header")
    qid, flags, qdcount, ancount, nscount, arcount = struct.unpack(">HHHHHH", data[:12])
    if flags & 0x8000:
        raise ValueError("not a query")
    if qdcount != 1:
        raise ValueError(f"expected 1 question, got {qdcount}")
    qname, off = _read_name(data, 12)
    if off + 4 > len(data):
        raise ValueError("truncated question tail")
    qtype, qclass = struct.unpack(">HH", data[off:off + 4])
    return {
        "id": qid,
        "qname": qname,
        "qtype": qtype,
        "qclass": qclass,
        "rd": bool(flags & 0x0100),
        "question": data[12:off + 4],
    }


def build_response(query: dict, answers: list[tuple[int, int, bytes]], rcode: int = 0) -> bytes:
    """Build a response packet for a parsed query.

    answers: list of (qtype, ttl_seconds, rdata_bytes). Each answer uses a
    name pointer (0xC00C) back to the echoed question's name. rcode 0 =
    NOERROR, 2 = SERVFAIL, 3 = NXDOMAIN. Anything else raises ValueError —
    the daemon answers only what it means.
    """
    if rcode not in _RCODE_NAMES:
        raise ValueError(f"unsupported rcode {rcode}")
    for qtype, ttl, rdata in answers:
        if ttl < 0 or len(rdata) > 65535:
            raise ValueError("bad answer")
    flags = 0x8000 | 0x0400 | rcode  # QR | AA | rcode
    if query["rd"]:
        flags |= 0x0100  # echo RD
    header = struct.pack(
        ">HHHHHH",
        query["id"], flags, 1, len(answers), 0, 0,
    )
    body = bytearray(query["question"])
    for qtype, ttl, rdata in answers:
        body += struct.pack(">HHHIH", 0xC00C, qtype, 1, ttl, len(rdata)) + rdata
    return header + bytes(body)


def error_response(raw: bytes, rcode: int = 2) -> bytes:
    """Last-resort response for a packet we could not parse.

    Echoes the query id when the header is readable, sets QR + AA + rcode
    (default SERVFAIL), and drops everything else. Never raises.

    AA is set deliberately: this is the bridge's own authoritative refusal,
    and the client contract (extension resolver.js) requires AA on every
    reply — a SERVFAIL without it would be misread as "not authoritative"
    and mask the bridge's actual failure signal behind a wire-malformation
    error. AA here asserts "the bridge itself refused", never a zone claim
    for a name the packet never yielded.
    """
    try:
        qid = struct.unpack(">H", raw[:2])[0] if len(raw) >= 2 else 0
    except Exception:
        qid = 0
    flags = 0x8000 | 0x0400 | (rcode & 0xF)  # QR | AA | rcode
    return struct.pack(">HHHHHH", qid, flags, 0, 0, 0, 0)
