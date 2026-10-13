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
    if ancount or nscount or arcount:
        # The header claims sections this codec never reads (answers,
        # authority, or additional — OPT and TSIG live in additional).
        # The module contract is refuse rather than half-parse: before,
        # such a packet was answered as a plain question, so a packet
        # carrying answers was treated as if it asked one, and an
        # OPT-carrying query was answered as if its EDNS promises (DO
        # bit, buffer size) had never been made. Bytes past the
        # question are NOT refused on their own — a compressed name
        # may legitimately point at labels living there (see
        # _read_name); what may not exist is a COUNTED section.
        raise ValueError(
            f"query carries counted sections (an={ancount}, "
            f"ns={nscount}, ar={arcount}) this codec never reads")
    qname, off = _read_name(data, 12)
    # The name itself must fit the DNS wire limit (255 octets in
    # uncompressed form: one length byte per label plus the root zero
    # — len(qname) + 2 for a non-root name). client._build_query
    # refuses to BUILD a name past that limit, but this codec accepted
    # one: five 63-byte labels parse to a 319-character name no legal
    # packet can carry, which was then answered or forwarded as if it
    # were a name. A name expanded through a pointer is judged by its
    # expanded length — the pointer is an encoding of that name, not
    # a shorter name. Refuse rather than half-parse.
    if qname and len(qname) + 2 > 255:
        raise ValueError("name exceeds the 255-byte DNS wire limit")
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
    # The header packs two caller-supplied fields the answer loop below
    # never sees: the query id and the answer count. Both are uint16 on
    # the wire; an out-of-range id (a hand-built query dict — parse_query
    # only yields 0..65535) or more than 65535 answers escaped as
    # struct.error from the header pack, the same ValueError-contract
    # break the answer fields had. Range-check them here too.
    if not 0 <= query["id"] <= 65535:
        raise ValueError("bad query id")
    if len(answers) > 65535:
        raise ValueError("too many answers")
    for qtype, ttl, rdata in answers:
        # Range-check every field struct will pack, not just ttl's
        # floor: a ttl past the uint32 wire field or a qtype outside
        # uint16 used to escape as struct.error, breaking this
        # function's ValueError contract (callers guarding ValueError
        # — the codec's fail-closed boundary language — missed it).
        if not 0 <= qtype <= 65535 or not 0 <= ttl <= 4294967295 \
                or len(rdata) > 65535:
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
    # An rcode is four bits on the wire, but masking (& 0xF) silently
    # ALIASED an out-of-range one to a different meaning: 16 became
    # NOERROR — a refusal dressed as success — and -1/255 became 15.
    # This function never raises, so an rcode outside 0..15 (or not an
    # int at all) falls back to SERVFAIL: fail-closed, never aliased.
    try:
        valid_rcode = 0 <= rcode <= 15
    except TypeError:
        valid_rcode = False
    if not valid_rcode:
        rcode = 2
    flags = 0x8000 | 0x0400 | rcode  # QR | AA | rcode
    return struct.pack(">HHHHHH", qid, flags, 0, 0, 0, 0)
