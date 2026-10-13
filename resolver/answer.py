"""Answer handler for cybernet-resolver.

The handler's whole decision tree:

    qname
      ├─ ends in .cyberspace, A/AAAA
      │     → resolve_cyberspace(qname, mirror)      # the six-step fail-closed resolver
      │        ├─ binding verified + live
      │        │     → node_url host resolved to address(es) of the asked family
      │        │       ├─ found  → NOERROR + A/AAAA answers, TTL = min(expires_at, cap)
      │        │       └─ none   → NOERROR, no answers (NODATA: name exists, family absent)
      │        └─ any failure → NXDOMAIN             # silence, never a guess
      ├─ ends in .cyberspace, other qtype → NOERROR, no answers (NODATA)
      ├─ anything else → forwarded to the upstream resolver untouched
      └─ malformed packet → SERVFAIL

The handler never answers from anything except resolve_cyberspace()'s
verified, unexpired, live-pinged result: the daemon adds no trust of its
own. A lying mirror can withhold a name (→ NXDOMAIN) but never redirect
one — the same guarantee Phase 1 makes to agent clients.
"""

import ipaddress
import socket
import urllib.parse
from datetime import datetime, timezone

from .dns import _read_name, build_response, error_response, parse_query

# Imported late on purpose: core.py is the six-step resolver's home.
# Its import has no network side effects (threads spawn only on demand).
from core import CYBERSPACE_SUFFIX, _parse_claim_time, resolve_cyberspace  # noqa: E402

QTYPE_A = 1
QTYPE_AAAA = 28
DEFAULT_TTL_CAP = 300       # seconds — revoked/expired names stop fast
UPSTREAM_TIMEOUT = 3.0      # seconds — a hanging upstream must not hang the daemon


def _ttl_for(expires_at: str, cap: int = DEFAULT_TTL_CAP) -> int:
    """TTL = min(seconds until the binding expires, cap), floored at 0.

    resolve_cyberspace() already proved expires_at parses and is in the
    future; the floor is a belt, not a crutch. The belt speaks the same
    language as the proof: the strict canonical-UTC parser every other
    claim-time seat uses. A stamp in any other spelling (date-only,
    fractional seconds, space separator, non-UTC offset, naive) floors
    at 0 here too — fromisoformat accepted all of those, and a naive
    stamp was silently read as UTC.
    """
    # The cap is caller-supplied (daemon env derives a real int, but
    # hand-built callers can pass anything): a bool aliased through
    # min/max (True -> a 1-second TTL, False -> 0), a float returned a
    # float TTL build_response then refused inside handle_query, and a
    # string/None raised TypeError from the comparison — all breaking
    # handle_query's never-raises path. A cap that is not a real int
    # (bool excluded, twin of dns._is_int) falls back to the default,
    # exactly as daemon._env_int falls back on a bad env value.
    if isinstance(cap, bool) or not isinstance(cap, int):
        cap = DEFAULT_TTL_CAP
    try:
        exp = _parse_claim_time(expires_at)
        seconds = int((exp - datetime.now(timezone.utc)).total_seconds())
    except (ValueError, TypeError):
        seconds = 0
    return max(0, min(cap, seconds))


def _family_addresses(node_url: str, qtype: int) -> list[bytes]:
    """Resolve the node_url host to wire-format addresses of the asked family.

    Returns the raw rdata bytes (4 for A, 16 for AAAA). Any failure —
    unparsable URL, DNS failure, no family match — returns []. The caller
    answers NXDOMAIN/NODATA; this function never guesses.
    """
    # The family lookup sat outside the guard below: an unasked qtype
    # (2, 255, "1", None) escaped as a raw KeyError instead of [], and
    # True/1.0 aliased through the dict key to the A family, answering
    # a family nobody asked for. Only a real int A/AAAA has a family
    # (bool excluded, twin of _ttl_for's cap gate); anything else has
    # no addresses, exactly like a family with no match.
    if (isinstance(qtype, bool) or not isinstance(qtype, int)
            or qtype not in (QTYPE_A, QTYPE_AAAA)):
        return []
    # The node_url is caller-supplied too (handle_query str()-coerces
    # its result dict, but the library seat is public): a non-string
    # escaped as AttributeError from urlsplit's .decode (int/float),
    # and a bytes URL was parsed and its host resolved — answering
    # for a URL nobody asked as a string. Only a real string has a
    # host; anything else has no addresses, exactly like junk input.
    if not isinstance(node_url, str):
        return []
    want = {QTYPE_A: socket.AF_INET, QTYPE_AAAA: socket.AF_INET6}[qtype]
    try:
        host = urllib.parse.urlsplit(node_url).hostname or ""
        if not host:
            return []
        infos = socket.getaddrinfo(host, None, family=want, type=socket.SOCK_STREAM)
    except (OSError, UnicodeError, ValueError):
        return []
    out: list[bytes] = []
    for info in infos:
        try:
            out.append(socket.inet_pton(want, info[4][0]))
        except OSError:
            continue
    # Dedupe, keep order.
    return list(dict.fromkeys(out))


def _upstream_target(upstream: tuple[str, int]):
    """(family, sockaddr, expected source IP) the forward wire dials.

    A literal keeps its own family and (host, port) target, exactly as
    before (an IPv6 literal — daemon._parse_upstream's "[v6]:port"
    form, stored unbracketed — needs AF_INET6; an AF_INET sendto to it
    raises and every forward would SERVFAIL). A HOSTNAME is resolved
    first (getaddrinfo, AF_UNSPEC) and the socket is created from the
    answer's family, dialing the resolved sockaddr, with that address
    as the expected reply source — the family can no longer be guessed
    from the string's shape. Before, every hostname picked AF_INET
    and sendto carried the unresolved string, so an upstream reached
    by a v6-only hostname (a host:port form _parse_upstream explicitly
    accepts) was never reached on the UDP wire and every forward
    SERVFAILed. First getaddrinfo result wins. An unresolvable
    hostname raises gaierror here, which _forward already reads as
    SERVFAIL, honestly."""
    host, port = upstream
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC,
                                   socket.SOCK_DGRAM)
        family, _kind, _proto, _canon, sockaddr = infos[0]
        return family, sockaddr, str(ipaddress.ip_address(sockaddr[0]))
    family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
    return family, (host, port), str(ip)


def _forward(raw: bytes, upstream: tuple[str, int]) -> bytes:
    """Relay the untouched query to the upstream resolver, return its reply
    byte-for-byte. Any failure answers SERVFAIL — the daemon forwards or
    admits failure, never invents.

    Note for testing: the dev sandbox blocks UDP sends (seccomp), so the
    live-relay path can't be exercised there — the handler's relay logic
    (verbatim send, reply passthrough, SERVFAIL on failure) is covered by
    the monkeypatched-socket harness instead. Exercise the real wire path
    on the HQ node when wiring it up."""
    try:
        family, target, expected = _upstream_target(upstream)
        sock = socket.socket(family, socket.SOCK_DGRAM)
        try:
            sock.settimeout(UPSTREAM_TIMEOUT)
            sock.sendto(raw, target)
            # Read a whole datagram (65535, the UDP maximum — twin of
            # daemon._serve_udp's read buffer): the query is forwarded
            # untouched, so a query carrying EDNS legitimately draws a
            # reply far past the classic 512, and recvfrom(512) silently
            # amputated it mid-record — the header counts still claimed
            # the bytes that were never delivered, breaking this
            # function's byte-for-byte contract.
            reply, source = sock.recvfrom(65535)
            # The datagram's SOURCE is part of the transaction (twin
            # of client._query_udp and wiring/smoke._query): UDP has
            # no connection, so a reply is only the upstream's if it
            # arrives from the exact (address, port) the query was
            # sent to. Before, the source was discarded, so any
            # perfectly formed packet that reached the ephemeral port
            # was relayed to the asker byte-for-byte as the upstream's
            # word. A stranger's packet is a failed forward: SERVFAIL,
            # never an invented (or borrowed) answer.
            try:
                source_ip = str(ipaddress.ip_address(source[0]))
            except ValueError:
                source_ip = source[0]
            if (source_ip, source[1]) != (expected, target[1]):
                return error_response(raw, 2)
            # The reply's TRANSACTION ID is part of the transaction
            # too (twin of client._parse_response's txid check and
            # wiring/smoke's): the query leaves untouched, so its
            # reply must echo its first two bytes. Before, a packet
            # from the exact upstream source carrying another query's
            # txid — a late reply to an earlier forward on a reused
            # ephemeral port — was relayed byte-for-byte as THIS
            # query's answer. A mismatched (or impossibly short)
            # reply is a failed forward: SERVFAIL, never a borrowed
            # answer.
            if len(reply) < 2 or bytes(reply[:2]) != raw[:2]:
                return error_response(raw, 2)
            # A reply must also BE a response: the QR bit (top bit of
            # the flags word) is what makes a packet an answer at all
            # (twin of client._parse_response's first check). Before,
            # a right-source, right-txid packet with QR clear — a
            # query, not an answer — was relayed byte-for-byte, and a
            # txid-only stub with no flags word at all passed likewise.
            # Unlike the daemon's own replies, an upstream's flags are
            # NOT otherwise policed here: a recursive resolver
            # legitimately sets RA and clears AA. Only QR is refused.
            # A reply must also carry a whole header: a DNS header is
            # 12 bytes (client._parse_response's first check), so a
            # QR-set stub of 4-11 bytes — txid and flags but truncated
            # counts — is not a response at all, however well addressed.
            if len(reply) < 12 or not reply[2] & 0x80:
                return error_response(raw, 2)
            # The reply's OPCODE must echo the query's (byte 2, bits
            # 6-3 — mask 0x78): an opcode is part of what was asked, so
            # a response carrying a different one answers a different
            # kind of question, however well addressed (client refuses
            # any opcode but the standard-query one on daemon replies;
            # a forwarder is generic — parse_query admits any opcode —
            # so the rule here is echo, not zero). A mismatched-opcode
            # reply is a failed forward: SERVFAIL, never a borrowed
            # answer.
            if reply[2] & 0x78 != raw[2] & 0x78:
                return error_response(raw, 2)
            # The reply must echo THIS query's question: exactly one
            # question, naming the asked name (case-insensitively) with
            # the asked type and class (twin of client._parse_response's
            # different-question refusal). Before, a right-source,
            # right-txid, QR-set, right-opcode reply whose question
            # named another name or family was relayed byte-for-byte —
            # its answers belong to another question. A generic
            # forwarder relays many names and families, so the rule is
            # echo, not any fixed value. A reply with no question, a
            # truncated question, or a mismatched one is a failed
            # forward: SERVFAIL, never a borrowed answer.
            if reply[4:6] != b"\x00\x01":
                return error_response(raw, 2)
            try:
                asked = parse_query(raw)
                seen_name, seen_off = _read_name(reply, 12)
                if seen_off + 4 > len(reply):
                    return error_response(raw, 2)
                seen_qtype, seen_qclass = (
                    int.from_bytes(reply[seen_off:seen_off + 2], "big"),
                    int.from_bytes(reply[seen_off + 2:seen_off + 4], "big"),
                )
            except ValueError:
                return error_response(raw, 2)
            if (seen_name.lower() != asked["qname"].lower()
                    or seen_qtype != asked["qtype"]
                    or seen_qclass != asked["qclass"]):
                return error_response(raw, 2)
            # The reply's counted sections must actually BE there, and
            # the packet must end exactly where they end: before, a
            # right-source, right-txid, QR-set, right-opcode reply
            # echoing the right question but claiming records its body
            # never contained (an answer count with no answer bytes, a
            # truncated record header, an rdlen running past the end)
            # — or carrying uncounted bytes after its last record —
            # was relayed byte-for-byte, while client._parse_response
            # has always refused truncated sections and trailing bytes
            # alike. The walk is generic (answer + authority +
            # additional, any type/class): a recursive upstream
            # legitimately carries all three sections, but no
            # legitimate reply claims bytes it does not hold or
            # appends bytes no count owns. A structurally impossible
            # reply is a failed forward: SERVFAIL, never a borrowed
            # answer.
            try:
                off = seen_off + 4
                records = sum(
                    int.from_bytes(reply[i:i + 2], "big") for i in (6, 8, 10)
                )
                for _ in range(records):
                    _owner, off = _read_name(reply, off)
                    if off + 10 > len(reply):
                        return error_response(raw, 2)
                    rdlen = int.from_bytes(reply[off + 8:off + 10], "big")
                    off += 10 + rdlen
                    if off > len(reply):
                        return error_response(raw, 2)
            except ValueError:
                return error_response(raw, 2)
            if off != len(reply):
                return error_response(raw, 2)
            return bytes(reply)
        finally:
            sock.close()
    except OSError:
        return error_response(raw, 2)


def handle_query(raw: bytes, *, mirror_url: str, upstream: tuple[str, int],
                 ttl_cap: int = DEFAULT_TTL_CAP) -> bytes:
    """One DNS question in, one DNS response out. See the module docstring."""
    try:
        query = parse_query(raw)
    except ValueError:
        return error_response(raw, 2)

    qname = (query["qname"] or "").lower()
    qtype = query["qtype"]

    if not qname.endswith(CYBERSPACE_SUFFIX):
        return _forward(raw, upstream)

    if qtype not in (QTYPE_A, QTYPE_AAAA):
        return build_response(query, [], 0)  # NODATA: our zone, unhandled type

    result = resolve_cyberspace(qname, mirror_url)
    if result is None:
        return build_response(query, [], 3)  # NXDOMAIN: the namespace is silent

    addrs = _family_addresses(str(result.get("node_url", "")), qtype)
    if not addrs:
        return build_response(query, [], 0)  # NODATA: name lives, family absent
    ttl = _ttl_for(str(result.get("expires_at", "")), ttl_cap)
    return build_response(query, [(qtype, ttl, a) for a in addrs], 0)
