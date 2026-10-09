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

import socket
import urllib.parse
from datetime import datetime, timezone

from .dns import build_response, error_response, parse_query

# Imported late on purpose: core.py is the six-step resolver's home.
# Its import has no network side effects (threads spawn only on demand).
from core import CYBERSPACE_SUFFIX, resolve_cyberspace  # noqa: E402

QTYPE_A = 1
QTYPE_AAAA = 28
DEFAULT_TTL_CAP = 300       # seconds — revoked/expired names stop fast
UPSTREAM_TIMEOUT = 3.0      # seconds — a hanging upstream must not hang the daemon


def _ttl_for(expires_at: str, cap: int = DEFAULT_TTL_CAP) -> int:
    """TTL = min(seconds until the binding expires, cap), floored at 0.

    resolve_cyberspace() already proved expires_at parses and is in the
    future; the floor is a belt, not a crutch.
    """
    try:
        exp = datetime.fromisoformat(expires_at)
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
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
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.settimeout(UPSTREAM_TIMEOUT)
            sock.sendto(raw, upstream)
            reply, _ = sock.recvfrom(512)
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
