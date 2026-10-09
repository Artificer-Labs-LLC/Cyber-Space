"""DNS-over-HTTPS bridge for .cyberspace (RFC 8484).

Phones can't run the UDP resolver daemon or do split-horizon wiring, but
they can speak DoH. This endpoint lets any DoH-capable client resolve
.cyberspace names by typing them — no IP, no asterisk. The canonical name
works anywhere.

POST /dns-query with Content-Type: application/dns-message, body = raw
DNS wire-format query. Returns application/dns-message with the wire-format
response. GET with ?dns=<base64url> also accepted per RFC 8484.

The query is handed to resolver.answer.handle_query — the same fail-closed
six-step verification as the UDP daemon. This bridge adds no trust of its
own; it only changes the transport. Blocking DNS work runs in a thread
(asyncio.to_thread) so the event loop stays free for the nested mirror
requests handle_query makes.
"""
import asyncio
import base64

from fastapi import APIRouter, Request, Response, HTTPException

from core import _check_rate
from resolver.answer import handle_query
from resolver.dns import error_response

router = APIRouter()

MIRROR_URL = "http://127.0.0.1:8471"
UPSTREAM = ("1.1.1.1", 53)
TTL_CAP = 300


DNS_BODY_LIMIT = 4096

# DoH is the only mounted router with no rate limit, and every query runs
# blocking network I/O (nested mirror HTTP + upstream UDP inside
# asyncio.to_thread on the shared default executor). Per-client-IP budget
# closes the threadpool-exhaustion thread: 120 queries/min/IP — 4x the
# generic bucket, because DNS clients are chattery, but still boundable so
# one IP can't camp the whole executor. The check runs before any body
# work, so a saturated IP never costs a thread.
DOH_RATE_LIMIT = 120
DOH_RATE_WINDOW = 60.0

# The rate gate bounds queries per minute, not queries *in flight*: a DoH
# resolution makes up to four sequential network round-trips (mirror
# binding, directory, node ping, claim re-fetch, each up to 8s against a
# slow mirror) inside asyncio.to_thread. One IP firing its whole 120/min
# budget at once parks 120 thread tasks on the 32-thread default executor
# and starves every concurrent resolution — its own legitimate clients
# first. Concurrency gates, per IP and global, answer 429 past the bound;
# the rate check still runs first so a saturated IP never reaches the
# inflight bookkeeping.
DOH_CONCURRENT_GLOBAL = 16   # executor headroom: leaves threads free
DOH_CONCURRENT_PER_IP = 4    # a real DNS client is chattery, not parallel
_DOH_SEM_IP_CAP = 4096       # per-IP gate state; oldest evicted past cap

_doh_inflight_global = 0
_doh_inflight: dict[str, int] = {}


def _doh_concurrency_gate(request: Request) -> None:
    """Claim one in-flight DoH slot for this client IP. Callers must release
    in a finally block. Raises 429 when the IP or the global bound is hit —
    a DNS client that wants 5 answers at once is a misbehaving one."""
    global _doh_inflight_global
    ip = request.client.host if request.client else "unknown"
    n = _doh_inflight.get(ip, 0)
    if n >= DOH_CONCURRENT_PER_IP or \
            _doh_inflight_global >= DOH_CONCURRENT_GLOBAL:
        raise HTTPException(status_code=429,
                            detail="Too many concurrent DNS queries")
    if ip not in _doh_inflight:
        if len(_doh_inflight) >= _DOH_SEM_IP_CAP:
            _doh_inflight.pop(next(iter(_doh_inflight)))
        _doh_inflight[ip] = 0
    _doh_inflight[ip] += 1
    _doh_inflight_global += 1


def _doh_concurrency_release(request: Request) -> None:
    global _doh_inflight_global
    ip = request.client.host if request.client else "unknown"
    n = _doh_inflight.get(ip, 1)
    _doh_inflight[ip] = n - 1
    if _doh_inflight[ip] <= 0:
        _doh_inflight.pop(ip, None)
    _doh_inflight_global = max(0, _doh_inflight_global - 1)


def _doh_check_rate(request: Request) -> None:
    client = request.client
    ip = client.host if client else "unknown"
    _check_rate(f"doh:{ip}", limit=DOH_RATE_LIMIT,
                window=DOH_RATE_WINDOW)


async def _read_bounded_body(request: Request) -> bytes:
    # Bound the request body *before* it can be buffered whole: a claimed
    # Content-Length past the limit is rejected without reading a byte, then
    # the body streams in chunks with an accumulating cap so a lying header
    # or a chunked body can't allocate past the DNS message limit ahead of
    # the check. (The old path used request.body() and only checked
    # len(raw) > 4096 afterwards — a megabyte POST was buffered whole
    # before the bound ran.)
    try:
        claimed = int(request.headers.get("content-length") or 0)
    except ValueError:
        claimed = 0
    if claimed > DNS_BODY_LIMIT:
        raise HTTPException(status_code=413, detail="DNS message too large")
    chunks = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > DNS_BODY_LIMIT:
            raise HTTPException(status_code=413,
                                detail="DNS message too large")
        chunks.append(chunk)
    return b"".join(chunks)


def _answer_wire(raw: bytes) -> bytes:
    # Belt, not a crutch: handle_query is contractually fail-closed (parse
    # raises ValueError only, resolve_cyberspace swallows Exception, the
    # bridge bound the body before it could be buffered) — but a DoH client
    # must never get an HTTP 500 where a DNS answer belongs. Any residual
    # exception (a future codec path, a library quirk) becomes SERVFAIL,
    # never silence and never a traceback: error_response never raises, so
    # this path can't fail either.
    try:
        return handle_query(raw, mirror_url=MIRROR_URL, upstream=UPSTREAM,
                            ttl_cap=TTL_CAP)
    except Exception:
        return error_response(raw, 2)


@router.post("/dns-query")
async def doh_post(request: Request):
    _doh_check_rate(request)
    ctype = (request.headers.get("content-type") or "").split(";")[0].strip()
    if ctype != "application/dns-message":
        raise HTTPException(status_code=415,
                            detail="Content-Type must be application/dns-message")
    raw = await _read_bounded_body(request)
    if not raw:
        raise HTTPException(status_code=400, detail="Bad DNS message")
    _doh_concurrency_gate(request)
    try:
        wire = await asyncio.to_thread(_answer_wire, raw)
    finally:
        _doh_concurrency_release(request)
    return Response(content=wire, media_type="application/dns-message")


def _decode_dns_param(dns: str) -> bytes:
    # Bound the *encoded* length first: a 4096-byte DNS message base64url-encodes
    # to at most 5464 chars (ceil(4096/3)*4), so anything longer can only ever
    # decode to an oversize message. Rejecting before the decode keeps a
    # megabyte-long ?dns= string from being decoded into memory ahead of the
    # decoded-bytes bound below.
    if not dns or len(dns) > 5464:
        raise HTTPException(status_code=400, detail="Bad dns parameter")
    try:
        raw = base64.urlsafe_b64decode(dns + "=" * (-len(dns) % 4))
    except Exception:
        raise HTTPException(status_code=400, detail="Bad dns parameter")
    if not raw or len(raw) > 4096:
        raise HTTPException(status_code=400, detail="Bad DNS message")
    return raw


@router.get("/dns-query")
async def doh_get(request: Request, dns: str = ""):
    _doh_check_rate(request)
    raw = _decode_dns_param(dns)
    _doh_concurrency_gate(request)
    try:
        wire = await asyncio.to_thread(_answer_wire, raw)
    finally:
        _doh_concurrency_release(request)
    return Response(content=wire, media_type="application/dns-message")
