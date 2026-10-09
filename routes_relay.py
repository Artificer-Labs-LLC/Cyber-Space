"""Relay server half, part 1 — hold-open registration (docs/HOSTING.md,
primitive 3). The dial half already exists in core.py (_relay_route /
_relay_open_session): a NAT-hidden hoster announces a relay strategy in
its reach list, and the dialer POSTs {relay}/relay/open. This module is
the other side of that socket.

Tor-model shape: the relay is a public node that holds host-initiated
hold-opens. NAT penetration is the HOSTER's outbound dial — the relay
never dials inbound. The relay sees bytes, never identity: a routing
token (name-key-signed into the hoster's descriptor, which the dialer
already verified) is the only thing that maps a dialer session to a
hoster's hold-open.

Part 1 wires the registration side:
  POST /relay/register  {"token": ...} -> 200 {"ok": true, "ttl": 300}
      The hoster's dial announcing it is holding this routing token.
  POST /relay/keepalive {"token": ...} -> 200 {"ok": true, "ttl": 300}
      Renews the hold-open before the TTL reaps it.
  POST /relay/open     {"name": label, "token": token}
      The dialer's session-open from core.py. Part 1 mints a session
      {session_id, challenge} and records it under the token's hold-open.
      Part 1 returned 404 because the answer half did not exist yet.
      Part 2 (below) adds the hoster's hold-open long-poll
      (POST /relay/wait) and the signed-answer bridge
      (POST /relay/answer): /relay/open now waits for the hoster to
      answer and returns 200 {"challenge", "name_key_sig"} — the exact
      pair the dial half (core.py _relay_open_session) expects and
      verifies fail-closed against the name key. The relay still sees
      bytes, never identity: it shape-checks the signature (128 hex),
      never verifies it — the DIALER verifies. Anything else is still
      404 silence.

Hold-opens and sessions live in memory, reaped lazily on every write
path; TTL is 300s (register) / 60s (session), no persistence — a relay
reboot simply drops hold-opens and hosters re-register on their own
cadence. Never raises; HTTP 404/429 carry the failure shapes.
"""
import asyncio
import secrets
import time
import threading

from fastapi import APIRouter, HTTPException, Request

from core import _check_rate, _RELAY_TOKEN_CAP
import rendezvous

router = APIRouter()

# Hold-open TTL: the hoster's dial must renew inside this window or the
# routing token is reaped and /relay/open stops matching it.
_RELAY_HOLD_TTL = 300.0
# Session TTL: a minted challenge must be answered inside this window.
_RELAY_SESSION_TTL = 60.0
# /relay/open waits this long for the hoster to answer before going
# silent. Must stay inside the dial half's _RESOLVE_TIMEOUT (8s) with
# margin left for the dial-side name-key verification.
_RELAY_ANSWER_WAIT = 7.0
# /relay/wait long-poll ceiling: the hoster's hold-open cycle re-dials
# inside this window.
_RELAY_HOLD_WAIT = 25.0
# Poll slice for the two waiting loops above (cooperative async sleeps).
_RELAY_POLL_SLICE = 0.05

_relay_lock = threading.Lock()
# token -> {"registered": epoch, "seen": epoch}
_relay_hold_opens: dict = {}
# session_id -> {"token": token, "challenge": 64-hex, "created": epoch}
_relay_sessions: dict = {}
# Rendezvous pairing index (docs/RENDEZVOUS.md frozen spec, primitive 3):
# point_id (64 hex, derived by BOTH sides from the name key and the
# epoch, nobody's choice) -> {"token": token, "name_pub": 64 hex,
# "seen": epoch}. The relay never learns the label — the point is
# opaque — and session material is still name-key-signed end-to-end.
# The point rides the shipped hold-open protocol unmodified: the hoster
# holds the derived points at the same mirror with its own tokens.
_relay_rendezvous: dict = {}


def _relay_belt(request: Request, surface: str) -> None:
    client = request.client
    ip = client.host if client else "unknown"
    _check_rate(f"relay:{surface}:{ip}", limit=60, window=60.0)


def _valid_token(token) -> str:
    if not isinstance(token, str) or not token:
        raise HTTPException(status_code=400, detail="token is required.")
    if len(token) > _RELAY_TOKEN_CAP:
        raise HTTPException(
            status_code=400,
            detail=f"token exceeds {_RELAY_TOKEN_CAP} chars.")
    return token


def _reap_relay(now: float) -> None:
    for t, rec in list(_relay_hold_opens.items()):
        if now - rec["seen"] > _RELAY_HOLD_TTL:
            _relay_hold_opens.pop(t, None)
    for s, rec in list(_relay_sessions.items()):
        if now - rec["created"] > _RELAY_SESSION_TTL:
            _relay_sessions.pop(s, None)
    for p, rec in list(_relay_rendezvous.items()):
        if now - rec["seen"] > _RELAY_HOLD_TTL:
            _relay_rendezvous.pop(p, None)


def _valid_rendezvous(point_id, name_pub, epoch_len=None):
    """Shape-proof a register-time rendezvous binding. Returns
    (point_id, name_pub, epoch_len) when both are well-formed 64-hex AND
    the point is willing right now (current-or-previous epoch under the
    binding's epoch_len, per the frozen epoch-tolerance spec); None when
    no binding was offered; raises 400 when a binding was offered but is
    stale or malformed — a hoster that miscomputed its point is told so,
    never silently mispaired. epoch_len is addition-only (the descriptor
    advertises it): malformed values refuse the binding, never a default
    guess — the point math must agree exactly on both sides."""
    if point_id is None and name_pub is None:
        return None
    for v in (point_id, name_pub):
        if not isinstance(v, str) or len(v) != 64:
            raise HTTPException(
                status_code=400,
                detail="rendezvous_point and name_pub must be 64 hex.")
        try:
            bytes.fromhex(v)
        except Exception:
            raise HTTPException(
                status_code=400,
                detail="rendezvous_point and name_pub must be 64 hex.")
    if epoch_len is None:
        epoch_len = rendezvous.EPOCH_LEN_DEFAULT
    if not rendezvous._epoch_len_ok(epoch_len):
        raise HTTPException(
            status_code=400,
            detail="epoch_len must be an integer in 60..86400.")
    if not rendezvous.point_is_current(point_id, time.time(), name_pub,
                                       epoch_len):
        raise HTTPException(
            status_code=400,
            detail="rendezvous point is not in a willing epoch.")
    return point_id, name_pub, epoch_len


def _resolve_rendezvous_token(point_id) -> str | None:
    """Resolve a derived rendezvous point to the held routing token for
    /relay/open. Returns the token only when the point is registered,
    fresh, still indexed under a live hold-open, AND in a willing epoch
    (current-or-previous, per the frozen spec). Malformed, unregistered,
    stale, or old-epoch points resolve to None — the caller answers 404
    silence, never a 4xx. The mirror pairs hold-opens by the point; it
    never learns the label."""
    if not isinstance(point_id, str) or len(point_id) != 64:
        return None
    try:
        bytes.fromhex(point_id)
    except Exception:
        return None
    with _relay_lock:
        _reap_relay(time.monotonic())
        prec = _relay_rendezvous.get(point_id)
        if prec is None:
            return None
        token = prec["token"]
        if token not in _relay_hold_opens:
            return None
        if not rendezvous.point_is_current(point_id, time.time(),
                                           prec["name_pub"],
                                           prec.get("epoch_len",
                                                    rendezvous.EPOCH_LEN_DEFAULT)):
            return None
        return token


@router.post("/relay/register")
async def relay_register(request: Request, body: dict):
    """Hold-open registration (part 1). Optional rendezvous binding
    (docs/RENDEZVOUS.md frozen spec): the hoster may also index this
    hold-open under a derived rendezvous point so a dialer can pair it
    without the mirror being steered. The hold-open protocol itself is
    unmodified — the point is an extra key on the same hold-open."""
    _relay_belt(request, "register")
    token = _valid_token((body or {}).get("token"))
    bind = _valid_rendezvous((body or {}).get("rendezvous_point"),
                             (body or {}).get("name_pub"),
                             (body or {}).get("epoch_len"))
    now = time.monotonic()
    with _relay_lock:
        _reap_relay(now)
        _relay_hold_opens[token] = {"registered": now, "seen": now}
        if bind is not None:
            point_id, name_pub, epoch_len = bind
            _relay_rendezvous[point_id] = {
                "token": token, "name_pub": name_pub,
                "epoch_len": epoch_len, "seen": now}
    return {"ok": True, "ttl": _RELAY_HOLD_TTL}


@router.post("/relay/keepalive")
async def relay_keepalive(request: Request, body: dict):
    _relay_belt(request, "keepalive")
    token = _valid_token((body or {}).get("token"))
    now = time.monotonic()
    with _relay_lock:
        _reap_relay(now)
        rec = _relay_hold_opens.get(token)
        if rec is None:
            raise HTTPException(
                status_code=404, detail="no hold-open for this token.")
        rec["seen"] = now
        for p, prec in _relay_rendezvous.items():
            if prec["token"] == token:
                prec["seen"] = now
    return {"ok": True, "ttl": _RELAY_HOLD_TTL}


@router.get("/relay/hold_query")
async def relay_hold_query(request: Request, point_id: str = ""):
    """Rendezvous willingness probe (docs/RENDEZVOUS.md frozen spec):
    is a hold-open being held under this derived point? True only when
    the point is registered, fresh, AND still in a willing epoch
    (current-or-previous — older epochs fail closed and SILENT, so a
    hoster whose daemon stopped re-registering reads as absent, never
    as a lie). Anything malformed answers held:false, never a 4xx —
    the dialer derives the point itself, nothing to correct. The mirror
    pairs hold-opens by the point; it never learns the label."""
    _relay_belt(request, "hold_query")
    try:
        if not isinstance(point_id, str) or len(point_id) != 64:
            return {"held": False}
        bytes.fromhex(point_id)
        now_mono = time.monotonic()
        with _relay_lock:
            _reap_relay(now_mono)
            prec = _relay_rendezvous.get(point_id)
            if prec is None:
                return {"held": False}
            if now_mono - prec["seen"] > _RELAY_HOLD_TTL:
                return {"held": False}
            if not rendezvous.point_is_current(point_id, time.time(),
                                               prec["name_pub"],
                                               prec.get("epoch_len",
                                                        rendezvous.EPOCH_LEN_DEFAULT)):
                return {"held": False}
            if prec["token"] not in _relay_hold_opens:
                return {"held": False}
            return {"held": True}
    except Exception:
        return {"held": False}


@router.post("/relay/open")
async def relay_open(request: Request, body: dict):
    """Dialer session-open (part 2, bridging). Looks up the hoster's
    hold-open by routing token — or, for derived-point rendezvous, by the
    derived rendezvous_point the dialer computed from the name key (the
    dialer never learns the token) — mints a session + fresh challenge
    against
    it, then waits up to _RELAY_ANSWER_WAIT for the hoster to sign the
    challenge through /relay/answer. On an answer, returns 200 with the
    exact pair the dial half verifies:

      {"challenge": "<64 hex>", "name_key_sig": "<128 hex>"}

    The relay does NOT verify the signature — the dialer (core.py
    _relay_open_session) verifies it fail-closed against the binding's
    name key; the relay only shape-checks. Anything else (no hold-open,
    no answer in time) is 404 silence. The answer is consumed exactly
    once: a session can answer for one dial, and one dial only."""
    _relay_belt(request, "open")
    payload = body or {}
    raw_token = payload.get("token")
    if isinstance(raw_token, str) and raw_token:
        token = _valid_token(raw_token)
    else:
        # Derived-point rendezvous: resolve the point to the held routing
        # token. An unresolvable point (malformed, unregistered, stale,
        # old-epoch) is 404 silence, exactly like an unknown token.
        # When both are given, the explicit token wins.
        token = _resolve_rendezvous_token(payload.get("rendezvous_point"))
        if token is None:
            raise HTTPException(
                status_code=404, detail="no hold-open for this point.")
    label = payload.get("name")
    if not isinstance(label, str) or not label or len(label) > 64:
        raise HTTPException(status_code=400, detail="name is required.")
    now = time.monotonic()
    with _relay_lock:
        _reap_relay(now)
        if token not in _relay_hold_opens:
            raise HTTPException(
                status_code=404, detail="no hold-open for this token.")
        session_id = secrets.token_hex(16)
        challenge = secrets.token_hex(32)
        _relay_sessions[session_id] = {
            "token": token, "challenge": challenge, "created": now,
            "answer": None}
    deadline = time.monotonic() + _RELAY_ANSWER_WAIT
    while time.monotonic() < deadline:
        await asyncio.sleep(_RELAY_POLL_SLICE)
        with _relay_lock:
            rec = _relay_sessions.pop(session_id, None)
        if rec is None:
            break  # reaped — no answer can arrive
        if rec.get("answer") is not None:
            return {"challenge": rec["challenge"],
                    "name_key_sig": rec["answer"]}
        # Not answered yet: put it back for the hoster's next /relay/wait.
        with _relay_lock:
            if rec.get("answer") is None:
                _relay_sessions[session_id] = rec
    raise HTTPException(status_code=404, detail="hoster did not answer.")


@router.post("/relay/wait")
async def relay_wait(request: Request, body: dict):
    """Hoster's hold-open long-poll. Blocks up to _RELAY_HOLD_WAIT for a
    dialer's session to appear against this token, then returns it so
    the hoster can sign the challenge:

      {"ok": true, "sessions": [{"session_id": ..., "challenge": ...}]}

    Only unanswered sessions are listed. No hold-open for the token is
    404. Empty wait window returns an empty list — the hoster re-polls.
    The long-poll is the hoster's OWN outbound dial, so NAT penetration
    stays the hoster's dial, never the relay's."""
    _relay_belt(request, "wait")
    token = _valid_token((body or {}).get("token"))
    deadline = time.monotonic() + _RELAY_HOLD_WAIT
    while time.monotonic() < deadline:
        with _relay_lock:
            _reap_relay(time.monotonic())
            if token not in _relay_hold_opens:
                raise HTTPException(
                    status_code=404, detail="no hold-open for this token.")
            sessions = [{"session_id": s, "challenge": r["challenge"]}
                        for s, r in _relay_sessions.items()
                        if r["token"] == token and r.get("answer") is None]
        if sessions:
            return {"ok": True, "sessions": sessions}
        await asyncio.sleep(_RELAY_POLL_SLICE)
    return {"ok": True, "sessions": []}


@router.post("/relay/answer")
async def relay_answer(request: Request, body: dict):
    """Hoster's signed answer. Records the name-key signature over the
    minted challenge against the session; the waiting /relay/open picks
    it up and returns it to the dialer. The relay shape-checks the sig
    (128 hex) and routes bytes — it does NOT verify it, because the
    relay has no standing to vouch: the DIALER verifies fail-closed
    against the binding's name key (core.py _relay_open_session). An
    answer is consumed exactly once by its session. Unknown or expired
    session is 404. Never raises."""
    _relay_belt(request, "answer")
    payload = body or {}
    session_id = payload.get("session_id")
    if not isinstance(session_id, str) or not session_id:
        raise HTTPException(status_code=400, detail="session_id required.")
    sig = payload.get("name_key_sig")
    if not isinstance(sig, str) or len(sig) != 128:
        raise HTTPException(
            status_code=400, detail="name_key_sig must be 128 hex chars.")
    try:
        bytes.fromhex(sig)
    except Exception:
        raise HTTPException(
            status_code=400, detail="name_key_sig must be 128 hex chars.")
    with _relay_lock:
        _reap_relay(time.monotonic())
        rec = _relay_sessions.get(session_id)
        if rec is None:
            raise HTTPException(
                status_code=404, detail="unknown or expired session.")
        if rec.get("answer") is not None:
            raise HTTPException(
                status_code=404, detail="session already answered.")
        rec["answer"] = sig
    return {"ok": True}


# Test hook: the hoster long-poll half reads pending sessions through
# this, not the raw dict.
def _relay_pending_sessions(token: str) -> list:
    now = time.monotonic()
    with _relay_lock:
        _reap_relay(now)
        return [{"session_id": s, "challenge": r["challenge"],
                 "created": r["created"]}
                for s, r in _relay_sessions.items() if r["token"] == token]
