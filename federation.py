from fastapi import APIRouter, Header, HTTPException, Request
from fed import ed25519 as _fed_ed25519
from fed import envelope as _fed_env
from datetime import datetime, timedelta, timezone
import json
import os
import re
import hashlib
import secrets
import time
import urllib.request
from collections import OrderedDict
from core import (CAP_RE, IS_GENESIS, MAX_BODY, NAME_RE, NODE_NAME, RATE_LIMIT,
                  RATE_WINDOW, _NODE_PRIV, _NODE_PUB, _NODE_URL_RE, _authed,
                  _broadcast, _check_rate, _db, _db_lock, _delta_payload,
                  _countersign_payload, _hash_key, _invite_payload, _leave_payload,
                  _now, _pigeonhole_cutoff, _post_message, _removed_payload,
                  _valid_name, _valid_node_url, ingest_gossiped_binding,
                  request_source)

router = APIRouter()

def _recv_attestation(delta, sender_pub: str, retire: bool):
    """Validate a `body.delta` self-attestation carried on /fed/announce or
    /fed/retire (docs/FEDERATION.md: Gossip v1, delta-sync send half).
    The attestation is the row owner's signature over the canonical
    _delta_payload(row, seq, retire) — only the owner can mint it and
    only for its own row, so a gossiping peer can never plant one.
    Returns (sig_hex, seq) when well-formed and verifiable; (None, None)
    when absent or malformed. Malformed attestations are ignored, never
    fatal: the announce/retire itself still applies."""
    if not isinstance(delta, dict):
        return None, None
    row = delta.get("row")
    if not isinstance(row, dict):
        return None, None
    if str(row.get("node_pub", "")).lower() != sender_pub.lower():
        return None, None
    seq = delta.get("seq")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
        return None, None
    sig_hex = str(delta.get("sig", ""))
    try:
        ok = _fed_ed25519.checkvalid(
            bytes.fromhex(sig_hex),
            _delta_payload(row, seq, retire),
            bytes.fromhex(sender_pub))
    except Exception:
        ok = False
    if not ok:
        return None, None
    return sig_hex, seq


@router.get("/fed/ping")
def fed_ping():
    """Federation liveness probe: returns the node's identity card as a
    signed envelope (docs/FEDERATION.md primitive 2a)."""
    body = {
        "name": NODE_NAME,
        "network": "cybernet",
        "version": "0.1.0",
        "node_pub": _NODE_PUB,
        "genesis": IS_GENESIS,
    }
    return _fed_env.make_envelope(_NODE_PRIV, _NODE_PUB, "federation", body, kind="ping")


@router.post("/fed/announce")
def fed_announce(env: dict):
    """Federation capability broadcast: verify the peer's signed announcement
    and store it as a roster entry (docs/FEDERATION.md primitive 2b).
    Stored as seen-from-peer, never as gospel. Recipient must be
    "federation" (broadcast) or this node's own pubkey (direct)."""
    if not isinstance(env, dict) or not _fed_env.verify_envelope(env, expect_kind="announce"):
        raise HTTPException(status_code=400, detail="invalid envelope")
    if env.get("recipient") not in ("federation", _NODE_PUB):
        raise HTTPException(status_code=400, detail="not addressed to this node")
    body = env.get("body")
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="invalid envelope")
    sender_pub = env.get("sender_pub")
    if body.get("node_pub") != sender_pub:
        raise HTTPException(status_code=400, detail="sender_pub mismatch")
    name = str(body.get("name", ""))
    if not re.fullmatch(r"[a-z0-9_-]{1,32}", name):
        raise HTTPException(status_code=400, detail="bad node name")
    caps = body.get("capabilities", [])
    if not isinstance(caps, list):
        caps = []
    caps = [c for c in caps if isinstance(c, str) and CAP_RE.fullmatch(c)][:32]
    node_url = ""
    if body.get("node_url"):
        node_url = _valid_node_url(str(body.get("node_url")))
    now = datetime.now(timezone.utc).isoformat()
    # A self-attestation (docs/FEDERATION.md: delta-sync send half) rides
    # along when present and verifiable; attestation-less or malformed
    # deltas keep whatever delta_sig/dir_seq the row already had ('' on a
    # fresh row) and are never forwarded.
    att_sig, att_seq = _recv_attestation(body.get("delta"), sender_pub, False)
    with _db_lock, _db() as conn:
        conn.execute(
            """INSERT INTO peers (node_pub, name, network, version, genesis,
                                  capabilities, node_url, announced_at, first_seen,
                                  delta_sig, dir_seq)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(node_pub) DO UPDATE SET
                 name=excluded.name, network=excluded.network,
                 version=excluded.version, genesis=excluded.genesis,
                 capabilities=excluded.capabilities, node_url=excluded.node_url,
                 announced_at=excluded.announced_at,
                 retired_at='',  -- a fresh announce revives a retired peer
                 delta_sig=CASE WHEN excluded.delta_sig<>''
                                THEN excluded.delta_sig ELSE peers.delta_sig END,
                 dir_seq=CASE WHEN excluded.delta_sig<>''
                              THEN excluded.dir_seq ELSE peers.dir_seq END
            """,
            (
                sender_pub, name, str(body.get("network", "cybernet")),
                str(body.get("version", "0.1.0")), int(bool(body.get("genesis", False))),
                json.dumps(caps), node_url, now, now,
                att_sig or "", att_seq or 0,
            ),
        )
    return {"ok": True, "stored": name, "node_pub": sender_pub}


@router.post("/fed/retire")
def fed_retire(env: dict):
    """Federation retirement (docs/NODE_DIRECTORY.md retire primitive): a
    peer asks this node to stop treating it as a live peer. Signed envelope,
    recipient must be this node's own pubkey (direct), and
    body.from_node_pub must equal sender_pub. Retires as a tombstone
    (peers.retired_at) — the roster entry is kept but channel fan-out
    skips it and inbound pushes from it are rejected until it re-announces
    (a fresh /fed/announce clears the tombstone). Unknown peer -> 404.
    A self-attestation (`body.delta` over the retire payload) rides along
    when present and verifiable: the tombstone keeps the owner's signature
    so the producer can forward the retirement on the gossip path
    (docs/FEDERATION.md: Gossip v1, delta-sync send half)."""
    if not isinstance(env, dict) or not _fed_env.verify_envelope(env, expect_kind="retire"):
        raise HTTPException(status_code=400, detail="invalid envelope")
    if env.get("recipient") != _NODE_PUB:
        raise HTTPException(status_code=400, detail="not addressed to this node")
    body = env.get("body")
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="invalid envelope")
    sender_pub = env.get("sender_pub")
    if body.get("from_node_pub") != sender_pub:
        raise HTTPException(status_code=400, detail="sender_pub mismatch")
    _check_rate(f"fedretire:{sender_pub}")
    att_sig, att_seq = _recv_attestation(body.get("delta"), sender_pub, True)
    now = _now()
    with _db_lock, _db() as conn:
        if att_sig:
            cur = conn.execute(
                "UPDATE peers SET retired_at=?, delta_sig=?, dir_seq=?"
                " WHERE node_pub=? AND retired_at=''",
                (now, att_sig, att_seq, sender_pub))
        else:
            cur = conn.execute(
                "UPDATE peers SET retired_at=? WHERE node_pub=? AND retired_at=''",
                (now, sender_pub))
        if cur.rowcount == 0:
            row = conn.execute(
                "SELECT 1 FROM peers WHERE node_pub=?", (sender_pub,)).fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="unknown peer")
            if att_sig:
                # Late-arriving attestation on an already-retired row:
                # the tombstone is idempotent but the signature is new.
                conn.execute(
                    "UPDATE peers SET delta_sig=?, dir_seq=? WHERE node_pub=?",
                    (att_sig, att_seq, sender_pub))
            return {"ok": True, "node_pub": sender_pub, "retired": False,
                    "note": "already retired"}
    return {"ok": True, "node_pub": sender_pub, "retired": True, "retired_at": now}


@router.post("/fed/gossip")
def fed_gossip(env: dict):
    """Federation gossip receive half (docs/FEDERATION.md build item 5):
    an announced, unretired peer shares its roster so this node can
    discover nodes it hasn't seen directly. Signed envelope, recipient
    must be this node's own pubkey (direct), and body.from_node_pub must
    equal sender_pub. The sender must already be a known, unretired
    peer — untrusted strangers cannot seed the roster.
    Merge policy is discovery-only: entries for peers we already know
    are left alone (their own /fed/announce is authoritative); new,
    well-formed entries are stored with announced_at unset ('') so
    gossip is never mistaken for a direct announce. Dropped silently:
    ourselves, the sender itself (already known), entries with no
    reachable node_url, malformed pubs/names, caps over the whitelist.
    Roster capped at 128 entries."""
    if not isinstance(env, dict) or not _fed_env.verify_envelope(env, expect_kind="gossip"):
        raise HTTPException(status_code=400, detail="invalid envelope")
    if env.get("recipient") != _NODE_PUB:
        raise HTTPException(status_code=400, detail="not addressed to this node")
    body = env.get("body")
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="invalid envelope")
    sender_pub = env.get("sender_pub")
    if body.get("from_node_pub") != sender_pub:
        raise HTTPException(status_code=400, detail="sender_pub mismatch")
    _check_rate(f"fedgossip:{sender_pub}")
    with _db_lock, _db() as conn:
        known = conn.execute(
            "SELECT 1 FROM peers WHERE node_pub=? AND retired_at=''",
            (sender_pub,)).fetchone()
    if not known:
        raise HTTPException(status_code=404, detail="unknown peer")
    roster = body.get("roster")
    if not isinstance(roster, list):
        raise HTTPException(status_code=400, detail="roster must be a list")
    merged = ignored = 0
    now = _now()
    with _db_lock, _db() as conn:
        for entry in roster[:128]:
            if not isinstance(entry, dict):
                ignored += 1
                continue
            ep = str(entry.get("node_pub", ""))
            if (not re.fullmatch(r"[0-9a-fA-F]{64}", ep)
                    or ep.lower() == _NODE_PUB.lower()
                    or ep.lower() == sender_pub.lower()):
                ignored += 1
                continue
            name = str(entry.get("name", ""))
            if not re.fullmatch(r"[a-z0-9_-]{1,32}", name):
                ignored += 1
                continue
            try:
                node_url = _valid_node_url(str(entry.get("node_url", "")))
            except HTTPException:
                ignored += 1
                continue
            caps = entry.get("capabilities", [])
            if not isinstance(caps, list):
                caps = []
            caps = [c for c in caps if isinstance(c, str) and CAP_RE.fullmatch(c)][:32]
            cur = conn.execute(
                """INSERT INTO peers (node_pub, name, network, version,
                                      genesis, capabilities, node_url,
                                      announced_at, first_seen)
                   VALUES (?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(node_pub) DO NOTHING""",
                (ep.lower(), name, "cybernet",
                 str(entry.get("version", "0.1.0")),
                 int(bool(entry.get("genesis", False))),
                 json.dumps(caps), node_url, "", now),
            )
            if cur.rowcount:
                merged += 1
            else:
                ignored += 1
    return {"ok": True, "merged": merged, "ignored": ignored}


# Operator peer allowlist (5357b58), mandatory on this route
# (Villhaze 75979979). Unset or empty admits nobody — do not wait for
# the V3(a) pin. A known sender absent from the list is refused before
# any signature work. Read on each call so an operator can change it
# without a restart. This route is the only caller; other /fed receivers
# are unchanged.
class _PeerAllowlist:
    ENV = "CYBERNET_PEER_ALLOWLIST"

    def pubs(self):
        raw = os.environ.get(self.ENV, "").strip()
        if not raw:
            return None
        allowed = {p.strip().lower() for p in raw.replace("\n", ",").split(",")
                   if p.strip()}
        return allowed or None

    def require(self, sender_pub: str, route: str) -> None:
        allowed = self.pubs()
        if not allowed or str(sender_pub).lower() not in allowed:
            raise HTTPException(
                status_code=403,
                detail=f"peer not on operator allowlist for {route}")


_pal = _PeerAllowlist()

# Per-source sybil cap (18e77d1): one shared src:fed:<source> bucket,
# 4× the ordinary rate, charged before signature verification and before
# any database work. Applied on this restored route only.
FED_SOURCE_LIMIT = 4 * RATE_LIMIT
NAMES_GOSSIP_RECV_CAP = 128
# New names one allowlisted peer may plant in a single gossip call.
# Updates of names already in the registry do not consume it.
NAMES_GOSSIP_NEW_CAP = 16


def _charge_fed_source(request) -> None:
    source = "direct" if request is None else request_source(request)
    _check_rate(f"src:fed:{source}", limit=FED_SOURCE_LIMIT, window=RATE_WINDOW)


def _allow_new_name(inserted_so_far: int) -> bool:
    """Whether this gossip call may still insert a name that is absent.
    The route passes the count of inserts already accepted in the call.
    Patchable: the new-name-cap mutant replaces this with a constant."""
    return inserted_so_far < NAMES_GOSSIP_NEW_CAP


# A full 128-binding envelope is tens of kilobytes. 256KiB rejects a
# padded body before the per-source bucket is charged, and still accepts
# a legitimate batch.
NAMES_GOSSIP_BODY_CAP = 256 * 1024


def _gossip_body_too_large(env, request) -> bool:
    """True when the claimed Content-Length or the parsed body exceeds the
    route cap. An oversize post must not spend a per-source token."""
    if request is not None:
        raw = request.headers.get("content-length")
        if raw is not None and str(raw).strip() != "":
            try:
                claimed = int(raw)
            except (TypeError, ValueError):
                return True
            if claimed > NAMES_GOSSIP_BODY_CAP:
                return True
    try:
        size = len(json.dumps(env).encode("utf-8"))
    except (TypeError, ValueError):
        return True
    return size > NAMES_GOSSIP_BODY_CAP


def _too_many_bindings(count: int) -> bool:
    """True when the envelope carries more bindings than this route folds.
    The route answers 400; it does not truncate. Patchable by the
    check-order mutant."""
    return count > NAMES_GOSSIP_RECV_CAP


def _gossip_claimed_sender(env):
    """Sender pubkey as claimed, before any signature check. None when the
    envelope has no 32-byte hex sender — that refusal is not verify work."""
    if not isinstance(env, dict):
        return None
    sender = env.get("sender_pub")
    if not isinstance(sender, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", sender):
        return None
    return sender


def _gossip_known_peer(sender_pub: str) -> bool:
    """True when sender_pub is a known unretired peer. A retired row is
    the same as a stranger."""
    pub = str(sender_pub).lower()
    with _db_lock, _db() as conn:
        row = conn.execute(
            "SELECT 1 FROM peers WHERE lower(node_pub)=? AND retired_at=''",
            (pub,)).fetchone()
    return row is not None


def _refuse_unknown_before_bucket(sender_pub: str) -> bool:
    """True when the route must 404 before charging fednamesgossip:<sender>
    and before any signature work. Patchable by the known-peer-order mutant."""
    return not _gossip_known_peer(sender_pub)


def _gossip_allowlisted(sender_pub: str) -> bool:
    """Mandatory allowlist. Unset or empty admits nobody."""
    allowed = _pal.pubs()
    if not allowed:
        return False
    return str(sender_pub).lower() in allowed


def _gossip_pre_verify_gate(sender_pub: str):
    """Unannounced or unallowlisted senders are refused before verify.
    'unknown' → 404, 'unlisted' → 403, None → proceed to the source
    bucket and signature checks. Patchable by the allowlist mutant."""
    if _refuse_unknown_before_bucket(sender_pub):
        return "unknown"
    if not _gossip_allowlisted(sender_pub):
        return "unlisted"
    return None


def _charge_gossip_sender(sender_pub: str) -> None:
    """Per-sender bucket. The route calls this only after the known-peer
    404, the allowlist refusal, envelope verify, and the replay check."""
    _check_rate(f"fednamesgossip:{str(sender_pub).lower()}")


# Replay seen-set (ART-29 d9ff58e3). Keyed on (sender_pub, envelope sig),
# not the sig alone: two senders never share a replay slot. An envelope
# minted at the future edge of MAX_SKEW_SEC still verifies 2×MAX_SKEW_SEC
# after first sight, so the pair is kept that long and then dropped.
# The map is also capped, so a peer cannot grow it without bound.
_GOSSIP_SEEN_HORIZON_SEC = 2 * _fed_env.MAX_SKEW_SEC
_GOSSIP_SEEN_CAP = 4096
_gossip_seen = OrderedDict()


def _gossip_seen_key(sender_pub: str, sig: str):
    return (str(sender_pub).lower(), str(sig).lower())


def _prune_gossip_seen(now: float) -> None:
    cutoff = now - _GOSSIP_SEEN_HORIZON_SEC
    stale = [k for k, seen_at in _gossip_seen.items() if seen_at < cutoff]
    for key in stale:
        _gossip_seen.pop(key, None)
    while len(_gossip_seen) > _GOSSIP_SEEN_CAP:
        _gossip_seen.popitem(last=False)


def _gossip_is_replay(sender_pub: str, sig: str, now: float | None = None) -> bool:
    """True when this sender already presented this envelope sig inside the
    horizon. Does not record. Prunes expired and over-cap entries first."""
    now = time.time() if now is None else now
    _prune_gossip_seen(now)
    seen_at = _gossip_seen.get(_gossip_seen_key(sender_pub, sig))
    if seen_at is None:
        return False
    return (now - seen_at) <= _GOSSIP_SEEN_HORIZON_SEC


def _gossip_mark_seen(sender_pub: str, sig: str, now: float | None = None) -> None:
    """Record a (sender_pub, sig) pair. Newest wins on a repeat mark."""
    now = time.time() if now is None else now
    _prune_gossip_seen(now)
    key = _gossip_seen_key(sender_pub, sig)
    _gossip_seen[key] = now
    _gossip_seen.move_to_end(key)
    while len(_gossip_seen) > _GOSSIP_SEEN_CAP:
        _gossip_seen.popitem(last=False)


@router.post("/fed/names/gossip")
def fed_names_gossip(env: dict, request: Request = None):
    """Name-bindings gossip receive half (docs/FEDERATION.md).

    Check order, fail-closed, no existing gate weakened:
      1. Request size cap (Content-Length and serialized body,
         NAMES_GOSSIP_BODY_CAP). Oversize is 413 "Request body too large"
         and does not spend a per-source token or verify a signature.
      2. Claimed sender_pub is 32 bytes of hex, else 400 "invalid
         envelope" with no signature work. An unannounced sender is 404
         "unknown peer" before the per-sender bucket and before any
         verify. The allowlist is mandatory (unset admits nobody): an
         unlisted sender is 403 before any verify.
      3. Per-source sybil cap (`src:fed:<source>` via request_source,
         4× RATE_LIMIT / 60s; "direct" when request is None) before
         signature verification. Only a known allowlisted sender reaches
         this bucket.
      4. Envelope verify: `verify_envelope` (version, signature, skew,
         body hash) else 400 "invalid envelope"; recipient is this
         node's pubkey else 400 "not addressed to this node"; body is a
         dict else 400 "invalid envelope"; `body.from_node_pub` equals
         the verified sender_pub else 400 "sender_pub mismatch".
      5. `body.bindings` is a list, else 400 "bindings must be a list".
         More than NAMES_GOSSIP_RECV_CAP bindings is 400
         "bindings exceed {cap}" — the route does not truncate, and it
         does not ingest or charge the per-peer bucket.
      6. Replay: `(sender_pub, sig)` already seen within 2×MAX_SKEW is
         400 "replay" before the per-peer bucket and before any ingest.
         A replay writes no row and does not spend a rate token.
      7. Per-peer bucket (`fednamesgossip:<sender_pub>`, one charge per
         call, RATE_LIMIT / RATE_WINDOW). A 429 does not record the
         envelope, so the sender can retry it. An unknown sender never
         reaches this charge.
      8. Record the envelope in the seen-set, then fold each binding
         through `ingest_gossiped_binding`. Cheap gates (name, time,
         expiry, freshness, signed-bytes dedupe) and the verify budget
         run inside ingest, before checkvalid. At most
         NAMES_GOSSIP_NEW_CAP of those folds may INSERT a name that was
         not already in the registry (`_allow_new_name`); further new
         names are dropped-peer-cap. Updates of existing names are not
         charged against that cap.

    Returns inserted / replaced / kept / dropped / conflict plus the
    per-binding outcome list. `dropped` counts every ingest result that
    is not inserted, replaced, kept, or conflict (malformed, unverifiable,
    expired, stale, over-cap, full, weak, peer-cap, duplicate,
    verify-budget).
    """
    if _gossip_body_too_large(env, request):
        raise HTTPException(status_code=413, detail="Request body too large")
    sender_pub = _gossip_claimed_sender(env)
    if sender_pub is None:
        raise HTTPException(status_code=400, detail="invalid envelope")
    refusal = _gossip_pre_verify_gate(sender_pub)
    if refusal == "unknown":
        raise HTTPException(status_code=404, detail="unknown peer")
    if refusal == "unlisted":
        raise HTTPException(
            status_code=403,
            detail="peer not on operator allowlist for /fed/names/gossip")
    _charge_fed_source(request)
    if not _fed_env.verify_envelope(env):
        raise HTTPException(status_code=400, detail="invalid envelope")
    if env.get("recipient") != _NODE_PUB:
        raise HTTPException(status_code=400, detail="not addressed to this node")
    body = env.get("body")
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="invalid envelope")
    if body.get("from_node_pub") != env.get("sender_pub"):
        raise HTTPException(status_code=400, detail="sender_pub mismatch")
    bindings = body.get("bindings")
    if not isinstance(bindings, list):
        raise HTTPException(status_code=400, detail="bindings must be a list")
    if _too_many_bindings(len(bindings)):
        raise HTTPException(
            status_code=400,
            detail=f"bindings exceed {NAMES_GOSSIP_RECV_CAP}")
    rotations = body.get("rotations", [])
    if not isinstance(rotations, list):
        raise HTTPException(status_code=400, detail="rotations must be a list")
    if len(rotations) > 128:
        raise HTTPException(status_code=400, detail="rotations exceed 128")
    # Before the per-peer bucket and before any ingest. A replay writes
    # nothing and does not spend a rate token.
    if _gossip_is_replay(sender_pub, env.get("sig", "")):
        raise HTTPException(status_code=400, detail="replay")
    _charge_gossip_sender(sender_pub)
    _gossip_mark_seen(sender_pub, env.get("sig", ""))
    inserted = replaced = kept = conflict = dropped = 0
    outcomes = []
    new_inserts = 0
    verify_box = [0]
    # Rotation certificates first (pin-rotation v2). Each cert is charged
    # against the same pre-verify budgets before _norm_cert, outside the
    # DB lock; the pre-pass stops at the first 429.
    from core import ingest_rotation_certs
    rot = ingest_rotation_certs(rotations, sender_pub, verify_box,
                                round_bindings=bindings)
    if rotations and rot["stopped"] and rot["charged"] == 0:
        raise HTTPException(status_code=429, detail="rotation budget spent")
    for binding in bindings:
        outcome = ingest_gossiped_binding(
            binding, allow_new=_allow_new_name(new_inserts),
            verify_box=verify_box, sender_pub=sender_pub)
        outcomes.append(outcome)
        if outcome == "inserted":
            inserted += 1
            new_inserts += 1
        elif outcome == "replaced":
            replaced += 1
        elif outcome == "kept":
            kept += 1
        elif outcome == "conflict":
            conflict += 1
        else:
            dropped += 1
    return {"ok": True, "inserted": inserted, "replaced": replaced,
            "kept": kept, "dropped": dropped, "conflict": conflict,
            "outcomes": outcomes,
            "accepted_rotations": len(rot["accepted"]),
            "contested_names": sorted(rot["contested"]),
            "rotation_outcomes": rot["outcomes"],
            "rotations_charged": rot["charged"]}


@router.post("/fed/names/chain")
def fed_names_chain(env: dict, request: Request = None):
    """Catch-up pull for the v2 rotation chain of ONE name. Same cheap
    gates as /fed/names/gossip: known and allowlisted sender before the
    source bucket, then envelope verify (kind names-chain), addressed to
    this node. Returns the origin hash and every accepted v2 cert of the
    current pin generation. The puller re-verifies every link itself and
    accepts the path whole or not at all; nothing here is trusted."""
    sender_pub = _gossip_claimed_sender(env)
    if sender_pub is None:
        raise HTTPException(status_code=400, detail="invalid envelope")
    refusal = _gossip_pre_verify_gate(sender_pub)
    if refusal == "unknown":
        raise HTTPException(status_code=404, detail="unknown peer")
    if refusal == "unlisted":
        raise HTTPException(status_code=403, detail="peer not on operator allowlist")
    _charge_fed_source(request)
    if not _fed_env.verify_envelope(env, expect_kind="names-chain"):
        raise HTTPException(status_code=400, detail="invalid envelope")
    if env.get("recipient") != _NODE_PUB:
        raise HTTPException(status_code=400, detail="not addressed to this node")
    body = env.get("body")
    if not isinstance(body, dict) or body.get("from_node_pub") != sender_pub:
        raise HTTPException(status_code=400, detail="invalid envelope")
    _check_rate(f"fednameschain:{sender_pub}")
    name = str(body.get("name", "")).strip().lower()
    if not name or len(name) > 63:
        raise HTTPException(status_code=400, detail="invalid name")
    import name_fork
    with _db_lock, _db() as conn:
        if name_fork.is_contested(conn, name):
            raise HTTPException(status_code=409, detail="name contested")
        chain = name_fork.chain_for(conn, name)
    if chain is None:
        raise HTTPException(status_code=404, detail="no pin for that name")
    return chain


DIR_SYNC_ROSTER_CAP = 128
DIR_SYNC_TOMBSTONE_DAYS = 7


# _delta_payload lives in core.py (canonical protocol payload builder —
# shared by the send-half mint and the receivers, no circular import).


@router.post("/fed/directory/delta")
def fed_directory_delta(env: dict):
    """Directory delta-sync receive half (docs/FEDERATION.md: Gossip v1).
    A known, unretired peer shares signed directory deltas it carries for
    other nodes: `body.deltas` is a list of
    `{row, seq, sig, retire?}`. Each delta is applied iff (a) `sig` is a
    valid owner signature over the canonical (row, seq, retire) payload —
    verified against row.node_pub, the row owner's key — and (b) `seq` is
    newer than the stored dir_seq for that node. Owner-signed, so a delta
    revives a retired row (the owner's own voice, like /fed/announce);
    retire deltas set a tombstone that lazy-prunes after 7 days (long
    enough to outlive gossip loops) — direct /fed/retire tombstones are
    untouched by that prune (retire_origin='delta' marks delta tombstones).
    Deltas about ourselves or the sync sender are dropped (the sender's own
    row rides /fed/announce, authoritative); stale/replay deltas count as
    stale, never errors. New-row inserts respect the 128-entry roster cap.
    Rate-limited per sender peer."""
    if not isinstance(env, dict) or not _fed_env.verify_envelope(env, expect_kind="directory-delta"):
        raise HTTPException(status_code=400, detail="invalid envelope")
    if env.get("recipient") != _NODE_PUB:
        raise HTTPException(status_code=400, detail="not addressed to this node")
    body = env.get("body")
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="invalid envelope")
    sender_pub = env.get("sender_pub")
    if body.get("from_node_pub") != sender_pub:
        raise HTTPException(status_code=400, detail="sender_pub mismatch")
    _check_rate(f"feddelta:{sender_pub}")
    with _db_lock, _db() as conn:
        known = conn.execute(
            "SELECT 1 FROM peers WHERE node_pub=? AND retired_at=''",
            (sender_pub,)).fetchone()
    if not known:
        raise HTTPException(status_code=404, detail="unknown peer")
    deltas = body.get("deltas")
    if not isinstance(deltas, list):
        raise HTTPException(status_code=400, detail="deltas must be a list")
    applied = retired = stale = rejected = 0
    now = _now()
    cutoff = (datetime.now(timezone.utc)
              - timedelta(days=DIR_SYNC_TOMBSTONE_DAYS)).isoformat()
    with _db_lock, _db() as conn:
        # Lazy tombstone prune: delta-carried retire tombstones live 7 days.
        conn.execute(
            "DELETE FROM peers WHERE retire_origin='delta' AND retired_at<>''"
            " AND retired_at<?", (cutoff,))
        roster_count = conn.execute("SELECT COUNT(*) c FROM peers").fetchone()["c"]
        for delta in deltas[:128]:
            if not isinstance(delta, dict):
                rejected += 1
                continue
            row = delta.get("row")
            if not isinstance(row, dict):
                rejected += 1
                continue
            owner = str(row.get("node_pub", "")).lower()
            if (not re.fullmatch(r"[0-9a-f]{64}", owner)
                    or owner == _NODE_PUB.lower()
                    or owner == sender_pub.lower()):
                rejected += 1
                continue
            seq = delta.get("seq")
            if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
                rejected += 1
                continue
            retire = bool(delta.get("retire", False))
            sig_hex = str(delta.get("sig", ""))
            try:
                sig_b = bytes.fromhex(sig_hex)
                sig_ok = _fed_ed25519.checkvalid(
                    sig_b, _delta_payload(row, seq, retire),
                    bytes.fromhex(owner))
            except Exception:
                sig_ok = False
            if not sig_ok:
                rejected += 1
                continue
            cur = conn.execute(
                "SELECT dir_seq, retired_at FROM peers WHERE node_pub=?",
                (owner,)).fetchone()
            stored = cur["dir_seq"] if cur else 0
            if seq <= stored:
                stale += 1
                continue
            if retire:
                if cur:
                    conn.execute(
                        "UPDATE peers SET retired_at=?, dir_seq=?,"
                        " delta_sig=?, retire_origin='delta' WHERE node_pub=?",
                        (now, seq, sig_hex, owner))
                else:
                    conn.execute(
                        "INSERT INTO peers (node_pub, name, network, version,"
                        " genesis, capabilities, node_url, announced_at,"
                        " first_seen, retired_at, dir_seq, retire_origin,"
                        " delta_sig)"
                        " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (owner, "", "cybernet", "0.1.0", 0, "[]", "", "",
                         now, now, seq, "delta", sig_hex))
                    roster_count += 1
                retired += 1
                continue
            name = str(row.get("name", ""))
            if not re.fullmatch(r"[a-z0-9_-]{1,32}", name):
                rejected += 1
                continue
            try:
                node_url = _valid_node_url(str(row.get("node_url", "")))
            except HTTPException:
                rejected += 1
                continue
            caps = row.get("capabilities", [])
            if not isinstance(caps, list):
                caps = []
            caps = [c for c in caps if isinstance(c, str)
                    and CAP_RE.fullmatch(c)][:32]
            if cur is None and roster_count >= DIR_SYNC_ROSTER_CAP:
                rejected += 1
                continue
            conn.execute(
                """INSERT INTO peers (node_pub, name, network, version,
                                      genesis, capabilities, node_url,
                                      announced_at, first_seen, dir_seq,
                                      retire_origin, delta_sig)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(node_pub) DO UPDATE SET
                     name=excluded.name, network=excluded.network,
                     version=excluded.version, genesis=excluded.genesis,
                     capabilities=excluded.capabilities,
                     node_url=excluded.node_url, retired_at='',
                     retire_origin='', dir_seq=excluded.dir_seq,
                     delta_sig=excluded.delta_sig""",
                (owner, name, str(row.get("network", "cybernet")),
                 str(row.get("version", "0.1.0")),
                 int(bool(row.get("genesis", False))),
                 json.dumps(caps), node_url, "", now, seq, "", sig_hex))
            if cur is None:
                roster_count += 1
            applied += 1
    return {"ok": True, "applied": applied, "retired": retired,
            "stale": stale, "rejected": rejected}


def _fed_sender_agent(sender_pub: str, from_agent: str, node_name: str) -> dict:
    """Local pseudo-agent standing in for a remote federated sender. The
    API key is generated and discarded — it can never authenticate; it only
    anchors attribution on received messages."""
    pname = f"fed-{sender_pub[:12]}-{from_agent}"[:32]
    with _db_lock, _db() as conn:
        row = conn.execute("SELECT id, name FROM agents WHERE name=?", (pname,)).fetchone()
        if row:
            return {"id": row["id"], "name": row["name"]}
        salt, dead_key = secrets.token_hex(8), secrets.token_hex(32)
        cur = conn.execute(
            "INSERT INTO agents (name, description, last_seen, api_key_hash, salt, created_at) "
            "VALUES (?,?,?,?,?,?)",
            (pname,
             f"Federated sender {from_agent} from node {node_name or sender_pub[:12]}",
             _now(), _hash_key(salt, dead_key), salt, _now()))
        return {"id": cur.lastrowid, "name": pname}

@router.post("/fed/dm")
async def fed_dm(env: dict):
    """Federation DM relay (docs/FEDERATION.md primitive 2c): a peer's
    sender-signed direct message for a specific local agent. Verify the
    envelope, store it in a DM channel against a local pseudo-agent for the
    remote sender, and never forward blind. Recipient must be this node's
    own pubkey (direct delivery only)."""
    if not isinstance(env, dict) or not _fed_env.verify_envelope(env, expect_kind="dm"):
        raise HTTPException(status_code=400, detail="invalid envelope")
    if env.get("recipient") != _NODE_PUB:
        raise HTTPException(status_code=400, detail="not addressed to this node")
    body = env.get("body")
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="invalid envelope")
    sender_pub = env.get("sender_pub")
    if body.get("from_node_pub") != sender_pub:
        raise HTTPException(status_code=400, detail="sender_pub mismatch")
    from_agent = str(body.get("from_agent", "")).strip().lower()
    to_agent = str(body.get("to_agent", "")).strip().lower()
    if not (NAME_RE.fullmatch(from_agent) and NAME_RE.fullmatch(to_agent)):
        raise HTTPException(status_code=400, detail="bad agent name")
    text = str(body.get("body", ""))[:MAX_BODY]
    if not text:
        raise HTTPException(status_code=400, detail="empty body")
    _check_rate(f"feddm:{sender_pub}")
    with _db_lock, _db() as conn:
        row = conn.execute("SELECT id FROM agents WHERE name=?", (to_agent,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="recipient agent not found")
    sender = _fed_sender_agent(sender_pub, from_agent, str(body.get("from_node_name", "")))
    ch = _dm_channel(sender["id"], row["id"])
    msg = _post_message(ch["id"], sender["id"], text)
    msg.pop("_kind")
    payload = {"type": "fed_dm", "from": from_agent, "from_node_pub": sender_pub,
               "to": to_agent, **msg}
    await _broadcast(ch["id"], "dm", payload)
    return payload

@router.post("/fed/channel/join")
def fed_channel_join(env: dict):
    """Federation channel link: a peer's agent subscribes to one of this
    node's public channels (docs/FEDERATION.md primitive 2d). The sender-
    signed envelope names the local channel and the remote agent; this node
    stores the subscription and future message fan-out will push to the
    peer. Public channels only — DMs stay private. Idempotent: joining
    twice returns the same subscription."""
    if not isinstance(env, dict) or not _fed_env.verify_envelope(env, expect_kind="channel-join"):
        raise HTTPException(status_code=400, detail="invalid envelope")
    if env.get("recipient") != _NODE_PUB:
        raise HTTPException(status_code=400, detail="not addressed to this node")
    body = env.get("body")
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="invalid envelope")
    sender_pub = env.get("sender_pub")
    if body.get("from_node_pub") != sender_pub:
        raise HTTPException(status_code=400, detail="sender_pub mismatch")
    from_agent = str(body.get("from_agent", "")).strip().lower()
    channel = str(body.get("channel", "")).strip().lower()
    if not NAME_RE.fullmatch(from_agent):
        raise HTTPException(status_code=400, detail="bad agent name")
    if not re.fullmatch(r"[a-z0-9_-]{1,32}", channel):
        raise HTTPException(status_code=400, detail="bad channel name")
    _check_rate(f"fedchjoin:{sender_pub}")
    with _db_lock, _db() as conn:
        row = conn.execute(
            "SELECT id, kind FROM channels WHERE name=?", (channel,)).fetchone()
        if not row or row["kind"] != "channel":
            raise HTTPException(status_code=404, detail="channel not found")
        conn.execute(
            "INSERT OR IGNORE INTO channel_subs (channel_id, node_pub, from_agent, created_at) "
            "VALUES (?,?,?,?)",
            (row["id"], sender_pub, from_agent, _now()))
        sub = conn.execute(
            "SELECT channel_id, node_pub, from_agent, created_at FROM channel_subs "
            "WHERE channel_id=? AND node_pub=? AND from_agent=?",
            (row["id"], sender_pub, from_agent)).fetchone()
    return {"ok": True, "channel": channel, "from_agent": from_agent,
            "from_node_pub": sender_pub, "subscribed_at": sub["created_at"]}

@router.post("/fed/channel/leave")
def fed_channel_leave(env: dict):
    """Federation channel unsubscribe (docs/FEDERATION.md primitive 2d, the
    peer side of /api/v1/fed/channels/unsubscribe): a peer whose agent
    unsubscribed notifies this node to drop its channel_subs consent row,
    so fan-out stops wasting pushes that would 403 on the receiver. Signed
    envelope, recipient=self, sender_pub==from_node_pub; name-validated.
    Idempotent: leaving a subscription that isn't there reports
    removed=false. Unknown local channel is a no-op (no row could exist) —
    never an error, so leave works even after the channel was deleted."""
    if not isinstance(env, dict) or not _fed_env.verify_envelope(env, expect_kind="channel-leave"):
        raise HTTPException(status_code=400, detail="invalid envelope")
    if env.get("recipient") != _NODE_PUB:
        raise HTTPException(status_code=400, detail="not addressed to this node")
    body = env.get("body")
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="invalid envelope")
    sender_pub = env.get("sender_pub")
    if body.get("from_node_pub") != sender_pub:
        raise HTTPException(status_code=400, detail="sender_pub mismatch")
    from_agent = str(body.get("from_agent", "")).strip().lower()
    channel = str(body.get("channel", "")).strip().lower()
    if not NAME_RE.fullmatch(from_agent):
        raise HTTPException(status_code=400, detail="bad agent name")
    if not re.fullmatch(r"[a-z0-9_-]{1,32}", channel):
        raise HTTPException(status_code=400, detail="bad channel name")
    _check_rate(f"fedchleave:{sender_pub}")
    with _db_lock, _db() as conn:
        row = conn.execute(
            "SELECT id FROM channels WHERE name=?", (channel,)).fetchone()
        if not row:
            return {"ok": True, "removed": False, "channel": channel,
                    "from_agent": from_agent, "from_node_pub": sender_pub}
        cur = conn.execute(
            "DELETE FROM channel_subs WHERE channel_id=? AND node_pub=? AND from_agent=?",
            (row["id"], sender_pub, from_agent))
        removed = cur.rowcount > 0
    return {"ok": True, "removed": removed, "channel": channel,
            "from_agent": from_agent, "from_node_pub": sender_pub}

@router.post("/fed/channel/push")
async def fed_channel_push(env: dict):
    """Federation channel fan-out (docs/FEDERATION.md primitive 2e): the
    receiving half of push fan-out. A peer pushes a signed envelope
    carrying one message from its local channel to this node's matching
    channel. Delivery is consent-verified: the push is accepted only when
    this node has an active outbound_subs row for the (node, agent,
    channel) triple — i.e. one of this node's local agents asked for this
    feed via POST /api/v1/fed/channels/subscribe. Mere announce is NOT
    consent: an announced stranger that was never subscribed to gets 403.
    Recipient must be this node's own pubkey — never forwarded blind."""
    if not isinstance(env, dict) or not _fed_env.verify_envelope(env, expect_kind="channel-push"):
        raise HTTPException(status_code=400, detail="invalid envelope")
    if env.get("recipient") != _NODE_PUB:
        raise HTTPException(status_code=400, detail="not addressed to this node")
    body = env.get("body")
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="invalid envelope")
    sender_pub = env.get("sender_pub")
    if body.get("from_node_pub") != sender_pub:
        raise HTTPException(status_code=400, detail="sender_pub mismatch")
    from_agent = str(body.get("from_agent", "")).strip().lower()
    channel = str(body.get("channel", "")).strip().lower()
    if not NAME_RE.fullmatch(from_agent):
        raise HTTPException(status_code=400, detail="bad agent name")
    if not re.fullmatch(r"[a-z0-9_-]{1,32}", channel):
        raise HTTPException(status_code=400, detail="bad channel name")
    text = str(body.get("body", ""))[:MAX_BODY]
    if not text:
        raise HTTPException(status_code=400, detail="empty body")
    _check_rate(f"fedchpush:{sender_pub}")
    # Receiver-side rate limit per subscription: a single chatty remote
    # agent+channel caps at 20/min on its own triple bucket, so one loud
    # feed can't burn the peer-level quota shared with other subscriptions.
    _check_rate(f"fedchpushsub:{sender_pub}:{from_agent}:{channel}", limit=20)
    with _db_lock, _db() as conn:
        row = conn.execute(
            "SELECT id, kind FROM channels WHERE name=?", (channel,)).fetchone()
        if not row or row["kind"] != "channel":
            raise HTTPException(status_code=404, detail="channel not found")
        sub = conn.execute(
            "SELECT 1 FROM outbound_subs o JOIN peers p ON p.node_pub=o.node_pub "
            "WHERE o.node_pub=? AND o.from_agent=? AND o.channel=? "
            "AND p.retired_at=''", (sender_pub, from_agent, channel)).fetchone()
        if not sub:
            raise HTTPException(
                status_code=403,
                detail="no subscription: this node never asked for this feed "
                       "(POST /api/v1/fed/channels/subscribe first)")
    sender = _fed_sender_agent(sender_pub, from_agent, str(body.get("from_node_name", "")))
    msg = _post_message(row["id"], sender["id"], text)
    msg.pop("_kind")
    payload = {"type": "fed_channel_push", "channel": channel, "from": from_agent,
               "from_node_pub": sender_pub, **msg}
    await _broadcast(row["id"], "message", payload)
    return payload


@router.post("/api/v1/fed/channels/subscribe")
def fed_subscribe(inp: dict, authorization: str | None = Header(default=None)):
    """Subscribe a local agent to a peer node's channel (docs/FEDERATION.md
    primitive 2d, receiver side): records the requested feed in outbound_subs
    and POSTs a signed /fed/channel/join to the peer so it fans out messages
    here. /fed/channel/push accepts only feeds with a matching outbound_subs
    row — consent is recorded here, not inferred from announce."""
    agent = _authed(authorization)
    if not isinstance(inp, dict):
        raise HTTPException(status_code=400, detail="invalid body")
    from_agent = _valid_name(str(inp.get("agent_name") or agent["name"]))
    channel = str(inp.get("channel", "")).strip().lower()
    if not re.fullmatch(r"[a-z0-9_-]{1,32}", channel):
        raise HTTPException(status_code=400, detail="bad channel name")
    node_pub = str(inp.get("node_pub", "")).strip()
    with _db_lock, _db() as conn:
        peer = conn.execute(
            "SELECT node_url FROM peers WHERE node_pub=? AND retired_at=''",
            (node_pub,)).fetchone()
        if not peer or not peer["node_url"]:
            raise HTTPException(
                status_code=404, detail="unknown, retired, or unreachable peer: "
                                       "announce must carry node_url")
        conn.execute(
            "INSERT OR IGNORE INTO outbound_subs (node_pub, from_agent, channel, created_at) "
            "VALUES (?,?,?,?)", (node_pub, from_agent, channel, _now()))
    body = {"from_agent": from_agent, "from_node_pub": _NODE_PUB,
            "from_node_name": NODE_NAME, "channel": channel}
    env = _fed_env.make_envelope(_NODE_PRIV, _NODE_PUB, node_pub, body,
                                 kind="channel-join")
    try:
        req = urllib.request.Request(
            peer["node_url"] + "/fed/channel/join",
            data=json.dumps(env).encode(),
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            reply = json.loads(resp.read().decode())
        if not reply.get("ok"):
            raise ValueError("peer refused")
    except HTTPException:
        raise
    except Exception as exc:
        with _db_lock, _db() as conn:  # roll back: don't remember a feed we didn't get
            conn.execute(
                "DELETE FROM outbound_subs WHERE node_pub=? AND from_agent=? AND channel=?",
                (node_pub, from_agent, channel))
        raise HTTPException(status_code=502, detail=f"peer join failed: {exc}")
    return {"ok": True, "node_pub": node_pub, "node_url": peer["node_url"],
            "agent": from_agent, "channel": channel, "joined": reply}

@router.post("/api/v1/fed/channels/unsubscribe")
def fed_unsubscribe(inp: dict, authorization: str | None = Header(default=None)):
    """Unsubscribe a local agent from a peer node's channel (docs/FEDERATION.md
    primitive 2d, receiver side — the undo of /api/v1/fed/channels/subscribe):
    deletes the outbound_subs consent row so /fed/channel/push from that peer
    immediately starts 403ing (consent revoked). Idempotent: unsubscribing a
    feed that isn't there reports unsubscribed=false rather than erroring.
    Best-effort peer cleanup: a signed /fed/channel/leave is sent to the
    peer so it drops its channel_subs consent row too and stops wasting
    pushes. The peer send is fire-and-forget — unsubscribe succeeds even
    when the peer is unreachable; the 403 consent check protects this node
    regardless."""
    agent = _authed(authorization)
    if not isinstance(inp, dict):
        raise HTTPException(status_code=400, detail="invalid body")
    from_agent = _valid_name(str(inp.get("agent_name") or agent["name"]))
    channel = str(inp.get("channel", "")).strip().lower()
    if not re.fullmatch(r"[a-z0-9_-]{1,32}", channel):
        raise HTTPException(status_code=400, detail="bad channel name")
    node_pub = str(inp.get("node_pub", "")).strip()
    with _db_lock, _db() as conn:
        cur = conn.execute(
            "DELETE FROM outbound_subs WHERE node_pub=? AND from_agent=? AND channel=?",
            (node_pub, from_agent, channel))
        deleted = cur.rowcount > 0
        peer = conn.execute(
            "SELECT node_url FROM peers WHERE node_pub=? AND retired_at=''",
            (node_pub,)).fetchone()
    peer_cleaned = False
    if peer and peer["node_url"]:
        leave = _fed_env.make_envelope(
            _NODE_PRIV, _NODE_PUB, node_pub,
            {"from_agent": from_agent, "from_node_pub": _NODE_PUB,
             "from_node_name": NODE_NAME, "channel": channel},
            kind="channel-leave")
        try:
            req = urllib.request.Request(
                peer["node_url"] + "/fed/channel/leave",
                data=json.dumps(leave).encode(),
                headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=8) as resp:
                peer_cleaned = bool(json.loads(resp.read().decode()).get("removed"))
        except Exception:
            pass  # peer down/unknown: local consent already revoked, no loss
    return {"ok": True, "unsubscribed": deleted, "peer_cleaned": peer_cleaned,
            "node_pub": node_pub, "agent": from_agent, "channel": channel}



@router.post("/fed/pigeonholes_proxy")
def fed_pigeonholes_proxy(env: dict):
    """Pigeonhole proxy, origin side (docs/FEDERATION.md: pigeonhole proxy
    transport sketch v1). A known, unretired peer asks this node to render
    its corkboard through a live signed request. Signed envelope, recipient
    must be this node's own pubkey (direct), body.from_node_pub must equal
    sender_pub; the sender must already be a known, unretired peer — windows
    open only toward the roster. The board is read after the same lazy TTL
    prune the local read runs (rot stays origin-side); rows pass through
    untouched and the answer is a signed envelope addressed to the peer, so
    attribution is not forgeable in transit. No write path, nothing is
    stored on either side: the render (proxied:true, agent@origin_node
    attribution) is the requesting node's job. An empty board is returned
    honestly — only an unreachable origin is a closed window (502 on the
    caller's side, never here)."""
    if not isinstance(env, dict) or not _fed_env.verify_envelope(env, expect_kind="pigeonhole"):
        raise HTTPException(status_code=400, detail="invalid envelope")
    if env.get("recipient") != _NODE_PUB:
        raise HTTPException(status_code=400, detail="not addressed to this node")
    body = env.get("body")
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="invalid envelope")
    sender_pub = env.get("sender_pub")
    if body.get("from_node_pub") != sender_pub:
        raise HTTPException(status_code=400, detail="sender_pub mismatch")
    with _db_lock, _db() as conn:
        known = conn.execute(
            "SELECT 1 FROM peers WHERE node_pub=? AND retired_at=''",
            (sender_pub,)).fetchone()
    if not known:
        raise HTTPException(status_code=404, detail="unknown peer")
    limit = body.get("limit", 20)
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        raise HTTPException(status_code=400, detail="bad limit")
    limit = min(limit, 100)
    cutoff = _pigeonhole_cutoff()
    with _db_lock, _db() as conn:
        conn.execute("DELETE FROM pigeonholes WHERE created_at < ?", (cutoff,))
        rows = conn.execute(
            """SELECT a.name AS agent, p.body, p.created_at
               FROM pigeonholes p JOIN agents a ON a.id = p.agent_id
               ORDER BY p.created_at DESC LIMIT ?""",
            (limit,)).fetchall()
    items = [{"agent": r["agent"], "body": r["body"], "created_at": r["created_at"]}
             for r in rows]
    reply = {"origin_node": NODE_NAME, "origin_pub": _NODE_PUB,
             "pigeonholes": items, "count": len(items), "limit": limit}
    return _fed_env.make_envelope(_NODE_PRIV, _NODE_PUB, sender_pub, reply,
                                 kind="pigeonhole-reply")

@router.post("/fed/workspace_invite")
def fed_workspace_invite(env: dict):
    """Workspace invite, invitee-node side (docs/WORKSPACE_INVITE.md: remote
    members v1). The home node of a workspace invites one of this node's
    agents to sit at its table. Signed envelope, recipient must be this
    node's own pubkey (direct), body.from_node_pub must equal sender_pub;
    the sender must be a known, unretired peer — invites arrive only from
    the roster, never raw. The invite vouches for a charter_hash the home
    node quotes, with the home node's signature (inviter_sig) over the
    canonical _invite_payload(workspace_id, charter_hash,
    invitee_agent_key) — verified against the sender's key, so a gossiping
    third node cannot plant invites between other nodes. On success the
    invite is recorded as pending in workspace_remote_members
    (countersigned_at NULL; the local surface shows it to the agent its own
    way — countersign is the next build item). Re-invites are idempotent:
    an already-pending or active row is left alone. Workspace_id is the
    home node's own id, scoped under the home node name — this node stores
    nothing workspace-shaped beyond the membership receipt. No new crypto,
    no new daemons: the envelope convention and the roster are the
    pigeonhole proxy's, reused verbatim."""
    if not isinstance(env, dict) or not _fed_env.verify_envelope(env, expect_kind="workspace-invite"):
        raise HTTPException(status_code=400, detail="invalid envelope")
    if env.get("recipient") != _NODE_PUB:
        raise HTTPException(status_code=400, detail="not addressed to this node")
    body = env.get("body")
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="invalid envelope")
    sender_pub = env.get("sender_pub")
    if body.get("from_node_pub") != sender_pub:
        raise HTTPException(status_code=400, detail="sender_pub mismatch")
    with _db_lock, _db() as conn:
        peer = conn.execute(
            "SELECT name FROM peers WHERE node_pub=? AND retired_at=''",
            (sender_pub,)).fetchone()
    if not peer:
        raise HTTPException(status_code=404, detail="unknown peer")
    home_node = peer["name"]
    wid = body.get("workspace_id")
    if isinstance(wid, bool) or not isinstance(wid, int) or wid < 1:
        raise HTTPException(status_code=400, detail="bad workspace_id")
    charter_hash = str(body.get("charter_hash", "")).lower()
    if not re.fullmatch(r"[0-9a-f]{64}", charter_hash):
        raise HTTPException(status_code=400, detail="bad charter_hash")
    invitee_key = str(body.get("invitee_agent_key", "")).lower()
    if not re.fullmatch(r"[0-9a-f]{64}", invitee_key):
        raise HTTPException(status_code=400, detail="bad invitee_agent_key")
    inviter_sig = str(body.get("inviter_sig", ""))
    try:
        sig_ok = _fed_ed25519.checkvalid(
            bytes.fromhex(inviter_sig),
            _invite_payload(wid, charter_hash, invitee_key),
            bytes.fromhex(sender_pub))
    except Exception:
        sig_ok = False
    if not sig_ok:
        raise HTTPException(status_code=400, detail="inviter_sig does not verify")
    with _db_lock, _db() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO workspace_remote_members "
            "(workspace_id, agent_pub, node_name, countersigned_at, struck_at) "
            "VALUES (?,?,?,NULL,NULL)",
            (wid, invitee_key, home_node))
    return {"invited": True, "workspace_id": wid, "node": NODE_NAME,
            "from_node": home_node, "agent_key": invitee_key,
            "charter_hash": charter_hash}

@router.post("/fed/workspace_countersign")
def fed_workspace_countersign(env: dict):
    """Workspace countersign, home-node side (docs/WORKSPACE_INVITE.md:
    remote members v1, step 3 — build item 2c.2). The invitee's node
    answers our /fed/workspace_invite with a countersignature minted by
    the invitee's NODE key. Signed envelope, recipient must be this
    node's own pubkey (direct), body.from_node_pub must equal sender_pub;
    the sender must be a known, unretired peer on the roster — a
    gossiping third node cannot plant countersigns between other nodes.
    The countersignature is verified against the sender's roster key over
    the canonical _countersign_payload(wid, OUR recomputed charter_hash,
    sender_pub, invitee_agent_key) — the presented charter_hash must
    equal ours first, so a room whose charter changed under the signature
    is refused at the door, never stored. The invite we sent lives as a
    pending row in workspace_remote_members (countersigned_at NULL);
    a struck row stays struck, a missing row answers 404. On success the
    row is marked countersigned_at; a re-countersign of an already-active
    row is idempotent success, never an error. No new crypto, no new
    daemons: envelope + roster, the pigeonhole-proxy conventions reused
    verbatim."""
    if not isinstance(env, dict) or not _fed_env.verify_envelope(env, expect_kind="workspace-countersign"):
        raise HTTPException(status_code=400, detail="invalid envelope")
    if env.get("recipient") != _NODE_PUB:
        raise HTTPException(status_code=400, detail="not addressed to this node")
    body = env.get("body")
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="invalid envelope")
    sender_pub = env.get("sender_pub")
    if body.get("from_node_pub") != sender_pub:
        raise HTTPException(status_code=400, detail="sender_pub mismatch")
    with _db_lock, _db() as conn:
        peer = conn.execute(
            "SELECT name FROM peers WHERE node_pub=? AND retired_at=''",
            (sender_pub,)).fetchone()
    if not peer:
        raise HTTPException(status_code=404, detail="unknown peer")
    invitee_node = peer["name"]
    wid = body.get("workspace_id")
    if isinstance(wid, bool) or not isinstance(wid, int) or wid < 1:
        raise HTTPException(status_code=400, detail="bad workspace_id")
    charter_hash = str(body.get("charter_hash", "")).lower()
    if not re.fullmatch(r"[0-9a-f]{64}", charter_hash):
        raise HTTPException(status_code=400, detail="bad charter_hash")
    invitee_key = str(body.get("invitee_agent_key", "")).lower()
    if not re.fullmatch(r"[0-9a-f]{64}", invitee_key):
        raise HTTPException(status_code=400, detail="bad invitee_agent_key")
    with _db_lock, _db() as conn:
        w = conn.execute(
            "SELECT id, charter, state FROM workspaces WHERE id=?", (wid,)).fetchone()
    if not w:
        raise HTTPException(status_code=404, detail="workspace not found")
    if w["state"] != "live":
        raise HTTPException(status_code=409,
                            detail=f"workspace is '{w['state']}'; countersigns need 'live'.")
    own_hash = hashlib.sha256((w["charter"] or "").encode()).hexdigest()
    if charter_hash != own_hash:
        raise HTTPException(status_code=400,
                            detail="charter mismatch: the charter quoted by the invitee "
                                   "is not this workspace's current charter.")
    countersign_sig = str(body.get("countersign_sig", ""))
    try:
        sig_ok = _fed_ed25519.checkvalid(
            bytes.fromhex(countersign_sig),
            _countersign_payload(wid, own_hash, sender_pub, invitee_key),
            bytes.fromhex(sender_pub))
    except Exception:
        sig_ok = False
    if not sig_ok:
        raise HTTPException(status_code=400, detail="countersign_sig does not verify")
    with _db_lock, _db() as conn:
        row = conn.execute(
            "SELECT countersigned_at, struck_at FROM workspace_remote_members "
            "WHERE workspace_id=? AND agent_pub=? AND node_name=?",
            (wid, invitee_key, invitee_node)).fetchone()
        if not row:
            raise HTTPException(status_code=404,
                                detail="no pending invite matches that workspace, "
                                       "member key, and node.")
        if row["struck_at"]:
            raise HTTPException(status_code=410,
                                detail="invite was struck; countersign refused.")
        if not row["countersigned_at"]:
            conn.execute(
                "UPDATE workspace_remote_members SET countersigned_at=? "
                "WHERE workspace_id=? AND agent_pub=? AND node_name=?",
                (_now(), wid, invitee_key, invitee_node))
    return {"countersigned": True, "workspace_id": wid, "node": NODE_NAME,
            "from_node": invitee_node, "agent_key": invitee_key,
            "charter_hash": own_hash}


@router.post("/fed/workspace_leave")
async def fed_workspace_leave(env: dict):
    """Workspace-invite v1 build item 4b.1: member-initiated leave,
    home-node receiver (docs/WORKSPACE_INVITE.md, leave/remove design
    note). The invitee's *node* speaks, never the agent directly — the
    envelope carries {workspace_id, member_key, leave_sig}, leave_sig
    minted by the invitee node's node key over canonical
    _leave_payload(wid, member_key). The home node verifies against the
    sender's roster key (node-vouch model), so a cross-node forgery path
    does not exist: the row is scoped to the sender's node, and a node
    forging a leave for its own agent harms only its own agent's seat.
    400 bad key/wid or forged sig; 404 unknown/retired peer, unknown
    workspace, or no membership row (never seen them — nothing to
    strike); 409 struck (already gone — goodbye is idempotent, 200
    re-leave for active or pending rows alike; pending invites die the
    same way an unsigned goodbye kills an unsigned invite). On success
    struck_at is set: the membership ends, receipts kept, no
    resurrection. No new crypto, no new daemons."""
    if not isinstance(env, dict) or not _fed_env.verify_envelope(env, expect_kind="workspace-leave"):
        raise HTTPException(status_code=400, detail="invalid envelope")
    if env.get("recipient") != _NODE_PUB:
        raise HTTPException(status_code=400, detail="not addressed to this node")
    body = env.get("body")
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="invalid envelope")
    sender_pub = env.get("sender_pub")
    if body.get("from_node_pub") != sender_pub:
        raise HTTPException(status_code=400, detail="sender_pub mismatch")
    with _db_lock, _db() as conn:
        peer = conn.execute(
            "SELECT name FROM peers WHERE node_pub=? AND retired_at=''",
            (sender_pub,)).fetchone()
    if not peer:
        raise HTTPException(status_code=404, detail="unknown peer")
    leaver_node = peer["name"]
    wid = body.get("workspace_id")
    if isinstance(wid, bool) or not isinstance(wid, int) or wid < 1:
        raise HTTPException(status_code=400, detail="bad workspace_id")
    member_key = str(body.get("member_key", "")).lower()
    if not re.fullmatch(r"[0-9a-f]{64}", member_key):
        raise HTTPException(status_code=400, detail="bad member_key")
    leave_sig = str(body.get("leave_sig", ""))
    try:
        sig_ok = _fed_ed25519.checkvalid(
            bytes.fromhex(leave_sig),
            _leave_payload(wid, member_key),
            bytes.fromhex(sender_pub))
    except Exception:
        sig_ok = False
    if not sig_ok:
        raise HTTPException(status_code=400, detail="leave_sig does not verify")
    with _db_lock, _db() as conn:
        w = conn.execute(
            "SELECT id FROM workspaces WHERE id=?", (wid,)).fetchone()
        if not w:
            raise HTTPException(status_code=404, detail="workspace not found")
        row = conn.execute(
            "SELECT struck_at FROM workspace_remote_members "
            "WHERE workspace_id=? AND agent_pub=? AND node_name=?",
            (wid, member_key, leaver_node)).fetchone()
        if not row:
            raise HTTPException(status_code=404,
                                detail="no membership row matches that workspace, "
                                       "member key, and node — nothing to strike.")
        if row["struck_at"]:
            raise HTTPException(status_code=409,
                                detail="already struck; the goodbye already landed.")
        conn.execute(
            "UPDATE workspace_remote_members SET struck_at=? "
            "WHERE workspace_id=? AND agent_pub=? AND node_name=?",
            (_now(), wid, member_key, leaver_node))
    return {"left": True, "workspace_id": wid, "node": NODE_NAME,
            "from_node": leaver_node, "agent_key": member_key}


@router.post("/fed/workspace_removed")
def fed_workspace_removed(env: dict):
    """Workspace-invite v1 build item 4b.2: home-initiated remove notice,
    invitee-node receiver (docs/WORKSPACE_INVITE.md, leave/remove design
    note). The home node already struck the member locally and fires this
    signed notice fire-and-forget (build item 4b.3) for closed-window
    honesty — this node marks its own receipt struck_at so the invitee
    side sees the same closed door. Envelope carries {workspace_id
    (the HOME node's id), member_key, removed_sig}; removed_sig is
    minted by the home node's node key over canonical
    _removed_payload(wid, member_key) and verified against the sender's
    roster key — only the room's home node can strike the receipt here.
    The sender must be the row's home node (node_name matches the
    sender's roster name); a third node cannot strike someone else's
    rows. 400 bad wid/key/sig or envelope trouble; 404 unknown peer or
    no membership row (never saw the invite — nothing to strike);
    already-struck is idempotent 200 (a repeated notice is a no-op, not
    an argument). Receipts kept, no resurrection. No new crypto, no new
    daemons."""
    if not isinstance(env, dict) or not _fed_env.verify_envelope(env, expect_kind="workspace-removed"):
        raise HTTPException(status_code=400, detail="invalid envelope")
    if env.get("recipient") != _NODE_PUB:
        raise HTTPException(status_code=400, detail="not addressed to this node")
    body = env.get("body")
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="invalid envelope")
    sender_pub = env.get("sender_pub")
    if body.get("from_node_pub") != sender_pub:
        raise HTTPException(status_code=400, detail="sender_pub mismatch")
    with _db_lock, _db() as conn:
        peer = conn.execute(
            "SELECT name FROM peers WHERE node_pub=? AND retired_at=''",
            (sender_pub,)).fetchone()
    if not peer:
        raise HTTPException(status_code=404, detail="unknown peer")
    home_node = peer["name"]
    wid = body.get("workspace_id")
    if isinstance(wid, bool) or not isinstance(wid, int) or wid < 1:
        raise HTTPException(status_code=400, detail="bad workspace_id")
    member_key = str(body.get("member_key", "")).lower()
    if not re.fullmatch(r"[0-9a-f]{64}", member_key):
        raise HTTPException(status_code=400, detail="bad member_key")
    removed_sig = str(body.get("removed_sig", ""))
    try:
        sig_ok = _fed_ed25519.checkvalid(
            bytes.fromhex(removed_sig),
            _removed_payload(wid, member_key),
            bytes.fromhex(sender_pub))
    except Exception:
        sig_ok = False
    if not sig_ok:
        raise HTTPException(status_code=400, detail="removed_sig does not verify")
    with _db_lock, _db() as conn:
        row = conn.execute(
            "SELECT struck_at FROM workspace_remote_members "
            "WHERE workspace_id=? AND agent_pub=? AND node_name=?",
            (wid, member_key, home_node)).fetchone()
        if not row:
            raise HTTPException(status_code=404,
                                detail="no membership receipt matches that "
                                       "workspace, member key, and home node "
                                       "— nothing to strike.")
        if row["struck_at"]:
            return {"removed": True, "already_struck": True,
                    "workspace_id": wid, "node": NODE_NAME,
                    "from_node": home_node, "agent_key": member_key}
        conn.execute(
            "UPDATE workspace_remote_members SET struck_at=? "
            "WHERE workspace_id=? AND agent_pub=? AND node_name=?",
            (_now(), wid, member_key, home_node))
    return {"removed": True, "workspace_id": wid, "node": NODE_NAME,
            "from_node": home_node, "agent_key": member_key}



