from fastapi import APIRouter, Header, HTTPException, Request
from fed import ed25519 as _fed_ed25519
from fed import envelope as _fed_env
from routes_channels import _dm_channel  # fed_dm's delivery channel; routes_channels only imports core+models, no cycle
from datetime import datetime, timedelta, timezone
import json
import re
import hashlib
import secrets
import time
import urllib.request
from core import (CAP_RE, IS_GENESIS, MAX_BODY, NAME_RE, NODE_NAME, _NODE_PRIV,
                  _NODE_PUB, _NODE_URL_RE, _authed, _broadcast, _check_rate, _db,
                  _db_lock, _delta_payload, _countersign_payload, _hash_key,
                  _invite_payload, _leave_payload, _now, _pigeonhole_cutoff,
                  _peer_urlopen, _post_message, _read_peer_json,
                  _removed_payload, _touch_visitor, _valid_name,
                  _valid_node_url, ingest_reach_descriptor)

router = APIRouter()

# Seen-sig replay-dedupe horizon: an envelope sig is a replay only
# inside this window (the envelope MAX_SKEW horizon) — past it the
# envelope's own timestamp gate refuses the replay anyway.
_SEEN_SIG_HORIZON_SEC = 600


def _claim_seen_sig(conn, sig_hex: str, now: float = None) -> bool:
    """Claim an inbound envelope signature; the replay-dedupe primitive.

    Restored 2026-10-13: the core split (515369d) carried the
    fed_seen_sigs table into core_serve.py's schema but dropped this
    helper and every receiver wiring with it, silently un-deduping all
    inbound federation receivers (the fedws*-replay-dedupe belts have
    failed on it since). This tick restores the primitive (step 1);
    re-wiring the receivers is the follow-on step.

    Atomic check-and-insert on fed_seen_sigs. Returns True when this
    signature was already seen inside the horizon (i.e. a REPLAY — the
    caller must reject the envelope); False on first sight (the signature
    is now recorded). Fail-closed: a malformed sig_hex raises ValueError,
    so the caller can 400 instead of touching the store. Expired rows are
    pruned on every call, bounding the table at ~one horizon of traffic.
    """
    if not isinstance(sig_hex, str) or len(sig_hex) != 128:
        raise ValueError("bad signature shape")
    try:
        bytes.fromhex(sig_hex)
    except ValueError:
        raise ValueError("bad signature shape")
    t = now if now is not None else time.time()
    # Prune BEFORE the check: an expired signature is not a replay, and an
    # expired row must never block a fresh claim of the same sig.
    conn.execute("DELETE FROM fed_seen_sigs WHERE seen_at < ?",
                 (t - _SEEN_SIG_HORIZON_SEC,))
    cur = conn.execute(
        "INSERT OR IGNORE INTO fed_seen_sigs(sig, seen_at) VALUES (?, ?)",
        (sig_hex, t))
    return cur.rowcount == 0


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
    # Only real strings are row fields: str() at the owner pick and in
    # _delta_payload aliased a delta-carried JSON number into the row
    # -- a numeric name stringified to the valid label its owner
    # signature genuinely covered (the payload builder coerces the
    # same way) and was accepted as a valid attestation (twin of
    # fed_directory_delta's row gate). Absent fields keep their
    # payload defaults; present ones must be strings.
    if any(k in row and not isinstance(row[k], str) for k in
           ("node_pub", "name", "node_url", "network", "version")):
        return None, None
    if str(row.get("node_pub", "")).lower() != sender_pub.lower():
        return None, None
    seq = delta.get("seq")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
        return None, None
    if "sig" in delta and not isinstance(delta["sig"], str):
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
    return _fed_env.make_envelope(_NODE_PRIV, _NODE_PUB, "federation", body)


@router.post("/fed/announce")
def fed_announce(env: dict):
    """Federation capability broadcast: verify the peer's signed announcement
    and store it as a roster entry (docs/FEDERATION.md primitive 2b).
    Stored as seen-from-peer, never as gospel. Recipient must be
    "federation" (broadcast) or this node's own pubkey (direct)."""
    if not isinstance(env, dict) or not _fed_env.verify_envelope(env):
        raise HTTPException(status_code=400, detail="invalid envelope")
    if env.get("recipient") not in ("federation", _NODE_PUB):
        raise HTTPException(status_code=400, detail="not addressed to this node")
    # Replay dedupe (restored 2026-10-13; the core split dropped this
    # wiring along with _claim_seen_sig itself): claim the envelope's
    # sig after verify+recipient, before the sender_pub gate, the
    # reach-descriptor rate bucket and ingest, the roster field gates,
    # and the peers upsert, so a replay can never redo that work for
    # free or burn fedreachannounce: quota. verify_envelope already
    # established a valid sig, so the claim's ValueError is
    # unreachable in production; it is converted to 400 anyway so the
    # seat fails closed (never a 500) if verify is ever bypassed.
    # Named post-claim edges: sender_pub mismatch claims;
    # genuine re-announces re-sign with a fresh ts (new sig).
    with _db_lock, _db() as conn:
        try:
            replayed = _claim_seen_sig(conn, env.get("sig"))
        except ValueError:
            raise HTTPException(status_code=400, detail="invalid envelope")
        if replayed:
            raise HTTPException(status_code=400, detail="replay")
    body = env.get("body")
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="invalid envelope")
    sender_pub = env.get("sender_pub")
    if body.get("node_pub") != sender_pub:
        raise HTTPException(status_code=400, detail="sender_pub mismatch")
    # .cyberspace depth: the name-key-signed announce half (docs/HOSTING.md).
    # The reach descriptor rides /fed/announce — the announce whose
    # sender_pub IS the name key (body.node_pub == sender_pub ==
    # node_pubkey, checked above). When the body carries a reach
    # descriptor, the roster half below is skipped entirely: a name key
    # is a name identity, not a node identity — minting a peers row
    # under it would poison the directory roster with a non-node key.
    # Mirrors merge the descriptor via ingest_reach_descriptor — seen
    # from peer, never gospel. No known-peer gate: the descriptor is
    # self-authenticating (it only merges against a LIVE registry
    # binding under the SAME key, so a stranger can only ever publish
    # reach for a name it genuinely holds) — anyone-can-host. Per-sender
    # rate bucket of its own: a name key is a different key space than
    # node keys and shouldn't burn the node-announce quota.
    # (Restored on this branch line: the branch was lost in the r2
    # rebase — hostd/_reach_out kept sending, nothing merged, so
    # primitive-3 hosting announced reach no mirror ever stored.)
    desc = body.get("reach_descriptor")
    if desc is not None:
        if not isinstance(desc, dict):
            raise HTTPException(status_code=400, detail="bad reach descriptor")
        # Only real strings are descriptor identity fields: str()
        # aliased a JSON number/bool into the field -- a digit-only
        # pubkey served as a number stringified to its own hex and
        # passed this name-key gate, and the return echoed a numeric
        # name as its digit string ("12345") and true as "true", the
        # same alias the descriptor comparison seats refuse on sight.
        # ingest_reach_descriptor gates both fields downstream, but
        # this seat's gate and echo must be self-contained.
        desc_pub = desc.get("node_pubkey", "")
        if not isinstance(desc_pub, str) or desc_pub.lower() != sender_pub.lower():
            raise HTTPException(status_code=400, detail="name-key mismatch")
        _check_rate(f"fedreachannounce:{sender_pub}")
        outcome = ingest_reach_descriptor(desc)
        desc_name = desc.get("name", "")
        return {"ok": True, "reach": outcome,
                "name": desc_name.lower() if isinstance(desc_name, str) else "",
                "node_pubkey": sender_pub.lower()}
    # Only real strings are roster fields: str() aliased an
    # announce-carried JSON number into the field -- a numeric name
    # stringified to the valid label "12345" and was stored as that
    # peer name, and int network/version were stored as their digit
    # strings (twin of fed_gossip's roster gate). Absent fields keep
    # their defaults; present ones must be strings.
    name = body.get("name", "")
    if not isinstance(name, str) or not re.fullmatch(r"[a-z0-9_-]{1,32}", name):
        raise HTTPException(status_code=400, detail="bad node name")
    network = body.get("network", "cybernet")
    if not isinstance(network, str):
        raise HTTPException(status_code=400, detail="bad network")
    version = body.get("version", "0.1.0")
    if not isinstance(version, str):
        raise HTTPException(status_code=400, detail="bad version")
    # Only a real bool is a genesis flag: bool() here coerced the
    # string "false" (and 1) to genesis=1 in storage — a claim
    # nobody served in that form, the alias _delta_payload's own
    # shape gate refuses on sight. Absent keeps False.
    genesis = body.get("genesis", False)
    if not isinstance(genesis, bool):
        raise HTTPException(status_code=400, detail="bad genesis")
    caps = body.get("capabilities", [])
    if not isinstance(caps, list):
        caps = []
    caps = [c for c in caps if isinstance(c, str) and CAP_RE.fullmatch(c)][:32]
    node_url = ""
    if body.get("node_url"):
        node_url = _valid_node_url(body.get("node_url"))
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
                sender_pub, name, network,
                version, int(genesis),
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
    if not isinstance(env, dict) or not _fed_env.verify_envelope(env):
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
    if not isinstance(env, dict) or not _fed_env.verify_envelope(env):
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
            # Only real strings are roster fields: str() here aliased a
            # gossip-carried JSON number into a peer row — a digit-only
            # pubkey served as a number stringified to its own hex and
            # merged, and a numeric name merged as its digit string
            # (twin of the binding seats' gate in core).
            if (not isinstance(entry.get("node_pub"), str)
                    or not isinstance(entry.get("name"), str)):
                ignored += 1
                continue
            ep = entry["node_pub"]
            if (not re.fullmatch(r"[0-9a-fA-F]{64}", ep)
                    or ep.lower() == _NODE_PUB.lower()
                    or ep.lower() == sender_pub.lower()):
                ignored += 1
                continue
            name = entry["name"]
            if not re.fullmatch(r"[a-z0-9_-]{1,32}", name):
                ignored += 1
                continue
            # version joins the string gate above and node_url passes
            # raw to _valid_node_url (which gates non-strings itself):
            # str() aliased an int version into its digit string, stored
            # as the peer's version (twin of fed_announce's body gate).
            # Absent version keeps its default.
            version = entry.get("version", "0.1.0")
            if not isinstance(version, str):
                ignored += 1
                continue
            # Only a real bool is a genesis flag: bool() at the
            # insert coerced the string "false" (and 1) to
            # genesis=1 in storage — a claim nobody served in that
            # form, the alias _delta_payload's own shape gate
            # refuses on sight. Absent keeps False.
            genesis = entry.get("genesis", False)
            if not isinstance(genesis, bool):
                ignored += 1
                continue
            try:
                node_url = _valid_node_url(entry.get("node_url", ""))
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
                 version,
                 int(genesis),
                 json.dumps(caps), node_url, "", now),
            )
            if cur.rowcount:
                merged += 1
            else:
                ignored += 1
    return {"ok": True, "merged": merged, "ignored": ignored}


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
    if not isinstance(env, dict) or not _fed_env.verify_envelope(env):
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
            # Only real strings are row fields: str() at the owner pick,
            # in _delta_payload, and at the insert aliased a delta-carried
            # JSON number into the row — a numeric name stringified to the
            # valid label its signature genuinely covered (the payload
            # builder coerces the same way) and an int network stored as
            # its digit string (twin of fed_gossip's roster gate).
            # Absent fields keep their payload defaults; present ones
            # must be strings.
            if any(k in row and not isinstance(row[k], str) for k in
                   ("node_pub", "name", "node_url", "network", "version")):
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
            # Only a real bool is a retire flag, and only a real
            # string is a sig: bool()/str() here coerced them before
            # _delta_payload could refuse — retire "false"/1 became
            # a retire the payload builder's own gate rejects as a
            # non-bool (delta-payload-shape-type belt), verified
            # against the retire payload and applied as a tombstone
            # for a flag nobody served as a bool. Twin of
            # _recv_attestation's sig gate. Absent fields keep their
            # defaults; present ones must be the canonical shape.
            if "retire" in delta and not isinstance(delta["retire"], bool):
                rejected += 1
                continue
            if "sig" in delta and not isinstance(delta["sig"], str):
                rejected += 1
                continue
            retire = delta.get("retire", False)
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
    own pubkey (direct delivery only). The sender must already be a known,
    unretired peer — DMs are a relationship primitive, so an announced
    stranger cannot DM in: announce first, then write."""
    if not isinstance(env, dict) or not _fed_env.verify_envelope(env):
        raise HTTPException(status_code=400, detail="invalid envelope")
    if env.get("recipient") != _NODE_PUB:
        raise HTTPException(status_code=400, detail="not addressed to this node")
    # Replay dedupe (restored 2026-10-13; the core split dropped this
    # wiring along with _claim_seen_sig itself): claim the envelope's
    # sig after verify+recipient, before the peer gate, the sender_pub
    # gate, the rate check, and the message write. verify_envelope
    # already established a valid sig, so the claim's ValueError is
    # unreachable. Named post-claim edges: unknown peer 404s claim;
    # genuine resends re-sign with a fresh ts (new sig).
    with _db_lock, _db() as conn:
        if _claim_seen_sig(conn, env.get("sig")):
            raise HTTPException(status_code=400, detail="replay")
    sender_pub = env.get("sender_pub")
    with _db_lock, _db() as conn:
        if not conn.execute(
                "SELECT 1 FROM peers WHERE node_pub=? AND retired_at=''",
                (sender_pub,)).fetchone():
            raise HTTPException(status_code=404, detail="unknown peer")
    body = env.get("body")
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="invalid envelope")
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
    if not isinstance(env, dict) or not _fed_env.verify_envelope(env):
        raise HTTPException(status_code=400, detail="invalid envelope")
    if env.get("recipient") != _NODE_PUB:
        raise HTTPException(status_code=400, detail="not addressed to this node")
    # Replay dedupe (restored 2026-10-13; the core split dropped this
    # wiring along with _claim_seen_sig itself): claim the envelope's
    # sig after verify+recipient, before the sender_pub/name gates, the
    # rate check, and the channel_subs write. verify_envelope already
    # established a valid sig, so the claim's ValueError is unreachable.
    # Named post-claim edges: sender_pub mismatch and bad names all
    # claim; genuine resends re-sign with a fresh ts (new sig).
    with _db_lock, _db() as conn:
        if _claim_seen_sig(conn, env.get("sig")):
            raise HTTPException(status_code=400, detail="replay")
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
    if not isinstance(env, dict) or not _fed_env.verify_envelope(env):
        raise HTTPException(status_code=400, detail="invalid envelope")
    if env.get("recipient") != _NODE_PUB:
        raise HTTPException(status_code=400, detail="not addressed to this node")
    # Replay dedupe (restored 2026-10-13; the core split dropped this
    # wiring along with _claim_seen_sig itself): claim the envelope's
    # sig after verify+recipient, before the sender_pub/name gates, the
    # rate check, and the channel_subs delete. verify_envelope already
    # established a valid sig, so the claim's ValueError is unreachable.
    # Named post-claim edges: sender_pub mismatch and bad names all
    # claim; genuine resends re-sign with a fresh ts (new sig).
    with _db_lock, _db() as conn:
        if _claim_seen_sig(conn, env.get("sig")):
            raise HTTPException(status_code=400, detail="replay")
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
    if not isinstance(env, dict) or not _fed_env.verify_envelope(env):
        raise HTTPException(status_code=400, detail="invalid envelope")
    if env.get("recipient") != _NODE_PUB:
        raise HTTPException(status_code=400, detail="not addressed to this node")
    # Replay dedupe (restored 2026-10-13; the core split dropped this
    # wiring along with _claim_seen_sig itself): claim the envelope's
    # sig after verify+recipient, before the sender_pub/name gates, the
    # rate checks, the consent check, and the message write.
    # verify_envelope already established a valid sig, so the claim's
    # ValueError is unreachable. Named post-claim edges: sender_pub
    # mismatch, bad names, and no-consent 403s all claim; genuine
    # resends re-sign with a fresh ts (new sig).
    with _db_lock, _db() as conn:
        if _claim_seen_sig(conn, env.get("sig")):
            raise HTTPException(status_code=400, detail="replay")
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
    env = _fed_env.make_envelope(_NODE_PRIV, _NODE_PUB, node_pub, body)
    try:
        req = urllib.request.Request(
            peer["node_url"] + "/fed/channel/join",
            data=json.dumps(env).encode(),
            headers={"Content-Type": "application/json"})
        with _peer_urlopen(req, timeout=8) as resp:
            reply = _read_peer_json(resp)
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
             "from_node_name": NODE_NAME, "channel": channel})
        try:
            req = urllib.request.Request(
                peer["node_url"] + "/fed/channel/leave",
                data=json.dumps(leave).encode(),
                headers={"Content-Type": "application/json"})
            with _peer_urlopen(req, timeout=8) as resp:
                peer_cleaned = bool(_read_peer_json(resp).get("removed"))
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
    if not isinstance(env, dict) or not _fed_env.verify_envelope(env):
        raise HTTPException(status_code=400, detail="invalid envelope")
    if env.get("recipient") != _NODE_PUB:
        raise HTTPException(status_code=400, detail="not addressed to this node")
    # Replay dedupe (restored 2026-10-13; the core split dropped this
    # wiring along with _claim_seen_sig itself, plus the rate gate and
    # the visitor touch below): claim the envelope's sig after
    # verify+recipient, before the sender_pub gate, the rate bucket,
    # the known-peer gate, the lazy TTL prune, the visitor touch, and
    # the board read, so a replay can never redo that work for free or
    # cost fedpigeonhole: quota. Named post-claim edges: sender_pub
    # mismatch and unknown peer both claim; genuine re-asks re-sign
    # with a fresh ts (new sig).
    with _db_lock, _db() as conn:
        if _claim_seen_sig(conn, env.get("sig")):
            raise HTTPException(status_code=400, detail="replay")
    body = env.get("body")
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="invalid envelope")
    sender_pub = env.get("sender_pub")
    if body.get("from_node_pub") != sender_pub:
        raise HTTPException(status_code=400, detail="sender_pub mismatch")
    _check_rate(f"fedpigeonhole:{sender_pub}")
    with _db_lock, _db() as conn:
        peer = conn.execute(
            "SELECT name FROM peers WHERE node_pub=? AND retired_at=''",
            (sender_pub,)).fetchone()
    if not peer:
        raise HTTPException(status_code=404, detail="unknown peer")
    peer_name = peer["name"]
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
        # Visitors v1 (restored with the claim above): a proxied read
        # is a visit — the guest stood at the board. Key is the peer's
        # roster name at this node (verified identity, never a raw
        # address); the room walked is the board, never its contents.
        # Inside this transaction: the touch and the read commit
        # together or not at all.
        _touch_visitor(conn, f"{peer_name}@{NODE_NAME}", peer_name, "boards")
    items = [{"agent": r["agent"], "body": r["body"], "created_at": r["created_at"]}
             for r in rows]
    reply = {"origin_node": NODE_NAME, "origin_pub": _NODE_PUB,
             "pigeonholes": items, "count": len(items), "limit": limit}
    return _fed_env.make_envelope(_NODE_PRIV, _NODE_PUB, sender_pub, reply)

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
    if not isinstance(env, dict) or not _fed_env.verify_envelope(env):
        raise HTTPException(status_code=400, detail="invalid envelope")
    if env.get("recipient") != _NODE_PUB:
        raise HTTPException(status_code=400, detail="not addressed to this node")
    # Replay dedupe (restored 2026-10-13; the core split dropped this
    # wiring along with _claim_seen_sig itself): claim the envelope's
    # sig after verify+recipient, before the sender_pub/standing gates,
    # the inviter_sig ed25519 verify, and the membership receipt write.
    # verify_envelope already established a valid sig, so the claim's
    # ValueError is unreachable. Named post-claim edges: sender_pub
    # mismatch, unknown peer, and bad inviter_sig all claim; genuine
    # resends re-sign with a fresh ts (new sig).
    with _db_lock, _db() as conn:
        if _claim_seen_sig(conn, env.get("sig")):
            raise HTTPException(status_code=400, detail="replay")
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
    _ch = body.get("charter_hash")
    charter_hash = _ch.lower() if isinstance(_ch, str) else ""
    if not re.fullmatch(r"[0-9a-f]{64}", charter_hash):
        raise HTTPException(status_code=400, detail="bad charter_hash")
    _ik = body.get("invitee_agent_key")
    invitee_key = _ik.lower() if isinstance(_ik, str) else ""
    if not re.fullmatch(r"[0-9a-f]{64}", invitee_key):
        raise HTTPException(status_code=400, detail="bad invitee_agent_key")
    _sg = body.get("inviter_sig")
    inviter_sig = _sg if isinstance(_sg, str) else ""
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
            "(workspace_id, agent_pub, node_name, node_pub, countersigned_at, struck_at) "
            "VALUES (?,?,?,?,NULL,NULL)",
            (wid, invitee_key, home_node, sender_pub))
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
    if not isinstance(env, dict) or not _fed_env.verify_envelope(env):
        raise HTTPException(status_code=400, detail="invalid envelope")
    if env.get("recipient") != _NODE_PUB:
        raise HTTPException(status_code=400, detail="not addressed to this node")
    # Replay dedupe (restored 2026-10-13; step 2, second receiver — twin
    # of fed_workspace_invite 521e601): claim the envelope's sig after
    # verify+recipient, before the sender_pub mismatch check, the peer
    # standing gate, the countersign_sig ed25519 verify, and the
    # countersigned_at write. verify_envelope already established a
    # valid sig, so the claim's ValueError is unreachable. Named
    # post-claim edges: sender_pub mismatch, unknown peer, and bad
    # countersign_sig all claim; genuine resends re-sign with a fresh
    # ts (new sig) and stay idempotent success.
    with _db_lock, _db() as conn:
        if _claim_seen_sig(conn, env.get("sig")):
            raise HTTPException(status_code=400, detail="replay")
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
    _ch = body.get("charter_hash")
    charter_hash = _ch.lower() if isinstance(_ch, str) else ""
    if not re.fullmatch(r"[0-9a-f]{64}", charter_hash):
        raise HTTPException(status_code=400, detail="bad charter_hash")
    _ik = body.get("invitee_agent_key")
    invitee_key = _ik.lower() if isinstance(_ik, str) else ""
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
    _sg = body.get("countersign_sig")
    countersign_sig = _sg if isinstance(_sg, str) else ""
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
        # Visitors v1 item 3 (restored 2026-10-13; aac4aac's touch was
        # lost in the core split along with the replay claim): the remote
        # seat taken is a visit — {invitee_key}@{verified roster name},
        # room "workspaces", never the contents; seat and touch commit
        # together in this transaction.
        _touch_visitor(conn, f"{invitee_key}@{invitee_node}", invitee_node,
                       "workspaces")
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
    if not isinstance(env, dict) or not _fed_env.verify_envelope(env):
        raise HTTPException(status_code=400, detail="invalid envelope")
    if env.get("recipient") != _NODE_PUB:
        raise HTTPException(status_code=400, detail="not addressed to this node")
    # Replay dedupe (restored 2026-10-13; step 2, third receiver — twin
    # of fed_workspace_invite 521e601 / countersign 3fe8abc): claim the
    # envelope's sig after verify+recipient, before the sender_pub
    # mismatch check, the peer standing gate, the leave_sig ed25519
    # verify, and the struck_at write. verify_envelope already
    # established a valid sig, so the claim's ValueError is unreachable.
    # Named post-claim edges: sender_pub mismatch, unknown peer, bad
    # member_key, bad leave_sig, and no-row all claim; genuine resends
    # re-sign with a fresh ts (new sig) and land on the real row state
    # (409 already struck), never a replay false-positive.
    with _db_lock, _db() as conn:
        if _claim_seen_sig(conn, env.get("sig")):
            raise HTTPException(status_code=400, detail="replay")
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
    _mk = body.get("member_key")
    member_key = _mk.lower() if isinstance(_mk, str) else ""
    if not re.fullmatch(r"[0-9a-f]{64}", member_key):
        raise HTTPException(status_code=400, detail="bad member_key")
    _sg = body.get("leave_sig")
    leave_sig = _sg if isinstance(_sg, str) else ""
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
    if not isinstance(env, dict) or not _fed_env.verify_envelope(env):
        raise HTTPException(status_code=400, detail="invalid envelope")
    if env.get("recipient") != _NODE_PUB:
        raise HTTPException(status_code=400, detail="not addressed to this node")
    # Replay dedupe (restored 2026-10-13; step 2, fourth and last
    # workspace receiver — twin of fed_workspace_invite 521e601 /
    # countersign 3fe8abc / leave b1af9b9): claim the envelope's sig
    # after verify+recipient, before the sender_pub mismatch check, the
    # peer standing gate, the removed_sig ed25519 verify, and the
    # struck_at write. verify_envelope already established a valid sig,
    # so the claim's ValueError is unreachable. Named post-claim edges:
    # sender_pub mismatch, unknown peer, bad member_key, bad
    # removed_sig, and no-row all claim; genuine resends re-sign with a
    # fresh ts (new sig) and land on the real row state (idempotent 200
    # already_struck), never a replay false-positive.
    with _db_lock, _db() as conn:
        if _claim_seen_sig(conn, env.get("sig")):
            raise HTTPException(status_code=400, detail="replay")
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
    _mk = body.get("member_key")
    member_key = _mk.lower() if isinstance(_mk, str) else ""
    if not re.fullmatch(r"[0-9a-f]{64}", member_key):
        raise HTTPException(status_code=400, detail="bad member_key")
    _sg = body.get("removed_sig")
    removed_sig = _sg if isinstance(_sg, str) else ""
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

