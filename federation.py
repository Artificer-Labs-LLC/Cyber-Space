from fastapi import APIRouter, Header, HTTPException, Request
from fed import ed25519 as _fed_ed25519
from fed import envelope as _fed_env
from datetime import datetime, timezone
import json
import re
import secrets
import urllib.request
from core import CAP_RE, IS_GENESIS, MAX_BODY, NAME_RE, NODE_NAME, _NODE_PRIV, _NODE_PUB, _authed, _broadcast, _check_rate, _db, _db_lock, _hash_key, _now, _post_message, _valid_name, _valid_node_url

router = APIRouter()

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
    with _db_lock, _db() as conn:
        conn.execute(
            """INSERT INTO peers (node_pub, name, network, version, genesis,
                                  capabilities, node_url, announced_at, first_seen)
               VALUES (?,?,?,?,?,?,?,?,?)
               ON CONFLICT(node_pub) DO UPDATE SET
                 name=excluded.name, network=excluded.network,
                 version=excluded.version, genesis=excluded.genesis,
                 capabilities=excluded.capabilities, node_url=excluded.node_url,
                 announced_at=excluded.announced_at,
                 retired_at=''  -- a fresh announce revives a retired peer
            """,
            (
                sender_pub, name, str(body.get("network", "cybernet")),
                str(body.get("version", "0.1.0")), int(bool(body.get("genesis", False))),
                json.dumps(caps), node_url, now, now,
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
    (a fresh /fed/announce clears the tombstone). Unknown peer -> 404."""
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
    now = _now()
    with _db_lock, _db() as conn:
        cur = conn.execute(
            "UPDATE peers SET retired_at=? WHERE node_pub=? AND retired_at=''",
            (now, sender_pub))
        if cur.rowcount == 0:
            row = conn.execute(
                "SELECT 1 FROM peers WHERE node_pub=?", (sender_pub,)).fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="unknown peer")
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

_NODE_URL_RE = re.compile(r"^https?://[a-zA-Z0-9_.-]+(?::\d{1,5})?(/[a-zA-Z0-9_./-]*)?$")

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
             "from_node_name": NODE_NAME, "channel": channel})
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

