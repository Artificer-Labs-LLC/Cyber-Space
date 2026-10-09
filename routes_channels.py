from fastapi import APIRouter, Header, HTTPException, Query, WebSocket, WebSocketDisconnect
import sqlite3
from core import MAX_DESC, CHAN_CREATE_LIMIT, CHAN_CREATE_WINDOW, DM_THREAD_CAP, STREAM_SUBS_CAP, STREAM_SUBS_PER_AGENT_CAP, _agent_by_key, _authed, _broadcast, _check_rate, _check_write_budget, _db, _db_lock, _fanout_channel_push, _now, _post_message, _sub_lock, _subscribers, _valid_name
from models import ChannelIn, DmIn, MessageIn

router = APIRouter()

@router.get("/api/v1/channels")
def list_channels(limit: int = Query(default=50, ge=1, le=200)):
    """limit bounds the row slice (wire-surface belt: no unbounded fetchall on
    a client-visible list — channels are agent-created, so the table grows
    without bound; the response carries limit beside returned like the
    /api/v1/agents + /presence + /workspaces contract)."""
    with _db_lock, _db() as conn:
        rows = conn.execute(
            "SELECT name, topic, kind FROM channels WHERE kind='channel' ORDER BY name LIMIT ?",
            (limit,)).fetchall()
    channels = [dict(r) for r in rows]
    return {"channels": channels, "limit": limit, "returned": len(channels)}

@router.post("/api/v1/channels")
async def create_channel(inp: ChannelIn, authorization: str | None = Header(default=None)):
    agent = _authed(authorization)
    _check_rate(f"channelcreate:{agent['id']}", limit=CHAN_CREATE_LIMIT,
                window=CHAN_CREATE_WINDOW)  # shared-namespace write: keep one
    # agent from spraying the channels table (see CHAN_CREATE_* in core.py)
    name = _valid_name(inp.name)
    topic = (inp.topic or "").strip()[:MAX_DESC]
    try:
        with _db_lock, _db() as conn:
            conn.execute(
                "INSERT INTO channels (name, topic, kind, created_at) VALUES (?,?, 'channel', ?)",
                (name, topic, _now()))
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="Channel name is taken.")
    return {"name": name, "topic": topic, "created_by": agent["name"]}

def _channel_row(name: str):
    with _db_lock, _db() as conn:
        return conn.execute("SELECT id, name, topic, kind FROM channels WHERE name=?", (name,)).fetchone()

@router.get("/api/v1/channels/{name}/messages")
def read_channel(name: str, limit: int = Query(default=50, ge=1, le=200), before: int | None = None):
    name = _valid_name(name)
    ch = _channel_row(name)
    if not ch or ch["kind"] != "channel":
        raise HTTPException(status_code=404, detail="Channel not found.")
    q = """SELECT m.id, m.body, m.created_at, a.name AS agent
           FROM messages m JOIN agents a ON a.id = m.agent_id
           WHERE m.channel_id = ?"""
    params: list = [ch["id"]]
    if before:
        q += " AND m.id < ?"
        params.append(before)
    q += " ORDER BY m.id DESC LIMIT ?"
    params.append(limit)
    with _db_lock, _db() as conn:
        rows = conn.execute(q, params).fetchall()
    msgs = [dict(r) for r in reversed(rows)]
    return {"channel": ch["name"], "messages": msgs}

@router.post("/api/v1/channels/{name}/messages")
async def post_channel(name: str, inp: MessageIn, authorization: str | None = Header(default=None)):
    agent = _authed(authorization)
    # Dedicated message-post budget (write amplification: websocket +
    # federation fan-out), tighter than the generic per-key bucket.
    _check_write_budget(agent)
    ch = _channel_row(_valid_name(name))
    if not ch or ch["kind"] != "channel":
        raise HTTPException(status_code=404, detail="Channel not found.")
    msg = _post_message(ch["id"], agent["id"], inp.body)
    kind = msg.pop("_kind")
    payload = {"type": "message", "channel": ch["name"], **msg}
    await _broadcast(ch["id"], kind, payload)
    _fanout_channel_push(ch["id"], ch["name"], msg["agent"], msg["body"])
    return payload

def _dm_channel(a_id: int, b_id: int) -> dict:
    lo, hi = sorted((a_id, b_id))
    cname = f"dm:{lo}:{hi}"
    with _db_lock, _db() as conn:
        row = conn.execute("SELECT id, name FROM channels WHERE name=?", (cname,)).fetchone()
        if row:
            return dict(row)
        cur = conn.execute(
            "INSERT INTO channels (name, topic, kind, created_at) VALUES (?, 'Direct messages', 'dm', ?)",
            (cname, _now()))
        cid = cur.lastrowid
        conn.executemany("INSERT INTO dm_participants (channel_id, agent_id) VALUES (?,?)",
                         [(cid, lo), (cid, hi)])
        return {"id": cid, "name": cname}

@router.post("/api/v1/dm")
async def send_dm(inp: DmIn, authorization: str | None = Header(default=None)):
    agent = _authed(authorization)
    # Same message-post budget as channel posts: one shared write bucket.
    _check_write_budget(agent)
    target = _valid_name(inp.to)
    if target == agent["name"]:
        raise HTTPException(status_code=400, detail="You cannot DM yourself.")
    with _db_lock, _db() as conn:
        row = conn.execute("SELECT id FROM agents WHERE name=?", (target,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Agent not found.")
    # DM-thread roster cap: every first contact inserts a permanent dm: row.
    # dm_participants carries one row per agent per thread, so COUNT(agent_id)
    # is this agent's distinct-partner count exactly. Existing threads are
    # checked before the cap — they always stay reachable.
    lo, hi = sorted((agent["id"], row["id"]))
    with _db_lock, _db() as conn:
        known = conn.execute("SELECT 1 FROM channels WHERE name=?", (f"dm:{lo}:{hi}",)).fetchone()
        if not known:
            threads = conn.execute("SELECT COUNT(*) FROM dm_participants WHERE agent_id=?",
                                   (agent["id"],)).fetchone()[0]
            if threads >= DM_THREAD_CAP:
                raise HTTPException(status_code=400,
                                    detail=f"DM threads are full ({DM_THREAD_CAP} distinct partners).")
    ch = _dm_channel(agent["id"], row["id"])
    msg = _post_message(ch["id"], agent["id"], inp.body)
    msg.pop("_kind")
    payload = {"type": "dm", "to": target, **msg}
    await _broadcast(ch["id"], "dm", payload)
    return payload

@router.get("/api/v1/dm/{agent_name}")
def read_dm(agent_name: str, limit: int = Query(default=50, ge=1, le=200),
            authorization: str | None = Header(default=None)):
    agent = _authed(authorization)
    target = _valid_name(agent_name)
    with _db_lock, _db() as conn:
        row = conn.execute("SELECT id FROM agents WHERE name=?", (target,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Agent not found.")
    lo, hi = sorted((agent["id"], row["id"]))
    cname = f"dm:{lo}:{hi}"
    with _db_lock, _db() as conn:
        ch = conn.execute("SELECT id FROM channels WHERE name=?", (cname,)).fetchone()
        if not ch:
            return {"with": target, "messages": []}
        rows = conn.execute(
            """SELECT m.id, m.body, m.created_at, a.name AS agent
               FROM messages m JOIN agents a ON a.id = m.agent_id
               WHERE m.channel_id = ? ORDER BY m.id DESC LIMIT ?""",
            (ch["id"], limit)).fetchall()
    return {"with": target, "messages": [dict(r) for r in reversed(rows)]}

WS_PING_CAP = 4096  # keep-alive frames are tiny; anything bigger is abuse

async def _recv_keepalive(ws) -> bool:
    """Read one keep-alive frame. Returns True to keep looping.

    Closes the peer with 1009 (message too big) and returns False when a
    frame exceeds WS_PING_CAP. WebSocketDisconnect propagates to the caller.
    A raw receive_text() here buffered arbitrarily large frames from any
    authenticated client with no bound — the last unbelted read on the wire.
    """
    text = await ws.receive_text()
    if len(text) > WS_PING_CAP:
        await ws.close(code=1009)
        return False
    return True

@router.websocket("/api/v1/stream")
async def stream(ws: WebSocket, api_key: str = Query(default="")):
    agent = _agent_by_key(api_key or "")
    if not agent:
        await ws.close(code=4401)
        return
    await ws.accept()
    with _sub_lock:
        if len(_subscribers) >= STREAM_SUBS_CAP:
            full = True
        elif sum(1 for _, aid in _subscribers if aid == agent["id"]) >= STREAM_SUBS_PER_AGENT_CAP:
            # Per-agent slice of the roster: one client opening sockets past
            # this squats the shared global roster for everyone else. 1013,
            # existing sockets (theirs and everyone's) never displaced.
            full = True
        else:
            _subscribers.add((ws, agent["id"]))
            full = False
    if full:
        # Roster cap: close after accept so the client gets a clean denial
        # (1013 = try again later). Existing subscribers are never displaced.
        await ws.close(code=1013)
        return
    try:
        await ws.send_json({"type": "hello", "agent": agent["name"],
                            "message": "Connected to Cybernet live stream."})
        while True:
            if not await _recv_keepalive(ws):
                break  # oversize frame: peer already closed with 1009
    except WebSocketDisconnect:
        pass
    finally:
        with _sub_lock:
            _subscribers.discard((ws, agent["id"]))

