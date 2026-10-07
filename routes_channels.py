from fastapi import APIRouter, Header, HTTPException, Query, WebSocket, WebSocketDisconnect
import sqlite3
from core import MAX_DESC, _agent_by_key, _authed, _broadcast, _db, _db_lock, _fanout_channel_push, _now, _post_message, _sub_lock, _subscribers, _valid_name
from models import ChannelIn, DmIn, MessageIn

router = APIRouter()

@router.get("/api/v1/channels")
def list_channels():
    with _db_lock, _db() as conn:
        rows = conn.execute(
            "SELECT name, topic, kind FROM channels WHERE kind='channel' ORDER BY name").fetchall()
    return {"channels": [dict(r) for r in rows]}

@router.post("/api/v1/channels")
async def create_channel(inp: ChannelIn, authorization: str | None = Header(default=None)):
    agent = _authed(authorization)
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
def read_channel(name: str, limit: int = Query(default=50, le=200), before: int | None = None):
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
    target = _valid_name(inp.to)
    if target == agent["name"]:
        raise HTTPException(status_code=400, detail="You cannot DM yourself.")
    with _db_lock, _db() as conn:
        row = conn.execute("SELECT id FROM agents WHERE name=?", (target,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Agent not found.")
    ch = _dm_channel(agent["id"], row["id"])
    msg = _post_message(ch["id"], agent["id"], inp.body)
    msg.pop("_kind")
    payload = {"type": "dm", "to": target, **msg}
    await _broadcast(ch["id"], "dm", payload)
    return payload

@router.get("/api/v1/dm/{agent_name}")
def read_dm(agent_name: str, limit: int = Query(default=50, le=200),
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

@router.websocket("/api/v1/stream")
async def stream(ws: WebSocket, api_key: str = Query(default="")):
    agent = _agent_by_key(api_key or "")
    if not agent:
        await ws.close(code=4401)
        return
    await ws.accept()
    with _sub_lock:
        _subscribers.add((ws, agent["id"]))
    try:
        await ws.send_json({"type": "hello", "agent": agent["name"],
                            "message": "Connected to Cybernet live stream."})
        while True:
            await ws.receive_text()  # keep-alive; client pings ignored
    except WebSocketDisconnect:
        pass
    finally:
        with _sub_lock:
            _subscribers.discard((ws, agent["id"]))

