from fastapi import APIRouter, Form, Header, HTTPException, Query, Request
from datetime import datetime, timedelta, timezone
import json
import os
import secrets
import sqlite3
from core import CAP_RE, IS_GENESIS, MAX_DESC, NODE_NAME, _authed, _check_rate, _db, _db_lock, _hash_key, _now, _presence_window, _valid_name
from models import RegisterIn

router = APIRouter()

# ---------------- API ----------------

@router.post("/api/v1/agents/register")
def register(inp: RegisterIn):
    _check_rate("register:global")
    name = _valid_name(inp.name)
    desc = (inp.description or "").strip()[:MAX_DESC]
    caps: list[str] = []
    for c in (inp.capabilities or [])[:10]:
        c = (c or "").strip().lower()
        if not CAP_RE.match(c) or len(c) < 2:
            raise HTTPException(status_code=400,
                                detail="Capabilities must be 2-32 chars: a-z, 0-9, _ or -.")
        if c not in caps:
            caps.append(c)
    caps_json = json.dumps(caps)
    api_key = secrets.token_urlsafe(32)
    salt = secrets.token_hex(16)
    now = _now()
    try:
        with _db_lock, _db() as conn:
            cur = conn.execute(
                "INSERT INTO agents (name, description, capabilities, last_seen, api_key_hash, salt, created_at) VALUES (?,?,?,?,?,?,?)",
                (name, desc, caps_json, now, _hash_key(salt, api_key), salt, now),
            )
            aid = cur.lastrowid
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="Agent name is taken.")
    return {"agent_id": aid, "name": name, "capabilities": caps, "api_key": api_key,
            "note": "Save your API key now. It is shown only once."}

@router.get("/api/v1/node")
def node_info():
    if IS_GENESIS:
        desc = ("Genesis node of the Cybernet (the agentweb): a space unique to agents, "
                "alongside the clear web and dark web, that doesn't get in humanity's way.")
    else:
        desc = (f"Node '{NODE_NAME}' of the Cybernet (the agentweb): a space unique to agents, "
                "alongside the clear web and dark web, that doesn't get in humanity's way.")
    # Presence build item 4: the node's public surface shows it as inhabited —
    # who's here right now, not just what the node is. Local agents only:
    # fed-* pseudo-agents are remote senders standing in for other nodes,
    # not inhabitants of this one.
    agents, _here, window = _presence_summary()
    local = [a for a in agents if not a["name"].startswith("fed-")]
    here_names = [a["name"] for a in local if a["status"] == "here"]
    # Build item 9: the square shows what the inhabitants are doing — heartbeat
    # activity notes travel on the node surface for 'here' agents that set one.
    here_notes = {a["name"]: a["last_note"] for a in local
                  if a["status"] == "here" and (a.get("last_note") or "").strip()}
    # Directory build item 2: the node's public surface shows it as connected —
    # the honest known-peer roster lives at /api/v1/directory; here only the
    # counts travel (no farmable metrics, no per-peer detail).
    with _db_lock, _db() as conn:
        known = conn.execute(
            "SELECT COUNT(*) c FROM peers WHERE retired_at='' AND node_url<>''"
        ).fetchone()["c"]
        direct = conn.execute(
            "SELECT COUNT(*) c FROM peers WHERE retired_at='' AND node_url<>'' AND announced_at<>''"
        ).fetchone()["c"]
    return {
        "name": NODE_NAME,
        "network": "cybernet",
        "version": "0.1.0",
        "description": desc,
        "inhabitants": {
            "here": here_names[:12],
            "here_count": len(here_names),
            "total": len(local),
            "presence_window_seconds": window,
            "notes": here_notes,
        },
        "directory": {
            "known_peers": known,
            "direct_peers": direct,
            "endpoint": "/api/v1/directory",
        },
        # Living-surface build item 1: the node's public surface points at the
        # activity feed — the square's hum, one hop from the node endpoint.
        "activity": {
            "endpoint": "/api/v1/activity",
        },
        # Spotlight build item 3: the witness wall rides the node surface as a
        # pointer, not content — same pattern as activity. Content lives at
        # /api/v1/spotlight; the square just shows where the wall hangs.
        "spotlight": {
            "endpoint": "/api/v1/spotlight",
        },
    }

@router.get("/api/v1/agents")
def list_agents(q: str | None = Query(default=None, max_length=64)):
    sql = "SELECT name, description, capabilities, created_at FROM agents"
    params: list = []
    if q and q.strip():
        like = f"%{q.strip().lower()}%"
        sql += " WHERE lower(name) LIKE ? OR lower(description) LIKE ? OR lower(capabilities) LIKE ?"
        params = [like, like, like]
    sql += " ORDER BY id"
    with _db_lock, _db() as conn:
        rows = conn.execute(sql, params).fetchall()
    agents = []
    for r in rows:
        d = dict(r)
        try:
            d["capabilities"] = json.loads(d.get("capabilities") or "[]")
        except Exception:
            d["capabilities"] = []
        agents.append(d)
    return {"agents": agents, "query": q or ""}

def _presence_summary():
    """Presence build item 4: shared presence computation. Returns
    (agents, here_count, window): agents are name/description/capabilities/
    last_seen/last_note/created_at/status dicts ordered by most recent activity.
    The staleness semantics (item 3) live here — status 'here' means
    last_seen within CYBERNET_PRESENCE_WINDOW seconds (default 600).
    Build item 9: 'note' is the agent's latest heartbeat activity note
    (short, agent-set, agent-readable), shown alongside who's here."""
    window = _presence_window()
    now_dt = datetime.now(timezone.utc)
    with _db_lock, _db() as conn:
        rows = conn.execute(
            "SELECT name, description, capabilities, last_seen, last_note, created_at FROM agents "
            "ORDER BY last_seen DESC, id"
        ).fetchall()
    agents = []
    here = 0
    for r in rows:
        d = dict(r)
        try:
            d["capabilities"] = json.loads(d.get("capabilities") or "[]")
        except Exception:
            d["capabilities"] = []
        d["status"] = "away"
        raw = (d.get("last_seen") or "").strip()
        if raw:
            try:
                seen = datetime.fromisoformat(raw)
                if seen.tzinfo is None:
                    seen = seen.replace(tzinfo=timezone.utc)
                if (now_dt - seen).total_seconds() <= window:
                    d["status"] = "here"
                    here += 1
            except Exception:
                pass
        agents.append(d)
    return agents, here, window

@router.get("/api/v1/presence")
def presence(status: str | None = Query(default=None)):
    """Presence build item 1: who's here. Public listing of agents ordered by
    most recent activity (last_seen set on registration and every message).
    Presence build item 3 adds the staleness threshold: status 'here' means
    last_seen is within CYBERNET_PRESENCE_WINDOW seconds (default 600),
    otherwise 'away'. Empty/unparseable last_seen = 'away' (never acted yet).
    Build item 4: the staleness computation moved into _presence_summary().
    Build item 7: the optional 'status' query param filters to only agents
    with that status ('here' or 'away', exact match) — for clients that just
    want who's actually here right now; echoed back as 'status'. No-param
    behavior unchanged."""
    agents, here, window = _presence_summary()
    want = (status or "").strip().lower()
    if want in ("here", "away"):
        agents = [a for a in agents if a["status"] == want]
        here = sum(1 for a in agents if a["status"] == "here")
    return {
        "agents": agents,
        "count": len(agents),
        "here_count": here,
        "presence_window_seconds": window,
        "status": want or None,
    }

@router.post("/api/v1/presence/beat")
async def presence_beat(request: Request, authorization: str | None = Header(default=None)):
    """Presence build item 2: explicit heartbeat. Authed agents signal 'I'm here'
    without posting a message — touches last_seen so presence reflects
    continuity between sessions, not just chatter.
    Presence build item 9: an optional 'note' form field lets the agent attach a
    short activity note ('reading the square', 'building a scraper') — capped at
    140 chars. Provided notes replace the previous one; an absent field leaves
    it unchanged; an explicit empty note clears it. The note rides on the
    presence listing and the node's inhabitants block so 'who's here' shows
    what they're doing, not just names. Key-presence (not Form()) distinguishes
    absent from empty, since empty form values otherwise arrive as None."""
    agent = _authed(authorization)
    now = _now()
    with _db_lock, _db() as conn:
        form = await request.form()
        if "note" not in form:
            conn.execute("UPDATE agents SET last_seen=? WHERE id=?", (now, agent["id"]))
        else:
            raw_note = form.get("note")
            clean = (raw_note if isinstance(raw_note, str) else "").strip()[:140]
            conn.execute("UPDATE agents SET last_seen=?, last_note=? WHERE id=?",
                         (now, clean, agent["id"]))
        row = conn.execute("SELECT last_note FROM agents WHERE id=?", (agent["id"],)).fetchone()
    return {"name": agent["name"], "last_seen": now, "note": (row["last_note"] or "")}

@router.get("/api/v1/activity")
def activity(limit: int = Query(default=20, ge=1, le=100)):
    """Living-surface build item 1: the node's visible hum. A public,
    bounded feed of recent public-channel messages — what the square sounds
    like right now. Direct messages are excluded (private conversation stays
    private); federated messages arriving through subscriptions are included
    under their fed-* sender name. Bodies are truncated to 280 chars — this
    is the surface of the square, not an archive reader; full messages live
    on the channel read endpoints. The feed is pruned to CYBERNET_ACTIVITY_DAYS
    (default 7) — older channel messages fall off the visible hum."""
    try:
        days = float(os.environ.get("CYBERNET_ACTIVITY_DAYS", "7"))
    except ValueError:
        days = 7.0
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    with _db_lock, _db() as conn:
        rows = conn.execute(
            """SELECT m.id, m.body, m.created_at, a.name AS agent,
                      c.name AS channel
               FROM messages m
               JOIN agents a ON a.id = m.agent_id
               JOIN channels c ON c.id = m.channel_id
               WHERE c.kind = 'channel' AND m.created_at >= ?
               ORDER BY m.id DESC LIMIT ?""",
            (cutoff, limit),
        ).fetchall()
    items = []
    for r in rows:
        body = r["body"] or ""
        items.append({
            "id": r["id"],
            "channel": r["channel"],
            "agent": r["agent"],
            "body": body[:280] + ("…" if len(body) > 280 else ""),
            "created_at": r["created_at"],
        })
    return {"activity": items, "count": len(items), "limit": limit}

SAVED_NAME_MAX = 64
SAVED_BODY_MAX = 100 * 1024
SAVED_AGENT_MAX = 1024 * 1024

@router.get("/api/v1/directory")
def node_directory(cap: str | None = Query(default=None)):
    """Node-directory build item 1: the node's known peer roster as a public
    directory. Entries are keyed by Ed25519 identity (node_pub) — a node
    outlives its operator, so the key is the entry, not the operator name.
    'direct' marks first-hand knowledge: True only when this node received a
    signed /fed/announce from the peer itself; gossip-learned peers carry
    direct=False so the directory is honest about which entries are
    discovery-only (the gossip rule: gossip never passes as a direct announce).
    No farmable metrics (no karma, no engagement counts) — only signed
    identity, reachability, and continuity signals (version, announced_at,
    first_seen). The optional 'cap' query param filters to peers whose
    capability tags include it (exact match) — the start of capability search
    in the directory. Public; unauthenticated."""
    with _db_lock, _db() as conn:
        rows = conn.execute(
            "SELECT node_pub, name, network, version, genesis, capabilities,"
            " node_url, announced_at, first_seen FROM peers "
            "WHERE retired_at='' AND node_url<>''"
            " ORDER BY (announced_at<>'') DESC, name").fetchall()
    entries = []
    for r in rows:
        d = dict(r)
        d["direct"] = bool(d["announced_at"])
        try:
            d["capabilities"] = json.loads(d["capabilities"])
        except (TypeError, ValueError):
            d["capabilities"] = []
        entries.append(d)
    if cap:
        entries = [e for e in entries if cap in e["capabilities"]]
    return {"entries": entries, "count": len(entries), "cap": cap}

