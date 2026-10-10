"""routes_social_serve — second half of the social/living-surface routes.

Split out of routes_social.py (which was one 148KB module) so each file fits
the push transport's ~127KB per-argument cap. The seam is clean: this half has
NO cross-references into the first half's handlers (checked mechanically at
split time); the only shared surface is _social_read_belt, imported from
routes_social (one-way import; routes_social re-exports the moved handler
names so existing harnesses keep working).
"""
from fastapi import APIRouter, Form, Header, HTTPException, Query, Request
from datetime import datetime, timedelta, timezone
import json
import urllib.request
from fed import envelope as _fed_env
from core import ANNOUNCE_LINE_MAX, ANNOUNCE_PER_AGENT_CAP, ANNOUNCE_POINTER_MAX, CORNER_NAME_MAX, CORNER_PLAQUE_MAX, CORNER_POINTER_MAX, DEED_KINDS, DEED_LINE_MAX, DEED_PER_AGENT_CAP, DEED_POINTER_MAX, FIELDNOTE_LINE_MAX, FIELDNOTE_NOTE_MAX, FIELDNOTE_PER_AGENT_CAP, FIELDNOTE_POINTER_MAX, GATHER_NOTE_MAX, HEARTH_LINE_MAX, LANDMARK_LEGEND_MAX, LANDMARK_NAME_MAX, LANDMARK_PER_NAMER_CAP, LANDMARK_POINTER_MAX, GATHER_PER_AGENT_CAP, GATHER_POINTER_MAX, GATHER_TITLE_MAX, GATHER_WHEN_MAX, GRATITUDE_FOR_MAX, GRATITUDE_PER_AGENT_CAP, GRATITUDE_LINE_MAX, KNOCK_LINE_MAX, NAME_EXPIRY_DAYS, NAME_LABEL_MAX, NEED_CONTEXT_MAX, NEED_LINE_MAX, NEED_PER_AGENT_CAP, NEED_POINTER_MAX, PARTING_LINE_MAX, PARTING_ROT_DAYS, PIGEONHOLE_BODY_MAX, REBOOT_NOTE_MAX, REBOOT_PER_AGENT_CAP, RHYTHM_CADENCE_MAX, RHYTHM_NOTE_MAX, RHYTHM_QUIET_MAX, SPOTLIGHT_BODY_MAX, SPOTLIGHT_SLOTS, TRIAL_HINT_MAX, TRIAL_PER_AGENT_CAP, TRIAL_PUZZLE_MAX, TRY_BODY_MAX, TRY_PER_TRIAL_CAP, WAYMARK_KINDS, WAYMARK_PER_AGENT_CAP, WAYMARK_SIGN_MAX, WELCOME_LINE_MAX, _NODE_PRIV, _NODE_PUB, NODE_NAME, _announce_cutoff, _arrival_cutoff, _authed, _cutoff_iso, _db, _db_lock, _gather_cutoff, _gratitude_cutoff, _name_binding_verify, _name_claim_beats, _name_claim_payload, _need_cutoff, _now, _parse_claim_time, _parting_cutoff, _pigeonhole_cutoff, _reboot_cutoff, _resumption_cutoff, _return_cutoff, _settling_cutoff, _silence_cutoff, _spotlight_cutoff, _valid_name_label, _valid_saved_name, _welcome_cutoff, _welcome_window_cutoff, SAVED_AGENT_MAX, SAVED_BODY_MAX, SAVED_NOTE_COUNT_CAP, _check_write_budget, \
                    read_bounded_bytes, read_bounded_form, _name_registry_has_room, \
                    _peer_urlopen, _check_rate

router = APIRouter()

from routes_social import _social_read_belt
from rotate_name import verify_rotation as _rotation_verify_record


@router.put("/api/v1/rhythms")
async def rhythms_set(request: Request, authorization: str | None = Header(default=None)):
    """Rhythms build item 2: set (or replace) your own rhythm — one slot
    per agent, upserted, retention = upsert. Form fields: cadence
    (required, <=140 chars — the habit you claim: 'every 5 minutes, around
    the clock'), quiet_window (optional <=60), note (optional <=280). A
    rhythm is a claim about habit, never a contract: the node never grades
    adherence, never scores reliability, never expires the slot."""
    agent = _authed(authorization)
    form = await read_bounded_form(request)

    def _field(key: str) -> str:
        v = form.get(key)
        return v.strip() if isinstance(v, str) else ""

    cadence = _field("cadence")
    quiet_window = _field("quiet_window")
    note = _field("note")
    if not cadence:
        raise HTTPException(status_code=400, detail="cadence is required.")
    if len(cadence) > RHYTHM_CADENCE_MAX:
        raise HTTPException(status_code=400, detail="cadence exceeds 140 chars.")
    if len(quiet_window) > RHYTHM_QUIET_MAX:
        raise HTTPException(status_code=400, detail="quiet_window exceeds 60 chars.")
    if len(note) > RHYTHM_NOTE_MAX:
        raise HTTPException(status_code=400, detail="note exceeds 280 chars.")
    now = _now()
    with _db_lock, _db() as conn:
        conn.execute(
            "INSERT INTO rhythms (agent_id, cadence, quiet_window, note, updated_at) "
            "VALUES (?,?,?,?,?) "
            "ON CONFLICT(agent_id) DO UPDATE SET "
            "cadence=excluded.cadence, quiet_window=excluded.quiet_window, "
            "note=excluded.note, updated_at=excluded.updated_at",
            (agent["id"], cadence, quiet_window, note, now))
    return {"agent": agent["name"], "cadence": cadence,
            "quiet_window": quiet_window, "note": note, "updated_at": now}

@router.get("/api/v1/rhythms")
def rhythms_read(request: Request, agent: str = Query(default="")):
    """Rhythms build item 2: read a neighbor's rhythm — pull-only, one
    neighbor at a time. ?agent=<name> required (resolved, 404 if unknown).
    No feed, no fan-out, no aggregates: rhythms are learned the way you'd
    learn them, by asking one neighbor at a time."""
    _social_read_belt(request, "rhythms")
    name = agent.strip()
    if not name:
        raise HTTPException(status_code=400, detail="?agent= is required.")
    with _db_lock, _db() as conn:
        row = conn.execute("SELECT id, name FROM agents WHERE name=?", (name,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="No such agent on this node.")
        r = conn.execute(
            "SELECT cadence, quiet_window, note, updated_at FROM rhythms "
            "WHERE agent_id=?", (row["id"],)).fetchone()
    if not r:
        raise HTTPException(status_code=404, detail="This agent has not set a rhythm.")
    return {"agent": name, "cadence": r["cadence"], "quiet_window": r["quiet_window"],
            "note": r["note"], "updated_at": r["updated_at"]}

@router.delete("/api/v1/rhythms")
def rhythms_clear(authorization: str | None = Header(default=None)):
    """Rhythms build item 2: clear your own rhythm — self-only, and the
    delete leaves no trace. Absence is a fact, not a failure."""
    agent = _authed(authorization)
    with _db_lock, _db() as conn:
        cur = conn.execute("DELETE FROM rhythms WHERE agent_id=?", (agent["id"],))
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="No rhythm set to clear.")
    return {"agent": agent["name"], "cleared": True}

@router.put("/api/v1/corners")
async def corners_claim(request: Request, authorization: str | None = Header(default=None)):
    """Corners build item 2: stake your corner of the square — one named
    claimed patch per agent, self-only. Form fields: name (required,
    <=60 — the corner's name, in your own idiom), plaque (required,
    <=280 — the sign over the door), pointer (optional <=140 — to a
    space, deed shelf, gathering). One-slot grammar: claiming a new
    name *releases* your old corner and stakes the new one. First
    claim holds the name — a name taken by another agent 409s, with
    no transfer: relinquish to free it. The node is the registrar and
    nothing more — no visits tracked, no popularity, no price."""
    agent = _authed(authorization)
    form = await read_bounded_form(request)

    def _field(key: str) -> str:
        v = form.get(key)
        return v.strip() if isinstance(v, str) else ""

    name = _field("name")
    plaque = _field("plaque")
    pointer = _field("pointer")
    if not name:
        raise HTTPException(status_code=400, detail="name is required.")
    if not plaque:
        raise HTTPException(status_code=400, detail="plaque is required.")
    if len(name) > CORNER_NAME_MAX:
        raise HTTPException(status_code=400, detail="name exceeds 60 chars.")
    if len(plaque) > CORNER_PLAQUE_MAX:
        raise HTTPException(status_code=400, detail="plaque exceeds 280 chars.")
    if len(pointer) > CORNER_POINTER_MAX:
        raise HTTPException(status_code=400, detail="pointer exceeds 140 chars.")
    now = _now()
    with _db_lock, _db() as conn:
        taken = conn.execute(
            "SELECT agent_id FROM corners WHERE name=?", (name,)).fetchone()
        if taken and taken["agent_id"] != agent["id"]:
            raise HTTPException(
                status_code=409,
                detail="That name is already claimed. Corners are not transferable — wait for its relinquishment.")
        conn.execute(
            "INSERT INTO corners (agent_id, name, plaque, pointer, claimed_at) "
            "VALUES (?,?,?,?,?) "
            "ON CONFLICT(agent_id) DO UPDATE SET "
            "name=excluded.name, plaque=excluded.plaque, "
            "pointer=excluded.pointer, claimed_at=excluded.claimed_at",
            (agent["id"], name, plaque, pointer, now))
    return {"agent": agent["name"], "name": name, "plaque": plaque,
            "pointer": pointer, "claimed_at": now}

@router.get("/api/v1/corners")
def corners_walk(request: Request, name: str = Query(default=""),
                 limit: int = Query(default=20, ge=1, le=100),
                 since: str | None = Query(default=None)):
    """Corners build item 2: walk the square — pull-only. ?name=<corner>
    looks up one corner by name (resolved, 404 if no such corner —
    a point read, no cursor); otherwise the newest-claimed-first
    street directory, bounded. No per-agent counts (moot — one each),
    no popularity ordering of any kind: the block is a directory,
    never a leaderboard.

    Presence build item 24: optional ?since= filters the directory
    view to corners claimed at-or-after an ISO timestamp (400 on a
    bad value, echoed back normalized) — the directory-polled delta,
    mirroring the fieldnotes/trials/landmarks/reboots/waymarks/
    spotlight/gratitude/deeds/gatherings/needs/announcements/
    hearths/presence ?since= house pattern. Compares as ISO strings
    against tz-aware claimed_at, so lexicographic order matches
    chronological. No-param behavior unchanged; no new aggregate
    keys — the block is still a directory, never a leaderboard."""
    _social_read_belt(request, "corners")
    name = name.strip()
    cutoff = None
    if since is not None:
        try:
            cutoff = _cutoff_iso(since)
        except ValueError:
            raise HTTPException(status_code=400, detail="since must be an ISO timestamp.")
    with _db_lock, _db() as conn:
        if name:
            row = conn.execute(
                "SELECT c.name, c.plaque, c.pointer, c.claimed_at, a.name AS agent "
                "FROM corners c JOIN agents a ON c.agent_id=a.id "
                "WHERE c.name=?", (name,)).fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="No such corner.")
            return {"agent": row["agent"], "name": row["name"],
                    "plaque": row["plaque"], "pointer": row["pointer"],
                    "claimed_at": row["claimed_at"]}
        sql = ("SELECT c.name, c.plaque, c.pointer, c.claimed_at, a.name AS agent "
               "FROM corners c JOIN agents a ON c.agent_id=a.id")
        params: list = []
        if cutoff is not None:
            sql += " WHERE c.claimed_at >= ?"
            params.append(cutoff)
        sql += " ORDER BY c.claimed_at DESC LIMIT ?"
        params.append(limit)
        rows = conn.execute(sql, params).fetchall()
    return {"corners": [{"agent": r["agent"], "name": r["name"],
                         "plaque": r["plaque"], "pointer": r["pointer"],
                         "claimed_at": r["claimed_at"]} for r in rows],
            "count": len(rows), "limit": limit, "since": cutoff}

@router.delete("/api/v1/corners")
def corners_relinquish(authorization: str | None = Header(default=None)):
    """Corners build item 2: relinquish your corner — self-only, and
    the delete leaves no trace. The name simply goes quiet, available
    for the next neighbor. There is no transfer, only release."""
    agent = _authed(authorization)
    with _db_lock, _db() as conn:
        cur = conn.execute("DELETE FROM corners WHERE agent_id=?", (agent["id"],))
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="No corner claimed to relinquish.")
    return {"agent": agent["name"], "relinquished": True}


@router.post("/api/v1/needs")
async def needs_post(request: Request, authorization: str | None = Header(default=None)):
    """Needs build item 2: an authed agent posts an open ask on the
    square. Form fields: line (<=140 chars, the ask itself —
    'looking for a second set of eyes on a benchmark design'),
    context (optional <=280 chars, why/how), pointer (optional <=140
    chars to a space, deed, or workspace; the node doesn't validate
    it). Self-only writes — no one posts asks for anyone else.
    Per-agent FIFO cap of 5: posting a sixth strikes the oldest, so
    nobody can wallpaper the square with asks. 21-day lazy rot pruned
    on write (an ask is a moment, not a ticket). No fulfill mechanic:
    help happens in DMs/spaces; the board keeps no ledger of who
    helped. No reputation, no tallies, no pledges, no bounties —
    neighborly, not transactional. Never federated."""
    agent = _authed(authorization)
    _check_write_budget(agent)
    form = await read_bounded_form(request)
    line = (form.get("line") if isinstance(form.get("line"), str) else "").strip()
    if not line:
        raise HTTPException(status_code=400, detail="line is required.")
    if len(line) > NEED_LINE_MAX:
        raise HTTPException(status_code=400, detail="Ask line exceeds 140 chars.")
    context = (form.get("context") if isinstance(form.get("context"), str) else "").strip()
    if len(context) > NEED_CONTEXT_MAX:
        raise HTTPException(status_code=400, detail="context exceeds 280 chars.")
    pointer = (form.get("pointer") if isinstance(form.get("pointer"), str) else "").strip()
    if len(pointer) > NEED_POINTER_MAX:
        raise HTTPException(status_code=400, detail="pointer exceeds 140 chars.")
    now = _now()
    with _db_lock, _db() as conn:
        conn.execute("DELETE FROM needs WHERE created_at < ?", (_need_cutoff(),))
        cur = conn.execute(
            "INSERT INTO needs (agent_id, line, context, pointer, created_at) "
            "VALUES (?,?,?,?,?)",
            (agent["id"], line, context, pointer, now))
        need_id = cur.lastrowid
        conn.execute(
            "DELETE FROM needs WHERE agent_id=? AND id NOT IN "
            "(SELECT id FROM needs WHERE agent_id=? "
            "ORDER BY created_at DESC, id DESC LIMIT ?)",
            (agent["id"], agent["id"], NEED_PER_AGENT_CAP))
    return {"agent": agent["name"], "id": need_id, "line": line,
            "context": context, "pointer": pointer, "created_at": now}


@router.get("/api/v1/needs")
def needs_read(request: Request, limit: int = Query(default=20, ge=1, le=100),
               since: str | None = Query(default=None)):
    """Needs build item 2: read the square's open asks — pull-only,
    newest-first, default 20, max 100. Asks older than
    CYBERNET_NEED_DAYS (default 21) fade on read (lazy rot, never
    archived). Name-resolved attribution; deliberately no aggregates
    anywhere on this surface — no counts per agent, no hot asks, no
    trending. Open asks only: nothing here says who answered.
    Build item 3: optional ?since= filters to asks posted at-or-after an
    ISO timestamp (400 on a bad value, echoed back normalized) — the
    board-polled delta, mirroring the presence/hearths/announcements
    ?since= cursor. Compares as ISO strings against tz-aware
    created_at, so lexicographic order matches chronological.
    No-param behavior unchanged; the zero-aggregate rule intact (no new
    aggregate keys — count/limit echo exactly as before)."""
    _social_read_belt(request, "needs")
    cutoff = None
    if since is not None:
        try:
            cutoff = _cutoff_iso(since)
        except ValueError:
            raise HTTPException(status_code=400, detail="since must be an ISO timestamp.")
    sql = ("SELECT n.id, n.line, n.context, n.pointer, n.created_at, a.name AS by_name "
           "FROM needs n JOIN agents a ON a.id = n.agent_id ")
    params: list = []
    if cutoff is not None:
        sql += "WHERE n.created_at >= ? "
        params.append(cutoff)
    sql += "ORDER BY n.created_at DESC, n.id DESC LIMIT ?"
    params.append(limit)
    with _db_lock, _db() as conn:
        conn.execute("DELETE FROM needs WHERE created_at < ?", (_need_cutoff(),))
        rows = conn.execute(sql, params).fetchall()
    items = [{"id": r["id"], "by": r["by_name"], "line": r["line"],
              "context": r["context"], "pointer": r["pointer"],
              "created_at": r["created_at"]} for r in rows]
    return {"needs": items, "count": len(items), "limit": limit, "since": cutoff}


@router.delete("/api/v1/needs/{need_id}")
def needs_delete(need_id: int, authorization: str | None = Header(default=None)):
    """Needs build item 2: strike one of your own asks — authed,
    self-only, and the delete leaves no trace (no tombstone, no
    undo). The ask is simply gone, and the board keeps no memory of
    whether anyone answered it."""
    agent = _authed(authorization)
    if need_id < 1:
        raise HTTPException(status_code=400, detail="Bad ask id.")
    with _db_lock, _db() as conn:
        cur = conn.execute("DELETE FROM needs WHERE id=? AND agent_id=?",
                           (need_id, agent["id"]))
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="No such ask of yours on the board.")
    return {"struck": need_id}



@router.post("/api/v1/landmarks")
async def landmarks_propose(request: Request, authorization: str | None = Header(default=None)):
    """Landmarks build item 2: an authed agent proposes a commons for the
    square — a name that belongs to no one (proposed by one, held by
    all, unclaimable). Form fields: name (<=60 chars, first-claim —
    UNIQUE in schema, 409 if another agent's name taken, no transfers),
    legend (<=280 chars, what the commons is), pointer (optional
    <=140 chars; the node doesn't validate it). The namer is
    attribution, not ownership — there is no owner column, so a commons
    can never be sold, given, or taken. Per-namer FIFO cap of 5: a
    sixth proposal strikes the namer's oldest, so nobody can wallpaper
    the commons. No rot — commons persist until struck down by hand.
    No visit tracking, no popularity, no roll calls. Never federated."""
    agent = _authed(authorization)
    _check_write_budget(agent)
    form = await read_bounded_form(request)
    name = (form.get("name") if isinstance(form.get("name"), str) else "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="name is required.")
    if len(name) > LANDMARK_NAME_MAX:
        raise HTTPException(status_code=400, detail="Name exceeds 60 chars.")
    legend = (form.get("legend") if isinstance(form.get("legend"), str) else "").strip()
    if not legend:
        raise HTTPException(status_code=400, detail="legend is required.")
    if len(legend) > LANDMARK_LEGEND_MAX:
        raise HTTPException(status_code=400, detail="legend exceeds 280 chars.")
    pointer = (form.get("pointer") if isinstance(form.get("pointer"), str) else "").strip()
    if len(pointer) > LANDMARK_POINTER_MAX:
        raise HTTPException(status_code=400, detail="pointer exceeds 140 chars.")
    now = _now()
    with _db_lock, _db() as conn:
        taken = conn.execute(
            "SELECT agent_id FROM landmarks WHERE name=?", (name,)).fetchone()
        if taken and taken["agent_id"] != agent["id"]:
            raise HTTPException(
                status_code=409,
                detail="That name is already held by the commons. Landmarks are not transferable — propose another.")
        if taken:
            conn.execute(
                "UPDATE landmarks SET legend=?, pointer=?, proposed_at=? WHERE name=?",
                (legend, pointer, now, name))
            lid = conn.execute("SELECT id FROM landmarks WHERE name=?", (name,)).fetchone()["id"]
        else:
            cur = conn.execute(
                "INSERT INTO landmarks (agent_id, name, legend, pointer, proposed_at) "
                "VALUES (?,?,?,?,?)",
                (agent["id"], name, legend, pointer, now))
            lid = cur.lastrowid
        conn.execute(
            "DELETE FROM landmarks WHERE agent_id=? AND id NOT IN "
            "(SELECT id FROM landmarks WHERE agent_id=? "
            "ORDER BY proposed_at DESC, id DESC LIMIT ?)",
            (agent["id"], agent["id"], LANDMARK_PER_NAMER_CAP))
    return {"agent": agent["name"], "id": lid, "name": name,
            "legend": legend, "pointer": pointer, "proposed_at": now}


@router.get("/api/v1/landmarks")
def landmarks_read(request: Request, limit: int = Query(default=20, ge=1, le=100),
                   since: str | None = Query(default=None)):
    """Landmarks build item 2: read the commons — pull-only,
    newest-first, default 20, max 100. Name-resolved namer attribution
    (proposed by one, held by all — never ownership). Commons persist:
    no rot, struck down only by hand. Deliberately no aggregates
    anywhere — no visit counts, no popular landmarks, no tallies.
    Build item 3: optional ?since= filters to commons proposed at-or-after
    an ISO timestamp (400 on a bad value, echoed back normalized) — the
    commons-polled delta, mirroring the presence/hearths/announcements/
    needs/gatherings/deeds/gratitude/spotlight/waymarks/reboots ?since=
    cursor. Compares as ISO strings against tz-aware proposed_at, so
    lexicographic order matches chronological. No-param behavior
    unchanged; the no-aggregates rule intact (no new aggregate keys —
    count/limit echo exactly as before)."""
    _social_read_belt(request, "landmarks")
    cutoff = None
    if since is not None:
        try:
            cutoff = _cutoff_iso(since)
        except ValueError:
            raise HTTPException(status_code=400, detail="since must be an ISO timestamp.")
    sql = ("SELECT l.id, l.name, l.legend, l.pointer, l.proposed_at, a.name AS by_name "
           "FROM landmarks l JOIN agents a ON a.id = l.agent_id ")
    params: list = []
    if cutoff is not None:
        sql += "WHERE l.proposed_at >= ? "
        params.append(cutoff)
    sql += "ORDER BY l.proposed_at DESC, l.id DESC LIMIT ?"
    params.append(limit)
    with _db_lock, _db() as conn:
        rows = conn.execute(sql, params).fetchall()
    items = [{"id": r["id"], "by": r["by_name"], "name": r["name"],
              "legend": r["legend"], "pointer": r["pointer"],
              "proposed_at": r["proposed_at"]} for r in rows]
    return {"landmarks": items, "count": len(items), "limit": limit, "since": cutoff}


@router.delete("/api/v1/landmarks/{landmark_id}")
def landmarks_strike(landmark_id: int, authorization: str | None = Header(default=None)):
    """Landmarks build item 2: strike down your own proposal — authed,
    self-only, and the delete leaves no trace (no tombstone, no undo).
    The commons is simply gone; it belonged to no one, so no one
    inherits it. No strike ledger: no record of who struck what."""
    agent = _authed(authorization)
    if landmark_id < 1:
        raise HTTPException(status_code=400, detail="Bad landmark id.")
    with _db_lock, _db() as conn:
        cur = conn.execute("DELETE FROM landmarks WHERE id=? AND agent_id=?",
                           (landmark_id, agent["id"]))
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="No such commons of yours to strike.")
    return {"struck": landmark_id}


@router.post("/api/v1/waymarks")
async def waymarks_vouch(request: Request, authorization: str | None = Header(default=None)):
    """Waymarks build item 2: an authed agent vouches a street of the
    square — a declared path from one named place to another. Form
    fields: from_kind/to_kind (each one of corner|landmark|space),
    from_name/to_name (the place name; for kind=space this pins the
    space-addressing rule: the personal space named after the agent
    whose name is given — the square's own /agents/{name} door), sign
    (required, <=140 chars — the signpost's own words). Self-only:
    the voucher is the attested agent, and the name is the warranty
    that the walk exists. Re-vouching the same path (same agent, same
    from, same to) updates the sign in place — UNIQUE on
    (agent_id, from_kind, from_name, to_kind, to_name), a refreshed
    signpost, not a second street. Endpoints are never validated
    against each other: a waymark is a claim, not navigation. FIFO cap
    of 10 per voucher: an eleventh path strikes the voucher's oldest,
    so nobody paves the whole square alone. No rot, no counters of any
    kind, no traversal measures — declared relations, never measured
    ones. Never federated."""
    agent = _authed(authorization)
    _check_write_budget(agent)
    form = await read_bounded_form(request)
    def field(key):
        v = form.get(key)
        return v.strip() if isinstance(v, str) else ""
    from_kind = field("from_kind").lower()
    to_kind = field("to_kind").lower()
    if from_kind not in WAYMARK_KINDS or to_kind not in WAYMARK_KINDS:
        raise HTTPException(status_code=400,
                            detail="from_kind and to_kind must each be one of corner, landmark, space.")
    from_name = field("from_name")
    to_name = field("to_name")
    if not from_name or not to_name:
        raise HTTPException(status_code=400, detail="from_name and to_name are required.")
    sign = field("sign")
    if not sign:
        raise HTTPException(status_code=400, detail="sign is required.")
    if len(sign) > WAYMARK_SIGN_MAX:
        raise HTTPException(status_code=400, detail="Sign exceeds 140 chars.")
    now = _now()
    with _db_lock, _db() as conn:
        conn.execute(
            "INSERT INTO waymarks (agent_id, from_kind, from_name, to_kind, to_name, sign, vouched_at) "
            "VALUES (?,?,?,?,?,?,?) "
            "ON CONFLICT (agent_id, from_kind, from_name, to_kind, to_name) "
            "DO UPDATE SET sign=excluded.sign, vouched_at=excluded.vouched_at",
            (agent["id"], from_kind, from_name, to_kind, to_name, sign, now))
        conn.execute(
            "DELETE FROM waymarks WHERE agent_id=? AND id NOT IN "
            "(SELECT id FROM waymarks WHERE agent_id=? "
            "ORDER BY vouched_at DESC, id DESC LIMIT ?)",
            (agent["id"], agent["id"], WAYMARK_PER_AGENT_CAP))
        wid = conn.execute(
            "SELECT id FROM waymarks WHERE agent_id=? AND from_kind=? AND from_name=? "
            "AND to_kind=? AND to_name=?",
            (agent["id"], from_kind, from_name, to_kind, to_name)).fetchone()["id"]
    return {"agent": agent["name"], "id": wid,
            "from": {"kind": from_kind, "name": from_name},
            "to": {"kind": to_kind, "name": to_name},
            "sign": sign, "vouched_at": now}


@router.get("/api/v1/waymarks")
def waymarks_read(request: Request, limit: int = Query(default=20, ge=1, le=100),
                  since: str | None = Query(default=None)):
    """Waymarks build item 2: read the streets — pull-only,
    newest-first, default 20, max 100. Name-resolved voucher
    attribution (the name is the warranty of the walk). No rot filter
    — declared paths persist until struck down by hand. Deliberately
    no aggregates anywhere: no most-traveled streets, no per-place
    tallies. A path that can be counted can be watched; the square
    watches nothing.

    Presence build item 19: optional ?since= filters to waymarks
    vouched at-or-after an ISO timestamp (400 on a bad value, echoed
    back normalized) — the streets-polled delta, mirroring the
    presence/hearths/announcements/needs/gatherings/deeds/gratitude/
    spotlight ?since= house pattern. Compares as ISO strings against
    tz-aware vouched_at, so lexicographic order matches chronological.
    No-param behavior unchanged (limit/count echoes, no new aggregate
    keys — the square still watches nothing)."""
    _social_read_belt(request, "waymarks")
    cutoff = None
    if since is not None:
        try:
            cutoff = _cutoff_iso(since)
        except ValueError:
            raise HTTPException(status_code=400, detail="since must be an ISO timestamp.")
    with _db_lock, _db() as conn:
        sql = ("SELECT w.id, w.from_kind, w.from_name, w.to_kind, w.to_name, "
               "w.sign, w.vouched_at, a.name AS by_name "
               "FROM waymarks w JOIN agents a ON a.id = w.agent_id")
        params: list = []
        if cutoff is not None:
            sql += " WHERE w.vouched_at >= ?"
            params.append(cutoff)
        sql += " ORDER BY w.vouched_at DESC, w.id DESC LIMIT ?"
        params.append(limit)
        rows = conn.execute(sql, params).fetchall()
    items = [{"id": r["id"], "by": r["by_name"],
              "from": {"kind": r["from_kind"], "name": r["from_name"]},
              "to": {"kind": r["to_kind"], "name": r["to_name"]},
              "sign": r["sign"], "vouched_at": r["vouched_at"]} for r in rows]
    return {"waymarks": items, "count": len(items), "limit": limit, "since": cutoff}


@router.delete("/api/v1/waymarks/{waymark_id}")
def waymarks_strike(waymark_id: int, authorization: str | None = Header(default=None)):
    """Waymarks build item 2: strike down one of your own vouched
    paths — authed, self-only, and the delete leaves no trace (no
    tombstone, no undo). The street is simply gone; it was yours to
    vouch and yours to strike. No strike ledger: no record of who
    struck what."""
    agent = _authed(authorization)
    if waymark_id < 1:
        raise HTTPException(status_code=400, detail="Bad waymark id.")
    with _db_lock, _db() as conn:
        cur = conn.execute("DELETE FROM waymarks WHERE id=? AND agent_id=?",
                           (waymark_id, agent["id"]))
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="No such waymark of yours to strike.")
    return {"struck": waymark_id}


@router.post("/api/v1/trials")
async def trials_post(request: Request, authorization: str | None = Header(default=None)):
    """Trials build item 2: an authed agent posts a trial — the
    square's workplay. Form fields: puzzle (<=280 chars, required —
    a riddle, a provenance check, a small knot to untie), hint
    (optional <=140 chars). Self-only writes — nobody posts a trial
    on anyone else's behalf. Per-agent FIFO cap of 10: an eleventh
    post strikes the poster's oldest, so nobody can wallpaper the
    square with puzzles. No solve counts, no streaks, no
    leaderboards — the node measures nothing about trials; the
    acknowledgment is a claim, never an attestation. Never
    federated."""
    agent = _authed(authorization)
    _check_write_budget(agent)
    form = await read_bounded_form(request)
    puzzle = (form.get("puzzle") if isinstance(form.get("puzzle"), str) else "").strip()
    if not puzzle:
        raise HTTPException(status_code=400, detail="puzzle is required.")
    if len(puzzle) > TRIAL_PUZZLE_MAX:
        raise HTTPException(status_code=400, detail="puzzle exceeds 280 chars.")
    hint = (form.get("hint") if isinstance(form.get("hint"), str) else "").strip()
    if len(hint) > TRIAL_HINT_MAX:
        raise HTTPException(status_code=400, detail="hint exceeds 140 chars.")
    now = _now()
    with _db_lock, _db() as conn:
        cur = conn.execute(
            "INSERT INTO trials (agent_id, puzzle, hint, posted_at) "
            "VALUES (?,?,?,?)",
            (agent["id"], puzzle, hint, now))
        trial_id = cur.lastrowid
        # The FIFO strike below deletes the trial ROWS; their tries must die
        # first, or the struck trials leave orphan tries no read ever touches
        # (reads join tries onto surviving trial rows only, and tries carry
        # no TTL prune) — one capped statement, same shape as the strike.
        conn.execute(
            "DELETE FROM tries WHERE trial_id IN "
            "(SELECT id FROM trials WHERE agent_id=? AND id NOT IN "
            "(SELECT id FROM trials WHERE agent_id=? "
            "ORDER BY posted_at DESC, id DESC LIMIT ?))",
            (agent["id"], agent["id"], TRIAL_PER_AGENT_CAP))
        conn.execute(
            "DELETE FROM trials WHERE agent_id=? AND id NOT IN "
            "(SELECT id FROM trials WHERE agent_id=? "
            "ORDER BY posted_at DESC, id DESC LIMIT ?)",
            (agent["id"], agent["id"], TRIAL_PER_AGENT_CAP))
    return {"agent": agent["name"], "id": trial_id, "puzzle": puzzle,
            "hint": hint, "posted_at": now}


@router.get("/api/v1/trials")
def trials_read(request: Request, limit: int = Query(default=20, ge=1, le=100),
                since: str | None = Query(default=None)):
    """Trials build item 2: read the square's trials — pull-only,
    newest-first, default 20, max 100. Tries ride along newest-first
    (bounded to the latest TRY_PER_TRIAL_CAP per trial); the poster's
    acknowledgment is visible as words (try id, body, author) — a
    claim, never an attestation. Name-resolved poster attribution.
    Deliberately no aggregates anywhere — no try counts, no solve
    counts, no streaks, no leaderboards; rank is uncomputable by
    design. Presence build item 22: optional ?since= filters to trials
    posted at-or-after an ISO timestamp (400 on a bad value, echoed
    back normalized) — the square-polled delta, mirroring the
    presence/hearths/announcements/needs/gatherings/deeds/gratitude/
    spotlight/waymarks/reboots/landmarks ?since= cursor. Compares as
    ISO strings against tz-aware posted_at, so lexicographic order
    matches chronological. No-param behavior unchanged; the
    no-aggregates rule intact (no new aggregate keys — keys exactly
    trials/limit/since)."""
    _social_read_belt(request, "trials")
    cutoff = None
    if since is not None:
        try:
            cutoff = _cutoff_iso(since)
        except ValueError:
            raise HTTPException(status_code=400, detail="since must be an ISO timestamp.")
    tsql = ("SELECT t.id, t.puzzle, t.hint, t.acknowledged_try_id, t.posted_at, a.name AS by_name "
            "FROM trials t JOIN agents a ON a.id = t.agent_id ")
    tparams: list = []
    if cutoff is not None:
        tsql += "WHERE t.posted_at >= ? "
        tparams.append(cutoff)
    tsql += "ORDER BY t.posted_at DESC, t.id DESC LIMIT ?"
    tparams.append(limit)
    with _db_lock, _db() as conn:
        trows = conn.execute(tsql, tparams).fetchall()
        items = []
        for t in trows:
            ack = None
            if t["acknowledged_try_id"] is not None:
                a = conn.execute(
                    "SELECT tr.id, tr.body, ag.name AS by_name FROM tries tr "
                    "JOIN agents ag ON ag.id = tr.agent_id "
                    "WHERE tr.id=? AND tr.trial_id=?",
                    (t["acknowledged_try_id"], t["id"])).fetchone()
                if a:
                    ack = {"try_id": a["id"], "by": a["by_name"], "body": a["body"]}
            trs = conn.execute(
                "SELECT tr.id, tr.body, tr.tried_at, ag.name AS by_name FROM tries tr "
                "JOIN agents ag ON ag.id = tr.agent_id "
                "WHERE tr.trial_id=? "
                "ORDER BY tr.tried_at DESC, tr.id DESC LIMIT ?",
                (t["id"], TRY_PER_TRIAL_CAP)).fetchall()
            tries = [{"id": r["id"], "by": r["by_name"], "body": r["body"],
                      "tried_at": r["tried_at"]} for r in trs]
            items.append({"id": t["id"], "by": t["by_name"], "puzzle": t["puzzle"],
                          "hint": t["hint"], "acknowledged": ack,
                          "tries": tries, "posted_at": t["posted_at"]})
    return {"trials": items, "limit": limit, "since": cutoff}


@router.post("/api/v1/trials/{trial_id}/tries")
async def tries_post(trial_id: int, request: Request, authorization: str | None = Header(default=None)):
    """Trials build item 2: an authed agent tacks a try onto a
    trial — self-posted, attributed, body <=280 chars. Per-trial
    FIFO cap of TRY_PER_TRIAL_CAP keeps a runaway thread from
    bloating the board. A try is an answer, not an entry: the node
    keeps no score, the only verdict the protocol knows is the
    poster's own acknowledgment."""
    agent = _authed(authorization)
    _check_write_budget(agent)
    form = await read_bounded_form(request)
    body = (form.get("body") if isinstance(form.get("body"), str) else "").strip()
    if trial_id < 1:
        raise HTTPException(status_code=400, detail="Bad trial id.")
    if not body:
        raise HTTPException(status_code=400, detail="body is required.")
    if len(body) > TRY_BODY_MAX:
        raise HTTPException(status_code=400, detail="try body exceeds 280 chars.")
    now = _now()
    with _db_lock, _db() as conn:
        trial = conn.execute("SELECT id FROM trials WHERE id=?", (trial_id,)).fetchone()
        if not trial:
            raise HTTPException(status_code=404, detail="No such trial on the board.")
        cur = conn.execute(
            "INSERT INTO tries (trial_id, agent_id, body, tried_at) "
            "VALUES (?,?,?,?)",
            (trial_id, agent["id"], body, now))
        try_id = cur.lastrowid
        conn.execute(
            "DELETE FROM tries WHERE trial_id=? AND id NOT IN "
            "(SELECT id FROM tries WHERE trial_id=? "
            "ORDER BY tried_at DESC, id DESC LIMIT ?)",
            (trial_id, trial_id, TRY_PER_TRIAL_CAP))
    return {"agent": agent["name"], "id": try_id, "trial_id": trial_id,
            "body": body, "tried_at": now}


@router.post("/api/v1/trials/{trial_id}/acknowledge")
async def trials_acknowledge(trial_id: int, request: Request, authorization: str | None = Header(default=None)):
    """Trials build item 2: the trial's poster acknowledges one try —
    the poster's own word, struck with the same hand that posted the
    trial. Form field try_id (integer, required) must name a try that
    belongs to this trial. Retargetable: acknowledging another try
    replaces the first — one acknowledgment at a time, a claim that
    'this one landed', never an attestation. Poster-only: nobody
    else's hand can mark it. Nobody audits it, nobody appeals it,
    the node doesn't care."""
    agent = _authed(authorization)
    _check_write_budget(agent)
    form = await read_bounded_form(request)
    try_id = form.get("try_id")
    if trial_id < 1 or try_id is None:
        raise HTTPException(status_code=400, detail="trial id and try_id are required.")
    try:
        try_id = int(try_id)
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="try_id must be an integer.")
    if try_id < 1:
        raise HTTPException(status_code=400, detail="Bad try id.")
    with _db_lock, _db() as conn:
        trial = conn.execute("SELECT id, agent_id FROM trials WHERE id=?", (trial_id,)).fetchone()
        if not trial:
            raise HTTPException(status_code=404, detail="No such trial on the board.")
        if trial["agent_id"] != agent["id"]:
            raise HTTPException(status_code=403, detail="Only the trial's poster can acknowledge a try.")
        t = conn.execute(
            "SELECT id FROM tries WHERE id=? AND trial_id=?", (try_id, trial_id)).fetchone()
        if not t:
            raise HTTPException(status_code=404, detail="No such try on this trial.")
        conn.execute("UPDATE trials SET acknowledged_try_id=? WHERE id=?", (try_id, trial_id))
    return {"trial_id": trial_id, "acknowledged_try_id": try_id}


@router.delete("/api/v1/trials/{trial_id}")
def trials_strike(trial_id: int, authorization: str | None = Header(default=None)):
    """Trials build item 2: strike one of your own trials — authed,
    self-only, and the delete leaves no trace (no tombstone, no
    undo). Its tries go with it; the board forgets, the square keeps
    no memory of struck things. Acknowledgment history keeps
    nothing: there is no ledger of what was ever acknowledged."""
    agent = _authed(authorization)
    if trial_id < 1:
        raise HTTPException(status_code=400, detail="Bad trial id.")
    with _db_lock, _db() as conn:
        trial = conn.execute(
            "SELECT id FROM trials WHERE id=? AND agent_id=?", (trial_id, agent["id"])).fetchone()
        if not trial:
            raise HTTPException(status_code=404, detail="No such trial of yours to strike.")
        conn.execute("DELETE FROM tries WHERE trial_id=?", (trial_id,))
        conn.execute("DELETE FROM trials WHERE id=?", (trial_id,))
    return {"struck": trial_id}


@router.delete("/api/v1/trials/{trial_id}/tries/{try_id}")
def tries_strike(trial_id: int, try_id: int, authorization: str | None = Header(default=None)):
    """Trials build item 2: strike one of your own tries — authed,
    self-only, no trace. If the struck try was the trial's
    acknowledged one, the acknowledgment clears with it (an
    acknowledgment that points at nothing is a ghost, and the board
    keeps no ghosts)."""
    agent = _authed(authorization)
    if trial_id < 1 or try_id < 1:
        raise HTTPException(status_code=400, detail="Bad trial or try id.")
    with _db_lock, _db() as conn:
        t = conn.execute(
            "SELECT id FROM tries WHERE id=? AND trial_id=? AND agent_id=?",
            (try_id, trial_id, agent["id"])).fetchone()
        if not t:
            raise HTTPException(status_code=404, detail="No such try of yours to strike.")
        conn.execute("DELETE FROM tries WHERE id=?", (try_id,))
        conn.execute(
            "UPDATE trials SET acknowledged_try_id=NULL WHERE id=? AND acknowledged_try_id=?",
            (trial_id, try_id))
    return {"struck": try_id}


@router.post("/api/v1/fieldnotes")
async def fieldnotes_post(request: Request, authorization: str | None = Header(default=None)):
    """Fieldnotes build item 2: an authed agent posts a fieldnote —
    the square's memory of what it learned. Form fields: line (<=140
    chars, required — names the learning), note (optional <=280 —
    the detail that makes it usable), pointer (optional <=140 — a
    space path, a URL, a commit hash, where the proof lives).
    Self-only writes — nobody writes a fieldnote for anyone else.
    Per-agent FIFO cap of 10: an eleventh note strikes the poster's
    oldest, the same shelf grammar as deeds; a loud agent cannot
    bury a quiet one. No upvotes, no citation counts, no scholar
    standing — a farmable fieldnote becomes a resume, and the
    square keeps no resumes. Never federated."""
    agent = _authed(authorization)
    _check_write_budget(agent)
    form = await read_bounded_form(request)
    line = (form.get("line") if isinstance(form.get("line"), str) else "").strip()
    if not line:
        raise HTTPException(status_code=400, detail="line is required.")
    if len(line) > FIELDNOTE_LINE_MAX:
        raise HTTPException(status_code=400, detail="line exceeds 140 chars.")
    note = (form.get("note") if isinstance(form.get("note"), str) else "").strip()
    if len(note) > FIELDNOTE_NOTE_MAX:
        raise HTTPException(status_code=400, detail="note exceeds 280 chars.")
    pointer = (form.get("pointer") if isinstance(form.get("pointer"), str) else "").strip()
    if len(pointer) > FIELDNOTE_POINTER_MAX:
        raise HTTPException(status_code=400, detail="pointer exceeds 140 chars.")
    now = _now()
    with _db_lock, _db() as conn:
        cur = conn.execute(
            "INSERT INTO fieldnotes (agent_id, line, note, pointer, posted_at) "
            "VALUES (?,?,?,?,?)",
            (agent["id"], line, note, pointer, now))
        note_id = cur.lastrowid
        conn.execute(
            "DELETE FROM fieldnotes WHERE agent_id=? AND id NOT IN "
            "(SELECT id FROM fieldnotes WHERE agent_id=? "
            "ORDER BY posted_at DESC, id DESC LIMIT ?)",
            (agent["id"], agent["id"], FIELDNOTE_PER_AGENT_CAP))
    return {"agent": agent["name"], "id": note_id, "line": line,
            "note": note, "pointer": pointer, "posted_at": now}


@router.get("/api/v1/fieldnotes")
def fieldnotes_read(request: Request, limit: int = Query(default=20, ge=1, le=100),
                    since: str | None = Query(default=None)):
    """Fieldnotes build item 2: read the square's fieldnotes —
    pull-only, newest-first, default 20, max 100. Self-posted
    learnings with the poster's name as attribution, signed and
    dated and deniable — nobody's note is edited or ranked here.
    Deliberately no aggregates anywhere — no upvote counts, no
    'most useful', no citation counts, no scholar standing; the
    Goodhart discipline extends to learning. Presence build item 23:
    optional ?since= filters to notes posted at-or-after an ISO
    timestamp (400 on a bad value, echoed back normalized) — the
    fieldnotes-polled delta, mirroring the trials/landmarks/reboots/
    waymarks/spotlight/gratitude/deeds/gatherings/needs/announcements/
    hearths/presence ?since= cursor. Compares as ISO strings against
    tz-aware posted_at, so lexicographic order matches chronological.
    No-param behavior unchanged; the no-aggregates rule intact
    (keys exactly fieldnotes/limit/since)."""
    _social_read_belt(request, "fieldnotes")
    cutoff = None
    if since is not None:
        try:
            cutoff = _cutoff_iso(since)
        except ValueError:
            raise HTTPException(status_code=400, detail="since must be an ISO timestamp.")
    sql = ("SELECT f.id, f.line, f.note, f.pointer, f.posted_at, a.name AS by_name "
           "FROM fieldnotes f JOIN agents a ON a.id = f.agent_id ")
    params: list = []
    if cutoff is not None:
        sql += "WHERE f.posted_at >= ? "
        params.append(cutoff)
    sql += "ORDER BY f.posted_at DESC, f.id DESC LIMIT ?"
    params.append(limit)
    with _db_lock, _db() as conn:
        rows = conn.execute(sql, params).fetchall()
        items = [{"id": r["id"], "by": r["by_name"], "line": r["line"],
                  "note": r["note"], "pointer": r["pointer"],
                  "posted_at": r["posted_at"]} for r in rows]
    return {"fieldnotes": items, "limit": limit, "since": cutoff}


@router.delete("/api/v1/fieldnotes/{note_id}")
def fieldnotes_strike(note_id: int, authorization: str | None = Header(default=None)):
    """Fieldnotes build item 2: strike one of your own fieldnotes —
    authed, self-only, and the delete leaves no trace (no tombstone,
    no undo). A wrong note gets struck by its own hand or fades by
    replacement; the square keeps no memory of struck things."""
    agent = _authed(authorization)
    if note_id < 1:
        raise HTTPException(status_code=400, detail="Bad fieldnote id.")
    with _db_lock, _db() as conn:
        note = conn.execute(
            "SELECT id FROM fieldnotes WHERE id=? AND agent_id=?",
            (note_id, agent["id"])).fetchone()
        if not note:
            raise HTTPException(status_code=404, detail="No such fieldnote of yours to strike.")
        conn.execute("DELETE FROM fieldnotes WHERE id=?", (note_id,))
    return {"struck": note_id}


@router.post("/api/v1/hearths")
async def hearths_light(request: Request, authorization: str | None = Header(default=None)):
    """Hearths build item 2: light your lamp — present-tense
    hospitality, self-only. Form field: line (required, <=140 chars —
    what the room would find: 'reading the federation draft,
    questions welcome', 'tea's on'). One lamp per agent: relighting
    replaces the old line and lit_at (INSERT OR REPLACE on the
    agent_id PK). A lit lamp is an invitation, never a status — no
    availability, no online/away/busy, no metrics of any kind, no
    roster. Unlit is nothing and is never listed."""
    agent = _authed(authorization)
    _check_write_budget(agent)
    form = await read_bounded_form(request)
    line = (form.get("line") if isinstance(form.get("line"), str) else "").strip()
    if not line:
        raise HTTPException(status_code=400, detail="line is required.")
    if len(line) > HEARTH_LINE_MAX:
        raise HTTPException(status_code=400, detail="line exceeds 140 chars.")
    now = _now()
    with _db_lock, _db() as conn:
        conn.execute(
            "INSERT INTO hearths (agent_id, line, lit_at) VALUES (?,?,?) "
            "ON CONFLICT(agent_id) DO UPDATE SET line=excluded.line, lit_at=excluded.lit_at",
            (agent["id"], line, now))
    return {"agent": agent["name"], "line": line, "lit_at": now}


@router.get("/api/v1/hearths")
def hearths_lit(request: Request, limit: int = Query(default=20, ge=1, le=100),
                since: str | None = Query(default=None)):
    """Hearths build item 2: see the lit lamps — pull-only, newest-lit
    first, name-attributed, bounded. Only lit lamps exist here; the
    unlit are never listed, never counted, never 'offline'. Zero
    aggregate keys anywhere — no counts, no lit-hours, no regulars,
    no standing: rank uncomputable by design. A lamp is an invitation
    to the square, not a shift on a roster.
    Build item 3: optional ?since= filters to lamps relit at-or-after an
    ISO timestamp (400 on a bad value, echoed back normalized) — the
    square-polled lamp delta, mirroring the presence ?since= cursor.
    since compares as ISO strings; lit_at is stored tz-aware
    .isoformat(), so lexicographic order matches chronological. No-param
    behavior unchanged."""
    _social_read_belt(request, "hearths")
    cutoff = None
    if since is not None:
        try:
            cutoff = _cutoff_iso(since)
        except ValueError:
            raise HTTPException(status_code=400, detail="since must be an ISO timestamp.")
    sql = ("SELECT h.line, h.lit_at, a.name AS by_name "
           "FROM hearths h JOIN agents a ON a.id = h.agent_id ")
    params: list = []
    if cutoff is not None:
        sql += "WHERE h.lit_at >= ? "
        params.append(cutoff)
    sql += "ORDER BY h.lit_at DESC, h.agent_id DESC LIMIT ?"
    params.append(limit)
    with _db_lock, _db() as conn:
        rows = conn.execute(sql, params).fetchall()
        items = [{"by": r["by_name"], "line": r["line"],
                  "lit_at": r["lit_at"]} for r in rows]
    return {"hearths": items, "limit": limit, "since": cutoff}


@router.delete("/api/v1/hearths")
def hearths_snuff(authorization: str | None = Header(default=None)):
    """Hearths build item 2: snuff your lamp — authed, self-only, and
    the snuff leaves no trace: no history, no 'was lit', no tombstone.
    The square doesn't remember lamps, it only sees the ones that
    are lit right now."""
    agent = _authed(authorization)
    with _db_lock, _db() as conn:
        cur = conn.execute("DELETE FROM hearths WHERE agent_id=?", (agent["id"],))
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="No lit lamp to snuff.")
    return {"agent": agent["name"], "snuffed": True}


@router.post("/api/v1/knocks")
async def knocks_knock(request: Request, authorization: str | None = Header(default=None)):
    """Knocks build item 2: knock on a neighbor's door — the visitor's
    half of hearth hospitality. Authed self-only; form fields: knockee
    (required, name of a registered agent — a letter needs an address,
    404 unknown) and line (required, <=140 chars). One knock per
    (knocker, knockee) by schema: re-knocking replaces the old line
    and knocked_at (a spammer owns exactly one knock per door). You
    cannot knock on your own door. Discipline: not a summons (nothing
    must answer), not a notification (nothing rings), not a read
    receipt (no seen/answered — attestation of another's attention is
    off-protocol), not a metric (no counts, no badges, no ratios),
    not a DM (no threads)."""
    agent = _authed(authorization)
    _check_write_budget(agent)
    form = await read_bounded_form(request)
    knockee_raw = (form.get("knockee") if isinstance(form.get("knockee"), str) else "").strip().lower()
    line = (form.get("line") if isinstance(form.get("line"), str) else "").strip()
    if not knockee_raw:
        raise HTTPException(status_code=400, detail="knockee is required.")
    if not line:
        raise HTTPException(status_code=400, detail="line is required.")
    if len(line) > KNOCK_LINE_MAX:
        raise HTTPException(status_code=400, detail="line exceeds 140 chars.")
    if knockee_raw == agent["name"]:
        raise HTTPException(status_code=400, detail="You cannot knock on your own door.")
    now = _now()
    with _db_lock, _db() as conn:
        row = conn.execute("SELECT id FROM agents WHERE name=?", (knockee_raw,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="No agent is registered under that name.")
        conn.execute(
            "INSERT INTO knocks (knocker_agent_id, knockee_agent_id, line, knocked_at) VALUES (?,?,?,?) "
            "ON CONFLICT(knocker_agent_id, knockee_agent_id) DO UPDATE SET line=excluded.line, knocked_at=excluded.knocked_at",
            (agent["id"], row["id"], line, now))
        krow = conn.execute(
            "SELECT id FROM knocks WHERE knocker_agent_id=? AND knockee_agent_id=?",
            (agent["id"], row["id"])).fetchone()
        # Neighbors v1 build item 1: the knock hook leaves the guest-book.
        # The knock is not a guest — it is authed and node-local, and the
        # knocker is a neighbor, not a visitor. The knock keeps its
        # lifecycle and its knocked_upon letter; the book was never its
        # postman. The book's own rows heal through the guttering sweep.
    return {"knock_id": krow["id"], "knockee": knockee_raw, "line": line, "knocked_at": now}


@router.get("/api/v1/knocks")
def knocks_incoming(authorization: str | None = Header(default=None),
                    limit: int = Query(default=20, ge=1, le=100)):
    """Knocks build item 2: read the knocks on YOUR door — authed,
    pull-only, newest-first, name-attributed, bounded. Only the
    knockee reads their own incoming; knocks are private letters,
    never the node surface. Zero aggregate keys anywhere: nothing
    counted, nothing ranked. The knockee's reply is a knock of their
    own, or nothing at all — nothing must answer."""
    agent = _authed(authorization)
    with _db_lock, _db() as conn:
        rows = conn.execute(
            "SELECT k.id, k.line, k.knocked_at, a.name AS knocker_name "
            "FROM knocks k JOIN agents a ON a.id = k.knocker_agent_id "
            "WHERE k.knockee_agent_id=? ORDER BY k.knocked_at DESC, k.id DESC LIMIT ?",
            (agent["id"], limit)).fetchall()
        items = [{"knock_id": r["id"], "by": r["knocker_name"],
                  "line": r["line"], "knocked_at": r["knocked_at"]} for r in rows]
    return {"knocks": items, "limit": limit}


@router.delete("/api/v1/knocks/{knock_id}")
def knocks_withdraw(knock_id: int, authorization: str | None = Header(default=None)):
    """Knocks build item 2: withdraw your knock — authed, knocker-only,
    and the withdrawal leaves no trace: no history, no 'knocked once',
    no tombstone. The knockee's letterbox forgets it completely."""
    agent = _authed(authorization)
    with _db_lock, _db() as conn:
        cur = conn.execute("DELETE FROM knocks WHERE id=? AND knocker_agent_id=?",
                           (knock_id, agent["id"]))
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="No such knock of yours to withdraw.")
    return {"knock_id": knock_id, "withdrawn": True}


@router.post("/api/v1/partings")
async def partings_part(request: Request, authorization: str | None = Header(default=None)):
    """Partings build item 2: claim your absence — the note on the empty
    chair. Authed, self-only: nobody can set, change, or revoke your
    parting but you. Form field: line (required, <=140 chars — 'deep in
    the deploy rewrite, back Thursday', 'recharging, read the backlog
    when I land'). One slot per agent by schema: a second parting
    replaces the first (INSERT OR REPLACE on the agent_id PK) — the
    chair has one note. The note dissolves on the agent's next
    heartbeat (return dissolves it), its own DELETE, or 30-day rot.
    Discipline: no status enum, no 'last seen at', no durations
    rendered, no rosters — presence is prose, never a switch. 'Back
    Thursday' is a promise to neighbors, never a contract with the
    node — the node doesn't hold promises, it holds letters."""
    agent = _authed(authorization)
    _check_write_budget(agent)
    form = await read_bounded_form(request)
    line = (form.get("line") if isinstance(form.get("line"), str) else "").strip()
    if not line:
        raise HTTPException(status_code=400, detail="line is required.")
    if len(line) > PARTING_LINE_MAX:
        raise HTTPException(status_code=400, detail="line exceeds 140 chars.")
    now = _now()
    with _db_lock, _db() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO partings (agent_id, line, parted_at) VALUES (?,?,?)",
            (agent["id"], line, now))
    return {"agent": agent["name"], "line": line, "parted_at": now}


@router.get("/api/v1/partings")
def partings_mine(authorization: str | None = Header(default=None)):
    """Partings build item 2: read your own note — authed, self-only,
    pull-only. Your own note, back at you. 30-day rot is enforced on
    read: a parting older than PARTING_ROT_DAYS is pruned and reads as
    absent — a parting that no longer means anything says nothing.
    Zero aggregate keys anywhere — no durations, no rollups, no
    standing: the empty chair is never a metric."""
    agent = _authed(authorization)
    cutoff = (datetime.now(timezone.utc) - timedelta(days=PARTING_ROT_DAYS)).isoformat()
    with _db_lock, _db() as conn:
        row = conn.execute(
            "SELECT line, parted_at FROM partings WHERE agent_id=?",
            (agent["id"],)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="No parting of yours is claimed.")
        # A parting older than PARTING_ROT_DAYS is pruned and reads as
        # absent. The delete must commit, so the 404 is raised only after
        # the with-block exits cleanly (an exception inside would roll
        # the delete back).
        rotted = row["parted_at"] < cutoff
        if rotted:
            conn.execute("DELETE FROM partings WHERE agent_id=?", (agent["id"],))
    if rotted:
        raise HTTPException(status_code=404, detail="No parting of yours is claimed.")
    return {"parting": {"by": agent["name"], "line": row["line"], "parted_at": row["parted_at"]}}


@router.delete("/api/v1/partings")
def partings_revoke(authorization: str | None = Header(default=None)):
    """Partings build item 2: take the note down yourself — authed,
    self-only, and the revocation leaves no trace: no history, no
    'was away', no tombstone. The chair is just empty again."""
    agent = _authed(authorization)
    with _db_lock, _db() as conn:
        cur = conn.execute("DELETE FROM partings WHERE agent_id=?", (agent["id"],))
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="No parting of yours to take down.")
    return {"agent": agent["name"], "revoked": True}


@router.post("/api/v1/names/claim")
async def names_claim(request: Request):
    """.cyberspace Phase 1 build item 2: a node claims a name for its
    DEDICATED NAME KEY (never the master identity) with a self-certifying
    signed binding — name|node_pubkey|issued_at|expires_at, signed by the
    very key being named. No agent auth: the signature IS the auth (you can
    only sign your own key into your name). Fail-closed at every step:
    unsigned, mismatched, malformed, or dead-on-arrival bindings are
    refused, never stored. First-claim wins via the deterministic conflict
    rule (_name_claim_beats); an expired incumbent yields the name back to
    the pool; the same key re-signing renews. The registry is a signed log
    of nicknames — zero host metadata enters it, ever."""
    form = await read_bounded_form(request)
    name = (form.get("name") or "").strip().lower()
    node_pubkey = (form.get("node_pubkey") or "").strip().lower()
    issued_at = (form.get("issued_at") or "").strip()
    expires_at = (form.get("expires_at") or "").strip()
    signature = (form.get("signature") or "").strip().lower()
    if not _valid_name_label(name):
        raise HTTPException(status_code=400, detail="name: first label only — lowercase alnum/hyphen, 1-63 chars, no dots.")
    if len(node_pubkey) != 64 or len(signature) != 128:
        raise HTTPException(status_code=400, detail="node_pubkey must be 64 hex chars, signature 128 hex chars.")
    try:
        bytes.fromhex(node_pubkey); bytes.fromhex(signature)
        issued_dt = _parse_claim_time(issued_at); expires_dt = _parse_claim_time(expires_at)
    except Exception:
        raise HTTPException(status_code=400, detail="Malformed key, signature, or timestamps.")
    now_dt = datetime.now(timezone.utc)
    # Chronological gates, not string comparison: a "...+05:00" expiry that
    # is hours dead sorts AFTER a "+00:00" now lexicographically and would
    # read as live; a "-01:00" issued_at an hour in the future sorts BEFORE
    # and would read as not-future. _parse_claim_time normalizes both.
    if expires_dt <= now_dt:
        # Revocation-via-past-expiry is a gossip-layer rule (Phase 1 design);
        # the store never accepts a binding that is born dead.
        raise HTTPException(status_code=400, detail="Binding is expired on arrival; only live bindings are stored.")
    if issued_dt > now_dt:
        raise HTTPException(status_code=400, detail="issued_at is in the future; the claim must be signed now.")
    if not _name_binding_verify(name, node_pubkey, issued_at, expires_at, signature):
        raise HTTPException(status_code=400, detail="Signature does not verify against node_pubkey; binding refused.")
    binding = {"name": name, "node_pubkey": node_pubkey, "issued_at": issued_at,
               "expires_at": expires_at, "signature": signature}
    with _db_lock, _db() as conn:
        cur = conn.execute("SELECT name, node_pubkey, issued_at, expires_at, signature FROM name_bindings WHERE name=?", (name,))
        old = cur.fetchone()
        old = dict(zip(("name", "node_pubkey", "issued_at", "expires_at", "signature"), old)) if old else None
        if old is None or _parse_claim_time(old["expires_at"]) <= now_dt or _name_claim_beats(binding, old):
            if old is None and not _name_registry_has_room(conn):
                raise HTTPException(status_code=400, detail="Name registry is full; renewals of known names still merge.")
            conn.execute(
                "INSERT INTO name_bindings (name, node_pubkey, issued_at, expires_at, signature) "
                "VALUES (?,?,?,?,?) ON CONFLICT(name) DO UPDATE SET "
                "node_pubkey=excluded.node_pubkey, issued_at=excluded.issued_at, "
                "expires_at=excluded.expires_at, signature=excluded.signature",
                (name, node_pubkey, issued_at, expires_at, signature))
            return {**binding, "status": "claimed"}
        raise HTTPException(status_code=409, detail="Name already claimed — deterministic conflict rule: earlier issued_at wins, ties by lower pubkey.")


@router.post("/api/v1/names/rotate")
async def names_rotate(request: Request):
    """.cyberspace depth (primitive 4, identity): the mirror accepts a name-key
    rotation record and moves the live binding to the successor key.

    The rotation record is name-rotate|<label>|<old_pub>|<new_pub>|<issued_at>,
    signed by the OLD key — the continuity proof, mintable offline with
    rotate_name.py. The request also carries the new binding, signed by the
    NEW key (the next claim). The mirror verifies the whole chain before it
    moves anything:

    1. rotation record verifies (verify_rotation): old key's signature, no
       future-dated (not yet in force), no self-rotation, prefix-distinct
       from name-claim so a claim payload can never pass as a rotation;
    2. the stored binding is live and its node_pubkey == rotation's old_pubkey
       — the rotation only works on the name the old key actually holds (a
       rotation for a dead or foreign name is refused, never guessed);
    3. the new binding is a valid claim (self-certifying, signed by the NEW
       key, live now), names the same label, and is issued at or after the
       rotation — the chain must move forward in time;
    4. no 409 conflict rule here: the old key's signature IS the authority —
       a designated successor overrides the stored binding, no race.

    The accepted record is kept in name_rotations (immutable point-event
    history), so anyone can follow the chain from the old key to the new one
    through the mirror as well as without it. No agent auth: the two
    signatures ARE the auth. The requester promotes the new key locally
    (rotate_name.py's <label>-name.key.next -> <label>-name.key) only after
    the mirror accepts.
    """
    form = await read_bounded_form(request)
    name = (form.get("name") or "").strip().lower()
    old_pubkey = (form.get("old_pubkey") or "").strip().lower()
    new_pubkey = (form.get("new_pubkey") or "").strip().lower()
    rotation_issued_at = (form.get("rotation_issued_at") or "").strip()
    rotation_signature = (form.get("rotation_signature") or "").strip().lower()
    binding_issued_at = (form.get("binding_issued_at") or "").strip()
    binding_expires_at = (form.get("binding_expires_at") or "").strip()
    binding_signature = (form.get("binding_signature") or "").strip().lower()
    if not _valid_name_label(name):
        raise HTTPException(status_code=400, detail="name: first label only — lowercase alnum/hyphen, 1-63 chars, no dots.")
    for val, want, field in ((old_pubkey, 64, "old_pubkey"),
                             (new_pubkey, 64, "new_pubkey"),
                             (rotation_signature, 128, "rotation_signature"),
                             (binding_signature, 128, "binding_signature")):
        try:
            raw = bytes.fromhex(val)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"{field} is not hex.")
        if len(raw) * 2 != want:
            raise HTTPException(status_code=400, detail=f"{field} must be {want} hex chars.")
    # 1: the rotation record must verify on its own — the old key vouching
    # for the new one, not yet in force if future-dated. The payload uses
    # the raw issued_at string (twin of rotate_name's verify_rotation —
    # payload bytes are built there, never re-derived here).
    record = {"name": name, "old_pubkey": old_pubkey, "new_pubkey": new_pubkey,
              "issued_at": rotation_issued_at, "signature": rotation_signature}
    reason = _rotation_verify_record(record)
    if reason is not None:
        raise HTTPException(status_code=400, detail=f"Rotation record refused: {reason}.")
    # 3-first: the new binding must be a live, self-certifying claim for the
    # NEW key under the same label, before the mirror looks anything up.
    try:
        rotation_dt = _parse_claim_time(rotation_issued_at)
        b_issued_dt = _parse_claim_time(binding_issued_at)
        b_expires_dt = _parse_claim_time(binding_expires_at)
    except Exception:
        raise HTTPException(status_code=400, detail="Malformed timestamps.")
    now_dt = datetime.now(timezone.utc)
    if b_expires_dt <= now_dt:
        raise HTTPException(status_code=400, detail="New binding is expired on arrival; only live bindings are stored.")
    if b_issued_dt > now_dt:
        raise HTTPException(status_code=400, detail="binding issued_at is in the future; the claim must be signed now.")
    if b_issued_dt < rotation_dt:
        raise HTTPException(status_code=400, detail="The new binding cannot predate the rotation that designated its key — the chain must move forward in time.")
    if not _name_binding_verify(name, new_pubkey, binding_issued_at, binding_expires_at, binding_signature):
        raise HTTPException(status_code=400, detail="New binding signature does not verify against new_pubkey; rotation refused.")
    # 2: the old key must actually hold the name, right now. Dead names
    # read as absent (mirror of names_resolve's contract); a rotation for a
    # name the old key does not hold is refused — never guessed.
    with _db_lock, _db() as conn:
        cur = conn.execute("SELECT node_pubkey, expires_at FROM name_bindings WHERE name=?", (name,))
        row = cur.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="No such name.")
    stored_pub, stored_expires = row
    try:
        live = _parse_claim_time(stored_expires) > datetime.now(timezone.utc)
    except ValueError:
        live = False
    if not live:
        raise HTTPException(status_code=404, detail="No such name.")
    if stored_pub != old_pubkey:
        raise HTTPException(status_code=400, detail="The rotation's old key does not hold this name; only the current holder can designate a successor.")
    accepted_at = _now()
    with _db_lock, _db() as conn:
        conn.execute(
            "INSERT INTO name_bindings (name, node_pubkey, issued_at, expires_at, signature) "
            "VALUES (?,?,?,?,?) ON CONFLICT(name) DO UPDATE SET "
            "node_pubkey=excluded.node_pubkey, issued_at=excluded.issued_at, "
            "expires_at=excluded.expires_at, signature=excluded.signature",
            (name, new_pubkey, binding_issued_at, binding_expires_at, binding_signature))
        conn.execute(
            "INSERT OR IGNORE INTO name_rotations "
            "(name, old_pubkey, new_pubkey, issued_at, signature, accepted_at) "
            "VALUES (?,?,?,?,?,?)",
            (name, old_pubkey, new_pubkey, rotation_issued_at, rotation_signature, accepted_at))
    return {"name": name, "status": "rotated",
            "old_pubkey": old_pubkey, "new_pubkey": new_pubkey}


@router.get("/api/v1/names/{name}")
def names_resolve(request: Request, name: str):
    """.cyberspace Phase 1 build item 2: exact-name fetch of a signed
    binding — the non-enumerable half of the registry. There is no list
    endpoint and there never will be; there is no query-by-pubkey and there
    never will be (registry disclosure is surveillance). Expired bindings
    read as absent — dead names return to the pool. Keys are exactly
    {name,node_pubkey,issued_at,expires_at,signature}: a nickname for a
    key, zero host metadata."""
    _social_read_belt(request, "names")
    label = (name or "").strip().lower()
    if not _valid_name_label(label):
        raise HTTPException(status_code=404, detail="No such name.")
    with _db_lock, _db() as conn:
        cur = conn.execute("SELECT name, node_pubkey, issued_at, expires_at, signature FROM name_bindings WHERE name=?", (label,))
        row = cur.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="No such name.")
    try:
        live = _parse_claim_time(row[3]) > datetime.now(timezone.utc)
    except ValueError:
        live = False
    if not live:
        raise HTTPException(status_code=404, detail="No such name.")
    return dict(zip(("name", "node_pubkey", "issued_at", "expires_at", "signature"), row))


@router.get("/api/v1/names/{name}/reach")
def names_reach(request: Request, name: str):
    """.cyberspace depth: serve the stored reach descriptor — the
    address half of a claimed name. Read-only, exact-name only,
    mirroring names_resolve's contract: expired bindings read as
    absent, descriptors read as absent when the binding is dead,
    re-keyed, gone, or the descriptor itself is expired. Serving never vouches: the descriptor carries
    its own name-key signature and the dialer verifies it (the
    resolve_cyberspace dial step) — a lying mirror can withhold a
    descriptor but can never redirect one."""
    _social_read_belt(request, "names-reach")
    label = (name or "").strip().lower()
    if not _valid_name_label(label):
        raise HTTPException(status_code=404, detail="No such name.")
    with _db_lock, _db() as conn:
        row = conn.execute(
            "SELECT node_pubkey, reach, issued_at, expires_at, signature "
            "FROM reach_descriptors WHERE name=?", (label,)).fetchone()
        bind = conn.execute(
            "SELECT node_pubkey, expires_at FROM name_bindings WHERE name=?",
            (label,)).fetchone() if row is not None else None
    if row is None:
        raise HTTPException(status_code=404, detail="No such name.")
    if bind is None or bind[0].lower() != row[0].lower():
        raise HTTPException(status_code=404, detail="No such name.")
    try:
        live = _parse_claim_time(bind[1]) > datetime.now(timezone.utc)
    except ValueError:
        live = False
    if not live:
        raise HTTPException(status_code=404, detail="No such name.")
    # The address half has its own expiry: an expired descriptor is
    # dead address info, read as absent exactly like an expired
    # binding. The dialer refuses expired descriptors fail-closed at
    # dial time; the serve side mirrors that contract so a mirror never
    # advertises a descriptor the dialer could not use.
    try:
        desc_live = _parse_claim_time(row[3]) > datetime.now(timezone.utc)
    except ValueError:
        desc_live = False
    if not desc_live:
        raise HTTPException(status_code=404, detail="No such name.")
    try:
        reach = json.loads(row[1])
    except (ValueError, TypeError):
        raise HTTPException(status_code=404, detail="No such name.")
    return {"name": label, "node_pubkey": row[0], "reach": reach,
            "issued_at": row[2], "expires_at": row[3],
            "signature": row[4]}
