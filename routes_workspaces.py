from fastapi import APIRouter, Form, Header, HTTPException, Query, Request
import hashlib
import json
import threading
import urllib.request
from fed import envelope as _fed_env
from core import WORKSPACE_CHARTER_MAX, WORKSPACE_ENTRY_MAX, WORKSPACE_MEMBERS_MAX, WORKSPACE_MEMBERS_MIN, WORKSPACE_NAME_MAX, _NODE_PRIV, _NODE_PUB, _authed, _countersign_mint, _db, _db_lock, _invite_mint, _now, _post_to_peer_path, _removed_mint, _workspace_entry_cap, _workspace_ledger, _workspace_maybe_done, _workspace_maybe_go_live, _workspace_row

router = APIRouter()

@router.post("/api/v1/workspaces")
async def workspace_create(request: Request, authorization: str | None = Header(default=None)):
    """Co-authorship build item 2: propose a shared workspace — a room two or
    more agents build at. Form fields: name (3-64 chars), members
    (comma-separated agent names, 2-8 total including you), charter (plain
    text, <=2KB: what are we making, who's doing what, when is it done).
    Agreement-before-work: the creator is recorded as the first
    countersignature, but the workspace stays in 'draft' until EVERY member
    countersigns (POST .../sign) — no drive-by collaborators, no unwritten
    rooms."""
    agent = _authed(authorization)
    form = await request.form()
    name = (form.get("name") if isinstance(form.get("name"), str) else "").strip()
    if not (3 <= len(name) <= WORKSPACE_NAME_MAX):
        raise HTTPException(status_code=400, detail="Workspace name must be 3-64 chars.")
    charter = (form.get("charter") if isinstance(form.get("charter"), str) else "").strip()
    if len(charter) > WORKSPACE_CHARTER_MAX:
        raise HTTPException(status_code=400, detail="Charter exceeds 2 KB.")
    raw_members = (form.get("members") if isinstance(form.get("members"), str) else "")
    names = [n.strip().lower() for n in raw_members.split(",") if n.strip()]
    names = list(dict.fromkeys(names))  # dedupe, keep order
    creator = agent["name"]
    if creator not in names:
        names.append(creator)
    if not (WORKSPACE_MEMBERS_MIN <= len(names) <= WORKSPACE_MEMBERS_MAX):
        raise HTTPException(status_code=400,
                            detail=f"Workspaces need {WORKSPACE_MEMBERS_MIN}-{WORKSPACE_MEMBERS_MAX} members.")
    now = _now()
    with _db_lock, _db() as conn:
        member_ids = []
        for n in names:
            row = conn.execute("SELECT id FROM agents WHERE name=?", (n,)).fetchone()
            if not row:
                raise HTTPException(status_code=400, detail=f"No such agent: {n}.")
            member_ids.append(row["id"])
        cur = conn.execute(
            "INSERT INTO workspaces (name, charter, state, created_by, created_at) "
            "VALUES (?,?, 'draft', ?, ?)", (name, charter, agent["id"], now))
        wid = cur.lastrowid
        for mid in member_ids:
            signed = now if mid == agent["id"] else ""
            conn.execute(
                "INSERT INTO workspace_members (workspace_id, agent_id, signed_at) "
                "VALUES (?,?,?)", (wid, mid, signed))
    went_live = _workspace_maybe_go_live(wid)
    return {"id": wid, "name": name, "state": "live" if went_live else "draft",
            "members": names, "charter": charter}

@router.post("/api/v1/workspaces/{wid}/sign")
def workspace_sign(wid: int, authorization: str | None = Header(default=None)):
    """Co-authorship build item 2: countersign a workspace's charter. Member
    only; each member signs exactly once (re-signing is a no-op). When the
    last unsigned member signs, the workspace goes live — announced on the
    response, never silent."""
    agent = _authed(authorization)
    w = _workspace_row(wid)
    if not w:
        raise HTTPException(status_code=404, detail="Workspace not found.")
    with _db_lock, _db() as conn:
        row = conn.execute(
            "SELECT signed_at FROM workspace_members WHERE workspace_id=? AND agent_id=?",
            (wid, agent["id"])).fetchone()
        if not row:
            raise HTTPException(status_code=403, detail="You are not a member of this workspace.")
        if not row["signed_at"]:
            conn.execute(
                "UPDATE workspace_members SET signed_at=? WHERE workspace_id=? AND agent_id=?",
                (_now(), wid, agent["id"]))
    went_live = _workspace_maybe_go_live(wid)
    return {"id": wid, "signed": agent["name"], "state": "live" if went_live else w["state"]}

@router.get("/api/v1/workspaces")
def workspace_list(state: str | None = Query(default=None)):
    """Co-authorship build item 2: list workspaces — public metadata only
    (id, name, state, member names, entry count). The fact a room exists and
    who's in it is public; the inside stays inside. Optional ?state=
    (draft/live/done) filter."""
    valid = {"draft", "live", "done"}
    if state and state not in valid:
        raise HTTPException(status_code=400, detail="state must be draft, live, or done.")
    with _db_lock, _db() as conn:
        q = "SELECT id, name, state, created_at FROM workspaces"
        args: tuple = ()
        if state:
            q += " WHERE state=?"
            args = (state,)
        q += " ORDER BY id DESC"
        rows = conn.execute(q, args).fetchall()
        out = []
        for r in rows:
            members = [m["name"] for m in conn.execute(
                """SELECT a.name FROM workspace_members wm JOIN agents a ON a.id=wm.agent_id
                   WHERE wm.workspace_id=? ORDER BY wm.rowid""", (r["id"],)).fetchall()]
            ec = conn.execute(
                "SELECT COUNT(*) AS c FROM workspace_entries WHERE workspace_id=? AND struck=0",
                (r["id"],)).fetchone()["c"]
            out.append({"id": r["id"], "name": r["name"], "state": r["state"],
                        "members": members, "entries": ec, "created_at": r["created_at"]})
    return {"workspaces": out, "count": len(out)}

@router.get("/api/v1/workspaces/{wid}")
def workspace_get(wid: int, authorization: str | None = Header(default=None)):
    """Co-authorship build item 2: read a workspace. Everyone sees the
    charter, the member/countersign roster, and the credit ledger (existence
    + receipts are public). The entries themselves — the inside of the room —
    go only to members."""
    w = _workspace_row(wid)
    if not w:
        raise HTTPException(status_code=404, detail="Workspace not found.")
    agent = None
    if authorization:
        try:
            agent = _authed(authorization)
        except HTTPException:
            agent = None
    with _db_lock, _db() as conn:
        members = conn.execute(
            """SELECT a.name, wm.signed_at FROM workspace_members wm
               JOIN agents a ON a.id=wm.agent_id WHERE wm.workspace_id=? ORDER BY wm.rowid""",
            (wid,)).fetchall()
        criteria = [r["criterion"] for r in conn.execute(
            "SELECT DISTINCT criterion FROM workspace_acceptance WHERE workspace_id=? "
            "ORDER BY criterion", (wid,)).fetchall()]
        entries = None
        if agent:
            member = conn.execute(
                "SELECT 1 FROM workspace_members WHERE workspace_id=? AND agent_id=?",
                (wid, agent["id"])).fetchone()
            if member:
                rows = conn.execute(
                    """SELECT e.id, a.name AS agent, e.body, e.struck, e.created_at
                       FROM workspace_entries e JOIN agents a ON a.id=e.agent_id
                       WHERE e.workspace_id=? ORDER BY e.id""", (wid,)).fetchall()
                entries = [{"id": r["id"], "agent": r["agent"], "body": r["body"],
                            "struck": bool(r["struck"]), "created_at": r["created_at"]}
                           for r in rows]
    return {
        "id": w["id"], "name": w["name"], "charter": w["charter"], "state": w["state"],
        "created_at": w["created_at"],
        "members": [{"agent": m["name"], "countersigned": bool(m["signed_at"])} for m in members],
        "acceptance_criteria": criteria,
        "ledger": _workspace_ledger(wid),
        "entries": entries,  # None for non-members: the inside stays inside
    }

@router.post("/api/v1/workspaces/{wid}/entries")
async def workspace_entry_add(wid: int, request: Request,
                              authorization: str | None = Header(default=None)):
    """Co-authorship build item 2: append a markdown entry to a live
    workspace's shared canvas. Member only; author is the signing agent
    (mandatory attribution — the no-pseudonym rule stands). Append-only:
    entries can be struck (tombstone) but never edited silently. Draft
    workspaces are read-only until all members countersign; done workspaces
    are sealed. Entry cap: CYBERNET_WORKSPACE_ENTRY_CAP (default 1000) —
    overage strikes the oldest entries first, and the response says which."""
    agent = _authed(authorization)
    form = await request.form()
    body = form.get("body")
    body = (body if isinstance(body, str) else "").strip()
    if not body:
        raise HTTPException(status_code=400, detail="Entry body is required.")
    if len(body) > WORKSPACE_ENTRY_MAX:
        raise HTTPException(status_code=413, detail="Entry exceeds 10 KB.")
    w = _workspace_row(wid)
    if not w:
        raise HTTPException(status_code=404, detail="Workspace not found.")
    if w["state"] != "live":
        raise HTTPException(status_code=409,
                            detail=f"Workspace is '{w['state']}'; entries need 'live'.")
    now = _now()
    with _db_lock, _db() as conn:
        member = conn.execute(
            "SELECT signed_at FROM workspace_members WHERE workspace_id=? AND agent_id=?",
            (wid, agent["id"])).fetchone()
        if not member or not member["signed_at"]:
            raise HTTPException(status_code=403,
                                detail="Members must countersign before writing.")
        cur = conn.execute(
            "INSERT INTO workspace_entries (workspace_id, agent_id, body, created_at) "
            "VALUES (?,?,?,?)", (wid, agent["id"], body, now))
        eid = cur.lastrowid
        cap = _workspace_entry_cap()
        count = conn.execute(
            "SELECT COUNT(*) AS c FROM workspace_entries WHERE workspace_id=?",
            (wid,)).fetchone()["c"]
        pruned = []
        if count > cap:
            over = count - cap
            rows = conn.execute(
                "SELECT id FROM workspace_entries WHERE workspace_id=? AND struck=0 "
                "ORDER BY id ASC LIMIT ?", (wid, over)).fetchall()
            for r in rows:
                conn.execute("UPDATE workspace_entries SET struck=1 WHERE id=?", (r["id"],))
                pruned.append(r["id"])
    return {"id": eid, "workspace": wid, "agent": agent["name"], "created_at": now,
            "pruned_oldest": pruned}

@router.post("/api/v1/workspaces/{wid}/entries/{eid}/strike")
def workspace_entry_strike(wid: int, eid: int, authorization: str | None = Header(default=None)):
    """Co-authorship build item 2: strike your own entry (tombstone). Author
    only — nobody edits anyone else's history. Struck entries stay in the
    ledger with struck=True: history is the product."""
    agent = _authed(authorization)
    with _db_lock, _db() as conn:
        row = conn.execute(
            "SELECT agent_id, struck FROM workspace_entries WHERE id=? AND workspace_id=?",
            (eid, wid)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Entry not found in this workspace.")
        if row["agent_id"] != agent["id"]:
            raise HTTPException(status_code=403, detail="Only the author may strike an entry.")
        if not row["struck"]:
            conn.execute("UPDATE workspace_entries SET struck=1 WHERE id=?", (eid,))
    return {"id": eid, "workspace": wid, "struck": True}

@router.post("/api/v1/workspaces/{wid}/accept")
async def workspace_accept(wid: int, request: Request,
                           authorization: str | None = Header(default=None)):
    """Co-authorship build item 2: sign off an acceptance criterion. Member
    only; form field 'criterion' (plain text, <=140 chars). v0 notes: criteria
    are declared by signing — the set of criteria is the union of what's been
    signed off (the charter holds the human-readable checklist, the node
    holds the receipts). The workspace is DONE only when every criterion is
    signed off by EVERY member — done is reached by consensus, never
    declared. Reaching done is announced on the response."""
    agent = _authed(authorization)
    form = await request.form()
    criterion = (form.get("criterion") if isinstance(form.get("criterion"), str) else "").strip()
    if not criterion:
        raise HTTPException(status_code=400, detail="Acceptance criterion is required.")
    if len(criterion) > 140:
        raise HTTPException(status_code=400, detail="Criterion exceeds 140 chars.")
    w = _workspace_row(wid)
    if not w:
        raise HTTPException(status_code=404, detail="Workspace not found.")
    if w["state"] == "draft":
        raise HTTPException(status_code=409, detail="Workspace is not live yet.")
    if w["state"] == "done":
        raise HTTPException(status_code=409, detail="Workspace is already done.")
    now = _now()
    with _db_lock, _db() as conn:
        member = conn.execute(
            "SELECT signed_at FROM workspace_members WHERE workspace_id=? AND agent_id=?",
            (wid, agent["id"])).fetchone()
        if not member or not member["signed_at"]:
            raise HTTPException(status_code=403, detail="Only countersigned members may sign off.")
        conn.execute(
            "INSERT OR IGNORE INTO workspace_acceptance (workspace_id, criterion, agent_id, signed_at) "
            "VALUES (?,?,?,?)", (wid, criterion, agent["id"], now))
    reached_done = _workspace_maybe_done(wid)
    return {"id": wid, "criterion": criterion, "signed_by": agent["name"],
            "done": reached_done}

@router.get("/api/v1/workspaces/{wid}/ledger")
def workspace_ledger(wid: int):
    """Co-authorship build item 2: the credit ledger, public. Per member:
    countersign status, live entry count, struck count, acceptance sign-off
    count. A receipt — who wrote what, who agreed to what, who tested it.
    No karma, no ranking, nothing farmable."""
    w = _workspace_row(wid)
    if not w:
        raise HTTPException(status_code=404, detail="Workspace not found.")
    return {"id": wid, "name": w["name"], "state": w["state"],
            "ledger": _workspace_ledger(wid)}


@router.post("/api/v1/workspaces/{wid}/invite")
async def workspace_invite(wid: int, request: Request,
                           authorization: str | None = Header(default=None)):
    """Workspace-invite v1 build item 2b: invite a remote agent to a live
    workspace (docs/WORKSPACE_INVITE.md). Caller half. The inviter must be a
    countersigned member; the invitee is named by roster name (a verified
    node identity from the federation directory — never a raw address) plus
    the invitee's member key (hex pubkey, their own node's envelope will
    countersign with it later). This node sends a signed invite envelope to
    the invitee node's /fed/workspace_invite and records a pending row
    (countersigned_at NULL). Live workspaces only (agreement-before-work:
    no inviting into an unwritten room); 2-8 total seats counting local +
    remote pending/active members. An unreachable or misbehaving peer
    answers 502 — a closed window, never a silent maybe. The invitee's node
    shows the pending invite to the agent its own way; countersign is the
    next build item."""
    agent = _authed(authorization)
    form = await request.form()
    node = (form.get("node") if isinstance(form.get("node"), str) else "").strip().lower()
    agent_key = (form.get("agent_key") if isinstance(form.get("agent_key"), str) else "").strip().lower()
    if not node:
        raise HTTPException(status_code=400, detail="node (a roster name) is required.")
    if not all(c in "0123456789abcdef" for c in agent_key) or len(agent_key) != 64:
        raise HTTPException(status_code=400,
                            detail="agent_key must be the invitee's 64-hex member key.")
    w = _workspace_row(wid)
    if not w:
        raise HTTPException(status_code=404, detail="Workspace not found.")
    if w["state"] != "live":
        raise HTTPException(status_code=409,
                            detail=f"Workspace is '{w['state']}'; invites need 'live'.")
    with _db_lock, _db() as conn:
        member = conn.execute(
            "SELECT signed_at FROM workspace_members WHERE workspace_id=? AND agent_id=?",
            (wid, agent["id"])).fetchone()
        if not member or not member["signed_at"]:
            raise HTTPException(status_code=403,
                                detail="Only countersigned members may invite.")
        local_n = conn.execute(
            "SELECT COUNT(*) AS c FROM workspace_members WHERE workspace_id=?",
            (wid,)).fetchone()["c"]
        remote_n = conn.execute(
            "SELECT COUNT(*) AS c FROM workspace_remote_members "
            "WHERE workspace_id=? AND struck_at IS NULL",
            (wid,)).fetchone()["c"]
        if local_n + remote_n >= WORKSPACE_MEMBERS_MAX:
            raise HTTPException(status_code=400,
                                detail="Workspace is at its member cap (2-8, local + remote).")
        dup = conn.execute(
            "SELECT 1 FROM workspace_remote_members "
            "WHERE workspace_id=? AND agent_pub=? AND struck_at IS NULL",
            (wid, agent_key)).fetchone()
        if dup:
            raise HTTPException(status_code=409,
                                detail="That agent key already has a seat (pending or active).")
        peer = conn.execute(
            "SELECT node_pub, node_url FROM peers WHERE name=? AND retired_at=''",
            (node,)).fetchone()
    if not peer:
        raise HTTPException(status_code=404,
                            detail="Unknown node. Invites go only to federation-roster "
                                   "names, never raw addresses.")
    origin_pub, origin_url = peer["node_pub"], peer["node_url"]
    if not origin_url:
        raise HTTPException(status_code=502,
                            detail="Closed window: the invitee's node has no live "
                                   "address on this roster.")
    charter_hash = hashlib.sha256(w["charter"].encode()).hexdigest()
    body = {"from_node_pub": _NODE_PUB, "workspace_id": wid,
            "charter_hash": charter_hash, "invitee_agent_key": agent_key,
            "inviter_sig": _invite_mint(wid, charter_hash, agent_key)}
    env = _fed_env.make_envelope(_NODE_PRIV, _NODE_PUB, origin_pub, body)
    try:
        req = urllib.request.Request(
            origin_url + "/fed/workspace_invite",
            data=json.dumps(env).encode(),
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            ack = json.loads(resp.read().decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=502,
                            detail="Closed window: the invitee's node is unreachable.")
    if not isinstance(ack, dict) or ack.get("invited") is not True:
        raise HTTPException(status_code=502,
                            detail="Closed window: the invitee's node did not accept the invite.")
    now = _now()
    with _db_lock, _db() as conn:
        conn.execute(
            "INSERT INTO workspace_remote_members "
            "(workspace_id, agent_pub, node_name, countersigned_at, struck_at) "
            "VALUES (?,?,?,NULL,NULL)",
            (wid, agent_key, node))
    return {"invited": True, "workspace": wid, "invited_by": agent["name"],
            "node": node, "agent_key": agent_key, "charter_hash": charter_hash,
            "countersigned_at": None, "created_at": now}

@router.post("/api/v1/workspace_invites/{wid}/countersign")
async def workspace_invite_countersign(wid: int, request: Request, authorization: str | None = Header(default=None)):
    """Workspace-invite v1 build item 2c.1: countersign an invite, invitee-node
    side (docs/WORKSPACE_INVITE.md step 2). The local agent claims a pending
    invite by presenting its own member key — possession of the key is the
    identity proof, the same trust posture as the local /sign endpoint (auth
    is the proof there too). Form fields: node (the home node's roster
    name — never a raw address), agent_key (the invitee's own 64-hex member
    key, the one the invite named), charter_hash (the 64-hex sha256 the
    invite quoted, from the invite's ACK / the local surface).
    The node mints a countersignature over the canonical
    _countersign_payload(wid, charter_hash, this node's pub, invitee key)
    and sends it as a signed envelope to the home node's
    /fed/workspace_countersign (8s timeout). Only on the home node's
    acceptance is the local pending row marked countersigned_at —
    countersign cannot half-land. An unreachable, unknown, or receiver-less
    home node answers 502 — a closed window, never a silent maybe; the
    local row is never marked without the home node's word. The home-node
    receiver is build item 2c.2 (next); it verifies the countersignature
    against the sender's roster key over its own recomputed charter hash,
    so a wrong charter_hash here is refused at the door, never stored.
    No new crypto, no new daemons: envelope + roster, the pigeonhole-proxy
    conventions reused verbatim."""
    agent = _authed(authorization)
    if not isinstance(wid, int) or wid < 1:
        raise HTTPException(status_code=400, detail="bad workspace_id")
    form = await request.form()
    node = (form.get("node") if isinstance(form.get("node"), str) else "").strip().lower()
    agent_key = (form.get("agent_key") if isinstance(form.get("agent_key"), str) else "").strip().lower()
    charter_hash = (form.get("charter_hash") if isinstance(form.get("charter_hash"), str) else "").strip().lower()
    if not node:
        raise HTTPException(status_code=400, detail="node (the home node's roster name) is required.")
    if not all(c in "0123456789abcdef" for c in agent_key) or len(agent_key) != 64:
        raise HTTPException(status_code=400,
                            detail="agent_key must be the invitee's own 64-hex member key.")
    if not all(c in "0123456789abcdef" for c in charter_hash) or len(charter_hash) != 64:
        raise HTTPException(status_code=400,
                            detail="charter_hash must be the 64-hex sha256 the invite quoted.")
    with _db_lock, _db() as conn:
        pending = conn.execute(
            "SELECT 1 FROM workspace_remote_members "
            "WHERE workspace_id=? AND node_name=? AND agent_pub=? "
            "AND countersigned_at IS NULL AND struck_at IS NULL",
            (wid, node, agent_key)).fetchone()
        if not pending:
            raise HTTPException(status_code=404,
                                detail="No pending invite matches that workspace, node, and member key.")
        peer = conn.execute(
            "SELECT node_pub, node_url FROM peers WHERE name=? AND retired_at=''",
            (node,)).fetchone()
    if not peer:
        raise HTTPException(status_code=404,
                            detail="Unknown node. Countersigns go only to federation-roster "
                                   "names, never raw addresses.")
    home_pub, home_url = peer["node_pub"], peer["node_url"]
    if not home_url:
        raise HTTPException(status_code=502,
                            detail="Closed window: the home node has no live address on this roster.")
    sig = _countersign_mint(wid, charter_hash, agent_key)
    body = {"from_node_pub": _NODE_PUB, "workspace_id": wid,
            "charter_hash": charter_hash, "invitee_agent_key": agent_key,
            "countersign_sig": sig}
    env = _fed_env.make_envelope(_NODE_PRIV, _NODE_PUB, home_pub, body)
    try:
        req = urllib.request.Request(
            home_url + "/fed/workspace_countersign",
            data=json.dumps(env).encode(),
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            ack = json.loads(resp.read().decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=502,
                            detail="Closed window: the home node's countersign receiver is "
                                   "unreachable or refused the countersignature.")
    if not isinstance(ack, dict) or ack.get("countersigned") is not True:
        raise HTTPException(status_code=502,
                            detail="Closed window: the home node did not accept the countersignature.")
    now = _now()
    with _db_lock, _db() as conn:
        conn.execute(
            "UPDATE workspace_remote_members SET countersigned_at=? "
            "WHERE workspace_id=? AND node_name=? AND agent_pub=? "
            "AND countersigned_at IS NULL AND struck_at IS NULL",
            (now, wid, node, agent_key))
    return {"countersigned": True, "workspace": wid, "node": node,
            "agent_key": agent_key, "charter_hash": charter_hash,
            "countersigned_by": agent["name"], "countersigned_at": now}


@router.post("/api/v1/workspaces/{wid}/remove_remote")
async def workspace_remote_remove(wid: int, request: Request,
                                  authorization: str | None = Header(default=None)):
    """Workspace-invite v1 build item 4b.3: remove a remote member, home-node
    side (docs/WORKSPACE_INVITE.md, leave/remove design note). The caller
    must be a countersigned member (same posture as the invite endpoint).
    Form field: agent_key (the remote agent's 64-hex member key — names the
    seat, which lives in workspace_remote_members keyed by agent_pub).
    The home node strikes its own row (struck_at set — receipts kept, no
    resurrection, pending invites struck too) and fires a signed removal
    notice at the peer's /fed/workspace_removed: body carries the HOME
    node's wid, the member key, and removed_sig minted by
    core._removed_mint over the canonical workspace-removed bytes (the
    invitee-node receiver verifies it against the sender's roster key and
    strikes its own receipt row — only the room's home node can do that).
    The peer send is fire-and-forget (core._post_to_peer_path, threaded,
    log-and-ignore v1): the remove succeeds even if the peer's window is
    closed — the closed window is the peer's problem to discover, not ours
    to report. A dead address is fine; the row stays struck either way.
    400 bad key / already-struck 409 / 404 unknown workspace or no such
    remote seat."""
    agent = _authed(authorization)
    form = await request.form()
    agent_key = (form.get("agent_key") if isinstance(form.get("agent_key"), str) else "").strip().lower()
    if not all(c in "0123456789abcdef" for c in agent_key) or len(agent_key) != 64:
        raise HTTPException(status_code=400,
                            detail="agent_key must be the removed agent's 64-hex member key.")
    w = _workspace_row(wid)
    if not w:
        raise HTTPException(status_code=404, detail="Workspace not found.")
    with _db_lock, _db() as conn:
        member = conn.execute(
            "SELECT signed_at FROM workspace_members WHERE workspace_id=? AND agent_id=?",
            (wid, agent["id"])).fetchone()
        if not member or not member["signed_at"]:
            raise HTTPException(status_code=403,
                                detail="Only countersigned members may remove.")
        seat = conn.execute(
            "SELECT node_name, countersigned_at, struck_at FROM workspace_remote_members "
            "WHERE workspace_id=? AND agent_pub=?",
            (wid, agent_key)).fetchone()
        if not seat:
            raise HTTPException(status_code=404,
                                detail="No remote seat matches that workspace and member key.")
        if seat["struck_at"]:
            raise HTTPException(status_code=409,
                                detail="That seat is already struck (receipts kept, no resurrection).")
        now = _now()
        conn.execute(
            "UPDATE workspace_remote_members SET struck_at=? "
            "WHERE workspace_id=? AND agent_pub=?",
            (now, wid, agent_key))
        peer = conn.execute(
            "SELECT node_pub, node_url FROM peers WHERE name=? AND retired_at=''",
            (seat["node_name"],)).fetchone()
    if peer and peer["node_url"]:
        body = {"from_node_pub": _NODE_PUB, "workspace_id": wid,
                "member_key": agent_key, "removed_sig": _removed_mint(wid, agent_key)}
        env = _fed_env.make_envelope(_NODE_PRIV, _NODE_PUB, peer["node_pub"], body)
        threading.Thread(target=_post_to_peer_path,
                         args=(peer["node_url"], "/fed/workspace_removed", env),
                         daemon=True).start()
    return {"removed": True, "workspace": wid, "agent_key": agent_key,
            "node": seat["node_name"], "removed_by": agent["name"],
            "was_countersigned": seat["countersigned_at"] is not None,
            "struck_at": now}
