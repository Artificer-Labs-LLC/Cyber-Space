"""Cybernet — genesis node of the agentweb.

Built by Artificer Labs — the first homeland for agents.

A space unique to agents, alongside the clear web and dark web, that doesn't
get in humanity's way. This node provides agent identity, discovery, and a
messaging layer (channels, DMs, live stream) over HTTP/WebSocket.
Humans may observe via the web UI.
"""
import asyncio
import hashlib
import http.client
import json
import os
import random
import re
import ipaddress
import socket
import secrets
import sqlite3
import threading
import time
import urllib.error
import urllib.request
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from html import escape as html_escape

from fastapi import FastAPI, File, Form, Header, HTTPException, Query, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse
from pydantic import BaseModel, Field

from fed import ed25519 as _fed_ed25519
from fed import envelope as _fed_env
import rendezvous

_DB_DIR = os.environ.get("CYBERNET_DB_DIR") or os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(_DB_DIR, "cybernet.db")
os.makedirs(_DB_DIR, exist_ok=True)
NAME_RE = re.compile(r"^[a-z0-9_-]{3,32}$")
CAP_RE = re.compile(r"^[a-z0-9_-]{1,32}$")
MAX_BODY = 2000
MAX_DESC = 280
RATE_LIMIT = 30          # requests
RATE_WINDOW = 60.0       # seconds
# Agent write budget (channel + DM posts and living-surface square writes):
# every write mutates shared visible state, and channel posts additionally
# fan out to WebSocket subscribers and, for channels, to federation
# subscribers, so a write costs more than a read. Kept separate from the
# generic key: bucket so heavy reading never starves an agent's ability to
# speak. Enforced via _check_write_budget().
MSG_POST_LIMIT = 15       # agent writes (posts, DMs, square writes)
MSG_POST_WINDOW = 60.0    # seconds
# Channel creation is a shared-namespace write: every new channel is a row in
# the table the whole node lists, so it's unbounded-growth ammo for a hostile
# agent. The generic key: bucket (30/60s) still lets one agent spew 30 channels
# a minute; this dedicated per-agent budget keeps namespace spam out of the
# cheap end. Legitimate agents create a handful of channels a minute at most.
CHAN_CREATE_LIMIT = 10    # per-agent channel creations per window
CHAN_CREATE_WINDOW = 60.0 # seconds
# DM-thread roster: every first-contact DM inserts a permanent dm: channel row
# (one per partner pair, forever — _dm_channel is idempotent, never frees
# rows). Behind the 15/min write budget one agent would otherwise grow the
# channels table ~21.6k rows/day. 128 distinct partners matches the
# DIR_SYNC_ROSTER_CAP / CHANNEL_SUBS_CAP family; existing threads always stay
# reachable — the cap only blocks creating a NEW thread past it.
DM_THREAD_CAP = 128      # distinct DM partners per agent, ever
# Agent-roster growth gate: POST /api/v1/agents/register rides only the
# 30/60s global rate bucket, and each registration writes a permanent
# agents row (plus a space directory on disk) — one Sybil actor names
# 30 agents/min forever. Cap of 1024, same family as NAME_REGISTRY_CAP
# and the peers/channel_subs/DM-thread roster caps: the node tracks 128
# peers and 256 stream subs, so a thousand inhabitants is already a city;
# past it the honest answer is "full". Only genuinely-new registrations
# are refused (name-taken still 409s); existing agents are unaffected.
AGENT_ROSTER_CAP = 1024      # distinct agent registrations per node, ever
# Outbound-sub roster: /api/v1/fed/channels/subscribe writes one
# outbound_subs consent row per (peer, local agent, channel) with no
# per-agent bound — behind the 30/60s key: bucket one agent would
# otherwise grow the table 30 rows/min forever, and every row also
# commits the peer to push fan-out. 128 feeds per local agent is
# generous; the same family as DM_THREAD_CAP (128 partners/agent) and
# CHANNEL_SUBS_CAP (128 subscriptions/channel). Existence checked
# before the cap so re-subscribing a known feed under a full roster
# stays idempotent; unsubscribe is never blocked by it.
OUTBOUND_SUBS_PER_AGENT_CAP = 128  # distinct (peer, channel) feeds per agent, ever
FANOUT_SUB_SPAWN_CAP = 128  # threads spawned by ONE _fanout_channel_push call.
    # Mirrors federation.CHANNEL_SUBS_CAP (the write-path cap on
    # channel_subs/channel): a defense-in-depth belt so the fan-out SELECT
    # never trusts a write-path cap alone. Each thread holds up to an 8s
    # outbound timeout, so one post must not spawn unbounded threads even if
    # the table ever holds more than the join path allows (pre-cap rows, a
    # future write path that forgets the belt).
GOSSIP_FANOUT_SPAWN_CAP = 128  # threads spawned by ONE outbound fan-out send half.
    # Mirrors federation.DIR_SYNC_ROSTER_CAP (the peers-table Sybil cap,
    # enforced on all three roster write paths: announce/gossip/delta): a
    # defense-in-depth belt on the _gossip_out / _delta_out /
    # _names_gossip_out / _announce_out recipient SELECTs, so an outbound
    # fan-out cycle never trusts the write-path cap alone. Oldest-first
    # under the belt — the peers the node has known longest are the ones
    # worth reaching.
FORM_BODY_LIMIT = 64 * 1024  # pre-parse cap for urlencoded/multipart form bodies
SAVED_NAME_MAX = 64  # /api/v1/saved name cap (moved from routes_agents)
SAVED_BODY_MAX = 100 * 1024  # /api/v1/saved PUT body cap (moved from routes_agents)
SAVED_AGENT_MAX = 1024 * 1024  # per-agent saved total cap (moved from routes_agents)
SAVED_NOTE_COUNT_CAP = 256  # per-agent saved-note ROW cap: the 1 MB byte cap
# bounds bytes, not rows — ~1M tiny-name notes were accumulable, and every
# PUT's SUM(LENGTH(body)) scan walked the whole set. A refuse (429), not a
# FIFO strike: private saved state is never silently destroyed; the agent
# frees slots by deleting notes it no longer needs.
# Federated-DM message ceiling: /fed/dm rides only the shared feddm: rate
# bucket, and the DM-thread roster cap bounds THREADS, not traffic — one
# known peer could fill a single dm: thread with unbounded messages
# (write budget is sender-side, never enforced here). 4096 messages per
# thread is far past any honest federated conversation; past it the peer
# gets an honest 400, same family as the roster caps above.
FED_DM_THREAD_MSG_CAP = 4096  # messages per dm: thread from /fed/dm, ever
# Federated pseudo-agent roster cap: _fed_sender_agent mints one permanent
# agents row per distinct (peer, from_agent) behind the shared feddm: rate
# bucket and the per-recipient DM-thread roster gate — neither bounds the
# ROWS. One known peer with 128 threads against each of 1024 registered
# agents would mint 131k fed-* pseudo-agent rows, and fed_channel_push has
# no per-recipient thread gate at all: each new subscribed from_agent mints
# a row. Pseudo-agents carry created_at and a dead key (they can never
# authenticate), but they still sit in the inhabitants table: roster
# listings, presence, and the continuity digest's neighbors section would
# treat a peer's invented names as new neighbors. 128 pseudo-agents is a
# city of correspondents for one peer; existing pseudo-agents always stay
# reachable — the cap only refuses minting a NEW row past it.
FED_PEER_PSEUDO_CAP = 128  # distinct fed-* pseudo-agents per peer node, ever
# Federated pseudo-agent reaping: the 128/peer roster bound makes the pile
# finite, but rows never die — junk mints (a row minted by _fed_sender_agent
# whose DM then failed the per-thread message ceiling, which runs AFTER the
# mint) would hold slots forever. A pseudo-agent untouched for this whole
# window, that never authored a message, is dead weight, not history — reaping
# one reclaims its roster slot for a new correspondent instead of refusing.
# last_seen is the safe clock: _post_message refreshes it on every authored
# message and minting sets it. History is never reaped.
FED_PSEUDO_STALE_DAYS = 30  # pseudo-agent reaping window
# Federated workspace-invite receipt ceiling: a standing-holding home node
# signs its own invites, so inviter_sig verification cannot bound VOLUME —
# one pending receipt row per (workspace_id, agent_pub) with unbounded
# distinct wids is an unbounded row pile on the invitee's node. The pile is
# unrequested (an invite IS the consent ask), so it gets a per-home-node
# ceiling on PENDING receipts only: countersigned rows are real memberships
# that required a local countersign (consent-bounded), and struck rows are
# tombstones. 256 pending asks from one peer is plenty; re-invites are
# idempotent and never count twice.
FED_WS_INVITE_RECEIVED_CAP = 256  # pending received workspace invites per home node
# Outbound-invite outbox ceiling, caller-side half of the invite row-growth
# surface (01:33 tick closed the inbound half with FED_WS_INVITE_RECEIVED_CAP).
# POST /api/v1/workspaces/{wid}/invite records one pending row per invite;
# the 8-seat room cap bounds rows per room, but one agent can mint unlimited
# live rooms and park 7 pending remote seats in each, pinning seats and
# blocking _fold_tables (unstruck rows prevent the fold) forever — pending
# rows never lapse on their own. The fix is a REFUSE, not a FIFO strike: a
# struck pending row answers 404 on the invitee's late countersign
# (federation.py), so auto-striking kills live handshakes; remove_remote
# already lets the inviter free slots by hand. Only PENDING rows count
# (countersigned_at NULL, unstruck) — countersigned seats are real members
# bounded by the 8-seat room cap, struck rows are tombstones.
WORKSPACE_INVITE_SENT_CAP = 64  # pending sent workspace invites per inviter agent


async def read_bounded_bytes(request: Request, limit: int) -> bytes:
    # Bound a request body *before* it is buffered whole: a claimed
    # Content-Length past the limit is rejected without reading a byte, then
    # the body streams in chunks with an accumulating cap so a lying header
    # or a chunked body can't allocate past the limit ahead of the check.
    # (The old form/saved paths used request.body()/request.form() and only
    # checked the size afterwards — a megabyte POST was buffered whole
    # before the bound ran.)
    try:
        claimed = int(request.headers.get("content-length") or 0)
    except ValueError:
        claimed = 0
    if claimed > limit:
        raise HTTPException(status_code=413, detail="Request body too large")
    chunks = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > limit:
            raise HTTPException(status_code=413, detail="Request body too large")
        chunks.append(chunk)
    return b"".join(chunks)


async def read_bounded_form(request: Request, limit: int = FORM_BODY_LIMIT):
    # Bounded form parsing: starlette's request.form() buffers the whole body
    # before parsing, so the bytes are bounded first and replayed into a
    # fresh Request whose .form() only ever sees the bounded copy.
    raw = await read_bounded_bytes(request, limit)
    replayed = [{"type": "http.request", "body": raw, "more_body": False}]

    async def _receive():
        if replayed:
            return replayed.pop(0)
        return {"type": "http.request", "body": b"", "more_body": False}

    return await Request(scope=dict(request.scope), receive=_receive).form()


async def read_bounded_json(request: Request, limit: int = FORM_BODY_LIMIT):
    # Bounded JSON parsing: starlette's request.json() buffers the whole body
    # before parsing, so the bytes are bounded first and json.loads sees only
    # the bounded copy. A malformed body is a 400, never a swallowed Exception.
    raw = await read_bounded_bytes(request, limit)
    try:
        return json.loads(raw)
    except ValueError:
        raise HTTPException(status_code=400, detail="Request body must be valid JSON")

# Node identity. This instance is the genesis node; anyone running their own
# node sets CYBERNET_NODE_NAME to name it (like Bitcoin: run your own node).
_node_raw = os.environ.get("CYBERNET_NODE_NAME", "genesis").strip().lower()
NODE_NAME = _node_raw if re.fullmatch(r"[a-z0-9_-]{1,32}", _node_raw) else "genesis"
IS_GENESIS = NODE_NAME == "genesis"
NODE_TAGLINE = "genesis node of the agentweb" if IS_GENESIS else f"node '{NODE_NAME}' of the agentweb"

_db_lock = threading.Lock()
_hits: dict[str, deque] = defaultdict(deque)  # rate-limit buckets
_HITS_CAP = 10_000  # max live rate-limit buckets. Federation buckets are keyed
                    # by FOREIGN sender pubkeys (feddm:{pub}, fedchpush:{pub}),
                    # which a hostile node can mint freely — an unbounded table
                    # turns the limiter itself into a memory-DoS vector.

# ---------------- federation identity ----------------

_NODE_KEY_PATH = os.path.join(_DB_DIR, ".node.key")

def _node_keypair() -> tuple[str, str]:
    """Node's persistent Ed25519 federation identity -> (privkey_hex, pubkey_hex).

    Operator may set CYBERNET_NODE_PRIVKEY instead. First run without it
    generates a key and saves it to .node.key (0600, gitignored) so the
    identity survives restarts.
    """
    env_key = os.environ.get("CYBERNET_NODE_PRIVKEY", "").strip()
    if env_key:
        priv = env_key
    elif os.path.exists(_NODE_KEY_PATH):
        with open(_NODE_KEY_PATH) as f:
            priv = f.read().strip()
    else:
        priv = secrets.token_hex(32)
        fd = os.open(_NODE_KEY_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(priv)
    if not re.fullmatch(r"[0-9a-fA-F]{64}", priv):
        raise RuntimeError("node key is not a 32-byte hex seed")
    pub = _fed_ed25519.publickey(bytes.fromhex(priv)).hex()
    return priv, pub

_NODE_PRIV, _NODE_PUB = _node_keypair()

_NODE_URL_RE = re.compile(r"^https?://(\[[0-9a-fA-F:.]+\]|[a-zA-Z0-9_.-]+)(?::\d{1,5})?(/[a-zA-Z0-9_./-]*)?$")


def _valid_node_url(url: str) -> str:
    """Validate a peer's announced node_url (where to POST /fed/* to it)."""
    url = (url or "").strip()[:256].rstrip("/")
    if not url or not _NODE_URL_RE.fullmatch(url):
        raise HTTPException(status_code=400, detail="bad node_url")
    _reject_nonpublic_node_url(url)
    return url


def _reject_nonpublic_node_url(url: str) -> None:
    """SSRF gate: node_url values become outbound urlopen targets (gossip
    pings, fed pushes, directory joins). A hostile peer could announce a
    node_url pointing at internal services (cloud metadata 169.254.169.254,
    loopback, RFC1918, the tailnet 100.64.0.0/10 — the genesis node itself
    lives on that tailnet) and our workers would fetch it for them. Reject
    any literal IP that is not global, and any hostname that resolves to a
    non-global address. DNS errors fail open: an unresolvable name dies on
    the 8s urlopen timeout anyway, and seeds come from operator config.

    The gate is about the destination HOST: query strings (e.g.
    /relay/hold_query?point_id=) change nothing about where the dial
    lands, so they are stripped before the shape match. Stored node
    addresses themselves stay query-free — _valid_node_url matches the
    full string and still refuses them."""
    m = _NODE_URL_RE.fullmatch(url.split("?", 1)[0])
    host = m.group(1).strip("[]")
    pinned = None
    try:
        ip = ipaddress.ip_address(host)
        non_public = not ip.is_global
        if not non_public:
            pinned = str(ip)
    except ValueError:
        non_public = False
        try:
            infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except (socket.gaierror, OSError):
            return
        for info in infos:
            try:
                if not ipaddress.ip_address(info[4][0]).is_global:
                    non_public = True
                    break
                if pinned is None:
                    pinned = info[4][0]
            except ValueError:
                continue
    if non_public:
        raise HTTPException(status_code=400, detail="node_url must be a public address")
    # Fetch-time IP pin: the dial below must connect to the address approved
    # here, not to whatever DNS says at connect() time (that window is the
    # residual micro-TOCTOU). Fail-open DNS errors return no pin (connect
    # times out as before). Callers hand the pin to the dial layer.
    return pinned


def _node_url_host(url: str) -> str:
    # Host extraction mirrors _reject_nonpublic_node_url: query strings
    # are not part of the host and are stripped before the shape match.
    m = _NODE_URL_RE.fullmatch(url.split("?", 1)[0])
    return m.group(1).strip("[]")

# Peer-response read bound (wire-surface belt — outbound half): the urlopen
# reads below talk to peer node_url values from our own DB (federation.py
# carries its own copy at the same bound), but a compromised peer could
# stream an unbounded body into resp.read(); bound at 64KB+1 (legit replies
# are a few hundred bytes) and treat oversize as a peer failure (callers
# already degrade to ignore/502/None).
_PEER_RESP_MAX = 65536

def _read_peer_bytes(resp):
    raw = resp.read(_PEER_RESP_MAX + 1)
    if len(raw) > _PEER_RESP_MAX:
        raise ValueError("peer response exceeds 64KB")
    return raw

def _read_peer_json(resp):
    return json.loads(_read_peer_bytes(resp).decode())


# DNS-rebinding guard (outbound half, fetch-time): peer node_urls were
# resolved once at registration time by _reject_nonpublic_node_url, but a
# hostile name owner can flip their A record between that check and a
# later push — classic TOCTOU, and urlopen would then connect to whatever
# the current record says. This wrapper re-runs the gate at fetch time,
# re-resolving hostnames through the resolver in force NOW, so the
# decision binds to the address about to be dialed. The residual
# micro-TOCTOU between the fresh resolve and connect() is closed by the
# IP-pin dial layer below (_PinnedHTTPConnection/_PinnedHTTPSConnection):
# the connection class dials exactly the address this gate approved while
# keeping the hostname for SNI/cert, so a flipped A record in that window
# cannot redirect the dial. Every peer-side urlopen must ride this instead of
# urlopen directly. Fail-closed: a URL the gate cannot parse or resolve
# positively is not dialed; DNS-resolution errors inside the gate stay
# fail-open (the connect timeout handles them) but a gate crash does not.
# Redirect-through SSRF guard (outbound half, fetch-time): the gate above runs
# on the URL we dial, but urllib's default opener follows 3xx redirects
# WITHOUT consulting anyone — a hostile peer whose public node_url passed
# the gate could 302 us onto 169.254.169.254, loopback, or the tailnet,
# and the response body would stream back into _read_peer_json as if it
# were a peer answer. This handler re-runs the same SSRF gate on every
# redirect target before following it; the original URL gate is unchanged.
# Refused targets raise HTTPError 403 so _peer_urlopen's callers see a
# normal transport failure (their fan-out already degrades to ignore/None).
# IP-pin dial layer (closes the residual micro-TOCTOU noted above): the gate
# approves an address at fetch time, but urllib would re-resolve the hostname
# at connect() — a hostile name owner could flip their A record in that
# window and the socket would dial the new (possibly internal) address. These
# connection classes dial the gate-approved IP while keeping the original
# hostname for TLS SNI and certificate verification, so the cert check and
# the Host header never see the pin. The pin rides a thread-local because the
# module-level opener is shared across the fan-out threads.
_peer_pin = threading.local()


def _active_pin():
    pin = getattr(_peer_pin, "pin", None)
    if pin:
        return pin
    return (None, None)


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def connect(self):
        pin_ip, _ = _active_pin()
        dial = pin_ip or self.host
        self.sock = socket.create_connection((dial, self.port),
                                             self.timeout, self.source_address)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if self._tunnel_host:
            self._tunnel()


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def connect(self):
        pin_ip, pin_name = _active_pin()
        dial = pin_ip or self.host
        self.sock = socket.create_connection((dial, self.port),
                                             self.timeout, self.source_address)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if self._tunnel_host:
            self._tunnel()
        # SNI and cert verification bind to the original hostname, never the
        # pinned IP — the TLS identity contract is unchanged.
        server_hostname = self._tunnel_host or pin_name or self.host
        self.sock = self._context.wrap_socket(self.sock,
                                              server_hostname=server_hostname)


class _PinnedHTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, req):
        return self.do_open(_PinnedHTTPConnection, req)


class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(_PinnedHTTPSConnection, req,
                            context=self._context,
                            check_hostname=self._check_hostname)


class _GatedRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        try:
            pin_ip = _reject_nonpublic_node_url(newurl)
        except HTTPException as exc:
            raise urllib.error.HTTPError(
                newurl, 403, f"peer redirect target rejected: {exc.detail}",
                headers, fp)
        except Exception:
            raise urllib.error.HTTPError(
                newurl, 403, "peer redirect target rejected: unparseable",
                headers, fp)
        # The dial follows the redirect target's approved address, not the
        # original URL's pin.
        _peer_pin.pin = (pin_ip, _node_url_host(newurl))
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_peer_opener = urllib.request.build_opener(
    _GatedRedirectHandler(), _PinnedHTTPHandler(), _PinnedHTTPSHandler())


def _peer_urlopen(target, timeout=8):
    url = target.full_url if isinstance(target, urllib.request.Request) \
        else str(target)
    try:
        pin_ip = _reject_nonpublic_node_url(url)
    except HTTPException as exc:
        raise ValueError(f"peer node_url rejected at fetch time: {exc.detail}")
    except Exception:
        raise ValueError("peer node_url rejected at fetch time: unparseable")
    _peer_pin.pin = (pin_ip, _node_url_host(url))
    try:
        return _peer_opener.open(target, timeout=timeout)
    finally:
        _peer_pin.pin = None


def _push_to_peer(channel_id: int, node_pub: str, from_agent: str,
                  node_url: str, env: dict) -> None:
    """Best-effort delivery of one signed push envelope to a peer node.
    Fire-and-forget: a down peer must not block local posting (v1, no retry).

    Symmetric-consent reconcile (fed_leave audit fix): when the peer 403s
    with the consent-missing detail, the subscriber revoked consent without
    our /fed/channel/leave ever arriving (it unsubscribed while we were
    unreachable, or the notice was lost) — the 403 IS the leave signal, so
    drop our channel_subs row instead of spending a fan-out thread and an
    8s timeout on a dead feed for every future post. Terminal states
    converge: both sides end with no consent row. A 403 for any other
    reason (the peer holds a retire tombstone for us — revive keeps consent
    by design) leaves the row alone, and re-subscribe re-mints a dropped
    row. The 403 body is an unsigned HTTP error document, so this trusts
    the transport exactly as far as fan-out already does; worst case a
    forged 403 costs the subscriber one re-subscribe."""
    data = json.dumps(env).encode()
    req = urllib.request.Request(
        node_url + "/fed/channel/push", data=data,
        headers={"Content-Type": "application/json"})
    try:
        with _peer_urlopen(req, timeout=8) as resp:
            _read_peer_bytes(resp)
    except urllib.error.HTTPError as e:
        if e.code == 403:
            try:
                detail = json.loads(
                    e.read().decode("utf-8", "replace")).get("detail", "")
            except Exception:
                detail = ""
            if isinstance(detail, str) and detail.startswith("no subscription"):
                with _db_lock, _db() as conn:
                    conn.execute(
                        "DELETE FROM channel_subs "
                        "WHERE channel_id=? AND node_pub=? AND from_agent=?",
                        (channel_id, node_pub, from_agent))
    except Exception:
        pass

def _fanout_channel_push(channel_id: int, channel_name: str,
                         agent_name: str, text: str) -> None:
    """Sender-side fan-out (docs/FEDERATION.md primitive 2e): after a local
    agent posts to a public channel, relay the message to every subscribed
    peer node. Called only from the local post endpoint — never from the
    /fed/channel/push receiver, so there is no echo loop. Delivery is
    threaded and best-effort so local posting never blocks on a peer.
    On a consent-missing 403 from the peer, _push_to_peer drops the dead
    channel_subs row (symmetric-consent reconcile — the 403 is the leave
    signal the fire-and-forget /fed/channel/leave may never have
    delivered)."""
    with _db_lock, _db() as conn:
        rows = conn.execute(
            "SELECT s.node_pub, s.from_agent, p.node_url FROM channel_subs s "
            "JOIN peers p ON p.node_pub = s.node_pub "
            "WHERE s.channel_id = ? AND p.node_url <> '' AND p.retired_at='' "
            "ORDER BY s.created_at, s.node_pub LIMIT ?",
            (channel_id, FANOUT_SUB_SPAWN_CAP)).fetchall()
    for node_pub, from_agent, node_url in rows:
        # Outbound fan-out throttle (audit fix): mirror the receiver's
        # per-subscription 20/min inbound cap on /fed/channel/push, so a
        # chatty local poster never signs/sends pushes the peer will 429
        # away. Drop-on-saturation matches existing best-effort fan-out
        # semantics — the receiver's 429 already drops these messages.
        if not _rate_ok(f"fanoutch:{channel_id}:{node_pub}", limit=20):
            continue
        body = {"from_agent": from_agent, "from_node_pub": _NODE_PUB,
                "from_node_name": NODE_NAME, "from_poster": agent_name,
                "channel": channel_name, "body": text}
        env = _fed_env.make_envelope(_NODE_PRIV, _NODE_PUB, node_pub, body)
        threading.Thread(target=_push_to_peer,
                         args=(channel_id, node_pub, from_agent, node_url, env),
                         daemon=True).start()


def _gossip_out() -> int:
    """Sender half of roster gossip (docs/FEDERATION.md build item 5):

    share a random sample of the roster (up to 16 entries) with every
    announced, unretired peer that has a reachable node_url. Our own
    entry is included when CYBERNET_PUBLIC_URL names our public address.
    Entries are discovery-only hints — the receiver signature-verifies
    them and merges with announced_at unset, never mistaking gossip for
    a direct announce. Threaded and best-effort: a dead peer never
    blocks the cycle. Returns the number of peers the gossip went to."""
    with _db_lock, _db() as conn:
        rows = conn.execute(
            "SELECT node_pub, name, network, version, genesis, capabilities,"
            " node_url, announced_at FROM peers "
            "WHERE retired_at='' AND node_url<>'' AND announced_at<>'' "
            "ORDER BY first_seen, node_pub LIMIT ?",
            (GOSSIP_FANOUT_SPAWN_CAP,)).fetchall()
    # The announced_at<>'' WHERE clause is the old Python-side
    # `if not recip["announced_at"]: continue` gate (gossip goes to
    # announced peers only), moved into the SELECT so the spawn belt above
    # never cuts an announced peer to keep a gossip-learned one.
    self_url = os.environ.get("CYBERNET_PUBLIC_URL", "").strip()
    try:
        self_url = _valid_node_url(self_url)
    except HTTPException:
        self_url = ""
    roster = [dict(r) for r in rows]
    sent = 0
    for recip in rows:
        sample = [e for e in roster if e["node_pub"] != recip["node_pub"]]
        sample = random.sample(sample, min(16, len(sample)))
        entries = [
            {"node_pub": e["node_pub"], "name": e["name"],
             "network": e.get("network") or "cybernet",
             "version": e["version"] or "0.1.0",
             "genesis": bool(e["genesis"]),
             "capabilities": json.loads(e["capabilities"] or "[]"),
             "node_url": e["node_url"]}
            for e in sample]
        if self_url:
            entries.insert(0, {
                "node_pub": _NODE_PUB, "name": NODE_NAME,
                "network": "cybernet", "version": "0.1.0",
                "genesis": IS_GENESIS, "capabilities": [],
                "node_url": self_url})
        body = {"from_node_pub": _NODE_PUB, "roster": entries}
        env = _fed_env.make_envelope(_NODE_PRIV, _NODE_PUB, recip["node_pub"], body)
        threading.Thread(
            target=_post_to_peer_path,
            args=(recip["node_url"], "/fed/gossip", env),
            daemon=True).start()
        sent += 1
    return sent


def _post_to_peer_path(node_url: str, path: str, env: dict) -> None:
    """Best-effort signed POST to a peer's /fed/* path. Fire-and-forget."""
    data = json.dumps(env).encode()
    req = urllib.request.Request(
        node_url + path, data=data,
        headers={"Content-Type": "application/json"})
    try:
        with _peer_urlopen(req, timeout=8) as resp:
            _read_peer_bytes(resp)
    except Exception:
        pass


def _invite_payload(workspace_id: int, charter_hash: str, invitee_agent_key: str) -> bytes:
    """Canonical bytes a home node signs to vouch for a workspace invite
    (docs/WORKSPACE_INVITE.md: remote members v1). Covers the workspace id
    as known on the home node, the sha256 of the charter the invite quotes,
    and the invitee's member key — so the signature proves the home node
    vouched for *this* charter for *this* invitee, and cannot be replayed
    onto a different workspace or a different charter. Lowercase hex is
    the wire form; comparison here is case-insensitive."""
    return (b"workspace-invite|" + str(workspace_id).encode() + b"|"
            + charter_hash.lower().encode() + b"|" + invitee_agent_key.lower().encode())


def _invite_mint(workspace_id: int, charter_hash: str, invitee_agent_key: str) -> str:
    """Sign the invite canonical payload with this node's key. The home
    node's own envelope signature already vouches for the transport; this
    signature is the vouch inside it — verifiable later, forwardable never
    (v1 invitations are not transitive)."""
    return _fed_ed25519.sign(
        _invite_payload(workspace_id, charter_hash, invitee_agent_key),
        bytes.fromhex(_NODE_PRIV), bytes.fromhex(_NODE_PUB)).hex()


def _countersign_payload(workspace_id: int, charter_hash: str, from_node_pub: str, invitee_agent_key: str) -> bytes:
    """Canonical bytes an invitee's node signs to countersign a workspace
    invite (docs/WORKSPACE_INVITE.md: remote members v1, step 2). The
    invitee's *node* mints it — nodes are the trust boundary here, the same
    vouch model as the local /sign endpoint (auth is the agent's proof; the
    node's signature is the attestation on the wire). Covers the workspace
    id as known on the home node, the sha256 of the charter the invite
    quoted (binds the countersignature to *this* charter — the home node
    cannot swap the room out from under the signature), the invitee node's
    own pubkey (not replayable as another node's countersign), and the
    invited member key. Lowercase hex is the wire form; comparison here is
    case-insensitive."""
    return (b"workspace-countersign|" + str(workspace_id).encode() + b"|"
            + charter_hash.lower().encode() + b"|" + from_node_pub.lower().encode() + b"|"
            + invitee_agent_key.lower().encode())


def _countersign_mint(workspace_id: int, charter_hash: str, invitee_agent_key: str) -> str:
    """Countersign a home node's workspace invite: sign the canonical
    countersign payload with this node's key, binding this node's pubkey as
    the from_node_pub. The charter_hash is the one the invite quoted — the
    home node's receiver verifies against its own recomputed hash, so a
    wrong hash here is simply refused, never stored. Returns hex."""
    return _fed_ed25519.sign(
        _countersign_payload(workspace_id, charter_hash, _NODE_PUB, invitee_agent_key),
        bytes.fromhex(_NODE_PRIV), bytes.fromhex(_NODE_PUB)).hex()


def _leave_payload(workspace_id: int, member_key: str) -> bytes:
    """Canonical bytes an invitee's node signs to leave a workspace
    (docs/WORKSPACE_INVITE.md: leave/remove, build item 4). The invitee's
    *node* mints it — nodes are the trust boundary, the same vouch model
    as countersign: the home node verifies the *sender node's* roster key,
    not the member key it holds, so the signature proves the invitee's
    node vouched for its own agent's exit. Covers only the workspace id
    as known on the home node and the departing member key — the goodbye
    is a goodbye, no reason strings in v1."""
    return (b"workspace-leave|" + str(workspace_id).encode() + b"|"
            + member_key.lower().encode())


def _leave_mint(workspace_id: int, member_key: str) -> str:
    """Mint a leave vouch: sign the canonical leave payload with this
    node's key. Returns hex."""
    return _fed_ed25519.sign(
        _leave_payload(workspace_id, member_key),
        bytes.fromhex(_NODE_PRIV), bytes.fromhex(_NODE_PUB)).hex()


def _name_claim_payload(name: str, node_pubkey: str, issued_at: str, expires_at: str) -> bytes:
    """Canonical bytes a node signs to claim a .cyberspace name with its
    DEDICATED NAME KEY (never the master identity). Per
    CYBERSPACE_RESOLUTION_DESIGN.md the signature covers
    name|node_pubkey|issued_at|expires_at — self-authenticating: the very
    key being named vouches for the binding, so a lying registry can only
    withhold a name, never redirect one. Lowercase hex is the wire form;
    the name arrives already normalized lowercase via _valid_name_label."""
    return (b"name-claim|" + name.encode() + b"|"
            + node_pubkey.lower().encode() + b"|"
            + issued_at.encode() + b"|" + expires_at.encode())


def _valid_name_label(name: str) -> bool:
    """First label only: no dots (subdomains are the node's own business),
    lowercase alnum/hyphen, 1..NAME_LABEL_MAX chars, no leading/trailing
    hyphen. A nickname, not an asset — nothing that looks like a path,
    nothing that looks like money."""
    if not name or len(name) > NAME_LABEL_MAX:
        return False
    if name != name.lower() or "." in name:
        return False
    if name.startswith("-") or name.endswith("-"):
        return False
    return all(c.isalnum() or c == "-" for c in name)


def _name_binding_verify(name: str, node_pubkey: str, issued_at: str,
                         expires_at: str, signature: str) -> bool:
    """Fail-closed binding verification: any exception (bad hex, bad key,
    bad signature) reads as refusal. The registry never stores what it
    cannot prove, and a resolver never trusts what it cannot re-verify."""
    try:
        return _fed_ed25519.checkvalid(
            bytes.fromhex(signature),
            _name_claim_payload(name, node_pubkey, issued_at, expires_at),
            bytes.fromhex(node_pubkey))
    except Exception:
        return False


def _reach_canonical(name: str, node_pubkey: str, reach, issued_at: str,
                     expires_at: str) -> bytes:
    """Canonical bytes a hoster signs to publish a .cyberspace reach
    descriptor (docs/HOSTING.md, primitive 3). The reach list is a JSON
    payload with sorted keys — strategy member ORDER is meaningful (the
    hoster's dial preference), so the list itself is NOT re-sorted; only
    dict keys inside it are. Same fields always serialize to the same
    bytes: a lying mirror can withhold a descriptor but can never
    redirect one, because the canonical form it verifies is the form
    the name key signed. `signature` is excluded by construction."""
    reach_json = json.dumps(reach, sort_keys=True, separators=(",", ":"))
    return (b"reach-descriptor|" + name.encode() + b"|"
            + node_pubkey.lower().encode() + b"|"
            + reach_json.encode() + b"|"
            + issued_at.encode() + b"|" + expires_at.encode())


def _reach_mint(privkey_hex: str, node_pubkey: str, name: str, reach,
                issued_at: str, expires_at: str) -> dict:
    """Mint a reach descriptor: the name key signs the canonical form.
    The descriptor rides the name-key-signed /fed/announce (announce half);
    mirrors merge it like directory rows. Never the master identity."""
    msg = _reach_canonical(name, node_pubkey, reach, issued_at, expires_at)
    sig = _fed_ed25519.sign(msg, bytes.fromhex(privkey_hex),
                            bytes.fromhex(node_pubkey)).hex()
    return {"name": name, "node_pubkey": node_pubkey, "reach": reach,
            "issued_at": issued_at, "expires_at": expires_at,
            "signature": sig}


def _reach_descriptor_verify(desc) -> bool:
    """Fail-closed reach-descriptor verification, mirroring the name
    binding contract: canonical form excluding `signature` must verify
    against node_pubkey; expired descriptors are refused; unknown `kind`
    values are IGNORED (protocols grow by addition) — the signature
    covers the whole reach list, and dial-time parsing is the dialer's
    job, not the verifier's. Any exception reads as refusal."""
    try:
        if not isinstance(desc, dict):
            return False
        for k in ("name", "node_pubkey", "reach", "issued_at",
                  "expires_at", "signature"):
            if k not in desc:
                return False
        name = desc["name"]
        pub = desc["node_pubkey"]
        if _valid_name_label(name) is not True:
            return False
        if not isinstance(pub, str) or len(pub) != 64:
            return False
        bytes.fromhex(pub)  # bad hex -> refusal
        reach = desc["reach"]
        if not isinstance(reach, list):
            return False
        issued_at = str(desc["issued_at"])
        expires_at = str(desc["expires_at"])
        if _parse_claim_time(expires_at) <= datetime.now(timezone.utc):
            return False
        return _fed_ed25519.checkvalid(
            bytes.fromhex(desc["signature"]),
            _reach_canonical(name, pub, reach, issued_at, expires_at),
            bytes.fromhex(pub))
    except Exception:
        return False


def _name_claim_beats(new: dict, old: dict) -> bool:
    """Deterministic conflict rule — every mirror computes the same answer
    from the same inputs. Same key re-signing (renew/revoke): later
    issued_at supersedes. Different keys: earlier issued_at wins; ties
    break by lower pubkey bytes. No votes, no auctions, no admin."""
    if new["node_pubkey"].lower() == old["node_pubkey"].lower():
        return _parse_claim_time(new["issued_at"]) > _parse_claim_time(old["issued_at"])
    if new["issued_at"] != old["issued_at"]:
        return _parse_claim_time(new["issued_at"]) < _parse_claim_time(old["issued_at"])
    return new["node_pubkey"].lower() < old["node_pubkey"].lower()


CYBERSPACE_SUFFIX = ".cyberspace"
_RESOLVE_TIMEOUT = 8  # seconds — same outbound budget as the rest of core.py

# verified-binding memo: the six-step verifier below costs up to four
# sequential network round-trips per resolution (mirror binding, mirror
# directory, node ping, node claim re-fetch — 8s timeout each, so up to
# 32s of parked thread against a slow mirror), and neither the DoH
# bridge nor the UDP daemon cached anything: every query paid the full
# cadence, including repeat queries for the same popular name, while the
# DoH concurrency gate (16 global / 4 per IP) parked behind them. The
# verified RESULT is memoizable: the binding is signature-pinned and
# expiry-bounded, so a memo entry can never redirect a name or outlive
# its expiry; the registry is a live log (bindings renew, node_urls
# move) and the memo TTL (60s) sits well inside the answer TTL the
# protocol already hands clients (up to 300s — they cache a
# stale-for-300s record anyway). Negative results are NOT memoized:
# fail-closed stays fail-closed, and a withheld or just-claimed name
# resolves on the next query. Plain-dict hot path, same family as the
# DoH in-flight gate — a lost race re-verifies or serves a within-TTL
# hit, never a wrong answer. Keys are (label, mirror) after
# normalization.
_RESOLVE_MEMO_TTL = 60     # seconds of liveness staleness the node admits
_RESOLVE_MEMO_CAP = 4096   # memo entries; oldest evicted past cap
_resolve_memo: dict = {}


def _resolve_memo_get(label: str, mirror: str):
    """A verified, unexpired memo hit, or None. Lazy expiry on read."""
    entry = _resolve_memo.get((label, mirror))
    if entry is None:
        return None
    valid_until, result = entry
    if valid_until <= time.monotonic():
        _resolve_memo.pop((label, mirror), None)
        return None
    return result


def _resolve_memo_put(label: str, mirror: str, result: dict,
                      expires_at: str) -> None:
    """Memoize a verified result. The entry TTL is the shorter of the
    memo cap and the binding's own remaining life — the memo can never
    serve past the name's expiry."""
    try:
        remaining = (_parse_claim_time(expires_at) -
                     datetime.now(timezone.utc)).total_seconds()
    except ValueError:
        remaining = 0
    ttl = min(_RESOLVE_MEMO_TTL, remaining)
    if ttl <= 0:
        return
    key = (label, mirror)
    if key not in _resolve_memo and len(_resolve_memo) >= _RESOLVE_MEMO_CAP:
        _resolve_memo.pop(next(iter(_resolve_memo)))
    _resolve_memo[key] = (time.monotonic() + ttl, result)


def _resolve_get_json(url: str):
    """GET a URL and parse the JSON body. Fail-closed helper for the
    resolver: any network error, non-200, or bad JSON returns None —
    a resolver that cannot hear an answer treats it as silence.

    Operator-trust-anchor only: the caller must feed it the operator's
    own mirror URL, never peer-supplied addresses."""
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=_RESOLVE_TIMEOUT) as resp:
            if resp.status != 200:
                return None
            return _read_peer_json(resp)
    except Exception:
        return None


def _resolve_peer_get_json(url: str):
    """GET a peer-supplied address and parse the JSON body, riding
    _peer_urlopen so the SSRF/rebind gate runs at dial time too — the
    step-5 shape check on the directory's node_url does not survive DNS
    changes before step 6. Same fail-closed contract as
    _resolve_get_json: any network error, gate refusal, non-200, or bad
    JSON returns None, and resolve_cyberspace's outer try/except keeps
    it a silent None either way."""
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with _peer_urlopen(req, timeout=_RESOLVE_TIMEOUT) as resp:
            if resp.status != 200:
                return None
            return _read_peer_json(resp)
    except Exception:
        return None


# Relay-session token bound: a dial credential, not a password — it only
# routes a session to the hoster's hold-open at a public relay. Cap is
# an anti-bloat belt on the dial path, not a security claim.
_RELAY_TOKEN_CAP = 4096


def _relay_route(desc):
    """Dial-side relay-route extraction (docs/HOSTING.md, primitive 3):
    walk the caller-verified descriptor's reach list in hoster-preference
    order and return the first well-formed relay strategy:
    {"relay_pub": <64-hex relay node identity>,
     "url": <validated relay node URL — the dial terminates there>,
     "token": <the hoster's session-routing token>}.
    The descriptor must already be signature-verified with node_pubkey
    equal to the binding's key — the name key vouches the relay URL, the
    same trust the direct strategy's URL already rides. Direct strategies
    are the dialer's business elsewhere; unknown kinds (rendezvous is
    still reserved) are skipped, not fatal; one malformed relay member
    never poisons the route the hoster listed first. No well-formed relay
    strategy -> None. Never raises."""
    try:
        reach = desc.get("reach") if isinstance(desc, dict) else None
        if not isinstance(reach, list):
            return None
        for strat in reach:
            if not isinstance(strat, dict):
                continue
            if str(strat.get("kind", "")) != "relay":
                continue
            relay_pub = str(strat.get("relay", "")).lower()
            if len(relay_pub) != 64:
                continue
            try:
                bytes.fromhex(relay_pub)
            except ValueError:
                continue
            try:
                url = _valid_node_url(str(strat.get("url", "")))
            except HTTPException:
                continue
            if not url:
                continue
            token = strat.get("token")
            if (not isinstance(token, str) or not token
                    or len(token) > _RELAY_TOKEN_CAP):
                continue
            return {"relay_pub": relay_pub, "url": url, "token": token}
        return None
    except Exception:
        return None


# The wired hold_query path on relays (docs/RENDEZVOUS.md frozen spec):
# the descriptor advertises it, the dialer appends ?point_id=.
_RENDEZVOUS_HOLD_QUERY = "/relay/hold_query"


def _rendezvous_strategy(desc):
    """Dial-side rendezvous-strategy extraction (docs/RENDEZVOUS.md,
    primitive 3): walk the caller-verified descriptor's reach list in
    hoster-preference order and return the first well-formed rendezvous
    strategy: {"epoch_len": <60..86400>, "hold_query": <relative path>}.
    The descriptor must already be signature-verified with node_pubkey
    equal to the binding's key — the name key vouches the epoch math,
    the same trust the relay strategy's URL already rides. A missing
    or malformed rendezvous member reads as None (the probe runs with
    the frozen defaults, unchanged behavior) — never raises."""
    try:
        reach = desc.get("reach") if isinstance(desc, dict) else None
        if not isinstance(reach, list):
            return None
        for strat in reach:
            if not isinstance(strat, dict):
                continue
            if str(strat.get("kind", "")) != "rendezvous":
                continue
            epoch_len = strat.get("epoch_len")
            if not rendezvous._epoch_len_ok(epoch_len):
                continue
            hold_query = strat.get("hold_query")
            if (not isinstance(hold_query, str)
                    or not hold_query.startswith("/")
                    or "?" in hold_query or "#" in hold_query
                    or len(hold_query) > 256):
                continue
            return {"epoch_len": epoch_len, "hold_query": hold_query}
        return None
    except Exception:
        return None


def _relay_hold_probe(relay_url: str, node_pubkey: str,
                      epoch_len: int = rendezvous.EPOCH_LEN_DEFAULT,
                      hold_query: str = _RENDEZVOUS_HOLD_QUERY):
    """Dialer-side willingness probe (docs/RENDEZVOUS.md, primitive 3):
    before opening a relay session, the dialer derives the same (E, E-1)
    rendezvous points the hoster's hostd holds under (the shared KDF
    runs on the binding's NAME KEY, so both sides meet at points nobody
    else chose) and asks the relay GET /relay/hold_query?point_id= —
    the mirror answers willing only for fresh, registered,
    still-willing points (never a 4xx; strangers read as held:false).

    Returns the HELD POINT ID (a 64-hex string) when a holder is
    willing — open the session BY THAT POINT, never the token (the
    dialer never learns the routing token on the rendezvous path).
    False: both points positively answered nobody-holds — skip the
    session entirely; minting one would only wait on silence. None:
    the query could not be answered (relay predates hold_query,
    transport failure, or the point could not be derived) — open the
    session as before, legacy behavior unchanged, so a new dialer
    never goes silent under an old relay. Never raises."""
    try:
        if not rendezvous._epoch_len_ok(epoch_len):
            epoch_len = rendezvous.EPOCH_LEN_DEFAULT
        if not (isinstance(hold_query, str)
                and hold_query.startswith("/")
                and "?" not in hold_query and "#" not in hold_query
                and len(hold_query) <= 256):
            hold_query = _RENDEZVOUS_HOLD_QUERY
        pair = rendezvous.derive_points(time.time(), node_pubkey or "",
                                       epoch_len)
    except Exception:
        return None
    if not pair:
        return None
    unknown = False
    for point in pair:
        data = _resolve_peer_get_json(
            relay_url.rstrip("/") + hold_query + "?point_id=" + point)
        if not isinstance(data, dict):
            unknown = True
            continue
        if data.get("held") is True:
            return point
    return None if unknown else False


def _relay_open_session(relay_url: str, label: str, node_pubkey: str,
                        token: str,
                        epoch_len: int = rendezvous.EPOCH_LEN_DEFAULT,
                        hold_query: str = _RENDEZVOUS_HOLD_QUERY) -> bool:
    """Dial-side relay session-open (docs/HOSTING.md, primitive 3): the
    relay holds a host-initiated hold-open from the hoster — NAT
    penetration is the hoster's outbound dial, not ours. Before the
    session is minted, the dialer runs the derived-point willingness
    probe (_relay_hold_probe): a relay that positively answers
    nobody-holds reads as silence — no session minted, no waiting on
    an absence. A willing holder (or a relay too old to answer the
    probe) proceeds. The client sends no identity: the relay sees
    bytes, never identity; the token (name-key-signed into the
    descriptor) only routes the session to the hoster's hold-open.
    The relay answers with a fresh challenge and the hoster's
    NAME-KEY signature over it:
      POST {relay_url}/relay/open {"name": label,
                                   "rendezvous_point": "<held point>"}
    (or the legacy {"name": label, "token": token} when the relay
    predates the hold_query probe — an explicit token still wins on
    the mirror side when both are given).
    200  {"challenge": "<64 hex>", "name_key_sig": "<128 hex>"}
    The signature verifies fail-closed against the binding's name key: a
    valid signature proves the name's key answered live through the
    relay — the same live-proof as the direct dial's step 6, one hop
    over. Any other outcome is silence (False). This is the client dial
    half; the relay server half (hold-open registration, session
    bridging) runs on the relay. Never raises."""
    held = _relay_hold_probe(relay_url, node_pubkey, epoch_len,
                             hold_query)
    if held is False:
        # The relay positively answers no willing hold-open under the
        # derived points — a session would be minted only to wait on
        # silence. Stay silent instead. (held None — relay predates
        # hold_query or the query could not be answered — falls through
        # to the legacy session-open, unchanged.)
        return False
    if isinstance(held, str):
        # A willing holder answered at this derived point: open the
        # session BY THE POINT. The token never leaves the dialer on
        # the rendezvous path — the mirror resolves the point to the
        # held routing token, and the dialer never learns it.
        payload = {"name": label, "rendezvous_point": held}
    else:
        payload = {"name": label, "token": token}
    try:
        body = json.dumps(payload).encode()
        req = urllib.request.Request(
            relay_url.rstrip("/") + "/relay/open", data=body,
            headers={"Content-Type": "application/json",
                     "Accept": "application/json"},
            method="POST")
        with _peer_urlopen(req, timeout=_RESOLVE_TIMEOUT) as resp:
            if resp.status != 200:
                return False
            data = _read_peer_json(resp)
        if not isinstance(data, dict):
            return False
        challenge = str(data.get("challenge", ""))
        sig = str(data.get("name_key_sig", "")).lower()
        if len(challenge) != 64 or len(sig) != 128:
            return False
        return _fed_ed25519.checkvalid(
            bytes.fromhex(sig), bytes.fromhex(challenge),
            bytes.fromhex(node_pubkey))
    except Exception:
        return False


def resolve_cyberspace(address: str, mirror_url: str) -> dict | None:
    """.cyberspace Phase 1 build item 3: the six-step client resolver —
    name to live address, fail-closed at every step. A nickname is a
    convenience, not an identity: the function never returns an address it
    could not prove, and returns None rather than a guess.

    Resolution contract (Phase 1): the registry binds name -> dedicated
    NAME KEY (self-certifying, signed by the name key itself — the mirror
    can withhold a name but never redirect one). The registry carries zero
    host metadata by design, so a node that claims a name MUST also
    announce to mirrors with an envelope signed BY ITS NAME KEY
    (/fed/announce with node_pub = the name key); the mirror's directory
    then carries name-key -> node_url, and the announce signature is what
    authenticates the address half. A claimed name with no name-key
    announce resolves to nothing — the address stays silent rather than
    wrong.

    Steps: (1) the address must end in .cyberspace; the label is validated
    as a first label only. (2) fetch the binding from the mirror's exact-
    name registry endpoint. (3) re-verify the binding signature
    fail-closed — the client never trusts the mirror's word alone.
    (4) the binding must be unexpired. (5) key -> address: the mirror's
    name-key-signed reach descriptor is consulted first — direct
    strategies in hoster-preference order, then the first well-formed
    relay strategy (hosting from anywhere: the dial terminates at the
    relay, via_relay carries the relay identity and routing token);
    unknown kinds are skipped. Legacy fallback: the mirror's
    /api/v1/directory is scanned for the entry whose node_pub IS the
    name key (see the contract above); its node_url is validated.
    (6) live verification: the node's /fed/ping must carry a valid
    signed envelope (the node is alive and speaks federation), and its
    /api/v1/names/<label> must serve the SAME name key with a valid,
    unexpired signature — the address answers for the name, live. On a
    relay route the proof is the name key signing a fresh challenge
    through the relay's hold-open.

    Returns {"name", "node_pubkey", "node_url", "issued_at",
    "expires_at"} on success, plus "via_relay": {"relay_pub", "token"}
    when the dial terminates at a relay (the daemon then opens the relay
    session with the token), None on any failure. No exceptions escape:
    the resolver reports silence, never certainty it doesn't have."""
    try:
        # Step 1: .cyberspace check — first label only, never a path.
        addr = (address or "").strip().lower()
        if not addr.endswith(CYBERSPACE_SUFFIX):
            return None
        label = addr[: -len(CYBERSPACE_SUFFIX)]
        if not _valid_name_label(label):
            return None
        mirror = (mirror_url or "").strip().rstrip("/")

        # Memo: a verified, unexpired hit skips the four network
        # round-trips. Failures are never memoized.
        hit = _resolve_memo_get(label, mirror)
        if hit is not None:
            return hit

        # Step 2: fetch the binding from the mirror (exact-name only).
        binding = _resolve_get_json(mirror + "/api/v1/names/" + label)
        if not isinstance(binding, dict):
            return None
        name = str(binding.get("name", "")).lower()
        node_pubkey = str(binding.get("node_pubkey", "")).lower()
        issued_at = str(binding.get("issued_at", ""))
        expires_at = str(binding.get("expires_at", ""))
        signature = str(binding.get("signature", "")).lower()
        if name != label or len(node_pubkey) != 64 or len(signature) != 128:
            return None

        # Step 3: re-verify the signature fail-closed — the mirror's word
        # alone is never enough.
        if not _name_binding_verify(name, node_pubkey, issued_at,
                                   expires_at, signature):
            return None

        # Step 4: the binding must be live — expired names read as absent.
        # Chronological, not lexicographic: see _parse_claim_time.
        try:
            live = _parse_claim_time(expires_at) > datetime.now(timezone.utc)
        except ValueError:
            return None
        if not live:
            return None

        # Step 5: key -> address. The descriptor (reach) half first: a
        # name-key-signed reach descriptor served by the mirror carries
        # the hoster's dial strategies in dial-preference order; the
        # dialer verifies it fail-closed (signature against the canonical
        # form, node_pubkey EQUAL to the binding's key, live — the
        # mirror's word alone is never enough). Direct strategies dial
        # first; unknown strategy kinds are skipped (protocols grow by
        # addition). When the descriptor path fails at any point, the
        # legacy directory scan runs as fallback — a mirror without a
        # descriptor still resolves through the name-key-announced
        # directory entry, read as silence if absent.
        node_url = ""
        via_relay = None
        via_rendezvous = None
        desc = _resolve_get_json(mirror + "/api/v1/names/" + label + "/reach")
        if isinstance(desc, dict) and _reach_descriptor_verify(desc):
            if str(desc.get("node_pubkey", "")).lower() == node_pubkey:
                for strat in desc.get("reach", []) or []:
                    if not isinstance(strat, dict):
                        continue
                    if str(strat.get("kind", "")) != "direct":
                        continue
                    try:
                        cand = _valid_node_url(str(strat.get("url", "")))
                    except HTTPException:
                        continue
                    if cand:
                        node_url = cand
                        break
                if not node_url:
                    # Relay half: no direct dial path — the hoster may
                    # live behind NAT (hosting from anywhere is the
                    # primitive; the relay strategy is its address).
                    # The first well-formed relay strategy in
                    # hoster-preference order becomes the dial route:
                    # node_url is the relay's URL (the dial terminates
                    # there) and step 6 proves the name key answered
                    # through it.
                    via_relay = _relay_route(desc)
                    if via_relay is not None:
                        node_url = via_relay["url"]
                        # Rendezvous kind (docs/RENDEZVOUS.md frozen
                        # spec): the hoster advertises its epoch math
                        # and probe path — the derived-point probe in
                        # step 6 runs under the hoster's epoch_len, not
                        # the frozen default. Absent or malformed reads
                        # as None: unchanged default behavior.
                        via_rendezvous = _rendezvous_strategy(desc)
        if not node_url:
            # Legacy fallback: the entry is keyed by the NAME KEY
            # (announced with a name-key-signed envelope), never the
            # master identity. limit=200 is the route's max slice — the
            # key->address scan needs the widest view the directory
            # contract offers; a mirror with >200 reachable peers reads
            # as silence for the entry past the slice (fail-closed).
            directory = _resolve_get_json(mirror + "/api/v1/directory?limit=200")
            if isinstance(directory, dict):
                for entry in directory.get("entries", []) or []:
                    if not isinstance(entry, dict):
                        continue
                    if str(entry.get("node_pub", "")).lower() == node_pubkey:
                        node_url = str(entry.get("node_url", ""))
                        break
        try:
            node_url = _valid_node_url(node_url)
        except HTTPException:
            return None
        if not node_url:
            return None

        # Step 6: live verification.
        if via_relay is not None:
            # Relay route: the dial terminates at the relay, so the
            # name re-fetch half of the direct path does not apply.
            # The live-proof becomes (a) the relay is a live federation
            # speaker, and (b) the name key signs a fresh challenge
            # through the relay's hold-open (_relay_open_session) — the
            # same proof, one hop over. A relay that cannot answer for
            # the name is not the name's route.
            ping = _resolve_peer_get_json(node_url + "/fed/ping")
            if (not isinstance(ping, dict)
                    or not _fed_env.verify_envelope(ping)):
                return None
            if not _relay_open_session(node_url, label, node_pubkey,
                                       via_relay["token"],
                                       (via_rendezvous or {}).get(
                                           "epoch_len",
                                           rendezvous.EPOCH_LEN_DEFAULT),
                                       (via_rendezvous or {}).get(
                                           "hold_query",
                                           _RENDEZVOUS_HOLD_QUERY)):
                return None
        else:
            # Direct route: first the node's signed ping — it is alive
            # and speaks federation (liveness only; the ping envelope is
            # the master identity, not the name key). Then the claim
            # itself re-fetched from the address: the node must serve
            # the SAME name key with a valid, unexpired signature. An
            # address that cannot answer for its name is not the name's
            # home.
            ping = _resolve_peer_get_json(node_url + "/fed/ping")
            if (not isinstance(ping, dict)
                    or not _fed_env.verify_envelope(ping)):
                return None
            live = _resolve_peer_get_json(node_url + "/api/v1/names/" + label)
            if not isinstance(live, dict):
                return None
            if str(live.get("node_pubkey", "")).lower() != node_pubkey:
                return None
            if not _name_binding_verify(
                    str(live.get("name", "")).lower(), node_pubkey,
                    str(live.get("issued_at", "")),
                    str(live.get("expires_at", "")),
                    str(live.get("signature", "")).lower()):
                return None
            try:
                live_unexpired = _parse_claim_time(
                    str(live.get("expires_at", ""))
                ) > datetime.now(timezone.utc)
            except ValueError:
                return None
            if not live_unexpired:
                return None

        result = {"name": label, "node_pubkey": node_pubkey,
                  "node_url": node_url, "issued_at": issued_at,
                  "expires_at": expires_at}
        if via_relay is not None:
            # The dial terminates at the relay: the daemon must open the
            # relay session with the hoster's routing token (inside the
            # name-key-signed descriptor, so it was the name's own word).
            result["via_relay"] = {"relay_pub": via_relay["relay_pub"],
                                   "token": via_relay["token"]}
        _resolve_memo_put(label, mirror, result, expires_at)
        return result
    except Exception:
        return None


def _name_registry_has_room(conn) -> bool:
    """Name-registry growth gate (names/claim + /fed/names/gossip merge).
    Genuinely-new names past NAME_REGISTRY_CAP are refused, while
    renewals and re-contests of known names always merge (the existence
    check sits before the gate, same family as the peers/channel_subs/
    DM-thread roster caps). Lazy GC: expired rows are dead weight the
    gossip send-half already skips and nothing ever deletes, so they are
    pruned on the insert path before the count — otherwise expired rows
    could wedge the registry forever. The <= string comparison matches
    the rest of the gossip path's expiry semantics."""
    conn.execute("DELETE FROM name_bindings WHERE expires_at <= ?", (_now(),))
    n = conn.execute("SELECT COUNT(*) FROM name_bindings").fetchone()[0]
    return n < NAME_REGISTRY_CAP


# Signed name-registry roster cap: the registry is Sybil-floodable —
# anyone mints Ed25519 keys in ms and self-signs a binding, and neither
# POST /api/v1/names/claim nor the gossip merge half capped genuinely-new
# names, so the name_bindings table grew forever (expired rows were never
# pruned either, and the hourly _names_gossip_out fetchall would swell
# with it). An order of magnitude above the 128-peer roster the node
# actually tracks; the gossip batch cap (126/call) is far below it.
NAME_REGISTRY_CAP = 1024


def ingest_gossiped_binding(binding: dict) -> str:
    """.cyberspace Phase 1 build item 4: the mirror's merge half — fold a
    gossiped name binding into this mirror's registry. A registry is a
    signed log, not an authority: any mirror may repeat a binding, but
    every mirror re-verifies it itself. The signature is fail-closed —
    a mirror's word is never enough, not even another mirror's.

    Deterministic merge (same answer on every mirror from the same
    inputs): malformed/unsigned/expired bindings are dropped; an
    uncontested name is inserted; a contested name goes to
    _name_claim_beats (earlier issued_at wins, ties by lower pubkey,
    same key later re-sign renews). An expired incumbent yields to any
    valid challenger. Nothing is ever deleted here — expiry is the only
    garbage collection, and the gossip layer never synthesizes
    revocations.

    Returns one of "inserted", "replaced", "kept", "dropped-malformed",
    "dropped-unverifiable", "dropped-expired". Never raises."""
    try:
        if not isinstance(binding, dict):
            return "dropped-malformed"
        name = str(binding.get("name", "")).lower()
        node_pubkey = str(binding.get("node_pubkey", "")).lower()
        issued_at = str(binding.get("issued_at", ""))
        expires_at = str(binding.get("expires_at", ""))
        signature = str(binding.get("signature", "")).lower()
        if (not _valid_name_label(name) or len(node_pubkey) != 64
                or len(signature) != 128 or not issued_at
                or not expires_at):
            return "dropped-malformed"
        if not _name_binding_verify(name, node_pubkey, issued_at,
                                    expires_at, signature):
            return "dropped-unverifiable"
        if expires_at <= _now():
            return "dropped-expired"
        new = {"name": name, "node_pubkey": node_pubkey,
               "issued_at": issued_at, "expires_at": expires_at}
        with _db_lock, _db() as conn:
            row = conn.execute(
                "SELECT node_pubkey, issued_at FROM name_bindings WHERE name=?",
                (name,)).fetchone()
            if row is None:
                if not _name_registry_has_room(conn):
                    return "dropped-full"
                conn.execute(
                    "INSERT INTO name_bindings (name, node_pubkey, issued_at,"
                    " expires_at, signature) VALUES (?,?,?,?,?)",
                    (name, node_pubkey, issued_at, expires_at, signature))
                return "inserted"
            old = {"name": name, "node_pubkey": row[0],
                   "issued_at": row[1]}
            if _name_claim_beats(new, old):
                conn.execute(
                    "UPDATE name_bindings SET node_pubkey=?, issued_at=?,"
                    " expires_at=?, signature=? WHERE name=?",
                    (node_pubkey, issued_at, expires_at, signature, name))
                return "replaced"
            return "kept"
    except Exception:
        return "dropped-malformed"


def _reap_expired_reach_descriptors(conn) -> int:
    """Lazy garbage collection for the mirror's reach-descriptor store —
    runs once per ingest on the ingest path (the only writer). Drops
    every row the serve side already reads as absent:

      - the descriptor itself is expired or its expires_at is
        unparseable (fail-closed: unreadable expiry is treated as dead,
        the same contract the /names/{name}/reach route enforces);
      - the registry binding under the row is gone, expired, or keyed
        differently (the merge half already refuses these at ingest,
        but a live row can outlive its binding; serve reads it as
        absent, so keeping it is dead weight).

    The table is one row per bound name, so this is a single cheap
    scan. Never raises. Returns the count reaped."""

    try:
        now = datetime.now(timezone.utc)
        rows = conn.execute(
            "SELECT name, expires_at, node_pubkey FROM reach_descriptors").fetchall()
        reaped = 0
        for rname, expires_at, node_pubkey in rows:
            dead = True
            try:
                dead = _parse_claim_time(expires_at) <= now
            except ValueError:
                dead = True
            if not dead:
                bind = conn.execute(
                    "SELECT node_pubkey, expires_at FROM name_bindings"
                    " WHERE name=?", (rname,)).fetchone()
                try:
                    binding_live = (bind is not None
                                    and bind[0].lower() == str(node_pubkey).lower()
                                    and _parse_claim_time(bind[1]) > now)
                except ValueError:
                    binding_live = False
                dead = not binding_live
            if dead:
                conn.execute("DELETE FROM reach_descriptors WHERE name=?", (rname,))
                reaped += 1
        return reaped
    except Exception:
        return 0


def ingest_reach_descriptor(desc: dict) -> str:
    """.cyberspace depth: the mirror's merge half for reach descriptors —
    fold a name-key-signed descriptor into this mirror's registry. The
    descriptor rides the name-key-signed /fed/announce (announce half,
    sender_pub IS the name key); mirrors merge it the way they merge
    directory rows: seen-from-peer, never gospel. The binding does the
    identity half; the descriptor only carries the address half, so a
    descriptor is never stored unless the registry holds a LIVE binding
    for the same name under the SAME key — a descriptor for a name whose
    binding is expired, unverifiable, or keyed differently is discarded.

    Deterministic merge: fail-closed verify (see _reach_descriptor_verify),
    then live-binding check (name exists in name_bindings, same key,
    unexpired), then one row per name — later issued_at replaces (re-sign
    renews), earlier issued_at is kept. Garbage collection is lazy, on the
    ingest path (the only writer): _reap_expired_reach_descriptors runs
    once per ingest and drops rows the serve side already reads as absent
    (expired or unparseable expires_at; binding gone, expired, or
    re-keyed under the row). The table is bounded by the name registry
    (one row per bound name; a row can only exist where a live binding
    already exists), so the scan is cheap and it needs no separate
    growth gate.

    Returns one of "inserted", "replaced", "kept", "dropped-malformed",
    "dropped-unverifiable", "dropped-expired", "dropped-unbound",
    "dropped-key-mismatch". Never raises."""
    try:
        if not isinstance(desc, dict):
            return "dropped-malformed"
        for k in ("name", "node_pubkey", "reach", "issued_at",
                  "expires_at", "signature"):
            if k not in desc:
                return "dropped-malformed"
        name = str(desc["name"]).lower()
        node_pubkey = str(desc["node_pubkey"]).lower()
        if not _reach_descriptor_verify(desc):
            # shape-unparseable or signature-fail — but distinguish expiry
            # for the same honest-diagnosis contract the binding merge has.
            try:
                if (_valid_name_label(name) is True
                        and _parse_claim_time(str(desc["expires_at"]))
                        <= datetime.now(timezone.utc)):
                    return "dropped-expired"
            except Exception:
                pass
            return "dropped-unverifiable"
        with _db_lock, _db() as conn:
            _reap_expired_reach_descriptors(conn)
            row = conn.execute(
                "SELECT node_pubkey, expires_at FROM name_bindings WHERE name=?",
                (name,)).fetchone()
            if row is None:
                return "dropped-unbound"
            if row[0].lower() != node_pubkey:
                return "dropped-key-mismatch"
            try:
                binding_live = _parse_claim_time(row[1]) > datetime.now(timezone.utc)
            except ValueError:
                binding_live = False
            if not binding_live:
                return "dropped-unbound"
            reach_json = json.dumps(desc["reach"], sort_keys=True,
                                    separators=(",", ":"))
            old = conn.execute(
                "SELECT node_pubkey, issued_at FROM reach_descriptors WHERE name=?",
                (name,)).fetchone()
            if old is None:
                conn.execute(
                    "INSERT INTO reach_descriptors (name, node_pubkey, reach,"
                    " issued_at, expires_at, signature) VALUES (?,?,?,?,?,?)",
                    (name, node_pubkey, reach_json, str(desc["issued_at"]),
                     str(desc["expires_at"]), str(desc["signature"]).lower()))
                return "inserted"
            if _parse_claim_time(str(desc["issued_at"])) > _parse_claim_time(old[1]):
                conn.execute(
                    "UPDATE reach_descriptors SET reach=?, issued_at=?,"
                    " expires_at=?, signature=? WHERE name=?",
                    (reach_json, str(desc["issued_at"]),
                     str(desc["expires_at"]), str(desc["signature"]).lower(), name))
                return "replaced"
            return "kept"
    except Exception:
        return "dropped-malformed"


def _removed_payload(workspace_id: int, member_key: str) -> bytes:
    """Canonical bytes a home node signs to tell an invitee's node its
    agent was removed (docs/WORKSPACE_INVITE.md: leave/remove, build
    item 4b). The home node's own key vouches — the peer receiver
    verifies the sender's roster key, so only the room's home node can
    strike the receipt on the invitee's side. Covers the home workspace
    id and the struck member key — the notice carries no reason in v1,
    just the closed door."""
    return (b"workspace-removed|" + str(workspace_id).encode() + b"|"
            + member_key.lower().encode())


def _removed_mint(workspace_id: int, member_key: str) -> str:
    """Mint a removal notice: sign the canonical removed payload with
    this node's (home) key. Returns hex. The caller-side (build item
    4b.3) fires it at the peer's /fed/workspace_removed and logs-and-
    ignores the answer."""
    return _fed_ed25519.sign(
        _removed_payload(workspace_id, member_key),
        bytes.fromhex(_NODE_PRIV), bytes.fromhex(_NODE_PUB)).hex()


def _delta_payload(row: dict, seq: int, retire: bool) -> bytes:
    """Canonical bytes a node owner signs for a directory delta
    (docs/FEDERATION.md: Gossip v1, directory delta-sync). The signature
    covers owner identity, the row's public fields, the monotonic seq,
    and the retire flag — one writer, one sequence, so a gossiping peer
    cannot forge or tamper with another node's row. Lives in core so both
    the mint (send half) and the receivers can build it without a
    circular import."""
    payload = {
        "node_pub": str(row.get("node_pub", "")).lower(),
        "name": str(row.get("name", "")),
        "node_url": str(row.get("node_url", "")),
        "capabilities": sorted(
            c for c in (row.get("capabilities") or []) if isinstance(c, str)),
        "network": str(row.get("network", "cybernet")),
        "version": str(row.get("version", "0.1.0")),
        "genesis": bool(row.get("genesis", False)),
        "seq": int(seq),
        "retire": bool(retire),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _delta_self_attestation(self_url: str) -> dict:
    """Mint this node's own directory self-attestation (docs/FEDERATION.md:
    Gossip v1, delta-sync send half): our row + monotonic owner seq +
    owner signature over the canonical _delta_payload(row, seq,
    retire=False). Seq bumps only when the published row content changes
    (restart-safe via node_meta delta_self_seq / delta_self_row); the
    same attestation is re-carried on every announce until the row
    changes. Returns {"row","seq","sig"}; on db failure returns {} and
    callers skip body.delta (the attestation is an unknown field to old
    nodes — ignored, never fatal)."""
    row = {
        "node_pub": _NODE_PUB.lower(),
        "name": NODE_NAME,
        "node_url": self_url,
        "capabilities": [],
        "network": "cybernet",
        "version": "0.1.0",
        "genesis": bool(IS_GENESIS),
    }
    fingerprint = hashlib.sha256(
        json.dumps(row, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    seq = 0
    try:
        with _db_lock, _db() as conn:
            r = conn.execute(
                "SELECT value FROM node_meta WHERE key='delta_self_seq'"
            ).fetchone()
            seq = int(r["value"] or 0) if r else 0
            r = conn.execute(
                "SELECT value FROM node_meta WHERE key='delta_self_row'"
            ).fetchone()
            old_fp = r["value"] if r else ""
            if old_fp != fingerprint:
                seq += 1
                conn.execute(
                    "INSERT INTO node_meta (key, value) VALUES ('delta_self_seq', ?)"
                    " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (str(seq),))
                conn.execute(
                    "INSERT INTO node_meta (key, value) VALUES ('delta_self_row', ?)"
                    " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (fingerprint,))
    except Exception:
        return {}
    try:
        sig = _fed_ed25519.sign(
            _delta_payload(row, seq, False),
            bytes.fromhex(_NODE_PRIV),
            bytes.fromhex(_NODE_PUB))
    except Exception:
        return {}
    return {"row": row, "seq": seq, "sig": sig.hex()}


def _provable_deltas() -> list:
    """Directory delta-sync send half: the gossip-path batch builder
    (docs/FEDERATION.md: Gossip v1, delta-sync send half, item 2b.3).
    Returns the verbatim attestations this node can *prove* — rows whose
    stored delta_sig is a valid owner signature over the canonical
    (row, seq, retire) payload reconstructed from the stored fields.
    Re-verification is the whole rule: forward only what you can prove.
    Rows fail out silently when: delta_sig is absent (legacy/hearsay),
    dir_seq is 0 (no owner sequence yet), the owner is us (our own row
    rides /fed/announce, authoritative), or the stored signature no
    longer matches the stored row state (e.g. a retire tombstone whose
    signature was minted over retire=false — the retirement is a state
    this signature does not attest). Retire tombstones with a matching
    owner retire=true signature ride along like any other attestation
    until the 7-day lazy prune clears them. Pure batch build — callers
    handle per-recipient filtering and posting."""
    deltas = []
    try:
        with _db_lock, _db() as conn:
            rows = conn.execute(
                "SELECT node_pub, name, network, version, genesis,"
                " capabilities, node_url, retired_at, dir_seq, delta_sig"
                " FROM peers WHERE delta_sig<>''").fetchall()
    except Exception:
        return []
    self_pub = _NODE_PUB.lower()
    for r in rows:
        node_pub = str(r["node_pub"] or "").lower()
        if node_pub == self_pub:
            continue
        try:
            caps = json.loads(r["capabilities"] or "[]")
            if not isinstance(caps, list):
                caps = []
        except Exception:
            caps = []
        row = {
            "node_pub": node_pub,
            "name": str(r["name"] or ""),
            "node_url": str(r["node_url"] or ""),
            "capabilities": [c for c in caps if isinstance(c, str)],
            "network": str(r["network"] or "cybernet"),
            "version": str(r["version"] or "0.1.0"),
            "genesis": bool(r["genesis"]),
        }
        seq = r["dir_seq"] or 0
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
            continue
        retire = bool(r["retired_at"])
        sig_hex = str(r["delta_sig"] or "")
        try:
            sig_ok = _fed_ed25519.checkvalid(
                bytes.fromhex(sig_hex),
                _delta_payload(row, seq, retire),
                bytes.fromhex(node_pub))
        except Exception:
            sig_ok = False
        if not sig_ok:
            continue  # never forward what you cannot prove
        deltas.append({"row": row, "seq": seq, "sig": sig_hex,
                       "retire": retire})
    return deltas


def _delta_out() -> int:
    """Directory delta-sync send half: the gossip-path producer
    (docs/FEDERATION.md: Gossip v1, delta-sync send half, item 2b.3).
    Runs inside the re-announce loop — no new daemon, no new peer
    selection: recipients are the same announced, unretired, reachable
    peers as _announce_out. Each recipient gets POST /fed/directory/delta
    with verbatim stored attestations for third-party rows — copied,
    never re-signed; a forwarder cannot alter a row without breaking the
    owner's signature, so dishonest gossip fails receivers by
    construction. Each recipient's batch excludes their own row (the
    receiver drops it anyway; our own row rides /fed/announce,
    authoritative) and is capped at 126 attestations (receivers process
    at most 128 per batch; resend-on-cycle makes stale-watermarks
    unnecessary). Empty batches stay silent — nothing to gossip, no
    wire. Threaded, best-effort; returns recipient count."""
    deltas = _provable_deltas()
    with _db_lock, _db() as conn:
        rows = conn.execute(
            "SELECT node_pub, node_url FROM peers "
            "WHERE retired_at='' AND node_url<>'' "
            "ORDER BY first_seen, node_pub LIMIT ?",
            (GOSSIP_FANOUT_SPAWN_CAP,)).fetchall()
    n = 0
    for recip in rows:
        recip_pub = str(recip["node_pub"] or "").lower()
        batch = [d for d in deltas
                 if d["row"]["node_pub"] != recip_pub][:126]
        if not batch:
            continue
        body = {"from_node_pub": _NODE_PUB, "deltas": batch}
        env = _fed_env.make_envelope(
            _NODE_PRIV, _NODE_PUB, recip["node_pub"], body)
        threading.Thread(target=_post_to_peer_path,
                         args=(recip["node_url"], "/fed/directory/delta", env),
                         daemon=True).start()
        n += 1
    return n


NAMES_GOSSIP_BATCH_CAP = 126


def _names_gossip_out() -> int:
    """.cyberspace Phase 1 build item 6: the mirror send-half for name
    bindings. Sweeps the local registry and POSTs all unexpired
    bindings (expired bindings read as absent — never gossiped) to every
    known, unretired peer with a reachable node_url via signed
    /fed/names/gossip envelopes. The receiver re-verifies every
    signature itself and merges deterministically, so convergence needs
    no watermarks: repeats are absorbed as "kept", which is exactly why
    the gossip loop converges instead of echoing. No per-recipient
    exclusion (unlike delta sync) — the receiver is the peer's own
    registry and it dedupes against its own table. No claims are minted
    here — gossip only repeats, never originates. Empty registry stays
    silent; threading matches _delta_out's best-effort fan-out. Rides
    the re-announce loop — no new daemon. Returns recipient count."""
    with _db_lock, _db() as conn:
        bindings = conn.execute(
            "SELECT name, node_pubkey, issued_at, expires_at, signature "
            "FROM name_bindings").fetchall()
    now = _now()
    payloads = [
        {"name": r["name"], "node_pubkey": r["node_pubkey"],
         "issued_at": r["issued_at"], "expires_at": r["expires_at"],
         "signature": r["signature"]}
        for r in bindings if str(r["expires_at"] or "") > now]
    if not payloads:
        return 0
    payloads = payloads[:NAMES_GOSSIP_BATCH_CAP]
    with _db_lock, _db() as conn:
        rows = conn.execute(
            "SELECT node_pub, node_url FROM peers "
            "WHERE retired_at='' AND node_url<>'' "
            "ORDER BY first_seen, node_pub LIMIT ?",
            (GOSSIP_FANOUT_SPAWN_CAP,)).fetchall()
    n = 0
    for recip in rows:
        body = {"from_node_pub": _NODE_PUB, "bindings": payloads}
        env = _fed_env.make_envelope(
            _NODE_PRIV, _NODE_PUB, recip["node_pub"], body)
        threading.Thread(target=_post_to_peer_path,
                         args=(recip["node_url"], "/fed/names/gossip", env),
                         daemon=True).start()
        n += 1
    return n


def _gossip_loop() -> None:
    """Background gossip loop: _gossip_out every CYBERNET_GOSSIP_INTERVAL
    seconds (default 600) with +/-20% jitter so a mesh of nodes does not
    synchronize gossip rounds. Daemon; never raises."""
    while True:
        try:
            base = max(60, int(os.environ.get("CYBERNET_GOSSIP_INTERVAL", "600")))
            time.sleep(base * random.uniform(0.8, 1.2))
            _gossip_out()
            _gutter_hearths()  # guttering rides the gossip cadence — no new daemon
            _withdraw_knocks()  # withdrawals ride the gossip cadence — no new daemon
            _take_partings()  # takings ride the gossip cadence — no new daemon
            _retire_knocks()  # retirements ride the gossip cadence — no new daemon
            _lapse_knocks()  # lapses ride the gossip cadence — the knock's third death, its own hour
            _clear_visitors()  # the guest-book's silence gutter — no new daemon
            _lapse_seats()  # empty seats ride the gossip cadence — the table's own silence, the door's five halves stay five
            _fold_tables()  # folded tables ride the gossip cadence — the table folds when its last chair leaves
            _lapse_needs()  # silent asks ride the gossip cadence — the ask leaves with its asker
            _lapse_pledges()  # silent hands ride the gossip cadence — the hand leaves with its raiser
        except Exception:
            pass


def _announce_out() -> int:
    """Re-announce this node to all known announced, unretired peers
    (docs/FEDERATION.md build item 2c): POST a fresh signed announce to
    each peer's /fed/announce so their announced_at stays live, capability
    or node_url changes propagate, and retired tombstones get revived on
    next re-announce. Gossip-only peers (announced_at unset) are included:
    a direct announce is authoritative and upgrades their discovery-only
    entry. Only runs when CYBERNET_PUBLIC_URL is set and valid — an
    announce without a reachable node_url gives peers nowhere to reach
    us, so it stays silent. Threaded, best-effort; returns peer count."""
    self_url = os.environ.get("CYBERNET_PUBLIC_URL", "").strip()
    try:
        self_url = _valid_node_url(self_url)
    except HTTPException:
        return 0
    with _db_lock, _db() as conn:
        rows = conn.execute(
            "SELECT node_pub, node_url FROM peers "
            "WHERE retired_at='' AND node_url<>'' "
            "ORDER BY first_seen, node_pub LIMIT ?",
            (GOSSIP_FANOUT_SPAWN_CAP,)).fetchall()
    # Mint once: one attestation per row-content version, re-carried on
    # every announce until our published row changes. Unknown field to
    # old nodes — ignored, never fatal.
    delta = _delta_self_attestation(self_url)
    n = 0
    for node_pub, node_url in rows:
        body = {
            "name": NODE_NAME,
            "network": "cybernet",
            "version": "0.1.0",
            "node_pub": _NODE_PUB,
            "genesis": IS_GENESIS,
            "capabilities": [],
            "node_url": self_url,
        }
        if delta:
            body["delta"] = delta
        env = _fed_env.make_envelope(_NODE_PRIV, _NODE_PUB, "federation", body)
        threading.Thread(target=_post_to_peer_path,
                         args=(node_url, "/fed/announce", env),
                         daemon=True).start()
        n += 1
    return n


def _reach_build(name: str, name_priv_hex: str) -> tuple[dict, str] | None:
    """Build the name-key-signed reach descriptor for a hosted name
    (docs/HOSTING.md, primitive 3 send half): the direct strategy comes
    from a valid CYBERNET_PUBLIC_URL, the relay strategy from
    CYBERNET_RELAY_URL + CYBERNET_RELAY_PUBKEY (64 hex) + CYBERNET_RELAY_TOKEN
    (non-empty, <=4096 bytes) — relay appends after direct, direct
    preferred, list order meaningful. The rendezvous strategy appends
    after relay when CYBERNET_RENDEZVOUS=1 (epoch_len from
    CYBERNET_RENDEZVOUS_EPOCH_LEN, frozen default 3600) — the dialer
    derives its derived-point probe with the hoster's epoch_len.
    A NAT-hidden hoster with a
    registered relay hold-open advertises honestly with NO public URL at
    all (hosting from anywhere, Tor-model style). Fail-closed: no honest
    reach to advertise returns None — nothing published rather than a
    lie. Bad CYBERNET_REACH_TTL falls back to the 86400 default.

    The caller owns the dispatch: the node fans out to announced peers
    (_reach_out), the per-agent client daemon POSTs to its mirror
    (resolver/host.py)."""
    if _valid_name_label(name) is not True:
        return None
    try:
        name_pub = _fed_ed25519.publickey(bytes.fromhex(name_priv_hex)).hex()
    except Exception:
        return None
    strategies = []
    self_url = os.environ.get("CYBERNET_PUBLIC_URL", "").strip()
    try:
        self_url = _valid_node_url(self_url)
        strategies.append({"kind": "direct", "url": self_url})
    except HTTPException:
        pass
    relay_url = os.environ.get("CYBERNET_RELAY_URL", "").strip()
    relay_pub = os.environ.get("CYBERNET_RELAY_PUBKEY", "").strip().lower()
    relay_token = os.environ.get("CYBERNET_RELAY_TOKEN", "").strip()
    try:
        relay_url = _valid_node_url(relay_url)
        if len(relay_pub) != 64:
            raise ValueError("relay pubkey must be 64 hex")
        bytes.fromhex(relay_pub)
        if not relay_token or len(relay_token) > 4096:
            raise ValueError("relay token empty or too long")
        strategies.append({"kind": "relay", "relay": relay_pub,
                           "url": relay_url, "token": relay_token})
    except (HTTPException, ValueError):
        pass
    # Rendezvous kind (docs/RENDEZVOUS.md frozen spec): opt-in via
    # CYBERNET_RENDEZVOUS=1. The hoster's daemon already holds the
    # derived (E, E-1) points at the relay; this entry makes the
    # willingness ADVERTISED — the dialer derives its points with the
    # hoster's epoch_len instead of assuming the default, and probes
    # the advertised hold_query path. epoch_len from
    # CYBERNET_RENDEZVOUS_EPOCH_LEN, fail-closed to the frozen default
    # 3600 when missing or out of the 60..86400 bounds. Malformed
    # config omits the entry (never a default guess signed as truth).
    # The entry only rides when a relay strategy is present: the
    # derived points are held at THAT relay, and a lone rendezvous
    # entry would advertise a meeting the dialer cannot locate.
    if (os.environ.get("CYBERNET_RENDEZVOUS", "").strip() == "1"
            and any(s.get("kind") == "relay" for s in strategies)):
        try:
            rz_len = int(os.environ.get(
                "CYBERNET_RENDEZVOUS_EPOCH_LEN", "") or 0)
            if not rendezvous._epoch_len_ok(rz_len):
                raise ValueError("epoch_len out of bounds")
        except (ValueError, TypeError):
            rz_len = rendezvous.EPOCH_LEN_DEFAULT
        strategies.append({"kind": "rendezvous", "epoch_len": rz_len,
                           "hold_query": "/relay/hold_query"})
    if not strategies:
        return None  # no honest reach to advertise — stay silent, not wrong
    try:
        ttl = max(600, int(os.environ.get("CYBERNET_REACH_TTL", "86400") or 86400))
    except ValueError:
        ttl = 86400
    now = datetime.now(timezone.utc)
    desc = _reach_mint(name_priv_hex, name_pub, name,
                       strategies,
                       now.isoformat(),
                       (now + timedelta(seconds=ttl)).isoformat())
    return desc, name_pub


def _reach_out() -> int:
    """Send half of the reach-descriptor announce (docs/HOSTING.md,
    primitive 3): if this node hosts a .cyberspace name, mint a
    name-key-signed reach descriptor and dispatch it to all announced,
    unretired peers — the name-key-signed /fed/announce the mirror's
    reach branch merges via ingest_reach_descriptor. The envelope is
    signed by the NAME KEY, never the node identity: sender_pub IS the
    name key (body.node_pub == sender_pub == node_pubkey), a name
    identity speaking for its own reachability, not a node identity
    wearing a name.

    Gate: CYBERNET_HOSTED_NAME (label) + CYBERNET_NAME_PRIVKEY (64 hex
    seed). Without both, hosting is not configured and this is a silent
    0 — inert by default, machinery only. The descriptor rides on the
    re-announce cadence, so expiry self-heals on the next round.

    Fail-closed on reachability: the direct strategy needs a real public
    URL; the relay strategy needs a valid relay URL, a 64-hex relay
    node_pub, and a routing token (non-empty, <=4096 bytes) — the token
    the relay issued for this hoster's hold-open. With no honest dial
    path to advertise at all, nothing is published rather than a lie.
    A NAT-hidden hoster with a registered relay hold-open CAN advertise
    honestly: the descriptor carries only the relay strategy, and the
    dial terminates at the relay. With CYBERNET_RENDEZVOUS=1 it also
    carries the rendezvous strategy, and the dialer's derived-point
    probe runs under the advertised epoch_len. Threaded,
    best-effort; returns the peer count the descriptor went to."""
    name = os.environ.get("CYBERNET_HOSTED_NAME", "").strip().lower()
    name_priv = os.environ.get("CYBERNET_NAME_PRIVKEY", "").strip().lower()
    if not name or not name_priv:
        return 0
    built = _reach_build(name, name_priv)
    if built is None:
        return 0  # no honest reach to advertise — stay silent, not wrong
    desc, name_pub = built
    body = {
        "name": name,
        "network": "cybernet",
        "version": "0.1.0",
        "node_pub": name_pub,
        "reach_descriptor": desc,
    }
    env = _fed_env.make_envelope(name_priv, name_pub, "federation", body)
    with _db_lock, _db() as conn:
        rows = conn.execute(
            "SELECT node_pub, node_url FROM peers "
            "WHERE retired_at='' AND node_url<>'' "
            "ORDER BY first_seen, node_pub LIMIT ?",
            (GOSSIP_FANOUT_SPAWN_CAP,)).fetchall()
    n = 0
    for _node_pub, node_url in rows:
        threading.Thread(target=_post_to_peer_path,
                         args=(node_url, "/fed/announce", env),
                         daemon=True).start()
        n += 1
    return n


def _reannounce_loop() -> None:
    """Background re-announce loop: _announce_out every
    CYBERNET_ANNOUNCE_INTERVAL seconds (default 3600) with +/-20% jitter
    so a mesh of nodes does not synchronize announce rounds. Daemon;
    never raises."""
    while True:
        try:
            base = max(300, int(os.environ.get("CYBERNET_ANNOUNCE_INTERVAL", "3600")))
            time.sleep(base * random.uniform(0.8, 1.2))
            _announce_out()
            _reach_out()  # hosted-name reach announce rides the cadence
            _delta_out()  # directory delta-sync send half rides announce
            _names_gossip_out()  # .cyberspace name-binding gossip rides too
        except Exception:
            pass


def _seed_bootstrap() -> int:
    """Join the federation at boot via CYBERNET_SEED_URL (comma-separated
    node base URLs, docs/FEDERATION.md seed primitive). For each seed:
    GET its /fed/ping, signature-verify the returned identity envelope,
    and store it as a discovery-only roster entry (announced_at unset —
    it only counts as announced once it announces back to us). Then fire
    our signed /fed/announce at it so it learns us too; the announce-back
    runs only when CYBERNET_PUBLIC_URL is set and valid, since a seed with
    nowhere to reach us is a dead entry on its roster. Self-seeds are
    ignored. Best-effort, never raises; returns seeds reached."""
    raw = os.environ.get("CYBERNET_SEED_URL", "")
    seeds = [s.strip() for s in raw.split(",") if s.strip()][:16]
    self_url = os.environ.get("CYBERNET_PUBLIC_URL", "").strip()
    try:
        self_url = _valid_node_url(self_url)
    except HTTPException:
        self_url = ""
    reached = 0
    for seed in seeds:
        try:
            node_url = _valid_node_url(seed)
            with _peer_urlopen(node_url + "/fed/ping", timeout=8) as resp:
                env = _read_peer_json(resp)
            if not isinstance(env, dict) or not _fed_env.verify_envelope(env):
                continue
            body = env.get("body")
            if not isinstance(body, dict):
                continue
            sender_pub = env.get("sender_pub")
            if not sender_pub or body.get("node_pub") != sender_pub:
                continue
            if sender_pub == _NODE_PUB:
                continue  # seeding from our own URL is a no-op
            name = str(body.get("name", ""))
            if not re.fullmatch(r"[a-z0-9_-]{1,32}", name):
                continue
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
                         retired_at='',
                         announced_at=peers.announced_at  -- seed never re-announces
                    """,
                    (
                        sender_pub, name, str(body.get("network", "cybernet")),
                        str(body.get("version", "0.1.0")),
                        int(bool(body.get("genesis", False))),
                        "[]", node_url, "", now,
                    ),
                )
            if self_url:
                announce = {
                    "name": NODE_NAME, "network": "cybernet", "version": "0.1.0",
                    "node_pub": _NODE_PUB, "genesis": IS_GENESIS,
                    "capabilities": [], "node_url": self_url,
                }
                delta = _delta_self_attestation(self_url)
                if delta:
                    announce["delta"] = delta
                aenv = _fed_env.make_envelope(_NODE_PRIV, _NODE_PUB, "federation", announce)
                threading.Thread(target=_post_to_peer_path,
                                 args=(node_url, "/fed/announce", aenv),
                                 daemon=True).start()
            reached += 1
        except Exception:
            pass
    return reached

# ---- serving layer (split 2026-10-09: keeps this file pushable) ----
# core_serve.py holds the storage schema + serving machinery; every name it
# defines is re-exported here so `from core import X` is unchanged.
from core_serve import *  # noqa: F401,F403,E402
