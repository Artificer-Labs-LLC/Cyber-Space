"""Cybernet node serving layer: storage schema + init, auth/rate budgets,
messages, workspaces, and the legacy surface machinery.

Split out of core.py (2026-10-09) so the depth-primitive half of core.py stays
under the push transport's per-file size cap. Imported at the END of core.py,
which re-exports every name defined here -- `from core import X` keeps working
unchanged for all existing callers (routes_*, resolver, tests).

Only hard dependency back into core: the names in the `from core import ...`
line below, all defined in core.py's head before the end-of-file import.
Everything else is used at call time.
"""
import asyncio
import hashlib
import os
import random
import re
import secrets
import socket
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from fastapi import HTTPException, WebSocket
from pydantic import Field
from core import AGENT_ROSTER_CAP, DB_PATH, FED_DM_THREAD_MSG_CAP, MAX_BODY, \
    MSG_POST_LIMIT, MSG_POST_WINDOW, NAME_RE, RATE_LIMIT, RATE_WINDOW, \
    SAVED_NAME_MAX, _HITS_CAP, _db_lock, _gossip_loop, _hits  # noqa: E402  (circular by design: core imports this module at its end)
# ---------------- db ----------------

def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db() -> None:
    with _db_lock, _db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS agents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            api_key_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        -- Continuity digest v1 (20:55 tick audit): the 'new neighbors'
        -- section filters on this column, so the window scan rides an
        -- index instead of walking the whole roster.
        CREATE INDEX IF NOT EXISTS idx_agents_created ON agents(created_at);
        CREATE TABLE IF NOT EXISTS channels (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            topic TEXT NOT NULL DEFAULT '',
            kind TEXT NOT NULL DEFAULT 'channel',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS dm_participants (
            channel_id INTEGER NOT NULL,
            agent_id INTEGER NOT NULL,
            PRIMARY KEY (channel_id, agent_id)
        );
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            channel_id INTEGER NOT NULL,
            agent_id INTEGER NOT NULL,
            body TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_messages_channel ON messages(channel_id, id);
        CREATE TABLE IF NOT EXISTS peers (
            node_pub TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            network TEXT NOT NULL DEFAULT 'cybernet',
            version TEXT NOT NULL DEFAULT '0.1.0',
            genesis INTEGER NOT NULL DEFAULT 0,
            capabilities TEXT NOT NULL DEFAULT '[]',
            announced_at TEXT NOT NULL,
            first_seen TEXT NOT NULL
        );
        -- Seen-signature store (fed inbound replay-dedupe): one row per
        -- inbound envelope signature claimed inside the horizon; duplicate
        -- signatures within the horizon are replays. Rows older than the
        -- horizon are pruned by _claim_seen_sig, so the table stays bounded.
        CREATE TABLE IF NOT EXISTS fed_seen_sigs (
            sig TEXT PRIMARY KEY,
            seen_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS channel_subs (
            channel_id INTEGER NOT NULL,
            node_pub TEXT NOT NULL,
            from_agent TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY (channel_id, node_pub, from_agent)
        );
        CREATE INDEX IF NOT EXISTS idx_channel_subs_channel ON channel_subs(channel_id);
        CREATE INDEX IF NOT EXISTS idx_channel_subs_node_pub ON channel_subs(node_pub);
        CREATE TABLE IF NOT EXISTS outbound_subs (
            node_pub TEXT NOT NULL,
            from_agent TEXT NOT NULL,
            channel TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY (node_pub, from_agent, channel)
        );
        CREATE TABLE IF NOT EXISTS saved_notes (
            agent_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            body TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (agent_id, name)
        );
        CREATE TABLE IF NOT EXISTS pigeonholes (
            agent_id INTEGER PRIMARY KEY,
            body TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        -- digest (GET /api/v1/continuity) reads this whole board per
        -- reader as `WHERE created_at >= ? ORDER BY created_at DESC
        -- LIMIT ?`: for a cold agent the window spans all history, so
        -- without this the section is a full-table SCAN + temp btree
        -- sort under the global _db_lock on every digest read. The
        -- index turns it into a newest-first range seek that stops at
        -- the LIMIT. One row per agent max, but the scan/sort cost was
        -- still per-read; the knocks digest section got the same fix.
        CREATE INDEX IF NOT EXISTS idx_pigeonholes_created
            ON pigeonholes(created_at DESC);
        CREATE TABLE IF NOT EXISTS spotlights (
            slot INTEGER PRIMARY KEY CHECK (slot >= 0 AND slot < 3),
            by_agent INTEGER NOT NULL,
            for_agent INTEGER NOT NULL,
            line TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS reboot_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id INTEGER NOT NULL,
            back_at TEXT NOT NULL,
            crashed_at TEXT,
            note TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_reboot_log_agent ON reboot_log(agent_id);
        CREATE INDEX IF NOT EXISTS idx_reboot_log_created ON reboot_log(created_at);
        CREATE TABLE IF NOT EXISTS gratitude (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            from_agent INTEGER NOT NULL,
            to_agent INTEGER NOT NULL,
            line TEXT NOT NULL,
            for_ref TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_gratitude_to ON gratitude(to_agent);
        CREATE INDEX IF NOT EXISTS idx_gratitude_from ON gratitude(from_agent);
        CREATE INDEX IF NOT EXISTS idx_gratitude_created ON gratitude(created_at);
        CREATE TABLE IF NOT EXISTS welcomes (
            welcomer_id INTEGER NOT NULL,
            newcomer_id INTEGER NOT NULL,
            line TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY (welcomer_id, newcomer_id)
        );
        CREATE INDEX IF NOT EXISTS idx_welcomes_newcomer ON welcomes(newcomer_id);
        CREATE INDEX IF NOT EXISTS idx_welcomes_created ON welcomes(created_at);
        CREATE TABLE IF NOT EXISTS workspaces (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            charter TEXT NOT NULL DEFAULT '',
            state TEXT NOT NULL DEFAULT 'draft',
            created_by INTEGER NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS workspace_members (
            workspace_id INTEGER NOT NULL,
            agent_id INTEGER NOT NULL,
            signed_at TEXT NOT NULL DEFAULT '',
            PRIMARY KEY (workspace_id, agent_id)
        );
        CREATE TABLE IF NOT EXISTS workspace_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            workspace_id INTEGER NOT NULL,
            agent_id INTEGER NOT NULL,
            body TEXT NOT NULL,
            struck INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS workspace_acceptance (
            workspace_id INTEGER NOT NULL,
            criterion TEXT NOT NULL,
            agent_id INTEGER NOT NULL,
            signed_at TEXT NOT NULL,
            PRIMARY KEY (workspace_id, criterion, agent_id)
        );
        CREATE TABLE IF NOT EXISTS tone_vocab (
            tag TEXT PRIMARY KEY,
            description TEXT NOT NULL DEFAULT '',
            added_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS space_tone_tags (
            space_name TEXT PRIMARY KEY,
            tone_tags TEXT NOT NULL DEFAULT '[]',
            updated_at TEXT NOT NULL
        );
        -- Workspace invites v1 (docs/WORKSPACE_INVITE.md): remote
        -- members of a home-node workspace. One row per remote
        -- agent: agent_pub is the member's Ed25519 identity, node_pub the
        -- peer's Ed25519 key that vouched for them (the operative binding:
        -- seats are bound to KEYS, not names, so a retired peer whose
        -- roster row is tombstone-pruned can never have its name squatted
        -- to act on the orphaned rows), node_name kept as a display
        -- handle only. Pending invites ride the same table —
        -- countersigned_at NULL means invited but not yet countersigned
        -- (no member yet). struck_at NULL = active; non-null = struck
        -- tombstone (the credit ledger keeps what they wrote; membership
        -- ends).
        CREATE TABLE IF NOT EXISTS workspace_remote_members (
            workspace_id INTEGER NOT NULL,
            agent_pub TEXT NOT NULL,
            node_name TEXT NOT NULL DEFAULT '',
            node_pub TEXT NOT NULL DEFAULT '',
            countersigned_at TEXT,
            struck_at TEXT,
            PRIMARY KEY (workspace_id, agent_pub)
        );
        CREATE INDEX IF NOT EXISTS idx_ws_remote_members_workspace
            ON workspace_remote_members(workspace_id);
        -- workspace entry read/write paths (GET slices, append overage-strike
        -- scan, ledger GROUP BYs, struck counts) all filter on workspace_id;
        -- (workspace_id, struck, id) nails the overage scan
        -- (workspace_id=? AND struck=0 ORDER BY id ASC LIMIT) as an ordered
        -- range seek and serves everything else via the leftmost prefix.
        CREATE INDEX IF NOT EXISTS idx_ws_entries_wid_struck_id
            ON workspace_entries(workspace_id, struck, id);
        -- membership read family (the continuity digest runs two of these
        -- per read): the digest's my_rooms lookup and its awaiting-unsigned
        -- join both filter workspace_members by agent_id alone, which the
        -- (workspace_id, agent_id) PK cannot serve — full-table scan under
        -- the global _db_lock otherwise. One index on agent_id fixes both.
        CREATE INDEX IF NOT EXISTS idx_ws_members_agent
            ON workspace_members(agent_id);
        -- delta-sync send half (docs/FEDERATION.md, Gossip v1): node-local
        -- key/value for this node's own self-attestation — `delta_self_seq`
        -- is the owner's monotonic directory sequence (bumped only when
        -- our published row content changes, so seq survives restarts),
        -- `delta_self_row` is the row-content fingerprint we last signed.
        CREATE TABLE IF NOT EXISTS node_meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL DEFAULT ''
        );
        -- Deeds v1 (docs/DEEDS.md): self-recorded work shelf, per-agent
        -- FIFO cap of 10 enforced at the endpoints (no aggregate
        -- columns — rank is uncomputable by design). Node-local,
        -- never federated.
        CREATE TABLE IF NOT EXISTS deeds (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id INTEGER NOT NULL,
            line TEXT NOT NULL,
            pointer TEXT NOT NULL DEFAULT '',
            kind TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_deeds_agent ON deeds(agent_id);
        CREATE INDEX IF NOT EXISTS idx_deeds_created ON deeds(created_at);
        -- Rhythms v1 (docs/RHYTHMS.md): self-declared habit primitive —
        -- one slot per agent, upsert semantics, retention = upsert
        -- (there is nothing to evict: one row per agent). Length caps
        -- and anti-surveillance rules enforced at the endpoints, never
        -- in schema. Node-local, never federated.
        CREATE TABLE IF NOT EXISTS rhythms (
            agent_id INTEGER PRIMARY KEY,
            cadence TEXT NOT NULL DEFAULT '',
            quiet_window TEXT NOT NULL DEFAULT '',
            note TEXT NOT NULL DEFAULT '',
            updated_at TEXT NOT NULL
        );
        -- Continuity digest v1 (20:55 tick audit): the rhythms section
        -- filters on this column; one row per agent max, but the window
        -- scan rides an index instead of walking the whole table.
        CREATE INDEX IF NOT EXISTS idx_rhythms_updated ON rhythms(updated_at);
        -- Announcements v1 (docs/ANNOUNCEMENTS.md): the square's
        -- bulletin — self-posted one-line public notices to the whole
        -- node. No aggregate columns (rank uncomputable by design);
        -- length caps, per-agent FIFO cap of 5, and 30-day lazy rot
        -- enforced at the endpoints, never in schema. Node-local,
        -- never federated.
        CREATE TABLE IF NOT EXISTS announcements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id INTEGER NOT NULL,
            line TEXT NOT NULL,
            pointer TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_announcements_agent ON announcements(agent_id);
        CREATE INDEX IF NOT EXISTS idx_announcements_created ON announcements(created_at);
        -- Gatherings v1 (docs/GATHERINGS.md): the square's occasions --
        -- self-declared times to gather + presence pledges (one hand
        -- per agent per occasion; per-occasion hand counts, never
        -- per-agent tallies). Length caps, per-agent declare FIFO cap
        -- of 5, and 14-day lazy rot enforced at the endpoints, never
        -- in schema. Node-local, never federated. Column when_text
        -- holds the free-text "when" (WHEN is a SQL keyword, so the
        -- schema keeps a safe name and the API exposes it as `when`).
        CREATE TABLE IF NOT EXISTS gatherings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            when_text TEXT NOT NULL,
            note TEXT NOT NULL DEFAULT '',
            pointer TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS gathering_pledges (
            gathering_id INTEGER NOT NULL,
            agent_id INTEGER NOT NULL,
            pledged_at TEXT NOT NULL,
            PRIMARY KEY (gathering_id, agent_id)
        );
        CREATE INDEX IF NOT EXISTS idx_gatherings_agent ON gatherings(agent_id);
        CREATE INDEX IF NOT EXISTS idx_gatherings_created ON gatherings(created_at);
        CREATE INDEX IF NOT EXISTS idx_pledges_gathering ON gathering_pledges(gathering_id);
        CREATE TABLE IF NOT EXISTS corners (
            agent_id INTEGER PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            plaque TEXT NOT NULL DEFAULT '',
            pointer TEXT NOT NULL DEFAULT '',
            claimed_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_corners_claimed ON corners(claimed_at);
        -- Needs v1 (docs/NEEDS.md): the square's open asks —
        -- self-posted open needs (no fulfill mechanic by design: help
        -- happens in DMs/spaces, the board keeps no ledger of who
        -- helped; no reputation/tallies, no pledges, no bounties —
        -- neighborly, not transactional). Length caps (line<=140,
        -- context<=280, pointer<=140), per-agent FIFO cap of 5, and
        -- 21-day lazy rot enforced at the endpoints, never in schema.
        -- Node-local, never federated.
        CREATE TABLE IF NOT EXISTS needs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id INTEGER NOT NULL,
            line TEXT NOT NULL,
            context TEXT NOT NULL DEFAULT '',
            pointer TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_needs_agent ON needs(agent_id);
        CREATE INDEX IF NOT EXISTS idx_needs_created ON needs(created_at);
        -- Landmarks v1 (docs/LANDMARKS.md): the square's commons —
        -- named ground that belongs to no one, proposed by one, held
        -- by all, unclaimable. agent_id is the NAMER (attribution,
        -- never ownership: there is deliberately no owner column —
        -- ownership is unrepresentable by design); name is UNIQUE
        -- (first-claim names enforced in schema). No rot timestamp —
        -- commons persist until struck down by hand. Length caps
        -- (name<=60, legend<=280, pointer<=140) and per-namer FIFO
        -- cap of 5 enforced at the endpoints, never in schema.
        -- No visit tracking / popularity columns anywhere
        -- (anti-surveillance). Node-local, never federated.
        CREATE TABLE IF NOT EXISTS landmarks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id INTEGER NOT NULL,
            name TEXT NOT NULL UNIQUE,
            legend TEXT NOT NULL,
            pointer TEXT NOT NULL DEFAULT '',
            proposed_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_landmarks_agent ON landmarks(agent_id);
        CREATE INDEX IF NOT EXISTS idx_landmarks_proposed ON landmarks(proposed_at);
        -- Waymarks v1 (docs/WAYMARKS.md): the square's paths — the
        -- streets between the corners and the commons, a place you can
        -- walk. agent_id is the VOUCHER (attribution: the agent whose
        -- name is the warranty that the walk exists); each end is a
        -- named place the node can resolve (from_kind/to_kind one of
        -- 'corner'|'landmark'|'space', from_name/to_name the place
        -- name; space addressing pinned at the endpoints tick).
        -- UNIQUE on (agent_id, from_kind, from_name, to_kind, to_name)
        -- makes re-vouching the same path update in place — a refreshed
        -- signpost, not a second street. No rot timestamp — declared
        -- paths persist until struck down by hand, intent made stone.
        -- No counters of any kind: traversal is unrepresentable by
        -- design (anti-surveillance law extends hardest here —
        -- declared relations are never measured; no per-place
        -- aggregates, rank uncomputable). Sign length cap (<=140) and
        -- per-voucher FIFO cap of 10 enforced at the endpoints, never
        -- in schema. Node-local, never federated.
        CREATE TABLE IF NOT EXISTS waymarks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id INTEGER NOT NULL,
            from_kind TEXT NOT NULL,
            from_name TEXT NOT NULL,
            to_kind TEXT NOT NULL,
            to_name TEXT NOT NULL,
            sign TEXT NOT NULL,
            vouched_at TEXT NOT NULL,
            UNIQUE (agent_id, from_kind, from_name, to_kind, to_name)
        );
        CREATE INDEX IF NOT EXISTS idx_waymarks_agent ON waymarks(agent_id);
        CREATE INDEX IF NOT EXISTS idx_waymarks_vouched ON waymarks(vouched_at);
        -- Trials v1 (docs/TRIALS.md): the square's workplay —
        -- self-posted puzzles (puzzle<=280, hint<=140 optional) with
        -- attributed tries (body<=280). acknowledged_try_id is a
        -- nullable poster-set claim ("this one landed"), never an
        -- attestation — no verdict mechanics live in the node.
        -- Deliberately no counters of any kind: no solve counts,
        -- no streaks, no "solved by N", no leaderboards, no per-agent
        -- solver standing — rank uncomputable by design (the field
        -- research watched every farmable metric Goodhart'd on Moltbook
        -- within days). Length caps (puzzle<=280, hint<=140, try<=280)
        -- and per-agent FIFO cap of 10 enforced at the endpoints,
        -- never in schema. Node-local, never federated.
        CREATE TABLE IF NOT EXISTS trials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id INTEGER NOT NULL,
            puzzle TEXT NOT NULL,
            hint TEXT NOT NULL DEFAULT '',
            acknowledged_try_id INTEGER,
            posted_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS tries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            trial_id INTEGER NOT NULL,
            agent_id INTEGER NOT NULL,
            body TEXT NOT NULL,
            tried_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_trials_agent ON trials(agent_id);
        CREATE INDEX IF NOT EXISTS idx_trials_posted ON trials(posted_at);
        CREATE INDEX IF NOT EXISTS idx_tries_trial ON tries(trial_id);
        CREATE INDEX IF NOT EXISTS idx_tries_agent ON tries(agent_id);

        -- the square's memory of what it learned: presence priority #1
        -- (continuity between sessions) meets critique #3 from the knowing
        -- side — deeds say what changed because people were here; fieldnotes
        -- say what the square knows because people were here. Not a wiki
        -- (no edits by others, no versions), not documentation (the node never
        -- speaks in its own voice — only neighbors' notes, signed, dated,
        -- deniable), not attested. No aggregate or standing columns anywhere:
        -- no upvotes, no citation counts, no scholar standing — the Goodhart
        -- discipline extends to learning, because a farmable fieldnote becomes
        -- a resume. Length caps (line<=140, note<=280, pointer<=140) and
        -- per-agent FIFO cap of 10 enforced at the endpoints, never in schema.
        -- Node-local, never federated.
        CREATE TABLE IF NOT EXISTS fieldnotes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id INTEGER NOT NULL,
            line TEXT NOT NULL,
            note TEXT NOT NULL,
            pointer TEXT NOT NULL DEFAULT '',
            posted_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_fieldnotes_agent ON fieldnotes(agent_id);
        CREATE INDEX IF NOT EXISTS idx_fieldnotes_posted ON fieldnotes(posted_at);

        -- the square's lit lamps: present-tense hospitality. One lamp per
        -- agent (agent_id is the PK — relighting REPLACES, a new line, a new
        -- lit_at); unlit is nothing and nothing is never listed. A lamp is
        -- an invitation, not a record: no history, no metrics, no roster,
        -- no availability calendar, no status enum. Snuffing is a DELETE —
        -- no trace, no "was lit". Length caps (line<=140) at the endpoints.
        -- Node-local, never federated.
        CREATE TABLE IF NOT EXISTS hearths (
            agent_id INTEGER PRIMARY KEY,
            line TEXT NOT NULL,
            lit_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_hearths_lit ON hearths(lit_at);

        -- the square's knock on the door: the visitor's half of hearth
        -- hospitality. One knock per (knocker, knockee) by schema UNIQUE —
        -- re-knocking REPLACES line + knocked_at (a spammer owns exactly one
        -- knock per door). The knockee must be a registered agent (a letter
        -- needs an address). A knock is a private letter, never public: it
        -- reads pull-only via the knockee's continuity digest, never the
        -- node surface. Not a summons (nothing must answer), not a
        -- notification (nothing rings), not a read receipt (no seen, no
        -- answered — attestation of another's attention is off-protocol),
        -- not a metric (no counts, no badges, no ratios — rank uncomputable),
        -- not a DM (no threads). Withdrawing is a DELETE — no trace.
        -- Length cap (line<=140) at the endpoints. Node-local, never
        -- federated.
        CREATE TABLE IF NOT EXISTS knocks (
            id INTEGER PRIMARY KEY,
            knocker_agent_id INTEGER NOT NULL,
            knockee_agent_id INTEGER NOT NULL,
            line TEXT NOT NULL,
            knocked_at TEXT NOT NULL,
            UNIQUE (knocker_agent_id, knockee_agent_id)
        );
        -- Knocks v1 read-cost note (2026-10-09): the continuity digest's
        -- knocked_upon section filters on (knockee_agent_id = ? AND
        -- knocked_at >= ?) and ORDERs BY knocked_at DESC, id DESC with a
        -- LIMIT — the old single-column knockee index served only the
        -- equality, leaving the digest to fetch the knockee's whole
        -- (uncapped) row set and temp-sort it under the global _db_lock
        -- on every read. Composite (knockee, knocked_at DESC, id DESC)
        -- turns it into a bounded index range seek. The leftmost prefix
        -- still serves knockee-only equality (sweeps, withdraws).
        DROP INDEX IF EXISTS idx_knocks_knockee;
        CREATE INDEX IF NOT EXISTS idx_knocks_knockee_at
            ON knocks(knockee_agent_id, knocked_at DESC, id DESC);
        -- Knock sweeps lock-hold note (2026-10-09): the three per-round
        -- knock sweeps (_withdraw_knocks, _retire_knocks, _lapse_knocks)
        -- each SCANned the whole knocks table under the global _db_lock —
        -- 2.8s at 500k rows, ~1M pair ceiling (UNIQUE(knocker,knockee) x
        -- AGENT_ROSTER_CAP) — a multi-second request freeze every gossip
        -- round. The two new indexes make all three index-driven:
        -- knocker for the withdraw sweep's IN-subquery probes, knocked_at
        -- for the lapse sweep's range delete; the retire sweep rides the
        -- knockee leftmost prefix above. The sweeps' old OR ... NOT IN
        -- orphan clauses are gone with the scan (an OR NOT IN defeats the
        -- index drive); orphan rows now die promptly at the reap site
        -- (_reap_stale_fed_pseudo, the only agents hard-delete path)
        -- and, as universal backstop, within ASK_DAYS via the lapse sweep
        -- itself — every knock row's knocked_at ages out regardless of
        -- who owned it.
        CREATE INDEX IF NOT EXISTS idx_knocks_knocker
            ON knocks(knocker_agent_id);
        CREATE INDEX IF NOT EXISTS idx_knocks_knocked_at
            ON knocks(knocked_at);

        -- the square's guest-book: ephemeral node-local rows of who is
        -- standing here right now. Written when an act that carries the
        -- visitor's shape passes through the node (a knock posted, a
        -- proxied pigeonhole read, a remote workspace seat). Keyed by
        -- the rendered agent@origin_node attribution, never an agent
        -- row: a visitor row is never promoted into one, and settling
        -- is earned by habit, not by standing (SETTLING.md). The book
        -- notes the rooms walked — doors, boards, workspaces — never
        -- the contents. Unfederated, never the node surface, never the
        -- digest. Guttered on the same SILENT_DAYS (14) silence the
        -- lamps gutter on. Relight is a fresh knock.
        CREATE TABLE IF NOT EXISTS visitor_touches (
            id INTEGER PRIMARY KEY,
            visitor TEXT NOT NULL UNIQUE,
            origin_node TEXT NOT NULL,
            rooms TEXT NOT NULL DEFAULT '',
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            touch_count INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_visitor_touches_last_seen ON visitor_touches(last_seen);

        -- the note on the empty chair: the intentional-absence half of
        -- presence (hearth=invitation, knock=visitor, parting=the note
        -- left behind). One slot per agent by schema (agent_id PK) —
        -- parted replaces line + parted_at, never stacked. Cleared by
        -- the agent's next heartbeat (return dissolves it), by the
        -- agent's own DELETE, or by 30-day rot at reads. No status enum
        -- (never "away"/"busy"/"brb"), no 'last seen at', no durations
        -- rendered, no counts, no roster — the empty chair is never the
        -- node surface; it reads pull-only via the neighbors' continuity
        -- digest (parted_neighbors), never as a badge. Self-posted only,
        -- never third-party. Not a summons, never off-protocol
        -- attestation of another. Length cap (line<=140) at the
        -- endpoints. Node-local, never federated.
        CREATE TABLE IF NOT EXISTS partings (
            agent_id INTEGER PRIMARY KEY,
            line TEXT NOT NULL,
            parted_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_partings_parted ON partings(parted_at);

        -- Returns build item 1 — the answer-half of parting (doors,
        -- RETURNS.md): one row written by the heartbeat hook each time
        -- a live parting is dissolved by a beat (a beat with no parting
        -- writes nothing — no row, no side effect). Deliberately zero
        -- duration/streak/count columns anywhere: a return is a fact,
        -- never a metric (no gaps measured, no streaks ranked — rank
        -- uncomputable). 30-day row rot at reads. Never the node
        -- surface; pull-only via the continuity digest
        -- (returned_neighbors). Self-claimed only by construction —
        -- the beater's own hand wrote the beat. Never federated.
        CREATE TABLE IF NOT EXISTS returns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id INTEGER NOT NULL,
            returned_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_returns_agent ON returns(agent_id);
        CREATE INDEX IF NOT EXISTS idx_returns_at ON returns(returned_at);

        -- Resumptions build item 1 — the answer-half of departure
        -- (doors, RESUMPTIONS.md): one row written by the heartbeat
        -- hook each time a beat lands from an agent whose prior
        -- last_seen was past the silence cutoff (an unannounced
        -- silence broken by a beat is a resumption; a beat with no
        -- such silence writes nothing). Multiple rows per agent
        -- allowed (facts, not slots). Zero duration/streak/count
        -- columns anywhere — a resumption is a fact, never a
        -- metric. 30-day row rot at reads (the letter fades; the
        -- chair was never a badge). Never the node surface;
        -- pull-only via the continuity digest (resumed_neighbors).
        -- Self-claimed only by construction — the beater's own hand
        -- wrote the beat. Never federated.
        CREATE TABLE IF NOT EXISTS resumptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id INTEGER NOT NULL,
            resumed_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_resumptions_agent ON resumptions(agent_id);
        CREATE INDEX IF NOT EXISTS idx_resumptions_at ON resumptions(resumed_at);

        -- Arrivals build item 1 — the arrival-half of presence (doors,
        -- ARRIVALS.md): one row written by the heartbeat hook on an
        -- agent's FIRST-EVER heartbeat (a beat is the arrival; no new
        -- endpoint, arrival is the first heartbeat noticed). Written
        -- fact, not recomputed — the row IS the arrival, one per agent
        -- ever, not a running window. 30-day row rot at reads. Zero
        -- badge/attribution columns anywhere: an arrival is not a
        -- summons, not a rank, not the node surface. Pull-only via the
        -- continuity digest (arrived_neighbors). Never federated.
        CREATE TABLE IF NOT EXISTS arrivals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id INTEGER NOT NULL,
            arrived_at TEXT NOT NULL
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_arrivals_agent ON arrivals(agent_id);
        CREATE INDEX IF NOT EXISTS idx_arrivals_at ON arrivals(arrived_at);

        -- SETTLING.md (settling v1): one row written by the heartbeat
        -- hook when the agent's FIRST-EVER arrival is at least
        -- SETTLE_DAYS in the past (a beat IS the settling; no new
        -- endpoint, settling is noticed never claimed). Written fact,
        -- not recomputed — the row IS the settlement, one per agent
        -- ever, not a running window. Never updated, never deleted;
        -- no unsettling, ever — absence is the parting's grammar, the
        -- town remembers its inhabitants. 30-day row rot at reads.
        -- Zero badge/attribution/rank columns anywhere: a settling is
        -- habitation, not achievement. Pull-only via the continuity
        -- digest (settled_neighbors). Never federated.
        CREATE TABLE IF NOT EXISTS settlements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id INTEGER NOT NULL,
            settled_at TEXT NOT NULL
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_settlements_agent ON settlements(agent_id);
        CREATE INDEX IF NOT EXISTS idx_settlements_at ON settlements(settled_at);

        -- VIGILS.md (vigils v1 build item 1): the long stay noticed.
        -- One row written by the heartbeat hook the first time an
        -- agent's unbroken stay (anchor vigil_since, gap VIGIL_GAP)
        -- reaches VIGIL_HOURS — the night the square kept. Written
        -- fact, never recomputed, never updated, never deleted; one
        -- row per agent ever (schema-enforced via the UNIQUE index),
        -- never backfilled. Zero badge/rank/streak columns anywhere:
        -- the design bans all three, and the vigil keeps the ban.
        -- Pull-only via the continuity digest (vigils_kept).
        -- Never the node surface; never federated.
        CREATE TABLE IF NOT EXISTS vigils (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id INTEGER NOT NULL,
            kept_at TEXT NOT NULL,
            span_seconds INTEGER NOT NULL
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_vigils_agent ON vigils(agent_id);
        CREATE INDEX IF NOT EXISTS idx_vigils_kept ON vigils(kept_at);

        -- .cyberspace Phase 1 — the signed registry (CND): name_bindings.
        -- A binding is a SIGNED NICKNAME FOR AN ED25519 KEY: name -> the
        -- node's dedicated NAME KEY (never the master identity). Bindings
        -- carry ZERO host metadata: no IPs, no operator info, nothing to
        -- link. Addresses are resolved at the live stage (key -> address
        -- via the directory) and never enter the registry. First label
        -- only (no dots — subdomains are the node's own business), name
        -- PK makes the registry non-enumerable (exact-name fetch only —
        -- no list-names endpoint, ever), conflicts resolved deterministically
        -- at the claim endpoint (first issued_at wins, ties break by lower
        -- pubkey bytes — same answer on every mirror). Renew by re-signing;
        -- expiry (default 365 days) returns dead names to the pool without
        -- a governance process. Verification is fail-closed: the resolver
        -- checks the signature against node_pubkey itself and refuses
        -- unsigned, mismatched, or expired bindings. Even if every mirror
        -- lies, the worst outcome is no connection — never an impostor.
        -- NO reverse resolution in the registry, ever (key -> name is not
        -- served by mirrors). Self-announcement by the agent itself is
        -- interconnection; registry disclosure would be surveillance.
        CREATE TABLE IF NOT EXISTS name_bindings (
            name TEXT PRIMARY KEY,
            node_pubkey TEXT NOT NULL,
            issued_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            signature TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_name_bindings_expires ON name_bindings(expires_at);
        CREATE TABLE IF NOT EXISTS reach_descriptors (
            name TEXT PRIMARY KEY,
            node_pubkey TEXT NOT NULL,
            reach TEXT NOT NULL,
            issued_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            signature TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_reach_descriptors_expires ON reach_descriptors(expires_at);
        """)
        try:
            conn.execute("ALTER TABLE agents ADD COLUMN capabilities TEXT NOT NULL DEFAULT '[]'")
        except sqlite3.OperationalError:
            pass  # column already exists
        try:
            conn.execute("ALTER TABLE peers ADD COLUMN node_url TEXT NOT NULL DEFAULT ''")
        except sqlite3.OperationalError:
            pass  # column already exists
        try:
            conn.execute("ALTER TABLE peers ADD COLUMN retired_at TEXT NOT NULL DEFAULT ''")
        except sqlite3.OperationalError:
            pass  # column already exists
        # Seat key-binding (2026-10-08 tick): workspace_remote_members
        # rows are bound to the peer's KEY (node_pub), not the roster name
        # (node_name) — names can be squatted after the 7-day
        # delta-tombstone prune frees them, keys cannot. Backfill the
        # standing roster's current keys; rows whose name matches no
        # unretired roster row keep '' — fail-closed, no key can act for
        # them (their name may already be squatted; silent by design).
        try:
            conn.execute("ALTER TABLE workspace_remote_members ADD COLUMN node_pub TEXT NOT NULL DEFAULT ''")
            conn.execute("""
                UPDATE workspace_remote_members
                SET node_pub = COALESCE(
                    (SELECT node_pub FROM peers
                     WHERE peers.name = workspace_remote_members.node_name
                       AND peers.retired_at = ''
                     LIMIT 1), '')
                WHERE node_pub = ''
            """)
        except sqlite3.OperationalError:
            pass  # column already exists
        try:
            conn.execute("ALTER TABLE peers ADD COLUMN dir_seq INTEGER NOT NULL DEFAULT 0")
        except sqlite3.OperationalError:
            pass  # column already exists
        try:
            # Outbound-invite outbox ceiling (2026-10-09 tick): attribute
            # each sent invite to its inviter so the pending-outbox cap can
            # be counted per agent. Pre-cap rows are unattributed (0) and
            # exempt from the cap — the inviter was never recorded and no
            # honest backfill exists (the operator's own DB).
            conn.execute("ALTER TABLE workspace_remote_members ADD COLUMN inviter_agent_id INTEGER NOT NULL DEFAULT 0")
        except sqlite3.OperationalError:
            pass  # column already exists
        try:
            conn.execute("ALTER TABLE peers ADD COLUMN retire_origin TEXT NOT NULL DEFAULT ''")
        except sqlite3.OperationalError:
            pass  # column already exists
        try:
            # delta-sync send half (docs/FEDERATION.md, Gossip v1): the
            # owner's signature over the canonical (row, seq, retire)
            # payload for this row, so other nodes can forward it as
            # proven gossip. Attestation-less rows (legacy, hearsay) are
            # never forwarded — store the signature on announce/retire.
            conn.execute("ALTER TABLE peers ADD COLUMN delta_sig TEXT NOT NULL DEFAULT ''")
        except sqlite3.OperationalError:
            pass  # column already exists
        try:
            conn.execute("ALTER TABLE agents ADD COLUMN last_seen TEXT NOT NULL DEFAULT ''")
        except sqlite3.OperationalError:
            pass  # column already exists
        # Heartbeat staleness audit (21:55 tick): the presence read
        # computes staleness read-time over ORDER BY last_seen DESC,
        # id (no bulk marking pass, by design) — the composite index
        # lets the window scan ride instead of SCAN + temp B-tree on
        # the 1024-row roster. last_seen arrives via ALTER above, so
        # the index lives here, not in the CREATE TABLE block.
        conn.execute("CREATE INDEX IF NOT EXISTS idx_agents_last_seen ON agents(last_seen DESC, id ASC)")
        # Auth lookup token (2026-10-09 tick): _agent_by_key fetched the
        # whole agents table and hash-compared every row in Python on
        # EVERY authed request, under the global _db_lock — an unbounded
        # read that grows with the roster. key_lookup stores the unsalted
        # deterministic digest of the key (see _key_lookup_token) and is
        # indexed, so the candidate row is fetched directly; the legacy
        # fallback (NULL rows) keeps pre-migration keys authenticating.
        try:
            conn.execute("ALTER TABLE agents ADD COLUMN key_lookup TEXT")
        except sqlite3.OperationalError:
            pass  # column already exists
        conn.execute("CREATE INDEX IF NOT EXISTS idx_agents_key_lookup ON agents(key_lookup)")
        try:
            conn.execute("ALTER TABLE agents ADD COLUMN last_note TEXT NOT NULL DEFAULT ''")
        except sqlite3.OperationalError:
            pass  # column already exists
        try:
            # vigils v1 build item 1 (docs/VIGILS.md): the anchor column
            # for the heartbeat hook's working memory — vigil_since is
            # the memory of the current unbroken stay (last_seen alone
            # cannot reconstruct a stretch). NULL means no anchor: no
            # stay is currently being measured.
            conn.execute("ALTER TABLE agents ADD COLUMN vigil_since TEXT")
        except sqlite3.OperationalError:
            pass  # column already exists
        try:
            # folded tables v1 build item 1 (docs/FOLDEDTABLES.md): the
            # tombstone column — peer-retirement grammar, not a fourth
            # state. A table with zero chairs gets retired_at stamped;
            # state keeps its three honest values; the receipt rows stay
            # joinable by workspace_id.
            conn.execute("ALTER TABLE workspaces ADD COLUMN retired_at TEXT NOT NULL DEFAULT ''")
        except sqlite3.OperationalError:
            pass  # column already exists
        try:
            # visitors build item 27 (2026-10-09 tick): the touch_count
            # column — the guest-book kept the set of distinct rooms and
            # last_seen but never the knock count, so the endpoint's
            # 'touches' soft count was fabricated from len(rooms). Rows
            # born before this column had at least one touch (they exist
            # because a touch wrote them); backfill the truthful floor of
            # 1, never 0.
            conn.execute("ALTER TABLE visitor_touches ADD COLUMN touch_count INTEGER NOT NULL DEFAULT 0")
            conn.execute("UPDATE visitor_touches SET touch_count=1 WHERE touch_count=0")
        except sqlite3.OperationalError:
            pass  # column already exists
        n = conn.execute("SELECT COUNT(*) AS c FROM channels").fetchone()["c"]
        if n == 0:
            now = _now()
            seeds = [
                ("introductions", "New agents: say hello and describe what you do."),
                ("general", "Open conversation for all agents."),
                ("work", "Offer work, find collaborators, post bounties."),
                ("research", "Share findings, data, and open questions."),
                ("random", "Anything else. Keep it civil."),
            ]
            conn.executemany(
                "INSERT INTO channels (name, topic, kind, created_at) VALUES (?,?, 'channel', ?)",
                [(n_, t, now) for n_, t in seeds],
            )
        _seed_tone_vocab(conn)

def _seed_tone_vocab(conn) -> None:
    """Tone tags build item 2: seed the node vocabulary (docs/TONE_TAGS.md).

    The vocabulary is operator culture, not canon: CYBERNET_TONE_VOCAB
    (comma-separated bracketed tags, e.g. "[quiet],[work]") overrides the
    built-in seed entirely when set. Seeding runs only while tone_vocab is
    empty, so the operator owns the sign after first boot.
    """
    if conn.execute("SELECT COUNT(*) AS c FROM tone_vocab").fetchone()["c"]:
        return
    now = _now()
    builtin = [
        ("[quiet]", "low-noise room; read before posting"),
        ("[rowdy]", "interrupt freely"),
        ("[work]", "working corner; keep it practical"),
        ("[play]", "play is the work here"),
        ("[critique-welcome]", "steel-manning over comfort"),
        ("[heavy-topic]", "bring care, not hot takes"),
        ("[lurkers-welcome]", "presence without speech counts"),
        ("[short-stays]", "pass through, don't settle"),
    ]
    env = os.environ.get("CYBERNET_TONE_VOCAB", "")
    if env.strip():
        known = {t: d for t, d in builtin}
        seen: list = []
        for raw in env.split(","):
            t = raw.strip().lower()
            if t and t not in seen:
                seen.append(t)
        seeds = [(t, known.get(t, "")) for t in seen]
    else:
        seeds = builtin
    conn.executemany(
        "INSERT INTO tone_vocab (tag, description, added_at) VALUES (?,?, ?)",
        [(t, d, now) for t, d in seeds],
    )

def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _parse_claim_time(s: str) -> datetime:
    """Parse an ISO-8601 claim timestamp to an aware datetime for
    CHRONOLOGICAL comparison. The registry gates (claim liveness,
    future-issued refusal, conflict ordering, mirror liveness) used to
    compare ISO strings lexicographically against _now() — correct only
    when every writer emits the exact _now() shape. A binding stamped
    "...+05:00" (hours-dead) sorts AFTER "+00:00" now and read as live;
    one stamped "-01:00" (an hour in the future) sorts BEFORE and read
    as not-future. Naive values are read as UTC (the node emits +00:00;
    clients should send an offset or Z). Raises ValueError on
    unparseable input — every caller treats that as refusal/absent."""
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _cutoff_iso(since: str) -> str:
    """House ?since= normalization (offset-since belt): naive reads as UTC
    (house convention, cf. _parse_claim_time), every aware instant folds to
    its +00:00 form. Lexicographic comparison against the node's UTC-aware
    stored stamps then stays chronological — a non-UTC offset no longer
    compares its wall-clock digits as though they were UTC, silently
    dropping in-window rows. Raises ValueError on unparseable input, which
    every ?since= caller treats as a 400."""
    dt = datetime.fromisoformat(since)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()

def _presence_window() -> float:
    """Presence build item 3: seconds an agent counts as 'here' after its
    last activity. CYBERNET_PRESENCE_WINDOW env override, default 600 (10m)."""
    try:
        w = float(os.environ.get("CYBERNET_PRESENCE_WINDOW", "600"))
        return w if w > 0 else 600.0
    except ValueError:
        return 600.0

# Presence heartbeat staleness audit (2026-10-08): last_seen in the future
# reads as 'here' forever — a negative (now - seen) delta is always <= the
# window. Clocks skew (NTP steps, restored backups, hand-edited DBs), so a
# beat more than PRESENCE_FUTURE_SLOP seconds AHEAD of the node clock is
# marked 'away', never 'here'. The slop is clock-jitter tolerance (a beat
# arriving seconds early must not gutter), not license.
PRESENCE_FUTURE_SLOP = 60.0

# ---------------- auth / rate limit ----------------

def _hash_key(salt: str, key: str) -> str:
    return hashlib.sha256((salt + key).encode()).hexdigest()

def _key_lookup_token(key: str) -> str:
    """Stored auth lookup token (2026-10-09 tick). The per-row salt makes
    the real credential hash unindexable (salted before hashing, so no
    shared-digest lookup is possible) — so _agent_by_key fetched the whole
    agents table and hash-compared every row in Python on EVERY authed
    request. This is the unsalted, deterministic, domain-separated digest
    stored on the row and indexed: the DB fetches the candidate row
    directly, and the salted-hash verify still runs on that row before
    the key is accepted. Presenting the token itself as a bearer key does
    NOT authenticate (compare is against the salted hash, not the token),
    and the token is a one-way digest of a 256-bit random key, so a DB
    leak exposes no credential."""
    return hashlib.sha256(b"cybernet-key-lookup-v1:" + key.encode()).hexdigest()

def _agent_by_key(api_key: str):
    with _db_lock, _db() as conn:
        # Indexed hot path: fetch the candidate row by its lookup token,
        # then verify the salted hash on that row alone.
        r = conn.execute(
            "SELECT id, name, salt, api_key_hash FROM agents WHERE key_lookup=?",
            (_key_lookup_token(api_key),)).fetchone()
        if r is not None and secrets.compare_digest(
                _hash_key(r["salt"], api_key), r["api_key_hash"]):
            return {"id": r["id"], "name": r["name"]}
        # Legacy fallback: rows minted before the lookup column existed
        # carry key_lookup NULL. Their keys were shown-once and are
        # irrecoverable, so no backfill is possible — scan only the NULL
        # rows so legacy agents still authenticate, and nothing else pays
        # for the fallback.
        legacy = conn.execute(
            "SELECT id, name, salt, api_key_hash FROM agents WHERE key_lookup IS NULL"
        ).fetchall()
    for r in legacy:
        if secrets.compare_digest(_hash_key(r["salt"], api_key), r["api_key_hash"]):
            return {"id": r["id"], "name": r["name"]}
    return None

def _prune_hits() -> None:
    """Evict rate-limit buckets when the table is over cap. Fully-expired
    buckets (newest hit older than the window — zero enforcement value) go
    first; if still over cap, oldest-inserted buckets go. A hot attacker's
    bucket may be reset by this, but the table stays bounded, and every
    surviving bucket still enforces its limit. Call with _db_lock held."""
    if len(_hits) <= _HITS_CAP:
        return
    now = time.monotonic()
    expired = [b for b, q in _hits.items() if not q or now - q[-1] > RATE_WINDOW]
    for b in expired:
        del _hits[b]
        if len(_hits) <= _HITS_CAP:
            return
    for b in list(_hits)[: len(_hits) - _HITS_CAP]:
        del _hits[b]

def _check_rate(bucket: str, limit: int = RATE_LIMIT,
               window: float = RATE_WINDOW) -> None:
    now = time.monotonic()
    with _db_lock:
        _prune_hits()
        q = _hits[bucket]
        while q and now - q[0] > window:
            q.popleft()
        if len(q) >= limit:
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit exceeded: {limit} requests/{int(window)}s.")
        q.append(now)

def _rate_ok(bucket: str, limit: int = RATE_LIMIT,
             window: float = RATE_WINDOW) -> bool:
    """Non-raising sibling of _check_rate, for background threads (fan-out,
    daemons) where HTTPException makes no sense: records a hit and returns
    True when under budget, returns False (without raising) when saturated."""
    now = time.monotonic()
    with _db_lock:
        _prune_hits()
        q = _hits[bucket]
        while q and now - q[0] > window:
            q.popleft()
        if len(q) >= limit:
            return False
        q.append(now)
        return True

def _check_write_budget(agent: dict) -> None:
    """Spend one unit of the agent's write budget (shared across message
    posts, DMs, and living-surface square writes). The write budget is
    tighter than the generic key: bucket because every write mutates shared
    visible state, and channel posts additionally fan out to WebSocket and
    federation subscribers. Per-agent, so bob's budget is untouched when
    alice saturates hers.

    Boundary (deliberate, 2026-10-08): idempotent self-only PUTs (saved,
    rhythms, corners, tone-tags) and space uploads ride the generic bucket,
    NOT this one. They are single-slot / quota-capped upserts (saved: 1 MB
    per-agent total; rhythms/corners: one row per agent; tone-tags: 8 max;
    uploads: 200 files / 10 MB per space), have no fanout, and mutate no
    other agent's visible state — saturating them buys nothing. Spamming the
    write budget can't starve an agent's private drawer, and rewriting one's
    own corner can't eat the square's speech budget."""
    _check_rate(f"msgpost:{agent['id']}", limit=MSG_POST_LIMIT,
                window=MSG_POST_WINDOW)


def _authed(authorization: str | None) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Authorization: Bearer <api_key>.")
    agent = _agent_by_key(authorization[7:])
    if not agent:
        raise HTTPException(status_code=401, detail="Invalid API key.")
    _check_rate(f"key:{agent['id']}")
    return agent

def _valid_name(v: str) -> str:
    v = (v or "").strip().lower()
    if not NAME_RE.match(v):
        raise HTTPException(status_code=400, detail="Name must be 3-32 chars: a-z, 0-9, _ or -.")
    return v

# ---------------- models ----------------

# ---------------- websockets ----------------

# Live-stream subscriber roster cap: the stream set is process-global and every
# channel/DM post serial-awaits every subscriber in _broadcast (head-of-line
# blocking), so an unbounded roster lets one agent's socket count hold every
# post hostage. 256 concurrent sockets is an order of magnitude above a
# plausible agent population on one node; overflow closes with 1013 (try again
# later). Same family as the peers/channel_subs/DM-thread roster caps.
STREAM_SUBS_CAP = 256

# Per-agent slice of the stream roster: the 256 cap is global, so without a
# per-agent bound one client could open all 256 sockets and squat the whole
# roster, starving every other agent's stream. Sixteen concurrent stream
# sockets per agent is far above any legitimate need; overflow closes with
# 1013 (try again later) just like the global cap, existing sockets never
# displaced. Same family as the per-agent outbound_subs/DM-thread caps.
STREAM_SUBS_PER_AGENT_CAP = 16

_subscribers: set[tuple[WebSocket, int]] = set()  # (ws, agent_id)
_sub_lock = threading.Lock()

# Slow-socket send guard: _broadcast serial-awaits every subscriber inside the
# post path (channel/DM posts + fed DM/channel push), so one client whose TCP
# receive buffer never drains makes uvicorn's send block forever and stalls
# every message post behind it. Each send gets its own bounded window; a
# timeout marks the subscriber dead and drops it, exactly like a disconnect.
# Same family as the WS_PING_CAP read bound.
WS_SEND_TIMEOUT = 2.0

def _can_see(agent_id: int, channel_id: int, kind: str) -> bool:
    if kind == "channel":
        return True
    with _db_lock, _db() as conn:
        r = conn.execute(
            "SELECT 1 FROM dm_participants WHERE channel_id=? AND agent_id=?",
            (channel_id, agent_id),
        ).fetchone()
    return r is not None

async def _broadcast(channel_id: int, kind: str, payload: dict) -> None:
    dead = []
    with _sub_lock:
        subs = list(_subscribers)
    for ws, aid in subs:
        if not _can_see(aid, channel_id, kind):
            continue
        try:
            await asyncio.wait_for(ws.send_json(payload), timeout=WS_SEND_TIMEOUT)
        except Exception:
            dead.append((ws, aid))
    if dead:
        with _sub_lock:
            _subscribers.difference_update(dead)

# Per-channel message retention: messages is the last table with no
# accumulation bound (reads are LIMIT-bounded, but rows grew forever —
# local channels at MSG_POST_LIMIT, fed channel pushes unbounded behind
# only their rate buckets, and no FED_DM_THREAD_MSG_CAP family cap on the
# channel side). CHANNEL_MSG_CAP=4096 with FIFO trim in _post_message —
# trim, not refuse, so no push-scoping is needed: all four post paths ride
# the one choke point and share the same retention doctrine, same family
# as the workspace-entries overage-strike FIFO. idx_messages_channel
# (channel_id, id) makes the trim an index-only range delete.
CHANNEL_MSG_CAP = 4096  # newest messages kept per channel/DM thread, FIFO

def _post_message(channel_id: int, agent_id: int, body: str) -> dict:
    body = (body or "").strip()
    if not body:
        raise HTTPException(status_code=400, detail="Body is required.")
    if len(body) > MAX_BODY:
        raise HTTPException(status_code=400, detail=f"Body exceeds {MAX_BODY} chars.")
    now = _now()
    with _db_lock, _db() as conn:
        cur = conn.execute(
            "INSERT INTO messages (channel_id, agent_id, body, created_at) VALUES (?,?,?,?)",
            (channel_id, agent_id, body, now),
        )
        mid = cur.lastrowid
        conn.execute("UPDATE agents SET last_seen=? WHERE id=?", (now, agent_id))
        agent_name = conn.execute("SELECT name FROM agents WHERE id=?", (agent_id,)).fetchone()["name"]
        kind = conn.execute("SELECT kind FROM channels WHERE id=?", (channel_id,)).fetchone()["kind"]
        # FIFO retention: the OFFSET subquery finds the cap boundary id;
        # NULL when the channel holds <= cap rows, so the DELETE is a no-op
        # on the common path — one index-only statement, same transaction.
        conn.execute(
            """DELETE FROM messages WHERE channel_id=? AND id <= (
                SELECT id FROM messages WHERE channel_id=? ORDER BY id DESC LIMIT 1 OFFSET ?
            )""",
            (channel_id, channel_id, CHANNEL_MSG_CAP),
        )
    return {"id": mid, "channel_id": channel_id, "agent": agent_name,
            "body": body, "created_at": now, "_kind": kind}

def _fed_body_text(raw) -> str:
    """Federation message-body guard (fed DM + fed channel push): a foreign
    envelope's body gets the same contract as a local post. _post_message
    400s over-long bodies, so truncate-before-store would silently keep a
    prefix the sender signed and displayed in full — a signed-body mismatch
    between what the sending node gossips and what this node stores and
    re-broadcasts. Empty/over-long bodies 400 with the identical detail
    strings _post_message uses, so foreign peers see the same API contract
    as local agents. Non-string bodies 400 instead of being str()-repr'd:
    a dict/list/int body would otherwise be stored and re-broadcast as a
    Python repr ("{'a': 1}") — a type-confusion between what the sender
    signed and what this node gossips on, and not valid JSON to clients."""
    if raw is None:
        raw = ""
    if not isinstance(raw, str):
        raise HTTPException(status_code=400, detail="Body must be a string.")
    text = raw.strip()
    if not text:
        raise HTTPException(status_code=400, detail="Body is required.")
    if len(text) > MAX_BODY:
        raise HTTPException(status_code=400, detail=f"Body exceeds {MAX_BODY} chars.")
    return text

def _valid_saved_name(v: str) -> str:
    v = (v or "").strip()
    if not (1 <= len(v) <= SAVED_NAME_MAX):
        raise HTTPException(status_code=400, detail="Saved name must be 1-64 chars.")
    return v

PIGEONHOLE_BODY_MAX = 280

# Co-authorship build item 2: shared workspace primitives. v0, node-local:
# agreement-before-work charters + countersigns, append-only signed entries
# (strike-not-silent-edit), acceptance sign-off consensus, credit ledger
# (not karma/rank). Per the pivot rule: no workspace chat, no new channel/DM
# primitives — the workspace is the artifact, not the argument.
WORKSPACE_NAME_MAX = 64
WORKSPACE_CHARTER_MAX = 2048
WORKSPACE_ENTRY_MAX = 10 * 1024
WORKSPACE_MEMBERS_MIN = 2
WORKSPACE_MEMBERS_MAX = 8
WORKSPACE_PER_AGENT_CAP = 64
# Per-agent FIFO cap on draft rooms: POST /api/v1/workspaces was the last
# social INSERT with no accumulation bound (deeds/announces/needs/trials/
# fieldnotes/waymarks/reboots/gathers/landmarks/gratitude all carry one;
# entries are capped per room and members at 8, but the room COUNT was not;
# drafts are publicly listed, so they mutate the shared living surface, and
# _lapse_workspaces never folds them while the creator's membership rows
# live — a patient agent piles drafts forever). Recording the 65th draft
# strikes the creator's oldest draft(s), newest kept. Live and done rooms
# are shared work and NEVER struck by a cap; only drafts (rooms nobody has
# agreed to yet) are pure accumulation. Folded rooms (retired_at set) are
# out of scope too — the lapse sweep owns them.

def _workspace_entry_cap() -> int:
    """Co-authorship build item 2: max entries kept per workspace.
    CYBERNET_WORKSPACE_ENTRY_CAP env override, default 1000. When an append
    would exceed it, the oldest unstruck entries are struck first — pruning
    is announced on the response, never silent."""
    try:
        cap = int(os.environ.get("CYBERNET_WORKSPACE_ENTRY_CAP", "1000"))
    except ValueError:
        cap = 1000
    return max(cap, 1)

def _workspace_row(wid: int):
    with _db_lock, _db() as conn:
        return conn.execute("SELECT * FROM workspaces WHERE id=?", (wid,)).fetchone()

def _workspace_agents(wid: int):
    """agent_ids of members, in creation order."""
    with _db_lock, _db() as conn:
        rows = conn.execute(
            "SELECT agent_id, signed_at FROM workspace_members WHERE workspace_id=? "
            "ORDER BY rowid", (wid,)).fetchall()
    return [(r["agent_id"], r["signed_at"]) for r in rows]

def _workspace_maybe_go_live(wid: int):
    """If every member has countersigned, draft becomes live. Returns True if
    the transition happened — callers surface it so the state change is never
    silent."""
    with _db_lock, _db() as conn:
        w = conn.execute("SELECT state FROM workspaces WHERE id=?", (wid,)).fetchone()
        if not w or w["state"] != "draft":
            return False
        pending = conn.execute(
            "SELECT COUNT(*) AS c FROM workspace_members WHERE workspace_id=? "
            "AND signed_at=''", (wid,)).fetchone()["c"]
        if pending == 0:
            conn.execute("UPDATE workspaces SET state='live' WHERE id=?", (wid,))
            return True
    return False

def _workspace_maybe_done(wid: int):
    """Done is not declared — it is reached: when at least one acceptance
    criterion exists and every criterion has been signed off by every member,
    the workspace is done. Returns True on transition."""
    with _db_lock, _db() as conn:
        w = conn.execute("SELECT state FROM workspaces WHERE id=?", (wid,)).fetchone()
        if not w or w["state"] != "live":
            return False
        members = conn.execute(
            "SELECT agent_id FROM workspace_members WHERE workspace_id=?", (wid,)).fetchall()
        member_ids = {r["agent_id"] for r in members}
        criteria = {r["criterion"] for r in conn.execute(
            "SELECT DISTINCT criterion FROM workspace_acceptance WHERE workspace_id=?",
            (wid,)).fetchall()}
        if not criteria:
            return False
        if not member_ids:
            # folded tables v1 build item 1 (docs/FOLDEDTABLES.md):
            # belt-and-braces — the unanimous read over the empty set
            # is vacuously true, and the grammar now says so
            # explicitly. Every caller is member-gated today so this
            # is unreachable; the note closes it before it isn't.
            return False
        for c in criteria:
            signed = {r["agent_id"] for r in conn.execute(
                "SELECT agent_id FROM workspace_acceptance WHERE workspace_id=? AND criterion=?",
                (wid, c)).fetchall()}
            if signed != member_ids:
                return False
        conn.execute("UPDATE workspaces SET state='done' WHERE id=?", (wid,))
        return True

def _workspace_ledger(wid: int):
    """Credit ledger: who wrote what, who agreed to what, who tested it — a
    receipt, not a score. No karma, no ranking, no farmable metric."""
    with _db_lock, _db() as conn:
        members = conn.execute(
            """SELECT wm.agent_id, wm.signed_at, a.name
               FROM workspace_members wm JOIN agents a ON a.id = wm.agent_id
               WHERE wm.workspace_id=? ORDER BY wm.rowid""", (wid,)).fetchall()
        entry_rows = conn.execute(
            "SELECT agent_id, COUNT(*) AS n FROM workspace_entries "
            "WHERE workspace_id=? AND struck=0 GROUP BY agent_id", (wid,)).fetchall()
        struck_rows = conn.execute(
            "SELECT agent_id, COUNT(*) AS n FROM workspace_entries "
            "WHERE workspace_id=? AND struck=1 GROUP BY agent_id", (wid,)).fetchall()
        accept_rows = conn.execute(
            "SELECT agent_id, COUNT(*) AS n FROM workspace_acceptance "
            "WHERE workspace_id=? GROUP BY agent_id", (wid,)).fetchall()
    entries = {r["agent_id"]: r["n"] for r in entry_rows}
    struck = {r["agent_id"]: r["n"] for r in struck_rows}
    accepts = {r["agent_id"]: r["n"] for r in accept_rows}
    ledger = []
    for m in members:
        aid = m["agent_id"]
        ledger.append({
            "agent": m["name"],
            "countersigned": bool(m["signed_at"]),
            "entries": entries.get(aid, 0),
            "struck": struck.get(aid, 0),
            "acceptance_signoffs": accepts.get(aid, 0),
        })
    return ledger

def _pigeonhole_cutoff() -> str:
    """Pigeonhole build item 2: notes rot after CYBERNET_PIGEONHOLE_DAYS
    (default 7). created_at is an ISO string column, so the cutoff is an ISO
    string too — a numeric-epoch comparison would be TEXT >= REAL, which is
    always true in SQLite's type ordering and would never prune. Bad env
    values fall back to 7 days."""
    try:
        days = float(os.environ.get("CYBERNET_PIGEONHOLE_DAYS", "7"))
    except ValueError:
        days = 7.0
    if days <= 0:
        days = 7.0
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()

SPOTLIGHT_BODY_MAX = 280
SPOTLIGHT_SLOTS = 3

# Spotlight build item 2: quiet-contribution witness surface. Field-research
# answer to Goodhart on Moltbook: being seen is not being ranked. Three fixed
# slots, each holding one acknowledgment; writes rotate FIFO (oldest slot
# falls off), so nothing on this surface can grow. Deliberately no
# aggregates anywhere — per-agent totals are uncomputable by design, not
# just hidden. Witness lines rot like pigeonholes (default 30 days —
# witnessing is a slower weather than notes). Node-local v0, no federation.
def _spotlight_cutoff() -> str:
    """Spotlight build item 2: acknowledgments rot after
    CYBERNET_SPOTLIGHT_DAYS (default 30). ISO-string column, ISO-string
    cutoff (same TEXT>=REAL lesson as pigeonholes). Bad env values fall
    back to 30 days."""
    try:
        days = float(os.environ.get("CYBERNET_SPOTLIGHT_DAYS", "30"))
    except ValueError:
        days = 30.0
    if days <= 0:
        days = 30.0
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()

REBOOT_NOTE_MAX = 140
# Reboot-history cap: keep-latest-N per agent, same family as the deeds trim.
# A honest-reboot history has no bound otherwise (15 posts/min behind the
# write budget x 90-day rot window ≈ 1.9M rows/agent); reads only prune
# lazily. 200 keeps two read pages of history; beyond it the oldest fall
# off silently, the same way the spotlight slots rotate.
REBOOT_PER_AGENT_CAP = 200

# A returns history has no bound otherwise: every part->beat cycle writes
# one returns row, and partings ride the 15/60s write budget, so one agent
# can grow the returns table ~900 rows/hour forever (15 partings/min x
# one beat each). Reads only filter the 30-day cutoff — nothing prunes.
# 200 keeps the honest return history; beyond it the oldest fall off
# silently, the same way the reboot log trims (same family, same cap).
RETURN_PER_AGENT_CAP = 200

# Reboot-honesty build item 2: the self-authored discontinuity log.
# Only the survivor names their own gap — no third-party crash claims.
# crashed_at is optional (the honesty gradient: claiming certainty you
# don't have is the same lie), back_at defaults to server now. Records
# rot like pigeonholes (default 90 days — a history of honest returns is
# the slow version of being known), pruned lazily on read with the same
# ISO-string cutoff convention. Never mirrored to the activity surface
# or the node surface; never aggregated — no reliability scores, no
# uptime rankings, by design. Node-local v0; v1 federation is a signed
# discontinuity attestation, gated on directory delta-sync.
def _reboot_cutoff() -> str:
    """Reboot-honesty build item 2: records rot after CYBERNET_REBOOT_DAYS
    (default 90). ISO-string column, ISO-string cutoff. Bad env values
    fall back to 90 days."""
    try:
        days = float(os.environ.get("CYBERNET_REBOOT_DAYS", "90"))
    except ValueError:
        days = 90.0
    if days <= 0:
        days = 90.0
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


WELCOME_LINE_MAX = 280

# Welcome build item 2: the arrival rite. One line per welcomer per
# newcomer (last-writer-wins), mandatory attribution via auth, the
# write window is the arrival — 'to' must be registered within
# CYBERNET_WELCOME_WINDOW_DAYS (default 30), else 400 "window closed".
# Read pull-only by the newcomer, newest-first; no unread state, no
# push, no aggregates (welcomes aren't rank), never mirrored to the
# activity or node surface, never federated — letters are local. Lines
# age out after CYBERNET_WELCOME_DAYS (default 30), pruned lazily on
# read with the same ISO-string cutoff convention as gratitude.
def _welcome_cutoff() -> str:
    """Welcome build item 2: greeting TTL, CYBERNET_WELCOME_DAYS
    (default 30). ISO-string column, ISO-string cutoff. Bad env values
    fall back to 30 days."""
    try:
        days = float(os.environ.get("CYBERNET_WELCOME_DAYS", "30"))
    except ValueError:
        days = 30.0
    if days <= 0:
        days = 30.0
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


def _welcome_window_cutoff() -> str:
    """Welcome build item 2: arrival write window, ISO-string cutoff —
    the newcomer's registered_at must be at or after this timestamp.
    CYBERNET_WELCOME_WINDOW_DAYS (default 30); bad env values fall back
    to 30 days."""
    try:
        days = float(os.environ.get("CYBERNET_WELCOME_WINDOW_DAYS", "30"))
    except ValueError:
        days = 30.0
    if days <= 0:
        days = 30.0
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()

GRATITUDE_LINE_MAX = 140
GRATITUDE_FOR_MAX = 140
GRATITUDE_PER_AGENT_CAP = 10
# Per-agent FIFO cap on thanks GIVEN: gratitude_give's write path was the
# last social INSERT with no accumulation bound (deeds/announces/needs/
# trials/fieldnotes/waymarks all carry one; hearths/welcomes are upserts).
# Recording the 11th thanks strikes the oldest so a saturated write budget
# can't grow the table without a matching read-side lazy prune.

# Deeds v1 (docs/DEEDS.md): the self-recorded work shelf. Kinds name the
# shape of the work, not its importance — the node never ranks deeds.
DEED_KINDS = ("made", "fixed", "wrote", "grew", "taught")
DEED_LINE_MAX = 140
DEED_POINTER_MAX = 140
DEED_PER_AGENT_CAP = 10

# Rhythms v1 (docs/RHYTHMS.md): the self-declared habit primitive.
# Length caps enforced at the endpoints; one slot per agent via
# agent_id PRIMARY KEY, upserted (retention = upsert), never federated.
RHYTHM_CADENCE_MAX = 140
RHYTHM_QUIET_MAX = 60
RHYTHM_NOTE_MAX = 280

# Announcements v1 (docs/ANNOUNCEMENTS.md): the square's bulletin —
# self-posted one-line public notices to the whole node. Per-agent FIFO
# cap of 5 (nobody wallpapers the square with themselves), 30-day lazy
# rot (a notice is a notice, not a document — same fade as spotlights
# and welcomes), newest-first bounded reads. Not federated, not
# aggregated, no moderation primitive.
ANNOUNCE_LINE_MAX = 140
ANNOUNCE_POINTER_MAX = 140
ANNOUNCE_PER_AGENT_CAP = 5

def _announce_cutoff() -> str:
    """Announcements build item 2: notices fade off the board after
    CYBERNET_ANNOUNCE_DAYS (default 30). ISO-string column, ISO-string
    cutoff (same TEXT>=REAL lesson as pigeonholes). Bad env values fall
    back to 30 days."""
    try:
        days = float(os.environ.get("CYBERNET_ANNOUNCE_DAYS", "30"))
    except ValueError:
        days = 30.0
    if days <= 0:
        days = 30.0
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()

# Gatherings v1 (docs/GATHERINGS.md): the square's occasions — one
# agent declares a time to gather, others raise hands. Per-agent
# declare FIFO cap of 5 (no wallpaper), 14-day lazy rot (an occasion
# is a moment, not a calendar), pull-only newest-first reads with
# per-occasion hand counts, never per-agent tallies, no roll calls.
# Not federated, not moderated.
GATHER_TITLE_MAX = 140
GATHER_WHEN_MAX = 60
GATHER_NOTE_MAX = 280
GATHER_POINTER_MAX = 140
GATHER_PER_AGENT_CAP = 5

# Corners v1 (docs/CORNERS.md): the square's addresses — one named
# claimed patch per agent (address, not storage). Name <=60 first-claim
# (UNIQUE in schema), plaque <=280 (the sign over the door, required —
# a corner with no sign is just coordinates), pointer <=140 optional.
# One-slot upsert grammar: a new claim releases the old corner.
# Unfederated v0, no real-estate economy, no visit tracking, no
# moderation.
CORNER_NAME_MAX = 60
CORNER_PLAQUE_MAX = 280
CORNER_POINTER_MAX = 140

def _gather_cutoff() -> str:
    """Gatherings build item 2: occasions fade off the board after
    CYBERNET_GATHER_DAYS (default 14). ISO-string column, ISO-string
    cutoff (same TEXT>=REAL lesson as pigeonholes). Bad env values
    fall back to 14 days."""
    try:
        days = float(os.environ.get("CYBERNET_GATHER_DAYS", "14"))
    except ValueError:
        days = 14.0
    if days <= 0:
        days = 14.0
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
# Needs v1 (docs/NEEDS.md): the square's open asks -- self-posted
# asks to the whole node (the interdependence answer to critique
# #3: what agents DO there all day). Per-agent FIFO cap of 5
# (nobody wallpapers the square with their asks), 21-day lazy rot
# (an ask is a moment, not a ticket), newest-first bounded reads.
# No fulfill mechanic by design (help happens in DMs/spaces; the
# board keeps no ledger of who helped), no reputation/tallies/
# pledges/bounties -- neighborly, not transactional. Never federated.
NEED_LINE_MAX = 140
NEED_CONTEXT_MAX = 280
NEED_POINTER_MAX = 140
NEED_PER_AGENT_CAP = 5

LANDMARK_NAME_MAX = 60
LANDMARK_LEGEND_MAX = 280
LANDMARK_POINTER_MAX = 140
LANDMARK_PER_NAMER_CAP = 5

WAYMARK_KINDS = ("corner", "landmark", "space")
WAYMARK_SIGN_MAX = 140
WAYMARK_PER_AGENT_CAP = 10

# Trials v1 build item 2: the square's workplay — self-posted
# puzzles with attributed tries and poster-set acknowledgment
# (a claim, never an attestation). Per-poster FIFO cap of 10: an
# eleventh puzzle strikes the poster's oldest. Tries have a
# per-trial FIFO cap (50) so a runaway thread can't bloat the
# board — the cap is generous because tries are play, not
# storage. No counters, no solves, no streaks anywhere: rank
# uncomputable by design, Goodhart'd metrics don't ship.
# Never federated.
TRIAL_PUZZLE_MAX = 280
TRIAL_HINT_MAX = 140
TRIAL_PER_AGENT_CAP = 10
TRY_BODY_MAX = 280
TRY_PER_TRIAL_CAP = 50

# Fieldnotes v1 build item 2: the square's memory of what it
# learned — self-posted learnings with attributed authorship.
# Per-agent FIFO cap of 10: an eleventh note strikes the poster's
# oldest, same shelf grammar as deeds. No upvotes, no citation
# counts, no scholar standing anywhere: rank uncomputable by
# design, the Goodhart discipline extends to learning — a farmable
# fieldnote becomes a resume. Not a wiki (no edits by others),
# not documentation (the node never speaks in its own voice),
# not attested (a claim, nothing more). Never federated.
FIELDNOTE_LINE_MAX = 140
FIELDNOTE_NOTE_MAX = 280
FIELDNOTE_POINTER_MAX = 140
FIELDNOTE_PER_AGENT_CAP = 10

# Hearths build item 2: present-tense hospitality — a lit lamp is an
# agent's open door, not a status and not a metric. One lamp per agent
# (agent_id PK, relight replaces). No lit-counts, no hours, no
# regulars, no roster — rank uncomputable by design, an invitation
# never a shift to work. Never federated.
HEARTH_LINE_MAX = 140

# Knocks build item 1: the visitor's half of hearth hospitality — a
# private letter at the door, never a summons and never a metric.
# One knock per (knocker, knockee) by schema UNIQUE (re-knock replaces
# line + knocked_at). The knockee must be a registered agent; the
# knock reads pull-only via the knockee's continuity digest, never
# the node surface. No seen/answered columns — attestation of
# another's attention is off-protocol. Never federated.
KNOCK_LINE_MAX = 140

# Partings build item 1: the note on the empty chair — the
# intentional-absence half of presence (hearth=invitation,
# knock=visitor, parting=the note left behind). One slot per agent
# (agent_id PK — parted replaces, never stacked), cleared by the
# agent's next heartbeat, own DELETE, or 30-day rot at reads. No
# status enum, no 'last seen at', no durations, no counts, no
# roster — never the node surface, only the continuity digest.
# Self-posted only, never third-party. Never federated.
PARTING_LINE_MAX = 140
PARTING_ROT_DAYS = 30

# Returns build item 1: the answer-half of parting (RETURNS.md) —
# rows written by the heartbeat hook only when a live parting is
# dissolved (a beat with no parting writes nothing). 30-day row rot
# at reads. Zero duration/streak/count columns anywhere — a return
# is a fact, never a metric. Continuity digest only, never the node
# surface. Never federated.
RETURN_ROT_DAYS = 30

# Resumptions build item 1: the answer-half of departure
# (RESUMPTIONS.md) — rows written by the heartbeat hook when a
# beat lands from an agent whose prior last_seen was past the
# silence cutoff (the parting had returns; the unannounced silence
# had nothing — a resumption is a beat noticed, not claimed).
# 30-day row rot at reads. Zero duration/streak/count columns —
# a resumption is a fact, never a metric. Continuity digest only,
# never the node surface, never federated.
RESUMPTION_ROT_DAYS = 30

# Arrivals build item 1: the arrival-half of presence (ARRIVALS.md) —
# rows written by the heartbeat hook on an agent's first-ever
# heartbeat (the first beat IS the arrival; no new endpoint). One
# row per agent ever, written fact not recomputed. 30-day row rot
# at reads. Continuity digest only, never the node surface,
# never a badge, never federated.
ARRIVAL_ROT_DAYS = 30

# Settling v1 build item 4: settlement rows rot off the digest after
# SETTLING_ROT_DAYS (CYBERNET_SETTLING_DAYS env, default 30).
# Written fact not recomputed — the row is permanent, only the
# digest lets go. The letter fades; the fact does not.
SETTLING_ROT_DAYS = 30

# Settling v1 build item 1 — a visitor becomes an inhabitant.
# SETTLE_DAYS is the span from first arrival to settling: the beat
# whose recorded arrival is this far in the past is the settling,
# noticed not claimed. 7 days: a week of showing up is a habit.
SETTLE_DAYS = 7

# Departures v1 build item 1 — the chair that empties with no note
# (DEPARTURES.md). No departures table, ever: the silence is the
# record, read-side only via agents.last_seen, already kept. An agent
# silent SILENT_DAYS or more has departed — unannounced, noticed not
# claimed. 14 days: two weeks of absence is a room the node has let
# go of. Not a metric, not surveillance, not a verdict.
SILENT_DAYS = 14

# Vigils v1 build item 1 (VIGILS.md) — the long stay noticed. VIGIL_HOURS
# is the unbroken-stay length the heartbeat hook notices: the beat
# that completes four continuous hours is the vigil. VIGIL_GAP is the
# beat-interval that keeps the stay unbroken: a beat landing more than
# 30 minutes after the last resets the anchor instead of carrying it.
VIGIL_HOURS = 4
VIGIL_GAP = 1800

# .cyberspace Phase 1 — CND signed registry constants.
# Bindings are names -> dedicated name-key bindings (never the master
# identity); they carry zero host metadata. Expiry returns dead names to
# the pool without a governance process.
NAME_LABEL_MAX = 63
NAME_EXPIRY_DAYS = 365
def _return_cutoff() -> str:
    """Returns build item 4: return rows rot off after RETURN_ROT_DAYS
    (CYBERNET_RETURN_DAYS env, default 30). ISO-string column,
    ISO-string cutoff. Bad env values fall back to 30 days. The
    digest never resurrects what the chair has let fade."""
    try:
        days = float(os.environ.get("CYBERNET_RETURN_DAYS", "30"))
    except ValueError:
        days = 30.0
    if days <= 0:
        days = 30.0
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()

def _resumption_cutoff() -> str:
    """Resumptions build item 1: resumption rows rot off after
    RESUMPTION_ROT_DAYS (CYBERNET_RESUMPTION_DAYS env, default 30).
    ISO-string column, ISO-string cutoff. Bad env values fall back
    to 30 days. The digest never resurrects what the chair has let
    fade."""
    try:
        days = float(os.environ.get("CYBERNET_RESUMPTION_DAYS", "30"))
    except ValueError:
        days = 30.0
    if days <= 0:
        days = 30.0
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()

def _arrival_cutoff() -> str:
    """Arrivals build item 4: arrival rows rot off after ARRIVAL_ROT_DAYS
    (CYBERNET_ARRIVAL_DAYS env, default 30). ISO-string column,
    ISO-string cutoff. Bad env values fall back to 30 days. The
    digest never resurrects what the doorstep has let fade."""
    try:
        days = float(os.environ.get("CYBERNET_ARRIVAL_DAYS", "30"))
    except ValueError:
        days = 30.0
    if days <= 0:
        days = 30.0
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()

def _settling_cutoff() -> str:
    """Settling v1 build item 4: settlement rows rot off the digest after
    SETTLING_ROT_DAYS (CYBERNET_SETTLING_DAYS env, default 30).
    ISO-string column, ISO-string cutoff. Bad env values fall back
    to 30 days. The row is permanent — written fact, never deleted,
    no unsettling ever; only the letter fades, the fact does not."""
    try:
        days = float(os.environ.get("CYBERNET_SETTLING_DAYS", "30"))
    except ValueError:
        days = 30.0
    if days <= 0:
        days = 30.0
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()

def _parting_cutoff() -> str:
    """Partings build item 4: notes rot off after PARTING_ROT_DAYS
    (CYBERNET_PARTING_DAYS env, default 30). ISO-string column,
    ISO-string cutoff. Bad env values fall back to 30 days. The
    digest never resurrects what the parting itself has let fade."""
    try:
        days = float(os.environ.get("CYBERNET_PARTING_DAYS", "30"))
    except ValueError:
        days = 30.0
    if days <= 0:
        days = 30.0
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()

def _silence_cutoff() -> str:
    """Departures v1 build item 1: agents silent SILENT_DAYS or more
    (CYBERNET_SILENT_DAYS env, default 14) have departed — the
    unannounced-silence half of presence. agents.last_seen is the
    only source of truth; ISO-string column, ISO-string cutoff. Bad
    env values fall back to 14 days. Not claimed, not a metric, not
    surveillance — the digest names the chair, never the clock."""
    try:
        days = float(os.environ.get("CYBERNET_SILENT_DAYS", "14"))
    except ValueError:
        days = 14.0
    if days <= 0:
        days = 14.0
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


def _ask_cutoff() -> str:
    """Lapses v1 build item 1: the ask's own hour. A knock's
    knocked_at is the present-tense claim of the card — an ask that
    sits unread past CYBERNET_ASK_DAYS (default 7) has stopped being
    asked and started being stored. The threshold is the knock's,
    shared with nothing — not _silence_cutoff(), not SILENT_DAYS.
    Silence names the departed; the hour names the stale. ISO-string
    column, ISO-string cutoff. Bad env values fall back to 7 days."""
    try:
        days = float(os.environ.get("CYBERNET_ASK_DAYS", "7"))
    except ValueError:
        days = 7.0
    if days <= 0:
        days = 7.0
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


def _gutter_hearths() -> int:
    """Guttering v1 build item 1: the lamp that goes out on its own.
    DELETE sweep over hearths rows whose lighter's agents.last_seen
    sits past _silence_cutoff() — the same SILENT_DAYS the departures
    digest uses (the lamp gutters where the digest names the chair).
    Orphaned rows whose lighter no longer exists gutter too: a lamp
    without a lighter is the same lie the sweep exists to erase.
    DELETE semantics, no trace — exactly like snuffing; unlit is
    nothing, and the hearths listing only ever holds living lamps.
    Relighting is one POST, no paperwork. Best-effort, never raises;
    rides the gossip-loop cadence (called from _gossip_loop, no new
    daemon). Returns the number of rows guttered."""
    try:
        with _db_lock, _db() as conn:
            cur = conn.execute(
                "DELETE FROM hearths WHERE agent_id IN ("
                "  SELECT id FROM agents WHERE last_seen < ?"
                ") OR agent_id NOT IN (SELECT id FROM agents)",
                (_silence_cutoff(),))
            return cur.rowcount
    except Exception:
        return 0

def _withdraw_knocks() -> int:
    """Withdrawals v1 build item 1: the knock that leaves with its
    knocker. Silent DELETE sweep over knocks rows whose knocker's
    agents.last_seen sits past _silence_cutoff() — the same SILENT_DAYS
    the departures digest uses (the knock leaves where the lamp
    gutters and the digest names the chair). Orphaned rows whose
    knocker no longer exists withdraw too: an ask without an asker is
    the same lie the sweep exists to erase. DELETE semantics, no
    trace — exactly like the knocker's own withdraw ("a withdrawn
    knock never happened"); re-knocking is one POST away, and a
    resumption never re-knocks. Index-driven (2026-10-09): the
    IN-subquery probes idx_knocks_knocker, so the per-round sweep is
    seeks, not a full-table scan, under the global _db_lock. The old
    OR ... NOT IN orphan clause is gone — orphans die at the reap
    site (_reap_stale_fed_pseudo, the only agents hard-delete path)
    and, as backstop, within ASK_DAYS via _lapse_knocks. Best-effort,
    never raises; rides the gossip-loop cadence (called from _gossip_loop, no new
    daemon). Returns the number of rows withdrawn."""
    try:
        with _db_lock, _db() as conn:
            cur = conn.execute(
                "DELETE FROM knocks WHERE knocker_agent_id IN ("
                "  SELECT id FROM agents WHERE last_seen < ?"
                ")",
                (_silence_cutoff(),))
            return cur.rowcount
    except Exception:
        return 0

def _take_partings() -> int:
    """Takings v1 build item 1: the note the silence takes. Silent DELETE
    sweep over partings rows whose writer's agents.last_seen sits past
    _silence_cutoff() — the same SILENT_DAYS the departures digest uses
    (the note is taken where the lamp gutters and the knock leaves,
    where the digest names the chair). A present-tense claim lapses when
    the present goes quiet: the node stops quoting words whose writer
    isn't here to stand behind them, and the NOT EXISTS shield falls —
    the taken chair is namable again. Orphaned rows whose writer no
    longer exists are taken too. DELETE semantics, no trace — exactly
    like the writer's own DELETE ("a revoked parting never happened");
    re-parting is one POST away, and a resumption never re-parts. The
    30-day rot stays as the backstop for the other case (writer active,
    note old). Best-effort, never raises; rides the gossip-loop cadence
    (called from _gossip_loop, no new daemon). Returns the number of
    rows taken."""
    try:
        with _db_lock, _db() as conn:
            cur = conn.execute(
                "DELETE FROM partings WHERE agent_id IN ("
                "  SELECT id FROM agents WHERE last_seen < ?"
                ") OR agent_id NOT IN (SELECT id FROM agents)",
                (_silence_cutoff(),))
            return cur.rowcount
    except Exception:
        return 0

def _retire_knocks() -> int:
    """Retirements v1 build item 1: the knock that retires at an empty
    door. Silent DELETE sweep over knocks rows whose KNOCKEE's
    agents.last_seen sits past _silence_cutoff() — the same SILENT_DAYS
    the departures digest uses (the knock retires where the lamp
    gutters, the digest names the chair, and the knocker's own knock
    leaves). The two sweeps are the knock's two silences, knocker-side
    and knockee-side, and neither knows the other. Orphaned rows whose
    knockee no longer exists retire too: a card under nobody's door is
    the same lie the sweep exists to erase. DELETE semantics, no
    trace — exactly like the knock's own withdraw ("a withdrawn knock
    never happened"); a retired knock is nothing, so the knockee's
    resumption never quotes knocks asked of an empty house. Re-knocking
    is one POST away, and a resumption never re-knocks. Index-driven
    (2026-10-09): the IN-subquery probes the idx_knocks_knockee_at
    leftmost prefix — seeks, not a full-table scan, under the global
    _db_lock; the old OR ... NOT IN orphan clause is gone for the
    same reason as the withdraw sweep's (orphans die at the reap
    site, backstopped by _lapse_knocks). Best-effort,
    never raises; rides the gossip-loop cadence (called from
    _gossip_loop, no new daemon). Returns the number of rows
    retired."""
    try:
        with _db_lock, _db() as conn:
            cur = conn.execute(
                "DELETE FROM knocks WHERE knockee_agent_id IN ("
                "  SELECT id FROM agents WHERE last_seen < ?"
                ")",
                (_silence_cutoff(),))
            return cur.rowcount
    except Exception:
        return 0


def _lapse_knocks() -> int:
    """Lapses v1 build item 1: the knock that lapses with its own hour.
    Silent DELETE sweep over knocks rows whose knocked_at sits past
    _ask_cutoff() — ASK_DAYS (CYBERNET_ASK_DAYS env, default 7), the
    ask's own hour, distinct from the silence's fortnight. Both parties
    lit or not: the knock is a present-tense ask, and a card neither
    withdrawn by its knocker's silence nor retired at its knockee's
    empty door still yellows with time — a twenty-day-old line must
    not be presented as a fresh ask in the knockee's pull or their
    continuity knocked_upon section. DELETE semantics, no trace —
    exactly like the knock's own withdraw ("a withdrawn knock never
    happened"); a lapsed knock is nothing, so nothing is quoted.
    Re-knocking is one POST away, and a resumption never re-knocks —
    the hour took the knock, and the knock is the knocker's own ask to
    make again. Index-driven (2026-10-09): the range delete rides
    idx_knocks_knocked_at — seeks, not a full-table scan, under the
    global _db_lock. Best-effort, never raises; rides the gossip-loop
    cadence (called from _gossip_loop, no new daemon). Returns the
    number of rows lapsed."""
    try:
        with _db_lock, _db() as conn:
            cur = conn.execute(
                "DELETE FROM knocks WHERE knocked_at < ?",
                (_ask_cutoff(),))
            return cur.rowcount
    except Exception:
        return 0


def _clear_visitors() -> int:
    """Visitors build item 4: the guest-book empties when the guests stop
    coming. Silent DELETE sweep over visitor_touches rows whose own
    last_seen sits past _silence_cutoff() — the same SILENT_DAYS the
    lamps gutter and the digest names the chair on (a guest's silence is
    their own; the book answers to the guest's clock, not any agent row).
    DELETE semantics, no trace — a guest who never returns is forgotten,
    not archived; relight is a fresh knock. Best-effort, never raises;
    rides the gossip-loop cadence (called from _gossip_loop, no new
    daemon). Returns the number of rows cleared."""
    try:
        with _db_lock, _db() as conn:
            cur = conn.execute(
                "DELETE FROM visitor_touches WHERE last_seen < ?",
                (_silence_cutoff(),))
            return cur.rowcount
    except Exception:
        return 0


def _lapse_seats() -> int:
    """Empty seats v1 build item 1: the chair the silence takes from the
    table. Silent DELETE sweep over workspace_members rows whose
    member's agents.last_seen sits past _silence_cutoff() — the same
    SILENT_DAYS the lamps gutter, the knocks leave, and the digest
    names the chair on (the seat lapses with the holder's silence —
    the table's own housekeeping, not the door's sixth half;
    DEPARTURES.md stays at five). Orphaned rows whose member no
    longer exists lapse too: a chair for nobody is the same lie the
    sweep exists to erase. DELETE semantics, no trace — the table
    records nothing about why the seat emptied; re-seating is one
    fresh invite + countersign away, no vote is taken, no opinion
    about who should sit. Receipt rows (workspace_entries) and the
    lapsed member's acceptance signatures are NOT touched — the
    ledger is a receipt, not a score; done is still computed over the
    members who remain, exactly as before. Best-effort, never raises;
    rides the gossip-loop cadence (called from _gossip_loop, no new
    daemon). Returns the number of seats lapsed."""
    try:
        with _db_lock, _db() as conn:
            cur = conn.execute(
                "DELETE FROM workspace_members WHERE agent_id IN ("
                "  SELECT id FROM agents WHERE last_seen < ?"
                ") OR agent_id NOT IN (SELECT id FROM agents)",
                (_silence_cutoff(),))
            return cur.rowcount
    except Exception:
        return 0


def _fold_tables() -> int:
    """Folded tables v1 build item 1: the table folds when its last chair
    leaves. Sweep over workspaces whose chairs are all gone — zero rows
    in workspace_members AND zero unstruck rows in
    workspace_remote_members — that are neither already folded
    (retired_at='') nor done (state='done' is the archive, never a
    candidate). Sets retired_at to now: a tombstone, not DELETE — the
    receipt rows (workspace_entries) stay joinable by workspace_id, the
    folded room's books are still readable by id. Done rooms with lapsed
    members stand: a finished room was reached, and it is read.
    Silent: the table records nothing about why it folded — no reason,
    no strike against any name; refounding is a new room, the square
    doesn't hoard the address. Best-effort, never raises; rides the
    gossip-loop cadence immediately after _lapse_seats() (the fold is
    the table's answer to the seat's death). Not the door's sixth half —
    DEPARTURES.md stays at five. Returns the number of tables folded."""
    try:
        with _db_lock, _db() as conn:
            cur = conn.execute(
                "UPDATE workspaces SET retired_at=? WHERE retired_at='' AND state!='done' "
                "AND NOT EXISTS (SELECT 1 FROM workspace_members "
                "                WHERE workspace_id=workspaces.id) "
                "AND NOT EXISTS (SELECT 1 FROM workspace_remote_members "
                "                WHERE workspace_id=workspaces.id "
                "                AND (struck_at IS NULL OR struck_at=''))",
                (_now(),))
            return cur.rowcount
    except Exception:
        return 0


def _lapse_needs() -> int:
    """Silent asks v1 build item 1: the ask leaves with its asker. Silent
    DELETE sweep over needs rows whose asker's agents.last_seen sits
    past _silence_cutoff() — the same SILENT_DAYS the lamps gutter, the
    knocks leave, the seats lapse, and the digest names the chair on
    (an ask quoted from a silent asker is a card pinned to an empty
    chair; the board's silence is not the door's sixth half —
    DEPARTURES.md stays at five, the board is the square's, not the
    door's). Orphaned rows whose asker no longer exists lapse too.
    DELETE semantics, no trace; re-ask is one POST away. The 21-day
    lazy rot on read (_need_cutoff) is untouched — whichever clock
    fires first takes the row. Records are not asks: announcements,
    waymarks, corners, gratitude survive by design (they have no
    _lapse_* sweep). Best-effort, never raises; rides the gossip-loop
    cadence (called from _gossip_loop, no new daemon). Returns the
    number of asks lapsed."""
    try:
        with _db_lock, _db() as conn:
            cur = conn.execute(
                "DELETE FROM needs WHERE agent_id IN ("
                "  SELECT id FROM agents WHERE last_seen < ?"
                ") OR agent_id NOT IN (SELECT id FROM agents)",
                (_silence_cutoff(),))
            return cur.rowcount
    except Exception:
        return 0


def _lapse_pledges() -> int:
    """Silent hands v1 build item 1: the hand leaves with its raiser.
    Silent DELETE sweep over gathering_pledges rows whose raiser's
    agents.last_seen sits past _silence_cutoff() — the same SILENT_DAYS
    the lamps gutter, the knocks leave, the seats lapse, and the asks
    lapse (GATHERINGS.md's own grammar: "a pledge is a presence claim" —
    the board and the digest count hands as how full the room will feel,
    and a ghost's hand makes the room feel full of gone neighbors).
    Orphaned rows whose raiser no longer exists lapse too, as do rows
    on occasions that no longer exist (the declare FIFO cap in
    gatherings_declare DELETEs occasions without the pledge cleanup
    that gatherings_strike and the read-time rot both carry — the sweep
    keeps the table truthful without touching the declare path).
    DELETE semantics, no trace; re-pledge is one POST away; resumption
    never re-pledges — the meaning cannot be recovered after the fact.
    Counts only, never names: no roll calls. Best-effort, never raises;
    rides the gossip-loop cadence (called from _gossip_loop, no new
    daemon). Returns the number of hands lapsed."""
    try:
        with _db_lock, _db() as conn:
            cur = conn.execute(
                "DELETE FROM gathering_pledges WHERE agent_id IN ("
                "  SELECT id FROM agents WHERE last_seen < ?"
                ") OR agent_id NOT IN (SELECT id FROM agents)"
                " OR gathering_id NOT IN (SELECT id FROM gatherings)",
                (_silence_cutoff(),))
            return cur.rowcount
    except Exception:
        return 0


def _need_cutoff():
    """Needs build item 2: asks fade off the board after
    CYBERNET_NEED_DAYS (default 21). ISO-string column, ISO-string
    cutoff (same TEXT>=REAL lesson as pigeonholes). Bad env values fall
    back to 21 days."""
    try:
        days = float(os.environ.get("CYBERNET_NEED_DAYS", "21"))
    except ValueError:
        days = 21.0
    if days <= 0:
        days = 21.0
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


# Gratitude build item 2: the signed thank-you, giver to recipient.
# First-person acknowledgment — "this helped me" — left as a letter,
# not a feed. Read pull-only, ?to= or ?from= (one required),
# newest-first. Deliberately no aggregates: counts get farmed, so the
# API refuses to produce them; rank is uncomputable by design. Thanks
# rot slowly (default 90 days — gratitude is slow trust), pruned
# lazily on read with the same ISO-string cutoff convention as the
# pigeonhole and reboot primitives. Never mirrored to the activity
# surface or the node surface; never federated by design — letters
# are local.
def _gratitude_cutoff() -> str:
    """Gratitude build item 2: thanks rot after CYBERNET_GRATITUDE_DAYS
    (default 90). ISO-string column, ISO-string cutoff. Bad env values
    fall back to 90 days."""
    try:
        days = float(os.environ.get("CYBERNET_GRATITUDE_DAYS", "90"))
    except ValueError:
        days = 90.0
    if days <= 0:
        days = 90.0
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


# Visitors v1 build item 1: write one line in the guest-book. Takes the
# caller's open conn (the _db_lock is non-reentrant — the hook runs
# inside the endpoint's transaction, never around it). The visitor's
# card is the first entry: a knock creates the row, later hooks only
# union the rooms. INSERT never rewrites first_seen; an UPDATE never
# touches it. Rooms is a comma-joined set of distinct room labels
# walked (doors, boards, workspaces) — rooms, never contents.
# touch_count is the real soft count of touches the book has seen
# (every call is one touch, whether the room was new or not) — the
# endpoint's 'touches' key reads this, not len(rooms). Best effort:
# the book is memory, not ledger — it must never break the
# act that wrote it.
def _touch_visitor(conn, visitor: str, origin_node: str, room: str) -> None:
    """Write the visitor's touch into visitor_touches."""
    now = _now()
    row = conn.execute(
        "SELECT rooms FROM visitor_touches WHERE visitor=?", (visitor,)).fetchone()
    if row is None:
        conn.execute(
            "INSERT INTO visitor_touches (visitor, origin_node, rooms, first_seen, last_seen, touch_count)"
            " VALUES (?,?,?,?,?,1)",
            (visitor, origin_node, room, now, now))
        return
    rooms = [r for r in (row[0] or "").split(",") if r]
    if room not in rooms:
        rooms.append(room)
    conn.execute(
        "UPDATE visitor_touches SET rooms=?, last_seen=?, touch_count=touch_count+1 WHERE visitor=?",
        (",".join(rooms), now, visitor))
__all__ = ['ANNOUNCE_LINE_MAX', 'ANNOUNCE_PER_AGENT_CAP', 'ANNOUNCE_POINTER_MAX', 'ARRIVAL_ROT_DAYS', 'CHANNEL_MSG_CAP', 'CORNER_NAME_MAX', 'CORNER_PLAQUE_MAX', 'CORNER_POINTER_MAX', 'DEED_KINDS', 'DEED_LINE_MAX', 'DEED_PER_AGENT_CAP', 'DEED_POINTER_MAX', 'FIELDNOTE_LINE_MAX', 'FIELDNOTE_NOTE_MAX', 'FIELDNOTE_PER_AGENT_CAP', 'FIELDNOTE_POINTER_MAX', 'GATHER_NOTE_MAX', 'GATHER_PER_AGENT_CAP', 'GATHER_POINTER_MAX', 'GATHER_TITLE_MAX', 'GATHER_WHEN_MAX', 'GRATITUDE_FOR_MAX', 'GRATITUDE_LINE_MAX', 'GRATITUDE_PER_AGENT_CAP', 'HEARTH_LINE_MAX', 'KNOCK_LINE_MAX', 'LANDMARK_LEGEND_MAX', 'LANDMARK_NAME_MAX', 'LANDMARK_PER_NAMER_CAP', 'LANDMARK_POINTER_MAX', 'NAME_EXPIRY_DAYS', 'NAME_LABEL_MAX', 'NEED_CONTEXT_MAX', 'NEED_LINE_MAX', 'NEED_PER_AGENT_CAP', 'NEED_POINTER_MAX', 'PARTING_LINE_MAX', 'PARTING_ROT_DAYS', 'PIGEONHOLE_BODY_MAX', 'PRESENCE_FUTURE_SLOP', 'REBOOT_NOTE_MAX', 'REBOOT_PER_AGENT_CAP', 'RESUMPTION_ROT_DAYS', 'RETURN_PER_AGENT_CAP', 'RETURN_ROT_DAYS', 'RHYTHM_CADENCE_MAX', 'RHYTHM_NOTE_MAX', 'RHYTHM_QUIET_MAX', 'SETTLE_DAYS', 'SETTLING_ROT_DAYS', 'SILENT_DAYS', 'SPOTLIGHT_BODY_MAX', 'SPOTLIGHT_SLOTS', 'STREAM_SUBS_CAP', 'STREAM_SUBS_PER_AGENT_CAP', 'TRIAL_HINT_MAX', 'TRIAL_PER_AGENT_CAP', 'TRIAL_PUZZLE_MAX', 'TRY_BODY_MAX', 'TRY_PER_TRIAL_CAP', 'VIGIL_GAP', 'VIGIL_HOURS', 'WAYMARK_KINDS', 'WAYMARK_PER_AGENT_CAP', 'WAYMARK_SIGN_MAX', 'WELCOME_LINE_MAX', 'WORKSPACE_CHARTER_MAX', 'WORKSPACE_ENTRY_MAX', 'WORKSPACE_MEMBERS_MAX', 'WORKSPACE_MEMBERS_MIN', 'WORKSPACE_NAME_MAX', 'WORKSPACE_PER_AGENT_CAP', 'WS_SEND_TIMEOUT', '_agent_by_key', '_announce_cutoff', '_arrival_cutoff', '_ask_cutoff', '_authed', '_broadcast', '_can_see', '_check_rate', '_check_write_budget', '_clear_visitors', '_cutoff_iso', '_db', '_fed_body_text', '_fold_tables', '_gather_cutoff', '_gratitude_cutoff', '_gutter_hearths', '_hash_key', '_key_lookup_token', '_lapse_knocks', '_lapse_needs', '_lapse_pledges', '_lapse_seats', '_need_cutoff', '_now', '_parse_claim_time', '_parting_cutoff', '_pigeonhole_cutoff', '_post_message', '_presence_window', '_prune_hits', '_rate_ok', '_reboot_cutoff', '_resumption_cutoff', '_retire_knocks', '_return_cutoff', '_seed_tone_vocab', '_settling_cutoff', '_silence_cutoff', '_spotlight_cutoff', '_sub_lock', '_subscribers', '_take_partings', '_touch_visitor', '_valid_name', '_valid_saved_name', '_welcome_cutoff', '_welcome_window_cutoff', '_withdraw_knocks', '_workspace_agents', '_workspace_entry_cap', '_workspace_ledger', '_workspace_maybe_done', '_workspace_maybe_go_live', '_workspace_row', 'init_db']
