# PROVENANCE (Examiner item 5): ported onto origin/villhaze/q1-name-fixes-r3
# @ 3cadf03 by cherry-pick, branch oracle/window-open-preconditions-r2.
# Source commits on oracle/window-open-preconditions (off 8e9291a):
#   86256ae (ART-40/41 minimal window_open) -> r2 3351f0f
#   7cc71a8 (board BLOCK fixes: mixed-order, chain-walk reserve, cap) -> r2 cf285cf
#   r2 follow-up: window close + naive/date-only e2e (Examiner items 6,7)
"""Window-open preconditions 3 and 4 (ART-40, ART-41) on the 8e9291a line.

PLAIN NOTE: this tree has no legacy_migration.py, _snapshot, open_window,
legacy_migrations table or agents table (those live only on the HQ-snapshot
history). Per Villhaze's ART-29 ruling this branch carries the MINIMAL
mechanism the two preconditions need, self-contained, no Q1 file touched:

ART-40 (refused-bindings):
  * is_weak_pubkey(): a 32-byte key that is non-canonical or small-order
    (or not hex / wrong length) is WEAK. Weak keys are classified REFUSED,
    never held (Lodestar).
  * record_refused_bindings(): pre-change record (Loom) of every weak row in
    name_bindings.node_pubkey, name_conflicts.challenger_pubkey and, if the
    table exists, agents.agent_pubkey, into window_refused_bindings, tagged
    with the window entry id, so later replays see them as pre-recorded
    refusals rather than new findings (is_prerecorded_refusal()).
  * snapshot_bindings(): the snapshot reads ALL rows (no SQL expires filter)
    and drops refused rows in Python, reporting them as refused.
ART-41 (start cap anchored to open_window):
  * open_window(): writes ONE window_open_log entry (the anchor) and the
    refused-bindings entry in the same transaction. Idempotent: a second
    call returns the first entry and writes nothing.
  * check_start_cap(): the rotation/recovery start cap (3, ART-20 b539f2ad)
    is anchored to the recorded open_window entry: no start (no row) before
    it, and after it EVERY legacy_migrations row for the account counts -
    no timestamp filter, not TLS go-live. Refusal is StartRefused (409).
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from datetime import datetime, timezone

import core
from fed import ed25519 as _ed

MAX_STARTS_PER_ACCOUNT = 3
# The snapshot counts against these. There is no per-source overflow
# column: exceeding either cap refuses open_window whole.
SNAPSHOT_PER_NAME = 64
SNAPSHOT_GLOBAL_CAP = 1024

_SCHEMA = (
    """CREATE TABLE IF NOT EXISTS window_open_log (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        opened_at TEXT NOT NULL,
        opened_by TEXT NOT NULL,
        orphan_count INTEGER NOT NULL DEFAULT 0)""",
    """CREATE TABLE IF NOT EXISTS window_refused_bindings (
        window_id INTEGER NOT NULL,
        source TEXT NOT NULL,
        row_key TEXT NOT NULL,
        pubkey TEXT NOT NULL,
        reason TEXT NOT NULL,
        PRIMARY KEY (source, row_key, pubkey))""",
    # Frozen snapshot for reserve-hold / name-refused. FLAG and orphan
    # refusals have no pubkey, and window_refused_bindings.pubkey is NOT
    # NULL, so those rows are keyed by name + source (name_rotations when
    # the binding was reaped). pubkey/reserved_for/origin/successor are the
    # exact 32 signed key bytes, or NULL. Never a re-encoded point.
    """CREATE TABLE IF NOT EXISTS window_kind_source (
        name TEXT NOT NULL,
        source TEXT NOT NULL,
        disposition TEXT NOT NULL,
        pubkey BLOB,
        reserved_for BLOB,
        origin BLOB,
        successor BLOB,
        orphan INTEGER NOT NULL,
        reason TEXT,
        PRIMARY KEY (name, source))""",
    """CREATE TABLE IF NOT EXISTS window_close_log (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        closed_at TEXT NOT NULL,
        closed_by TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS legacy_migrations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        account TEXT NOT NULL,
        kind TEXT NOT NULL,
        started_at TEXT NOT NULL)""",
    # Parallel witness log. legacy_migrations stays the bare cap table the
    # preconditions suite counts. These rows carry seq, prev_hash and the
    # R2 fields (agent_prev_seq, name_sha256) so a second node can run
    # legacy_witness.verify_chain without trusting this node's row count.
    """CREATE TABLE IF NOT EXISTS legacy_log_meta (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        log_id TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS legacy_migration_log (
        seq INTEGER PRIMARY KEY,
        prev_hash TEXT NOT NULL,
        kind TEXT NOT NULL,
        agent_id INTEGER,
        agent_prev_seq INTEGER,
        name_sha256 TEXT,
        body_sha256 TEXT NOT NULL,
        entry_hash TEXT NOT NULL,
        name TEXT,
        migration_id INTEGER,
        k0_pub TEXT,
        detail TEXT NOT NULL,
        logged_at INTEGER NOT NULL,
        node_sig TEXT NOT NULL,
        log_id TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS legacy_imports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        log_id TEXT NOT NULL,
        k0_pub TEXT NOT NULL,
        public_key TEXT NOT NULL,
        head_seq INTEGER NOT NULL,
        imported_at INTEGER NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS legacy_observed_heads (
        log_id TEXT NOT NULL,
        seq INTEGER NOT NULL,
        head_hash TEXT NOT NULL,
        seen_at INTEGER NOT NULL,
        PRIMARY KEY (log_id, seq, head_hash))""",
)


def init_schema(conn) -> None:
    for s in _SCHEMA:
        conn.execute(s)
    if _has_table(conn, "window_open_log") and "orphan_count" not in _cols(conn, "window_open_log"):
        conn.execute(
            "ALTER TABLE window_open_log ADD COLUMN orphan_count INTEGER NOT NULL DEFAULT 0")


def weak_reason(pubkey_hex) -> str | None:
    """None if the key is a canonical, non-small-order point; else why not."""
    try:
        raw = bytes.fromhex(pubkey_hex or "")
    except ValueError:
        return "not-hex"
    if len(raw) != 32:
        return "bad-length"
    try:
        P = _ed._decodepoint_strict(raw)
    except Exception:
        return "non-canonical"
    if _ed._is_small_order(P):
        return "small-order"
    # ART-40 (Lodestar/Cipher BLOCK on 86256ae): honest key + torsion
    # component. L*A must be the identity for a prime-order-subgroup key.
    if _ed._scalarmult(P, _ed._L) != _ed._IDENT:
        return "mixed-order"
    return None


def is_weak_pubkey(pubkey_hex) -> bool:
    return weak_reason(pubkey_hex) is not None


def _has_table(conn, name) -> bool:
    return conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                        (name,)).fetchone() is not None


def _cols(conn, table):
    return {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}


def scan_weak(conn):
    """[(source, row_key, pubkey, reason)] across the three named columns."""
    out = []
    specs = [("name_bindings", "name", "node_pubkey"),
             ("name_conflicts", "id", "challenger_pubkey"),
             ("agents", None, "agent_pubkey")]
    for table, key, col in specs:
        if not _has_table(conn, table) or col not in _cols(conn, table):
            continue
        k = key if key and key in _cols(conn, table) else "rowid"
        for rk, pk in conn.execute(f"SELECT {k}, {col} FROM {table}"):
            why = weak_reason(pk)
            if why:
                out.append((f"{table}.{col}", str(rk), pk or "", why))
    return out


def record_refused_bindings(conn, window_id: int) -> int:
    rows = scan_weak(conn)
    conn.executemany(
        "INSERT OR IGNORE INTO window_refused_bindings "
        "(window_id, source, row_key, pubkey, reason) VALUES (?,?,?,?,?)",
        [(window_id, s, rk, pk, why) for s, rk, pk, why in rows])
    return len(rows)


def is_prerecorded_refusal(conn, source, row_key, pubkey) -> bool:
    return conn.execute(
        "SELECT 1 FROM window_refused_bindings WHERE source=? AND row_key=? AND pubkey=?",
        (source, str(row_key), pubkey)).fetchone() is not None


def _anchor_from_hops(hops):
    """Lodestar/Cipher rule (ART-40) over one name's hops, already ordered
    by node-side accepted_at (rowid tie-break), never the signer's
    issued_at: reserve for the earliest weak hop's old_pubkey if that key
    is non-weak; if the earliest weak hop STARTS on a weak key, refuse
    with FLAG-VILLHAZE (no backward walk: the Z1->X->Z1 PoC showed a walk
    lets an attacker X anchor a name first bound to a weak key).
    Returns (None, None) when the history has no weak hop."""
    for old, new in hops:
        if is_weak_pubkey(old) or is_weak_pubkey(new):
            if is_weak_pubkey(old):
                return None, "FLAG-VILLHAZE: chain starts on weak key"
            return old, None
    return None, None


def _all_histories(conn):
    """ONE indexed scan of name_rotations (PK prefix = name), grouped in
    Python: {name: [(old, new), ...]} in accepted_at, rowid order. No
    per-name query and no network call (Bulwark 44b3923c cost bound)."""
    out = {}
    for name, old, new in conn.execute(
            "SELECT name, old_pubkey, new_pubkey FROM name_rotations "
            "ORDER BY name ASC, accepted_at ASC, rowid ASC"):
        out.setdefault(name, []).append((old, new))
    return out


def _history_anchor(conn, name):
    hops = conn.execute(
        "SELECT old_pubkey, new_pubkey FROM name_rotations WHERE name=? "
        "ORDER BY accepted_at ASC, rowid ASC", (name,)).fetchall()
    return _anchor_from_hops(hops)


def _exact32(text):
    """The 32 signed key bytes, or None. Hex decode only: never encodepoint."""
    if not isinstance(text, str):
        return None
    s = text.strip()
    if len(s) != 64:
        return None
    try:
        raw = bytes.fromhex(s)
    except ValueError:
        return None
    if len(raw) != 32:
        return None
    return raw


def _kind_source_row(name, hops, disposition, *, orphan, reason, reserved_for, pubkey):
    """One frozen row. Orphan and FLAG rows are keyed by name_rotations
    because window_refused_bindings.pubkey is NOT NULL."""
    origin = hops[0][0] if hops else None
    successor = hops[0][1] if hops else None
    return {
        "name": name,
        "source": "name_rotations" if orphan else "name_bindings",
        "disposition": disposition,
        "orphan": bool(orphan),
        "reason": reason,
        "reserved_for": reserved_for,
        "pubkey": pubkey,
        "origin": origin,
        "successor": successor,
        "reserved_for_raw": _exact32(reserved_for),
        "pubkey_raw": _exact32(pubkey),
        "origin_raw": _exact32(origin),
        "successor_raw": _exact32(successor),
    }


def snapshot_bindings(conn):
    """All name_bindings rows (no SQL expires filter). Weak keys are never
    held. Any name whose rotation history touches a weak key (old or new,
    any hop) is RESERVED for the last non-weak key before the earliest weak
    hop - even if the current key is honest (K->Z->K2 reserves for K).
    A history whose earliest weak hop starts on a weak key is REFUSED with
    FLAG-VILLHAZE (no backward walk, so no loop/dead-end/hop-cap paths).
    A weak key with no rotation history is REFUSED.

    ORPHAN PASS (board BLOCK on dd79315, Lodestar item 1 / Cipher /
    Bulwark 44b3923c): _name_registry_has_room (core.py) reaps expired
    name_bindings rows on any claim, so K->Z1 followed by Z1 expiring would
    erase K's reservation. EVERY name in name_rotations therefore runs
    through the same anchor rule; a name with history but no binding row is
    reported reserved (current_pubkey None) or refused (FLAG), never
    dropped. Names with no history and no binding appear nowhere.

    kind_source, orphan_count, and hops_per_name come from this same scan.
    open_window must not scan again to decide what to write."""
    held, refused, reserved, kind_source = [], [], [], []
    hist = _all_histories(conn) if _has_table(conn, "name_rotations") else {}
    seen = set()
    for row in conn.execute(
            "SELECT name, node_pubkey, issued_at, expires_at, signature FROM name_bindings ORDER BY name"):
        seen.add(row[0])
        hops = hist.get(row[0], ())
        anchor, why = _anchor_from_hops(hops)
        if anchor:
            reserved.append({"name": row[0], "reserved_for": anchor, "current_pubkey": row[1],
                             "weak_pubkey": row[1] if is_weak_pubkey(row[1]) else None})
            kind_source.append(_kind_source_row(
                row[0], hops, "reserve-hold", orphan=False, reason=None,
                reserved_for=anchor, pubkey=row[1]))
        elif why:
            refused.append(tuple(row) + (why,))
            kind_source.append(_kind_source_row(
                row[0], hops, "name-refused", orphan=False, reason=why,
                reserved_for=None, pubkey=row[1]))
        elif is_weak_pubkey(row[1]):
            refused.append(tuple(row))
            kind_source.append(_kind_source_row(
                row[0], hops, "name-refused", orphan=False, reason=weak_reason(row[1]) or "weak-key",
                reserved_for=None, pubkey=row[1]))
        else:
            held.append(row)
    orphan_names = set(hist) - seen
    for name in sorted(orphan_names):  # orphan pass
        hops = hist[name]
        anchor, why = _anchor_from_hops(hops)
        if anchor:
            reserved.append({"name": name, "reserved_for": anchor, "current_pubkey": None,
                             "weak_pubkey": None, "orphan": True})
            kind_source.append(_kind_source_row(
                name, hops, "reserve-hold", orphan=True, reason=None,
                reserved_for=anchor, pubkey=None))
        elif why:
            refused.append((name, None, None, None, None, why))
            kind_source.append(_kind_source_row(
                name, hops, "name-refused", orphan=True, reason=why,
                reserved_for=None, pubkey=None))
    return {
        "held": held,
        "refused": refused,
        "reserved": reserved,
        "kind_source": kind_source,
        "orphan_count": len(orphan_names),
        "hops_per_name": {name: len(hops) for name, hops in hist.items()},
    }


def window_entry(conn):
    return conn.execute("SELECT id, opened_at, opened_by FROM window_open_log WHERE id=1").fetchone()


def close_window(closed_by: str) -> dict:
    """Examiner item 7: record the window close once. After it, every start
    is refused (409, no row), regardless of the account's count."""
    with core._db_lock, core._db() as conn:
        init_schema(conn)
        if window_entry(conn) is None:
            raise StartRefused("cannot close: window was never opened")
        row = conn.execute("SELECT closed_at, closed_by FROM window_close_log WHERE id=1").fetchone()
        if row:
            return {"closed_at": row[0], "closed_by": row[1], "already_closed": True}
        at = _now()
        conn.execute("INSERT INTO window_close_log (id, closed_at, closed_by) VALUES (1,?,?)", (at, closed_by))
    return {"closed_at": at, "closed_by": closed_by, "already_closed": False}


class StartRefused(Exception):
    """Start refused (window not open, or cap reached). HTTP 409 shape."""
    status_code = 409


class WindowRefused(Exception):
    """open_window refused the whole snapshot. Nothing was written."""
    status_code = 409


def bounds_problem(snap) -> str | None:
    """None when the snapshot fits. Per-name hop cap, then the global ceiling
    on saved kind rows. No per-source column, so this never demotes a row."""
    for name, n in snap.get("hops_per_name", {}).items():
        if n > SNAPSHOT_PER_NAME:
            return f"per-name cap exceeded for {name} ({n}/{SNAPSHOT_PER_NAME})"
    if len(snap.get("kind_source", ())) > SNAPSHOT_GLOBAL_CAP:
        return f"global ceiling exceeded ({len(snap['kind_source'])}/{SNAPSHOT_GLOBAL_CAP})"
    return None


def _overflow(snap, why: str) -> None:
    """Real policy: refuse whole. A mutant may return and demote instead."""
    raise WindowRefused(why)


def _hex32(raw: bytes | None) -> str | None:
    return None if raw is None else raw.hex()


def _plan_entries(row: dict) -> list:
    """Log entries for one frozen row. At most the four ruled-in kinds.
    hold-closure is not per row; open_window writes that record once.
    No resolution record."""
    orphan = 1 if row["orphan"] else 0
    out = []
    if row["disposition"] == "reserve-hold" and row["reserved_for_raw"] is not None:
        k = _hex32(row["reserved_for_raw"])
        out.append(("reserve-hold", k, {"reserved_for": k, "orphan": orphan}))
    elif row["disposition"] == "name-refused":
        out.append(("name-refused", _hex32(row["pubkey_raw"]), {
            "reason": row["reason"] or "refused",
            "orphan": orphan,
            "source": row["source"],
        }))
    else:
        return out
    if row["origin_raw"] is not None:
        origin = _hex32(row["origin_raw"])
        out.append(("origin-pin", origin, {"origin": origin, "orphan": orphan}))
        if row["successor_raw"] is not None:
            out.append(("origin-handoff", origin, {
                "origin": origin,
                "successor": _hex32(row["successor_raw"]),
                "orphan": orphan,
            }))
    return out


def _sign_witness(kind: str, fields: dict) -> str:
    import legacy_witness as lw
    # Kind is admitted before the signature is produced.
    msg = lw.witness_message(kind, {k: fields[k] for k in fields})
    return _ed.sign(msg, bytes.fromhex(core._NODE_PRIV), bytes.fromhex(core._NODE_PUB)).hex()


def _save_kind_source(conn, rows) -> None:
    conn.executemany(
        "INSERT INTO window_kind_source "
        "(name, source, disposition, pubkey, reserved_for, origin, successor, orphan, reason) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        [(r["name"], r["source"], r["disposition"], r["pubkey_raw"], r["reserved_for_raw"],
          r["origin_raw"], r["successor_raw"], 1 if r["orphan"] else 0, r["reason"])
         for r in rows])


def _append_kind_entries(conn, rows) -> int:
    n = 0
    for row in rows:
        for kind, k0, detail in _plan_entries(row):
            signed = dict(detail)
            signed["witness_sig"] = _sign_witness(kind, {k: detail[k] for k in detail})
            append_log_entry(conn, kind=kind, name=row["name"], k0_pub=k0, detail=signed)
            n += 1
    return n


def _hold_closure_fields() -> dict:
    """The admission hold is closed on Villhaze's accepted witness port.
    A resolution record is not this and is not written here."""
    import legacy_witness as lw
    return {
        "precondition": lw.HOLD_CLOSURE_PRECONDITION,
        "state": "closed",
        "port": lw.HOLD_CLOSURE_PORT,
        "ruling": lw.HOLD_CLOSURE_RULING,
    }


def _append_hold_closure(conn, rows) -> None:
    """One hold-closure for the open, not one per frozen row.

    `rows` is the snapshot the caller just froze. The real writer does not
    iterate it. A mutant that does is how the belt shows the record is
    singular. The basis is the closed witness + weak_reason precondition.
    """
    del rows
    detail = _hold_closure_fields()
    signed = dict(detail)
    signed["witness_sig"] = _sign_witness("hold-closure", detail)
    append_log_entry(conn, kind="hold-closure", detail=signed)


# Private clock hook: tests may set window_open._now_hook; no public
# caller-supplied `now` exists on open_window/record_start (ART-41 BLOCK).
_now_hook = None


def _now() -> str:
    if _now_hook is not None:
        return _now_hook()
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def open_window(opened_by: str) -> dict:
    """Record the window-open anchor, the refused-bindings entry, and the
    witness kinds, once, in one transaction.

    snapshot_bindings runs once. Its reserved and refused rows are the
    frozen source for reserve-hold and name-refused (plus origin-pin and
    origin-handoff from that same scan). The same transaction writes one
    hold-closure: the witness + weak_reason admission hold is closed on
    the accepted witness port. The orphan count pinned on the anchor is
    that scan's orphan count. If the saved rows would exceed the per-name
    cap or the global ceiling, this raises WindowRefused before any write.
    """
    import legacy_witness as lw
    with core._db_lock, core._db() as conn:
        init_schema(conn)
        existing = window_entry(conn)
        if existing:
            return {"id": existing[0], "opened_at": existing[1], "opened_by": existing[2],
                    "already_open": True}
        snap = snapshot_bindings(conn)
        why = bounds_problem(snap)
        if why:
            # Raises WindowRefused before any write. A mutant may return
            # after rewriting dispositions; there is still no per-source
            # column, and the real function never does that.
            _overflow(snap, why)
        rows = snap["kind_source"]
        planned = sum(len(_plan_entries(r)) for r in rows) + lw.HOLD_CLOSURE_ENTRIES
        live = sum(1 for r in rows if not r["orphan"])
        # orphan_count is the orphan pass this snapshot just ran, not a
        # second query.
        budget = lw.max_log_entries(0, live, snap["orphan_count"])
        existing_n = conn.execute("SELECT COUNT(*) FROM legacy_migration_log").fetchone()[0]
        if existing_n + planned > budget:
            _overflow(snap, "snapshot exceeds the pinned log ceiling")
        opened_at = _now()
        conn.execute(
            "INSERT INTO window_open_log (id, opened_at, opened_by, orphan_count) VALUES (1,?,?,?)",
            (opened_at, opened_by, snap["orphan_count"]))
        n = record_refused_bindings(conn, 1)
        _save_kind_source(conn, rows)
        kinds_n = _append_kind_entries(conn, rows)
        _append_hold_closure(conn, rows)
    return {"id": 1, "opened_at": opened_at, "opened_by": opened_by,
            "refused_recorded": n, "already_open": False,
            "orphan_count": snap["orphan_count"], "kinds_recorded": kinds_n}


def check_start_cap(conn, account: str) -> tuple[bool, str]:
    """(allowed, reason). open_window is the gate: nothing starts before it
    is recorded. The cap counts EVERY legacy_migrations row for the account
    (Cipher/Lodestar): no timestamp filter, so a backdated or differently
    formatted (Z vs +00:00) started_at cannot slip under it."""
    init_schema(conn)
    entry = window_entry(conn)
    if entry is None:
        return False, "window not open: no recorded open_window entry"
    closed = conn.execute("SELECT closed_at FROM window_close_log WHERE id=1").fetchone()
    if closed is not None:
        return False, f"window closed at {closed[0]}: no new starts"
    n = conn.execute("SELECT COUNT(*) FROM legacy_migrations WHERE account=?",
                     (account,)).fetchone()[0]
    if n >= MAX_STARTS_PER_ACCOUNT:
        return False, f"start cap reached ({n}/{MAX_STARTS_PER_ACCOUNT})"
    return True, f"{n}/{MAX_STARTS_PER_ACCOUNT}"


def run_admission(verify, write):
    """Check order for a write route: verify (signature, then weak_reason),
    then write. A mutant that writes first is how the belt shows a refused
    request must not leave a row."""
    verify()
    return write()


def _account_agent_id(account: str) -> int:
    """Stable positive agent id. 73a08c2 used agents.id; this tree has no
    legacy agents row, so the id is 63 bits of sha256(account)."""
    digest = hashlib.sha256(account.encode()).digest()
    return int.from_bytes(digest[:8], "big") & ((1 << 63) - 1)


def _ensure_log_id(conn) -> str:
    row = conn.execute("SELECT log_id FROM legacy_log_meta WHERE id=1").fetchone()
    if row is not None:
        return row[0]
    pinned = os.environ.get("CYBERNET_GENESIS_LOG_ID", "").strip().lower()
    if len(pinned) == 64 and all(c in "0123456789abcdef" for c in pinned):
        log_id = pinned
    else:
        log_id = hashlib.sha256(
            b"cyberspace-legacy-log/v1\n" + core._NODE_PUB.encode()).hexdigest()
    conn.execute("INSERT INTO legacy_log_meta (id, log_id) VALUES (1, ?)", (log_id,))
    return log_id


def append_log_entry(conn, *, kind: str, account: str | None = None,
                     name: str | None = None, migration_id: int | None = None,
                     k0_pub: str | None = None, detail: dict | None = None) -> dict:
    """Append one witness-log entry on an open connection. Caller owns the
    transaction. logged_at is the node clock (unix seconds); an equal stamp
    is allowed, a backwards clock is refused so verify_chain can succeed."""
    import legacy_witness as lw
    if kind not in lw.KINDS:
        raise ValueError(f"unknown legacy-log kind {kind!r}")
    init_schema(conn)
    log_id = _ensure_log_id(conn)
    prev = conn.execute(
        "SELECT seq, entry_hash, agent_id, logged_at FROM legacy_migration_log ORDER BY seq DESC LIMIT 1"
    ).fetchone()
    seq = 1 if prev is None else int(prev[0]) + 1
    prev_hash = "none" if prev is None else prev[1]
    now = int(time.time())
    if prev is not None and now < int(prev[3]):
        raise RuntimeError("legacy log clock moved backwards")
    agent_id = _account_agent_id(account) if account is not None else None
    agent_prev = None
    if agent_id is not None:
        back = conn.execute(
            "SELECT MAX(seq) FROM legacy_migration_log WHERE agent_id=?", (agent_id,)
        ).fetchone()
        if back is not None and back[0] is not None:
            agent_prev = int(back[0])
    detail_s = json.dumps(detail or {}, sort_keys=True, separators=(",", ":"))
    entry = {
        "seq": seq,
        "prev_hash": prev_hash,
        "kind": kind,
        "agent_id": agent_id,
        "agent_prev_seq": agent_prev,
        "name_sha256": lw.name_hash(name),
        "name": name,
        "migration_id": migration_id,
        "k0_pub": k0_pub,
        "detail": detail_s,
        "logged_at": now,
    }
    # body_hash reads name/migration_id/k0_pub/detail/logged_at.
    entry["body_sha256"] = lw.body_hash(entry)
    ehash = lw.entry_hash(entry, log_id)
    msg = lw.header_bytes(entry, log_id)
    node_sig = _ed.sign(msg, bytes.fromhex(core._NODE_PRIV), bytes.fromhex(core._NODE_PUB)).hex()
    conn.execute(
        """INSERT INTO legacy_migration_log
           (seq, prev_hash, kind, agent_id, agent_prev_seq, name_sha256,
            body_sha256, entry_hash, name, migration_id, k0_pub, detail,
            logged_at, node_sig, log_id)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (seq, prev_hash, kind, agent_id, agent_prev, entry["name_sha256"],
         entry["body_sha256"], ehash, name, migration_id, k0_pub, entry["detail"],
         now, node_sig, log_id))
    entry["entry_hash"] = ehash
    return entry


def export_log(conn) -> tuple[str, list]:
    """(log_id, full entries) for legacy_witness.verify_chain. Empty when
    nothing has been appended."""
    init_schema(conn)
    meta = conn.execute("SELECT log_id FROM legacy_log_meta WHERE id=1").fetchone()
    if meta is None:
        return "", []
    rows = conn.execute(
        """SELECT seq, prev_hash, kind, agent_id, agent_prev_seq, name_sha256,
                  body_sha256, name, migration_id, k0_pub, detail, logged_at, entry_hash
           FROM legacy_migration_log ORDER BY seq"""
    ).fetchall()
    entries = []
    for r in rows:
        entries.append({
            "seq": r[0], "prev_hash": r[1], "kind": r[2], "agent_id": r[3],
            "agent_prev_seq": r[4], "name_sha256": r[5], "body_sha256": r[6],
            "name": r[7], "migration_id": r[8], "k0_pub": r[9], "detail": r[10],
            "logged_at": r[11], "entry_hash": r[12],
        })
    return meta[0], entries


def record_start(account: str, kind: str) -> str:
    """Write one start row or raise StartRefused (409); a refusal writes nothing.

    On success the same transaction appends a migrate-pending witness-log
    entry (seq, prev hash, agent_prev_seq, name_sha256). The caller's kind
    (rotation / recovery) is not a log kind; it is stored in the entry detail.
    """
    with core._db_lock, core._db() as conn:
        ok, why = check_start_cap(conn, account)
        if not ok:
            raise StartRefused(why)
        started = _now()
        cur = conn.execute("INSERT INTO legacy_migrations (account, kind, started_at) VALUES (?,?,?)",
                           (account, kind, started))
        append_log_entry(conn, kind="migrate-pending", account=account,
                         migration_id=cur.lastrowid,
                         detail={"account": account, "start_kind": kind, "started_at": started})
    return why
