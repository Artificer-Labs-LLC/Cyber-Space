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

from datetime import datetime, timezone

import core
from fed import ed25519 as _ed

MAX_STARTS_PER_ACCOUNT = 3

_SCHEMA = (
    """CREATE TABLE IF NOT EXISTS window_open_log (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        opened_at TEXT NOT NULL,
        opened_by TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS window_refused_bindings (
        window_id INTEGER NOT NULL,
        source TEXT NOT NULL,
        row_key TEXT NOT NULL,
        pubkey TEXT NOT NULL,
        reason TEXT NOT NULL,
        PRIMARY KEY (source, row_key, pubkey))""",
    """CREATE TABLE IF NOT EXISTS window_close_log (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        closed_at TEXT NOT NULL,
        closed_by TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS legacy_migrations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        account TEXT NOT NULL,
        kind TEXT NOT NULL,
        started_at TEXT NOT NULL)""",
)


def init_schema(conn) -> None:
    for s in _SCHEMA:
        conn.execute(s)


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
    dropped. Names with no history and no binding appear nowhere."""
    held, refused, reserved = [], [], []
    hist = _all_histories(conn) if _has_table(conn, "name_rotations") else {}
    seen = set()
    for row in conn.execute(
            "SELECT name, node_pubkey, issued_at, expires_at, signature FROM name_bindings ORDER BY name"):
        seen.add(row[0])
        anchor, why = _anchor_from_hops(hist.get(row[0], ()))
        if anchor:
            reserved.append({"name": row[0], "reserved_for": anchor, "current_pubkey": row[1],
                             "weak_pubkey": row[1] if is_weak_pubkey(row[1]) else None})
        elif why:
            refused.append(tuple(row) + (why,))
        elif is_weak_pubkey(row[1]):
            refused.append(tuple(row))
        else:
            held.append(row)
    for name in sorted(set(hist) - seen):  # orphan pass
        anchor, why = _anchor_from_hops(hist[name])
        if anchor:
            reserved.append({"name": name, "reserved_for": anchor, "current_pubkey": None,
                             "weak_pubkey": None, "orphan": True})
        elif why:
            refused.append((name, None, None, None, None, why))
    return {"held": held, "refused": refused, "reserved": reserved}


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


# Private clock hook: tests may set window_open._now_hook; no public
# caller-supplied `now` exists on open_window/record_start (ART-41 BLOCK).
_now_hook = None


def _now() -> str:
    if _now_hook is not None:
        return _now_hook()
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def open_window(opened_by: str) -> dict:
    """Record the window-open anchor + refused-bindings entry, once."""
    with core._db_lock, core._db() as conn:
        init_schema(conn)
        existing = window_entry(conn)
        if existing:
            return {"id": existing[0], "opened_at": existing[1], "opened_by": existing[2],
                    "already_open": True}
        opened_at = _now()
        conn.execute("INSERT INTO window_open_log (id, opened_at, opened_by) VALUES (1,?,?)",
                     (opened_at, opened_by))
        n = record_refused_bindings(conn, 1)
    return {"id": 1, "opened_at": opened_at, "opened_by": opened_by,
            "refused_recorded": n, "already_open": False}


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


def record_start(account: str, kind: str) -> str:
    """Write one start row or raise StartRefused (409); a refusal writes nothing."""
    with core._db_lock, core._db() as conn:
        ok, why = check_start_cap(conn, account)
        if not ok:
            raise StartRefused(why)
        conn.execute("INSERT INTO legacy_migrations (account, kind, started_at) VALUES (?,?,?)",
                     (account, kind, _now()))
    return why
