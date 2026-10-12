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
    counts ALL legacy_migrations rows for the account since the recorded
    open_window entry (Cipher's wording) - not TLS go-live, not wall-clock
    since boot. Before open_window is recorded, no start is allowed.
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


def snapshot_bindings(conn):
    """All name_bindings rows (no SQL expires filter); weak keys -> refused."""
    held, refused = [], []
    for row in conn.execute(
            "SELECT name, node_pubkey, issued_at, expires_at, signature FROM name_bindings ORDER BY name"):
        (refused if is_weak_pubkey(row[1]) else held).append(row)
    return {"held": held, "refused": refused}


def window_entry(conn):
    return conn.execute("SELECT id, opened_at, opened_by FROM window_open_log WHERE id=1").fetchone()


def open_window(opened_by: str, now: str | None = None) -> dict:
    """Record the window-open anchor + refused-bindings entry, once."""
    with core._db_lock, core._db() as conn:
        init_schema(conn)
        existing = window_entry(conn)
        if existing:
            return {"id": existing[0], "opened_at": existing[1], "opened_by": existing[2],
                    "already_open": True}
        opened_at = now or datetime.now(timezone.utc).isoformat(timespec="seconds")
        conn.execute("INSERT INTO window_open_log (id, opened_at, opened_by) VALUES (1,?,?)",
                     (opened_at, opened_by))
        n = record_refused_bindings(conn, 1)
    return {"id": 1, "opened_at": opened_at, "opened_by": opened_by,
            "refused_recorded": n, "already_open": False}


def check_start_cap(conn, account: str) -> tuple[bool, str]:
    """(allowed, reason). Counts ALL legacy_migrations rows for the account
    started at/after the recorded open_window entry."""
    init_schema(conn)
    entry = window_entry(conn)
    if entry is None:
        return False, "window not open: no recorded open_window entry"
    n = conn.execute(
        "SELECT COUNT(*) FROM legacy_migrations WHERE account=? AND started_at>=?",
        (account, entry[1])).fetchone()[0]
    if n >= MAX_STARTS_PER_ACCOUNT:
        return False, f"start cap reached ({n}/{MAX_STARTS_PER_ACCOUNT} since open_window {entry[1]})"
    return True, f"{n}/{MAX_STARTS_PER_ACCOUNT} since open_window {entry[1]}"


def record_start(account: str, kind: str, now: str | None = None) -> tuple[bool, str]:
    with core._db_lock, core._db() as conn:
        ok, why = check_start_cap(conn, account)
        if ok:
            conn.execute("INSERT INTO legacy_migrations (account, kind, started_at) VALUES (?,?,?)",
                         (account, kind, now or datetime.now(timezone.utc).isoformat(timespec="seconds")))
    return ok, why
