"""Name pins and rotation-fork discipline (ART-29, Villhaze 1556e24a).

Rebuilt to the gate Villhaze adopted on ART-29 (524ef05b + 2dcc893c) after
the Cipher (b0fa3fae), Bulwark (35c9c527) and Lodestar BLOCKs on b606d2e,
with the ART-42 rulings in 392140b7.

A pin is the key this node will resolve a name to. It moves only when the
current pin signs a contiguous v2 rotation certificate (rotate_name.py):
old_pubkey == pin, seq == pin seq + 1, prev_hash == pin head hash. The pin
log is append-only: a move is a new row, never an edit of an old one.

Gate, in the order a certificate meets it:

G0. namefork budget. The caller charges the per-peer bucket once per cert
    BEFORE any cert is normalized, outside the DB lock (prepare_round).
    Verifies are the expensive resource; nobody spends them and pays later.
G1. _norm_cert: shape, then weak_reason on BOTH keys, then the signature
    (strict checkvalid). A weak old key or a weak new key refuses the cert
    before any verify. A v1 record (no seq, no prev_hash) never moves a pin.
G2. A cert never introduces a name. A name with no pin and no binding is
    refused (unknown-name) — it pins nothing and contests nothing. A name
    with a binding but no pin is considered only from an introducer: a node
    key pinned out of band (CYBERNET_OOB_NODE_PINS), or the local rotate
    route, whose holder check already ran. Otherwise unpinned-sender.
G3. A contested name never moves and is never silently un-contested.
G4. Contiguity. old == pin, seq == pin seq + 1, prev_hash == head. A cert
    at an already-accepted seq that is byte-identical to the accepted one
    is a replay: refused, nothing changes. A different valid cert that
    continues the same (name, prior key, seq) is fork evidence: CONTESTED.
    The v2 chain is necessary, not sufficient: G1, G2 and G5 still apply.
G5. F3: one accepted rotation per name per gossip round. A round is not a
    POST. The accept time is stored in name_pins.last_round_at, so a second
    rotation for the name waits round_seconds() across calls. That pause is
    what gives fork evidence time to gossip before a fast chain builds depth.

Fork rule (chain depth is never a tiebreak; a winner is not chosen by
chain depth or by cross-node first-seen — only witness receipts may do
that, and none are consulted here):

F1. Rotation certificates are first-class gossip objects. A second valid
    certificate for the same (name, prior key, seq) is stored as fork
    evidence and the name is marked CONTESTED. Resolve refuses a contested
    name. The local row is not served.
F2. Two distinct valid continuations of the same generation arriving in one
    round make the name contested from birth. First-seen does not pick.
F3. At most one rotation is accepted per name per gossip round (G5).
F4. The first two distinct fork certificates per (name, prior key, seq) are
    stored. The rest are counted. The caller charges the per-peer bucket
    once per counted cert, on top of the G0 charge.

Pins never expire (Villhaze 392140b7, (B) refined). A pin dies only by a
pinned-key rotation cert or by the operator's own logged local unpin. When
the binding has expired, day 90 has passed, and a claim arrives under a
different key with no rotation cert, the name is marked PIN-STALE for local
decision: neither the old key nor the new one is served silently.

The fork rule buys per-node consistency. It does not buy mirror agreement
after a fork, and it does not recover a stolen key. Any holder of a key the
chain has pinned can freeze a name by signing a second certificate for that
key's generation. A contested name has no recovery path in this build.
"""

from __future__ import annotations

import os
import sqlite3
import time
from datetime import datetime, timedelta, timezone

from rotate_name import (is_v2, pin_anchor_hash, rotation_cert_hash,
                         verify_rotation)

# Published prefix of the genesis name key (docs/NAMES.md). The full pin
# is CYBERNET_GENESIS_NAME_PIN (64 hex, must start with this prefix).
# Unset means this process has no genesis constant loaded.
GENESIS_LABEL = "genesis"
GENESIS_PIN_PREFIX = "46b62b6c"

# Chain depth is never a tiebreak. Stated here, where the fork rule lives.
FORK_RULE = (
    "Chain depth is never a tiebreak. A second valid rotation certificate "
    "for the same (name, prior key, seq) marks the name CONTESTED. Resolve "
    "refuses it. Winner determination is by witness receipts only — never "
    "by chain depth, never by cross-node first-seen."
)

# Pins never auto-expire. This is only the lapse threshold for PIN-STALE.
PIN_STALE_AFTER_DAYS = 90

# The local rotate route. It is an introducer for a bound-but-unpinned
# name because the route has already checked that the old key holds the
# binding and that the new key signed the new binding. Not a string: a
# network sender_pub can never equal it.
LOCAL_ROUTE = object()


def second_cert_contests(name: str, old_pubkey: str, new_pubkey: str) -> bool:
    """Production fork policy. A mutant that returns False keeps a local
    winner and fails the F1-split row."""
    return True


def bootstrap_picks_first() -> bool:
    """Production bootstrap policy. A mutant that returns True is the
    first-seen adoption the F2-boot row must reject."""
    return False


def cert_introduces_name() -> bool:
    """G2. Production: a cert never introduces a name. A mutant that
    returns True seeds an unknown name from the cert's own old key — the
    Lodestar/Bulwark squat the unknown-name row must reject."""
    return False


def round_seconds() -> int:
    """One gossip round: the names-gossip cadence (_reannounce_loop)."""
    try:
        base = int(os.environ.get("CYBERNET_ANNOUNCE_INTERVAL", "3600"))
    except ValueError:
        base = 3600
    return max(300, base)


def round_gate_open(state: dict, now: float) -> bool:
    """G5 / F3. True when this name has not accepted a rotation within the
    last gossip round. A mutant that returns True accepts a burst."""
    last = state.get("last_round_at")
    if last is None:
        return True
    return (now - float(last)) >= round_seconds()


def genesis_pin() -> str | None:
    raw = os.environ.get("CYBERNET_GENESIS_NAME_PIN", "").strip().lower()
    if len(raw) != 64 or not raw.startswith(GENESIS_PIN_PREFIX):
        return None
    try:
        bytes.fromhex(raw)
    except ValueError:
        return None
    return raw


def oob_allowlist() -> set[str] | None:
    """Node keys pinned out of band. None means the operator has not
    configured an allowlist. A gossip sender may not introduce an unpinned
    name until the list exists and contains that sender."""
    raw = os.environ.get("CYBERNET_OOB_NODE_PINS")
    if raw is None:
        return None
    return {p.strip().lower() for p in raw.split(",") if p.strip()}


def sender_may_introduce(sender_pub) -> bool:
    if sender_pub is None or not isinstance(sender_pub, str):
        return False
    allow = oob_allowlist()
    if allow is None:
        return False
    return sender_pub.strip().lower() in allow


def _introducer_ok(sender_pub) -> bool:
    if sender_pub is LOCAL_ROUTE:
        return True
    return sender_may_introduce(sender_pub)


def _weak_reason(pub):
    """G1: the same weak_reason every admission point uses (strict decode,
    small-order, mixed-order). Belt mutants replace this with a no-op."""
    import window_open  # lazy: window_open imports core
    return window_open.weak_reason(pub)


def _old_key_weak(pub) -> bool:
    """G1, old key. A mixed-order holder passes strict checkvalid; this is
    what refuses it. The old-key belt mutant replaces this."""
    return _weak_reason(pub) is not None


def _new_key_weak(pub) -> bool:
    """G1, new key. An all-zero or mixed-order successor pins nothing,
    ever. The new-key belt mutant replaces this."""
    return _weak_reason(pub) is not None


def _verify(rec: dict) -> bool:
    return verify_rotation(rec) is None


def _has_table(conn: sqlite3.Connection, table: str) -> bool:
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (table,)).fetchone() is not None


def ensure_rotation_columns(conn: sqlite3.Connection) -> None:
    """name_rotations carries seq + prev_hash so a v2 row re-verifies.
    Legacy v1 rows keep NULLs (history: they verify, they move no pin)."""
    if not _has_table(conn, "name_rotations"):
        return
    cols = {r[1] for r in conn.execute("PRAGMA table_info(name_rotations)")}
    if "seq" not in cols:
        conn.execute("ALTER TABLE name_rotations ADD COLUMN seq INTEGER")
    if "prev_hash" not in cols:
        conn.execute("ALTER TABLE name_rotations ADD COLUMN prev_hash TEXT")


def ensure_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """CREATE TABLE IF NOT EXISTS name_pins (
            name TEXT PRIMARY KEY,
            pubkey TEXT NOT NULL,
            seq INTEGER NOT NULL,
            head_hash TEXT NOT NULL,
            last_round_at REAL,
            updated_at TEXT NOT NULL
        )""")
    conn.execute(
        """CREATE TABLE IF NOT EXISTS name_pin_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            pubkey TEXT NOT NULL,
            seq INTEGER NOT NULL,
            prev_pubkey TEXT NOT NULL,
            prev_hash TEXT NOT NULL,
            issued_at TEXT NOT NULL,
            cert_signature TEXT NOT NULL,
            cert_hash TEXT NOT NULL,
            event TEXT NOT NULL,
            recorded_at TEXT NOT NULL
        )""")
    conn.execute(
        """CREATE INDEX IF NOT EXISTS idx_name_pin_log_seq
           ON name_pin_log(name, seq)""")
    conn.execute(
        """CREATE TABLE IF NOT EXISTS name_fork_certs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            old_pubkey TEXT NOT NULL,
            new_pubkey TEXT NOT NULL,
            issued_at TEXT NOT NULL,
            seq INTEGER NOT NULL,
            prev_hash TEXT NOT NULL,
            signature TEXT NOT NULL,
            cert_hash TEXT NOT NULL UNIQUE,
            recorded_at TEXT NOT NULL
        )""")
    conn.execute(
        """CREATE TABLE IF NOT EXISTS name_fork_overflow (
            name TEXT NOT NULL,
            old_pubkey TEXT NOT NULL,
            seq INTEGER NOT NULL,
            overflow_count INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (name, old_pubkey, seq)
        )""")
    conn.execute(
        """CREATE TABLE IF NOT EXISTS name_contested (
            name TEXT PRIMARY KEY,
            since TEXT NOT NULL,
            reason TEXT NOT NULL
        )""")
    conn.execute(
        """CREATE TABLE IF NOT EXISTS name_pin_stale (
            name TEXT PRIMARY KEY,
            since TEXT NOT NULL,
            pin TEXT NOT NULL,
            challenger TEXT NOT NULL
        )""")
    ensure_rotation_columns(conn)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")


def _insert_pin(conn: sqlite3.Connection, name: str, pub: str) -> None:
    now = _now()
    head = pin_anchor_hash(name, pub)
    conn.execute(
        "INSERT INTO name_pins (name, pubkey, seq, head_hash, last_round_at,"
        " updated_at) VALUES (?,?,0,?,NULL,?)",
        (name, pub, head, now))
    conn.execute(
        "INSERT INTO name_pin_log (name, pubkey, seq, prev_pubkey, prev_hash,"
        " issued_at, cert_signature, cert_hash, event, recorded_at)"
        " VALUES (?,?,0,'','','','',?,'pin',?)",
        (name, pub, head, now))


def ensure_genesis_pin(conn: sqlite3.Connection) -> None:
    """The genesis label is pinned to the out-of-band constant when one
    is configured and no pin row exists yet. A later contiguous cert can
    still move it — the log records that move. The lost genesis key makes
    the practical pin permanent; the shape is not a leash with no rotation."""
    ensure_schema(conn)
    pin = genesis_pin()
    if not pin:
        return
    row = conn.execute(
        "SELECT pubkey FROM name_pins WHERE name=?", (GENESIS_LABEL,)).fetchone()
    if row is not None:
        return
    _insert_pin(conn, GENESIS_LABEL, pin)


def _pin_state(conn: sqlite3.Connection, name: str) -> dict | None:
    ensure_schema(conn)
    if name == GENESIS_LABEL:
        ensure_genesis_pin(conn)
    row = conn.execute(
        "SELECT pubkey, seq, head_hash, last_round_at FROM name_pins"
        " WHERE name=?", (name,)).fetchone()
    if row is None:
        return None
    return {"name": name, "pubkey": str(row[0]).lower(), "seq": int(row[1]),
            "head": str(row[2]).lower(), "last_round_at": row[3],
            "virtual": False}


def current_pin(conn: sqlite3.Connection, name: str) -> str | None:
    st = _pin_state(conn, name)
    return None if st is None else st["pubkey"]


def current_seq(conn: sqlite3.Connection, name: str) -> int | None:
    st = _pin_state(conn, name)
    return None if st is None else st["seq"]


def current_head(conn: sqlite3.Connection, name: str) -> str | None:
    st = _pin_state(conn, name)
    return None if st is None else st["head"]


def last_round_at(conn: sqlite3.Connection, name: str):
    st = _pin_state(conn, name)
    return None if st is None else st["last_round_at"]


def is_contested(conn: sqlite3.Connection, name: str) -> bool:
    ensure_schema(conn)
    row = conn.execute(
        "SELECT 1 FROM name_contested WHERE name=?", (name,)).fetchone()
    return row is not None


def is_pin_stale(conn: sqlite3.Connection, name: str) -> bool:
    ensure_schema(conn)
    row = conn.execute(
        "SELECT 1 FROM name_pin_stale WHERE name=?", (name,)).fetchone()
    return row is not None


def pin_refuses_before_signature(conn: sqlite3.Connection, name: str,
                                 pubkey: str) -> bool:
    """V1 / contested / PIN-STALE gate. Callers invoke this before any
    signature count on a served binding. True means resolve must refuse."""
    if is_contested(conn, name) or is_pin_stale(conn, name):
        return True
    pin = current_pin(conn, name)
    if pin is None:
        return False
    return str(pubkey or "").strip().lower() != pin


def pin_initial(conn: sqlite3.Connection, name: str, pubkey: str) -> None:
    """TOFU from the claim path: the first admitted key is the pin at seq 0
    with head pin_anchor_hash(name, key). A pin already present is left
    alone — it moves only through a certificate."""
    ensure_schema(conn)
    if name == GENESIS_LABEL:
        ensure_genesis_pin(conn)
    if current_pin(conn, name) is not None:
        return
    _insert_pin(conn, name, pubkey.lower())


def lapse_refusal(conn: sqlite3.Connection, name: str, pubkey: str,
                  now_dt: datetime | None = None) -> bool:
    """Villhaze 392140b7 lapse case. The pin is never forgotten. When the
    binding is gone or expired more than PIN_STALE_AFTER_DAYS ago, and a
    claim arrives under a different key with no rotation cert, mark the
    name PIN-STALE for local decision and return True. Otherwise False
    (the ordinary pin refusal applies, or there is no refusal at all)."""
    pin = current_pin(conn, name)
    pub = str(pubkey or "").strip().lower()
    if pin is None or pub == pin:
        return False
    now_dt = now_dt or datetime.now(timezone.utc)
    try:
        row = conn.execute(
            "SELECT expires_at FROM name_bindings WHERE name=?",
            (name,)).fetchone()
    except sqlite3.OperationalError:
        row = None
    if row is not None:
        try:
            exp = datetime.fromisoformat(str(row[0]))
        except ValueError:
            return False
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if exp + timedelta(days=PIN_STALE_AFTER_DAYS) > now_dt:
            return False
    conn.execute(
        "INSERT INTO name_pin_stale (name, since, pin, challenger)"
        " VALUES (?,?,?,?) ON CONFLICT(name) DO NOTHING",
        (name, _now(), pin, pub))
    return True


def local_unpin(conn: sqlite3.Connection, name: str, reason: str) -> bool:
    """The operator's own deliberate unpin (392140b7 death (2)). Logged in
    the append-only pin log. Never called by gossip or by any route."""
    st = _pin_state(conn, name)
    if st is None:
        return False
    conn.execute(
        "INSERT INTO name_pin_log (name, pubkey, seq, prev_pubkey, prev_hash,"
        " issued_at, cert_signature, cert_hash, event, recorded_at)"
        " VALUES (?,'',?,?,?,'','',?,?,?)",
        (name, st["seq"] + 1, st["pubkey"], st["head"],
         "local-unpin", f"local-unpin: {reason}"[:200], _now()))
    conn.execute("DELETE FROM name_pins WHERE name=?", (name,))
    conn.execute("DELETE FROM name_pin_stale WHERE name=?", (name,))
    return True


def _mark_contested(conn: sqlite3.Connection, name: str) -> None:
    conn.execute(
        "INSERT INTO name_contested (name, since, reason) VALUES (?,?,?)"
        " ON CONFLICT(name) DO NOTHING",
        (name, _now(),
         "fork: two valid certs for the same (name, prior key, seq)"))


def _store_fork_cert(conn: sqlite3.Connection, rec: dict) -> str:
    """F4. Store the first two distinct certs per (name, prior key, seq).
    Count the rest. Returns 'stored', 'duplicate', or 'overflow'."""
    have = conn.execute(
        "SELECT cert_hash FROM name_fork_certs WHERE name=? AND old_pubkey=?"
        " AND seq=?", (rec["name"], rec["old_pubkey"], rec["seq"])).fetchall()
    hashes = [str(r[0]) for r in have]
    if rec["cert_hash"] in hashes:
        return "duplicate"
    if len(hashes) >= 2:
        conn.execute(
            "INSERT INTO name_fork_overflow (name, old_pubkey, seq,"
            " overflow_count) VALUES (?,?,?,1) ON CONFLICT(name, old_pubkey,"
            " seq) DO UPDATE SET overflow_count = overflow_count + 1",
            (rec["name"], rec["old_pubkey"], rec["seq"]))
        return "overflow"
    conn.execute(
        "INSERT OR IGNORE INTO name_fork_certs (name, old_pubkey, new_pubkey,"
        " issued_at, seq, prev_hash, signature, cert_hash, recorded_at)"
        " VALUES (?,?,?,?,?,?,?,?,?)",
        (rec["name"], rec["old_pubkey"], rec["new_pubkey"], rec["issued_at"],
         rec["seq"], rec["prev_hash"], rec["signature"], rec["cert_hash"],
         _now()))
    return "stored"


class _Prepared(dict):
    """A certificate that already passed G1 in prepare_round."""


_FIELDS = ("name", "old_pubkey", "new_pubkey", "issued_at", "signature")


def _norm_cert(rec) -> dict | None:
    """G1: shape, weak_reason on BOTH keys, then the signature. The weak
    checks run before any verify: a weak old key or a weak new key refuses
    the cert and costs no signature check. A v1 record moves no pin."""
    if not isinstance(rec, dict) or not is_v2(rec):
        return None
    for k in _FIELDS + ("prev_hash",):
        if not isinstance(rec.get(k), str):
            return None
    seq = rec.get("seq")
    if isinstance(seq, bool) or not isinstance(seq, int):
        return None
    out = {
        "v": 2,
        "name": rec["name"].strip().lower(),
        "old_pubkey": rec["old_pubkey"].strip().lower(),
        "new_pubkey": rec["new_pubkey"].strip().lower(),
        "issued_at": rec["issued_at"],
        "seq": seq,
        "prev_hash": rec["prev_hash"].strip().lower(),
        "signature": rec["signature"].strip().lower(),
    }
    if _old_key_weak(out["old_pubkey"]):
        return None
    if _new_key_weak(out["new_pubkey"]):
        return None
    if not _verify(out):
        return None
    out["cert_hash"] = rotation_cert_hash(out)
    return _Prepared(out)


def prepare_round(certs, charge=None) -> list:
    """G0 then G1, outside the DB lock. `charge` is called once per cert
    BEFORE any cert is normalized; a charge that raises (429) stops the
    round with zero verifies spent."""
    raw = list(certs) if isinstance(certs, list) else []
    if charge is not None:
        for _ in raw:
            charge()
    out = []
    for item in raw:
        rec = _norm_cert(item)
        if rec is not None:
            out.append(rec)
    return out


def _binding_key(conn: sqlite3.Connection, name: str) -> str | None:
    try:
        row = conn.execute(
            "SELECT node_pubkey FROM name_bindings WHERE name=?",
            (name,)).fetchone()
    except sqlite3.OperationalError:
        return None
    if row is None:
        return None
    return str(row[0]).lower()


def _state_for(conn: sqlite3.Connection, rec: dict, sender_pub):
    """G2. Returns (state, None) or (None, refusal reason)."""
    name = rec["name"]
    st = _pin_state(conn, name)
    if st is not None:
        return st, None
    bound = _binding_key(conn, name)
    if bound is None:
        if not cert_introduces_name():
            return None, "unknown-name"
        bound = rec["old_pubkey"]  # mutant only
    elif not _introducer_ok(sender_pub):
        return None, "unpinned-sender"
    if _weak_reason(bound) is not None:
        return None, "weak-binding"
    return {"name": name, "pubkey": bound, "seq": 0,
            "head": pin_anchor_hash(name, bound), "last_round_at": None,
            "virtual": True}, None


def _contiguous(state: dict, rec: dict) -> bool:
    """G4. The cert's signer is the current pin, its seq is the next pin
    generation, and its prev_hash is the head of this node's chain. No
    jumps, no other key, no replay of an older generation."""
    return (rec["old_pubkey"] == state["pubkey"]
            and rec["seq"] == state["seq"] + 1
            and rec["prev_hash"] == state["head"])


def _is_historical(state: dict, rec: dict) -> bool:
    """G4. A cert at or below the pin's generation never moves the pin: it
    is a replay, fork evidence, or stale. The seq-dropped mutant returns
    False here (with _contiguous reduced to the old-key check) — that is
    the b606d2e replay the belt must refuse."""
    return rec["seq"] <= state["seq"]


def _frozen(conn: sqlite3.Connection, name: str, contested: set) -> bool:
    """G3. A contested name does not move. The un-contest mutant returns
    False."""
    return name in contested or is_contested(conn, name)


def _log_row(conn: sqlite3.Connection, name: str, seq: int) -> dict | None:
    row = conn.execute(
        "SELECT pubkey, prev_pubkey, prev_hash, issued_at, cert_signature,"
        " cert_hash FROM name_pin_log WHERE name=? AND seq=? AND event IN"
        " ('pin','rotate') ORDER BY id DESC LIMIT 1", (name, seq)).fetchone()
    if row is None:
        return None
    return {"pubkey": row[0], "prev_pubkey": row[1], "prev_hash": row[2],
            "issued_at": row[3], "signature": row[4], "cert_hash": row[5]}


def _historical(conn: sqlite3.Connection, state: dict, rec: dict):
    """A cert at or below the pin's seq. Returns ('replay', None),
    ('fork', accepted_cert) or ('stale', None)."""
    if state.get("virtual"):
        return "stale", None
    logged = _log_row(conn, rec["name"], rec["seq"])
    prior = _log_row(conn, rec["name"], rec["seq"] - 1)
    if logged is None or prior is None:
        return "stale", None
    if logged["cert_hash"] == rec["cert_hash"]:
        return "replay", None
    if prior["pubkey"] == rec["old_pubkey"] and prior["cert_hash"] == rec["prev_hash"]:
        accepted = {"name": rec["name"], "old_pubkey": logged["prev_pubkey"],
                    "new_pubkey": logged["pubkey"],
                    "issued_at": logged["issued_at"], "seq": rec["seq"],
                    "prev_hash": logged["prev_hash"],
                    "signature": logged["signature"],
                    "cert_hash": logged["cert_hash"]}
        return "fork", accepted
    return "stale", None


def _note_fork(conn: sqlite3.Connection, rec: dict, accepted: dict | None) -> str:
    """F1. Returns 'contested', 'overflow', or 'ignored' (the F1 mutant)."""
    if not second_cert_contests(rec["name"], rec["old_pubkey"], rec["new_pubkey"]):
        return "ignored"
    if accepted is not None:
        _store_fork_cert(conn, accepted)
    stored = _store_fork_cert(conn, rec)
    _mark_contested(conn, rec["name"])
    return "overflow" if stored == "overflow" else "contested"


def _persist_round(conn: sqlite3.Connection, name: str, now: float) -> None:
    """G5: the round is stored in the DB, so it holds across calls. The
    per-POST mutant replaces this with a no-op."""
    conn.execute("UPDATE name_pins SET last_round_at=? WHERE name=?",
                 (now, name))


def _move_pin(conn: sqlite3.Connection, state: dict, rec: dict,
              now: float) -> dict:
    """Append one pin-log row and point the current pin at the new key.
    The log is insert-only. Chain depth is not consulted."""
    name = rec["name"]
    if state.get("virtual"):
        _insert_pin(conn, name, state["pubkey"])
    stamp = _now()
    conn.execute(
        "INSERT INTO name_pin_log (name, pubkey, seq, prev_pubkey, prev_hash,"
        " issued_at, cert_signature, cert_hash, event, recorded_at)"
        " VALUES (?,?,?,?,?,?,?,?,'rotate',?)",
        (name, rec["new_pubkey"], rec["seq"], rec["old_pubkey"],
         rec["prev_hash"], rec["issued_at"], rec["signature"],
         rec["cert_hash"], stamp))
    conn.execute(
        "UPDATE name_pins SET pubkey=?, seq=?, head_hash=?, updated_at=?"
        " WHERE name=?",
        (rec["new_pubkey"], rec["seq"], rec["cert_hash"], stamp, name))
    _persist_round(conn, name, now)
    if _has_table(conn, "name_rotations"):
        conn.execute(
            "INSERT OR IGNORE INTO name_rotations (name, old_pubkey,"
            " new_pubkey, issued_at, signature, accepted_at, seq, prev_hash)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (name, rec["old_pubkey"], rec["new_pubkey"], rec["issued_at"],
             rec["signature"], stamp, rec["seq"], rec["prev_hash"]))
    return {"name": name, "pubkey": rec["new_pubkey"], "seq": rec["seq"],
            "head": rec["cert_hash"], "last_round_at": now, "virtual": False}


def ingest_rotation_round(conn: sqlite3.Connection, certs: list, sender_pub,
                          now: float | None = None) -> dict:
    """One gossip round from `sender_pub` (G2 needs the sender).

    Certs from prepare_round are taken as G1-checked; anything else runs
    _norm_cert here. Certificates are considered in arrival order; a cert
    that does not continue the current pin is not promoted because a
    longer chain sits later in the batch. Chain depth is never a tiebreak.

    Returns accepted (name -> new pubkey), contested names, deferred names
    (G5 held them), refused (reason -> count), and overflow_n (F4 — the
    caller charges the peer bucket that many times).
    """
    ensure_schema(conn)
    now = time.time() if now is None else float(now)
    recs = []
    for item in certs or []:
        rec = item if isinstance(item, _Prepared) else _norm_cert(item)
        if rec is not None:
            recs.append(rec)
    accepted: dict[str, str] = {}
    contested: set[str] = set()
    deferred: set[str] = set()
    refused: dict[str, int] = {}
    overflow_n = 0

    def refuse(why: str) -> None:
        refused[why] = refused.get(why, 0) + 1

    # Pass 1 — classify against the state at round start.
    states: dict[str, dict] = {}
    pending: list[dict] = []
    for rec in recs:
        name = rec["name"]
        if name not in states:
            st, why = _state_for(conn, rec, sender_pub)
            if st is None:
                refuse(why)
                continue
            states[name] = st
        st = states[name]
        if _is_historical(st, rec):
            kind, acc = _historical(conn, st, rec)
            if kind == "replay":
                refuse("replay")
                continue
            if kind == "fork":
                noted = _note_fork(conn, rec, acc)
                if noted == "ignored":
                    refuse("fork-ignored")
                    continue
                contested.add(name)
                if noted == "overflow":
                    overflow_n += 1
                continue
            refuse("non-contiguous")
            continue
        pending.append(rec)

    # F2 — two distinct valid continuations of the round-start generation.
    # First-seen does not pick. Chain depth is never a tiebreak.
    groups: dict[str, list[dict]] = {}
    for rec in pending:
        st = states[rec["name"]]
        if not is_contested(conn, rec["name"]) and _contiguous(st, rec):
            groups.setdefault(rec["name"], []).append(rec)
    for name, group in groups.items():
        distinct = list({r["cert_hash"]: r for r in group}.values())
        if len(distinct) < 2 or bootstrap_picks_first():
            continue
        _mark_contested(conn, name)
        contested.add(name)
        for rec in distinct:
            if _store_fork_cert(conn, rec) == "overflow":
                overflow_n += 1

    # Pass 2 — apply, in arrival order, at most one generation per round.
    for rec in pending:
        name = rec["name"]
        if _frozen(conn, name, contested):
            refuse("contested")  # G3: no move, no silent un-contest
            continue
        st = states[name]
        if not _contiguous(st, rec):
            refuse("non-contiguous")
            continue
        if not round_gate_open(st, now):
            deferred.add(name)
            refuse("round")
            continue
        states[name] = _move_pin(conn, st, rec, now)
        accepted[name] = rec["new_pubkey"]
    return {
        "accepted": accepted,
        "contested": contested,
        "deferred": deferred,
        "refused": refused,
        "overflow_n": overflow_n,
    }


def consider_rotation(conn: sqlite3.Connection, rec: dict,
                      now: float | None = None) -> str:
    """Single-certificate entry used by the rotate route (an introducer for
    a bound-but-unpinned name: its holder check already ran). Same gate as
    a one-cert gossip round. Returns 'accepted', 'contested', 'deferred',
    or 'refused'."""
    result = ingest_rotation_round(conn, [rec], LOCAL_ROUTE, now=now)
    name = str(rec.get("name", "")).strip().lower() if isinstance(rec, dict) else ""
    if name in result["contested"] or (name and is_contested(conn, name)):
        return "contested"
    if name in result["accepted"]:
        return "accepted"
    if name in result["deferred"]:
        return "deferred"
    return "refused"


def fork_cert_count(conn: sqlite3.Connection, name: str) -> int:
    ensure_schema(conn)
    row = conn.execute(
        "SELECT COUNT(*) FROM name_fork_certs WHERE name=?", (name,)).fetchone()
    return int(row[0]) if row else 0


def overflow_count(conn: sqlite3.Connection, name: str) -> int:
    ensure_schema(conn)
    row = conn.execute(
        "SELECT COALESCE(SUM(overflow_count), 0) FROM name_fork_overflow"
        " WHERE name=?", (name,)).fetchone()
    return int(row[0]) if row else 0


def pin_log_moves(conn: sqlite3.Connection, name: str) -> int:
    ensure_schema(conn)
    row = conn.execute(
        "SELECT COUNT(*) FROM name_pin_log WHERE name=? AND event='rotate'",
        (name,)).fetchone()
    return int(row[0]) if row else 0


def gossip_rotations(conn: sqlite3.Connection, names: list[str]) -> list[dict]:
    """Certificates this node will repeat, as v2 objects. Fork evidence goes
    first (a peer cannot see a split from the binding alone), then the
    accepted pin chain, oldest generation first."""
    ensure_schema(conn)
    if not names:
        return []
    qmarks = ",".join("?" for _ in names)
    forks = conn.execute(
        f"SELECT name, old_pubkey, new_pubkey, issued_at, seq, prev_hash,"
        f" signature FROM name_fork_certs WHERE name IN ({qmarks})"
        f" ORDER BY id", tuple(names)).fetchall()
    chain = conn.execute(
        f"SELECT name, prev_pubkey, pubkey, issued_at, seq, prev_hash,"
        f" cert_signature FROM name_pin_log WHERE name IN ({qmarks})"
        f" AND event='rotate' ORDER BY name, seq", tuple(names)).fetchall()
    out = []
    seen = set()
    for row in list(forks) + list(chain):
        key = (row[0], row[4], row[6])
        if key in seen:
            continue
        seen.add(key)
        out.append({"v": 2, "name": row[0], "old_pubkey": row[1],
                    "new_pubkey": row[2], "issued_at": row[3],
                    "seq": int(row[4]), "prev_hash": row[5],
                    "signature": row[6]})
    return out
