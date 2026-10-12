"""Name pins and rotation-fork discipline (ART-29, Villhaze 1556e24a).

A pin is the key this node will resolve a name to. It moves only when the
current pin signs a contiguous rotation certificate. The pin log is
append-only: a move is a new row, never an edit of an old one.

Fork rule (chain depth is never a tiebreak; a winner is not chosen by
chain depth or by cross-node first-seen — only witness receipts may do
that, and none are consulted here):

F1. Rotation certificates are first-class gossip objects. A second valid
    certificate for the same (name, prior key) — the prior key's pin
    generation, not a longer chain — is stored as fork evidence and the
    name is marked CONTESTED. Resolve refuses a contested name. The local
    row is not served.
F2. A name that arrives with more than one certificate for the same prior
    key is contested from birth. First-seen does not pick at bootstrap.
F3. At most one rotation is accepted per name per gossip round.
F4. The first two distinct fork certificates are stored. The rest are
    counted. The caller charges the per-peer bucket once per counted cert.

The fork rule buys per-node consistency. It does not buy mirror agreement
after a fork, and it does not recover a stolen key. Any holder of the
pinned key can freeze a name by signing two certificates for that prior
key until a witness-receipt rule exists.
"""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone

# Published prefix of the genesis name key (docs/NAMES.md). The full pin
# is CYBERNET_GENESIS_NAME_PIN (64 hex, must start with this prefix).
# Unset means this process has no genesis constant loaded.
GENESIS_LABEL = "genesis"
GENESIS_PIN_PREFIX = "46b62b6c"

# Chain depth is never a tiebreak. Stated here, where the fork rule lives.
FORK_RULE = (
    "Chain depth is never a tiebreak. A second valid rotation certificate "
    "for the same (name, prior key) marks the name CONTESTED. Resolve "
    "refuses it. Winner determination is by witness receipts only — never "
    "by chain depth, never by cross-node first-seen."
)


def second_cert_contests(name: str, old_pubkey: str, new_pubkey: str) -> bool:
    """Production fork policy. A mutant that returns False keeps a local
    winner and fails the F1-split row."""
    return True


def bootstrap_picks_first() -> bool:
    """Production bootstrap policy. A mutant that returns True is the
    first-seen adoption the F2-boot row must reject."""
    return False


def rotations_per_round() -> int:
    """F3. A mutant that returns more than one accepts a burst."""
    return 1


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


def sender_may_introduce(sender_pub: str) -> bool:
    allow = oob_allowlist()
    if allow is None:
        return False
    return str(sender_pub or "").strip().lower() in allow


def ensure_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """CREATE TABLE IF NOT EXISTS name_pins (
            name TEXT PRIMARY KEY,
            pubkey TEXT NOT NULL,
            seq INTEGER NOT NULL,
            updated_at TEXT NOT NULL
        )""")
    conn.execute(
        """CREATE TABLE IF NOT EXISTS name_pin_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            pubkey TEXT NOT NULL,
            seq INTEGER NOT NULL,
            prev_pubkey TEXT NOT NULL,
            cert_signature TEXT NOT NULL,
            recorded_at TEXT NOT NULL
        )""")
    conn.execute(
        """CREATE TABLE IF NOT EXISTS name_fork_certs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            old_pubkey TEXT NOT NULL,
            new_pubkey TEXT NOT NULL,
            issued_at TEXT NOT NULL,
            signature TEXT NOT NULL,
            seq INTEGER NOT NULL,
            recorded_at TEXT NOT NULL
        )""")
    conn.execute(
        """CREATE UNIQUE INDEX IF NOT EXISTS idx_name_fork_cert
           ON name_fork_certs(name, old_pubkey, new_pubkey, issued_at)""")
    conn.execute(
        """CREATE TABLE IF NOT EXISTS name_fork_overflow (
            name TEXT NOT NULL,
            old_pubkey TEXT NOT NULL,
            overflow_count INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (name, old_pubkey)
        )""")
    conn.execute(
        """CREATE TABLE IF NOT EXISTS name_contested (
            name TEXT PRIMARY KEY,
            since TEXT NOT NULL,
            reason TEXT NOT NULL
        )""")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")


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
    now = _now()
    conn.execute(
        "INSERT INTO name_pins (name, pubkey, seq, updated_at) VALUES (?,?,0,?)",
        (GENESIS_LABEL, pin, now))
    conn.execute(
        "INSERT INTO name_pin_log (name, pubkey, seq, prev_pubkey,"
        " cert_signature, recorded_at) VALUES (?,?,0,'','',?)",
        (GENESIS_LABEL, pin, now))


def current_pin(conn: sqlite3.Connection, name: str) -> str | None:
    ensure_schema(conn)
    if name == GENESIS_LABEL:
        ensure_genesis_pin(conn)
    row = conn.execute(
        "SELECT pubkey FROM name_pins WHERE name=?", (name,)).fetchone()
    if row is None:
        return None
    return str(row[0]).lower()


def current_seq(conn: sqlite3.Connection, name: str) -> int | None:
    row = conn.execute(
        "SELECT seq FROM name_pins WHERE name=?", (name,)).fetchone()
    if row is None:
        return None
    return int(row[0])


def is_contested(conn: sqlite3.Connection, name: str) -> bool:
    ensure_schema(conn)
    row = conn.execute(
        "SELECT 1 FROM name_contested WHERE name=?", (name,)).fetchone()
    return row is not None


def pin_refuses_before_signature(conn: sqlite3.Connection, name: str,
                                 pubkey: str) -> bool:
    """V1 / contested gate. Callers invoke this before any signature
    count on a served binding. True means resolve must refuse."""
    if is_contested(conn, name):
        return True
    pin = current_pin(conn, name)
    if pin is None:
        return False
    return str(pubkey or "").strip().lower() != pin


def pin_initial(conn: sqlite3.Connection, name: str, pubkey: str) -> None:
    """TOFU: the first admitted key is the pin at seq 0. A pin already
    present is left alone — it moves only through a certificate."""
    ensure_schema(conn)
    if name == GENESIS_LABEL:
        ensure_genesis_pin(conn)
    if current_pin(conn, name) is not None:
        return
    now = _now()
    pub = pubkey.lower()
    conn.execute(
        "INSERT INTO name_pins (name, pubkey, seq, updated_at) VALUES (?,?,0,?)",
        (name, pub, now))
    conn.execute(
        "INSERT INTO name_pin_log (name, pubkey, seq, prev_pubkey,"
        " cert_signature, recorded_at) VALUES (?,?,0,'','',?)",
        (name, pub, now))


def _mark_contested(conn: sqlite3.Connection, name: str) -> None:
    conn.execute(
        "INSERT INTO name_contested (name, since, reason) VALUES (?,?,?)"
        " ON CONFLICT(name) DO NOTHING",
        (name, _now(), "fork: two valid certs for the same prior key"))


def _stored_successors(conn: sqlite3.Connection, name: str,
                       old_pubkey: str) -> list[str]:
    rows = conn.execute(
        "SELECT new_pubkey FROM name_fork_certs WHERE name=? AND old_pubkey=?"
        " ORDER BY id",
        (name, old_pubkey)).fetchall()
    found = [str(r[0]).lower() for r in rows]
    rot = conn.execute(
        "SELECT new_pubkey FROM name_rotations WHERE name=? AND old_pubkey=?",
        (name, old_pubkey)).fetchall()
    for r in rot:
        pub = str(r[0]).lower()
        if pub not in found:
            found.append(pub)
    return found


def _store_fork_cert(conn: sqlite3.Connection, rec: dict, seq: int) -> str:
    """Store the first two distinct successors. Count the rest.
    Returns 'stored', 'duplicate', or 'overflow'."""
    name = rec["name"]
    old_pub = rec["old_pubkey"]
    new_pub = rec["new_pubkey"]
    have = conn.execute(
        "SELECT new_pubkey FROM name_fork_certs WHERE name=? AND old_pubkey=?",
        (name, old_pub)).fetchall()
    pubs = [str(r[0]).lower() for r in have]
    if new_pub in pubs:
        return "duplicate"
    if len(pubs) >= 2:
        conn.execute(
            "INSERT INTO name_fork_overflow (name, old_pubkey, overflow_count)"
            " VALUES (?,?,1) ON CONFLICT(name, old_pubkey) DO UPDATE SET"
            " overflow_count = overflow_count + 1",
            (name, old_pub))
        return "overflow"
    conn.execute(
        "INSERT OR IGNORE INTO name_fork_certs (name, old_pubkey, new_pubkey,"
        " issued_at, signature, seq, recorded_at) VALUES (?,?,?,?,?,?,?)",
        (name, old_pub, new_pub, rec["issued_at"], rec["signature"],
         seq, _now()))
    return "stored"


def _verify(rec: dict) -> bool:
    from rotate_name import verify_rotation
    return verify_rotation(rec) is None


def _norm_cert(rec: dict) -> dict | None:
    if not isinstance(rec, dict):
        return None
    try:
        out = {
            "name": str(rec["name"]).strip().lower(),
            "old_pubkey": str(rec["old_pubkey"]).strip().lower(),
            "new_pubkey": str(rec["new_pubkey"]).strip().lower(),
            "issued_at": str(rec["issued_at"]),
            "signature": str(rec["signature"]).strip().lower(),
        }
    except (KeyError, AttributeError):
        return None
    if not _verify(out):
        return None
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


def _move_pin(conn: sqlite3.Connection, rec: dict) -> None:
    """Append one pin-log row and point the current pin at the new key.
    The log is insert-only. Chain depth is not consulted."""
    name = rec["name"]
    old_pub = rec["old_pubkey"]
    new_pub = rec["new_pubkey"]
    now = _now()
    seq = current_seq(conn, name)
    if seq is None:
        conn.execute(
            "INSERT INTO name_pin_log (name, pubkey, seq, prev_pubkey,"
            " cert_signature, recorded_at) VALUES (?,?,0,'','',?)",
            (name, old_pub, now))
        seq = 0
        conn.execute(
            "INSERT INTO name_pins (name, pubkey, seq, updated_at)"
            " VALUES (?,?,0,?)",
            (name, old_pub, now))
    nxt = seq + 1
    conn.execute(
        "INSERT INTO name_pin_log (name, pubkey, seq, prev_pubkey,"
        " cert_signature, recorded_at) VALUES (?,?,?,?,?,?)",
        (name, new_pub, nxt, old_pub, rec["signature"], now))
    conn.execute(
        "UPDATE name_pins SET pubkey=?, seq=?, updated_at=? WHERE name=?",
        (new_pub, nxt, now, name))
    try:
        conn.execute(
            "INSERT OR IGNORE INTO name_rotations (name, old_pubkey,"
            " new_pubkey, issued_at, signature, accepted_at)"
            " VALUES (?,?,?,?,?,?)",
            (name, old_pub, new_pub, rec["issued_at"], rec["signature"], now))
    except sqlite3.OperationalError:
        pass


def _contiguous(conn: sqlite3.Connection, rec: dict) -> bool:
    """The cert's signer is the current pin. No jumps. No other key.
    With no pin yet, the signer must be the live binding key, or there
    is no binding and this is the first cert for a name being seeded."""
    pin = current_pin(conn, rec["name"])
    if pin is not None:
        return rec["old_pubkey"] == pin
    bound = _binding_key(conn, rec["name"])
    if bound is None:
        return True
    return rec["old_pubkey"] == bound


def _note_fork(conn: sqlite3.Connection, rec: dict,
               earlier: list[str]) -> str:
    """Record fork evidence for a second (or later) successor of the same
    prior key. Returns 'contested' or 'ignored' (the F1 mutant)."""
    if not second_cert_contests(rec["name"], rec["old_pubkey"], rec["new_pubkey"]):
        return "ignored"
    seq = current_seq(conn, rec["name"])
    slot = 0 if seq is None else max(0, seq - 1) if seq else 0
    for existing_new in earlier:
        if existing_new == rec["new_pubkey"]:
            continue
        row = None
        try:
            row = conn.execute(
                "SELECT issued_at, signature FROM name_rotations"
                " WHERE name=? AND old_pubkey=? AND new_pubkey=?",
                (rec["name"], rec["old_pubkey"], existing_new)).fetchone()
        except sqlite3.OperationalError:
            row = None
        if row is None:
            continue
        _store_fork_cert(conn, {
            "name": rec["name"],
            "old_pubkey": rec["old_pubkey"],
            "new_pubkey": existing_new,
            "issued_at": row[0],
            "signature": row[1],
        }, slot)
    stored = _store_fork_cert(conn, rec, slot)
    _mark_contested(conn, rec["name"])
    return "overflow" if stored == "overflow" else "contested"


def ingest_rotation_round(conn: sqlite3.Connection, certs: list) -> dict:
    """One gossip round. At most `rotations_per_round()` acceptances per
    name. Chain depth is never a tiebreak: certificates are considered in
    arrival order, and a certificate that does not continue the current
    pin is not promoted just because a longer chain sits later in the batch.

    Returns accepted (name -> new pubkey), contested names, and
    overflow_n (F4 — the caller charges the peer bucket that many times).
    """
    ensure_schema(conn)
    accepted: dict[str, str] = {}
    accepted_n: dict[str, int] = {}
    contested: set[str] = set()
    overflow_n = 0
    normalized: list[dict] = []
    for raw in certs or []:
        rec = _norm_cert(raw)
        if rec is not None:
            normalized.append(rec)

    # F2 — contested from birth. A name this node has never pinned and
    # has no binding for, arriving with two successors of the same prior
    # key, is not awarded to whichever cert was listed first.
    # Chain depth is never a tiebreak.
    birth_fork: set[str] = set()
    multi_birth: set[str] = set()
    groups: dict[tuple[str, str], list[dict]] = {}
    for rec in normalized:
        groups.setdefault((rec["name"], rec["old_pubkey"]), []).append(rec)
    for (name, _old), group in groups.items():
        distinct: list[str] = []
        for rec in group:
            if rec["new_pubkey"] not in distinct:
                distinct.append(rec["new_pubkey"])
        if len(distinct) < 2:
            continue
        if _binding_key(conn, name) is not None or current_pin(conn, name) is not None:
            continue
        multi_birth.add(name)
        if bootstrap_picks_first():
            # Mutant: first-seen adoption. The real rule does not take this branch.
            continue
        birth_fork.add(name)
        _mark_contested(conn, name)
        contested.add(name)
        for rec in group:
            stored = _store_fork_cert(conn, rec, 0)
            if stored == "overflow":
                overflow_n += 1

    limit = max(0, int(rotations_per_round()))
    for rec in normalized:
        name = rec["name"]
        if name in birth_fork:
            continue
        prior = [p for p in _stored_successors(conn, name, rec["old_pubkey"])
                 if p != rec["new_pubkey"]]
        if prior and name in multi_birth and bootstrap_picks_first():
            continue
        if prior:
            noted = _note_fork(conn, rec, prior)
            if noted == "overflow":
                overflow_n += 1
            if noted != "ignored":
                contested.add(name)
            continue
        if is_contested(conn, name) or name in contested:
            continue
        # F3 — one acceptance per name per round. Further certificates,
        # including a longer contiguous chain, are not a tiebreak.
        if accepted_n.get(name, 0) >= limit:
            continue
        if not _contiguous(conn, rec):
            continue
        _move_pin(conn, rec)
        _store_fork_cert(
            conn, rec, max(0, (current_seq(conn, name) or 1) - 1))
        accepted[name] = rec["new_pubkey"]
        accepted_n[name] = accepted_n.get(name, 0) + 1
    return {
        "accepted": accepted,
        "contested": contested,
        "overflow_n": overflow_n,
    }


def consider_rotation(conn: sqlite3.Connection, rec: dict) -> str:
    """Single-certificate entry used by the rotate route. Same fork rule
    as a one-cert gossip round: a second successor contests and is not
    applied. Returns 'accepted', 'contested', or 'refused'."""
    result = ingest_rotation_round(conn, [rec])
    name = str(rec.get("name", "")).strip().lower()
    if name in result["contested"] or is_contested(conn, name):
        return "contested"
    if name in result["accepted"]:
        return "accepted"
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


def gossip_rotations(conn: sqlite3.Connection, names: list[str]) -> list[dict]:
    """Certificates this node will repeat. Accepted hops and stored fork
    evidence both go out — a peer cannot see a split from the binding alone."""
    ensure_schema(conn)
    if not names:
        return []
    qmarks = ",".join("?" for _ in names)
    out = []
    seen = set()
    try:
        rows = conn.execute(
            f"SELECT name, old_pubkey, new_pubkey, issued_at, signature"
            f" FROM name_rotations WHERE name IN ({qmarks})",
            tuple(names)).fetchall()
    except sqlite3.OperationalError:
        rows = []
    forks = conn.execute(
        f"SELECT name, old_pubkey, new_pubkey, issued_at, signature"
        f" FROM name_fork_certs WHERE name IN ({qmarks})",
        tuple(names)).fetchall()
    for row in list(rows) + list(forks):
        key = (row[0], row[1], row[2], row[3], row[4])
        if key in seen:
            continue
        seen.add(key)
        out.append({
            "name": row[0],
            "old_pubkey": row[1],
            "new_pubkey": row[2],
            "issued_at": row[3],
            "signature": row[4],
        })
    return out
