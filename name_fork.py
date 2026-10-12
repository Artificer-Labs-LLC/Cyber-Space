"""Name pins, the v2 rotation chain, and fork discipline (ART-29 / ART-42).

Binding rulings: Villhaze 1556e24a, 524ef05b, 392140b7, ART-29 2dcc893c.

PINS
  A pin is the key this node resolves a name to. A pin is created ONLY by
  a binding that passed the claim gates (source=claim_gate) or a binding
  relayed by an out-of-band allowlisted node (source=oob_allowlist). A
  rotation certificate never creates a pin and never introduces a name.
  Pins are permanent: a pin dies only by a rotation signed by the pinned
  key, or by a logged local unpin (the startup guard, below).

  name_pin_log is INSERT-only (SQLite triggers abort UPDATE and DELETE).
  The served state of a name is its LATEST log entry:
    kind=pin     a new pin generation (source + origin_hash recorded)
    kind=rotate  the pin moved by a v2 rotation certificate
    kind=unpin   the pin was refused (startup guard); the name is unpinned
  name_pins is a cache of that latest state and is rebuilt from the log.

V2 CERTIFICATES
  signed bytes = lp(TAG) lp(name) lp(old_pub) lp(new_pub) lp(issued_at)
                 lp(seq u64be) lp(prev_hash)      TAG = cyberspace-name-rotate/v2
  cert_hash    = sha256(signed bytes || lp(sig))  (signed content only;
                 never rowid, local seq, or received time)
  The first link's prev_hash is the origin_hash of the pinning binding.
  R, S (S < L), old_pub and new_pub are strict-decoded and must re-encode
  to the input bytes before any hash is computed. weak_reason and strict
  point checks run on BOTH keys before verify.

FORKS
  Fork evidence is keyed on (name, prev_hash). Two verified certificates
  on the same prev_hash with different new keys mark the name CONTESTED.
  Chain depth is never a tiebreak. An unknown prev_hash is PENDING, never
  CONTESTED. A contested name has no recovery path in this build.

RATE BOUND (not a fork gate)
  At most one accepted rotation per name per round, where a round is a
  wall-clock window (CYBERNET_NAME_ROTATION_ROUND_SEC, default the
  announce interval), persisted in name_rotation_round. This is a RATE
  BOUND on hops: it holds a chain still long enough for fork evidence to
  gossip. Fork safety comes from the prev_hash chain, not from this limit.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
from datetime import datetime, timedelta, timezone

GENESIS_LABEL = "genesis"
GENESIS_PIN_PREFIX = "46b62b6c"

TAG = b"cyberspace-name-rotate/v2"
KIND = "name-rotate"
VERSION = 2
ORIGIN_TAG = b"cyberspace-name-pin-origin/v1"

SOURCES_THAT_PIN = ("claim_gate", "oob_allowlist")

FORK_RULE = (
    "Chain depth is never a tiebreak. Two verified rotation certificates "
    "on the same (name, prev_hash) with different new keys mark the name "
    "CONTESTED. Resolve refuses it. An unknown prev_hash is PENDING, never "
    "CONTESTED."
)

# Evidence store (certs for names this node has no pin for). Charged and
# capped before any write.
EVIDENCE_PER_NAME = 4
EVIDENCE_PER_SENDER = 32
EVIDENCE_GLOBAL = 256
EVIDENCE_TTL_SEC = 24 * 3600

# Pending queue (certs whose prev_hash this node does not know).
PENDING_PER_NAME = 8
PENDING_PER_SENDER = 32
PENDING_TTL_SEC = 3600  # floor; see pending_ttl()

# Fork evidence per (name, prev_hash): the first two distinct successors
# are stored, the rest are counted.
FORK_STORE_PER_LINK = 2

# PIN-STALE: the day-90 release after binding expiry.
RELEASE_DAYS = 90

# Counters the belt reads. Production never resets them.
_verify_calls = 0
_hash_calls = 0


def round_seconds() -> int:
    raw = os.environ.get("CYBERNET_NAME_ROTATION_ROUND_SEC")
    if raw is None:
        raw = os.environ.get("CYBERNET_ANNOUNCE_INTERVAL", "3600")
    try:
        return max(1, int(raw))
    except ValueError:
        return 3600


def current_round(now: float | None = None) -> int:
    now = time.time() if now is None else now
    return int(now // round_seconds())


def pin_cap() -> int:
    """Pins are capped exactly like name_bindings."""
    import core
    return int(core.NAME_REGISTRY_CAP)


# --------------------------------------------------------------- policy
# Each policy below is a single seam a belt mutant replaces.

def second_cert_contests(name: str, prev_hash: str, new_pubkey: str) -> bool:
    return True


def bootstrap_picks_first() -> bool:
    return False


def rotations_per_round() -> int:
    """RATE BOUND, not a fork gate."""
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
    raw = os.environ.get("CYBERNET_OOB_NODE_PINS")
    if raw is None:
        return None
    return {p.strip().lower() for p in raw.split(",") if p.strip()}


def sender_may_introduce(sender_pub: str | None) -> bool:
    allow = oob_allowlist()
    if allow is None or sender_pub is None:
        return False
    return str(sender_pub).strip().lower() in allow


# --------------------------------------------------------------- schema

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
    cols = {r[1] for r in conn.execute("PRAGMA table_info(name_pin_log)")}
    for col, decl in (("kind", "TEXT NOT NULL DEFAULT 'pin'"),
                      ("source", "TEXT NOT NULL DEFAULT ''"),
                      ("origin_hash", "TEXT NOT NULL DEFAULT ''"),
                      ("head_hash", "TEXT NOT NULL DEFAULT ''"),
                      ("cert", "TEXT NOT NULL DEFAULT ''"),
                      ("reason", "TEXT NOT NULL DEFAULT ''")):
        if col not in cols:
            conn.execute(f"ALTER TABLE name_pin_log ADD COLUMN {col} {decl}")
    conn.execute(
        """CREATE TRIGGER IF NOT EXISTS name_pin_log_no_update
           BEFORE UPDATE ON name_pin_log
           BEGIN SELECT RAISE(ABORT, 'name_pin_log is insert-only'); END""")
    conn.execute(
        """CREATE TRIGGER IF NOT EXISTS name_pin_log_no_delete
           BEFORE DELETE ON name_pin_log
           BEGIN SELECT RAISE(ABORT, 'name_pin_log is insert-only'); END""")
    conn.execute(
        """CREATE TABLE IF NOT EXISTS name_pin_origins (
            origin_hash TEXT PRIMARY KEY,
            source TEXT NOT NULL,
            name TEXT NOT NULL,
            pubkey TEXT NOT NULL,
            issued_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            signature TEXT NOT NULL,
            recorded_at TEXT NOT NULL
        )""")
    conn.execute(
        """CREATE TABLE IF NOT EXISTS name_fork_evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            prev_hash TEXT NOT NULL,
            new_pubkey TEXT NOT NULL,
            cert_hash TEXT NOT NULL,
            cert TEXT NOT NULL,
            recorded_at TEXT NOT NULL
        )""")
    conn.execute(
        """CREATE UNIQUE INDEX IF NOT EXISTS idx_name_fork_evidence
           ON name_fork_evidence(name, prev_hash, new_pubkey)""")
    conn.execute(
        """CREATE TABLE IF NOT EXISTS name_fork_overflow (
            name TEXT NOT NULL,
            prev_hash TEXT NOT NULL,
            overflow_count INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (name, prev_hash)
        )""")
    conn.execute(
        """CREATE TABLE IF NOT EXISTS name_contested (
            name TEXT PRIMARY KEY,
            since TEXT NOT NULL,
            reason TEXT NOT NULL
        )""")
    conn.execute(
        """CREATE TABLE IF NOT EXISTS name_cert_evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            sender TEXT NOT NULL,
            cert_hash TEXT NOT NULL UNIQUE,
            cert TEXT NOT NULL,
            recorded_ts REAL NOT NULL
        )""")
    conn.execute(
        """CREATE TABLE IF NOT EXISTS name_pending (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            sender TEXT NOT NULL,
            prev_hash TEXT NOT NULL,
            cert_hash TEXT NOT NULL UNIQUE,
            cert TEXT NOT NULL,
            recorded_ts REAL NOT NULL
        )""")
    conn.execute(
        """CREATE TABLE IF NOT EXISTS name_pending_pulls (
            prev_hash TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            sender TEXT NOT NULL,
            requested_ts REAL NOT NULL
        )""")
    # RATE BOUND (not a fork gate): last round a rotation was accepted.
    conn.execute(
        """CREATE TABLE IF NOT EXISTS name_rotation_round (
            name TEXT PRIMARY KEY,
            last_round INTEGER NOT NULL
        )""")
    conn.execute(
        """CREATE TABLE IF NOT EXISTS name_pin_stale (
            name TEXT PRIMARY KEY,
            since TEXT NOT NULL,
            pin TEXT NOT NULL,
            refused_pubkey TEXT NOT NULL
        )""")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")


def _lp(b: bytes) -> bytes:
    return len(b).to_bytes(4, "big") + b


# --------------------------------------------------------------- hashes

def binding_signed_bytes(name, pubkey, issued_at, expires_at) -> bytes:
    import core
    return core._name_claim_payload(name, pubkey, issued_at, expires_at)


def origin_hash(name, pubkey, issued_at, expires_at, signature) -> str:
    """The hash of the signed binding that set a pin: the v2 chain's
    first prev_hash."""
    signed = binding_signed_bytes(name, pubkey, issued_at, expires_at)
    return hashlib.sha256(
        _lp(ORIGIN_TAG) + _lp(signed) + _lp(bytes.fromhex(signature))
    ).hexdigest()


def genesis_origin_hash(pin: str) -> str:
    return hashlib.sha256(
        _lp(ORIGIN_TAG) + _lp(b"genesis-constant") + _lp(bytes.fromhex(pin))
    ).hexdigest()


def cert_payload(name: str, old_pub: str, new_pub: str, issued_at: str,
                 seq: int, prev_hash: str, tag: bytes = TAG) -> bytes:
    return (_lp(tag) + _lp(name.encode()) + _lp(bytes.fromhex(old_pub))
            + _lp(bytes.fromhex(new_pub)) + _lp(issued_at.encode())
            + _lp(int(seq).to_bytes(8, "big")) + _lp(bytes.fromhex(prev_hash)))


def cert_hash(rec: dict) -> str:
    """H(tag || signed fields || sig). Callers pass only certificates that
    already passed _canonical."""
    global _hash_calls
    _hash_calls += 1
    return hashlib.sha256(
        cert_payload(rec["name"], rec["old_pubkey"], rec["new_pubkey"],
                     rec["issued_at"], rec["seq"], rec["prev_hash"])
        + _lp(bytes.fromhex(rec["signature"]))).hexdigest()


def mint_cert(name: str, old_seed: bytes, new_pub: str, seq: int,
              prev_hash: str, issued_at: str | None = None) -> dict:
    from fed import ed25519 as _ed
    old_pub = _ed.publickey(old_seed).hex()
    issued_at = issued_at or _now()
    payload = cert_payload(name, old_pub, new_pub, issued_at, seq, prev_hash)
    sig = _ed.sign(payload, old_seed, bytes.fromhex(old_pub)).hex()
    return {"v": VERSION, "kind": KIND, "tag": TAG.decode(), "name": name,
            "old_pubkey": old_pub, "new_pubkey": new_pub,
            "issued_at": issued_at, "seq": seq, "prev_hash": prev_hash,
            "signature": sig}


# --------------------------------------------------------------- checks

def _strict_point_ok(raw: bytes) -> bool:
    from fed import ed25519 as _ed
    try:
        P = _ed._decodepoint_strict(raw)
    except Exception:
        return False
    return _ed._encodepoint(P) == raw


def _canonical(rec: dict) -> bool:
    """Strict-decode R, S, old_pub, new_pub. Refuse any encoding whose
    re-encoding differs from the input. Runs before any hash."""
    from fed import ed25519 as _ed
    sig = bytes.fromhex(rec["signature"])
    if len(sig) != 64:
        return False
    if not _strict_point_ok(sig[:32]):
        return False
    if int.from_bytes(sig[32:], "little") >= _ed._L:
        return False
    for key in (rec["old_pubkey"], rec["new_pubkey"]):
        if not _strict_point_ok(bytes.fromhex(key)):
            return False
    return True


def _weak(pub: str) -> str | None:
    import window_open
    return window_open.weak_reason(pub)


def _keys_ok(rec: dict) -> bool:
    """Strict checkvalid on both keys (canonical, not small-order) plus
    weak_reason (mixed-order) on BOTH old_pub and new_pub. Before verify."""
    from fed import ed25519 as _ed
    for key in (rec["old_pubkey"], rec["new_pubkey"]):
        raw = bytes.fromhex(key)
        try:
            P = _ed._decodepoint_strict(raw)
        except Exception:
            return False
        if _ed._is_small_order(P):
            return False
        if _weak(key) is not None:
            return False
    return True


def _tag_ok(raw: dict) -> bool:
    """Kind binding: the record must claim exactly this kind, version and
    tag. The tag is also inside the signed bytes, so a cert signed under
    any other tag cannot verify here."""
    return (raw.get("kind") == KIND and raw.get("v") == VERSION
            and raw.get("tag", TAG.decode()) == TAG.decode())


def _signing_tag(raw: dict) -> bytes:
    """The tag the verifier puts in the signed bytes: always the constant.
    The kind-binding mutant uses the record's own tag instead."""
    return TAG


def _verify(rec: dict, tag: bytes) -> bool:
    global _verify_calls
    from fed import ed25519 as _ed
    _verify_calls += 1
    payload = cert_payload(rec["name"], rec["old_pubkey"], rec["new_pubkey"],
                           rec["issued_at"], rec["seq"], rec["prev_hash"],
                           tag=tag)
    return _ed.checkvalid(bytes.fromhex(rec["signature"]), payload,
                          bytes.fromhex(rec["old_pubkey"]))


def _shape(raw) -> dict | None:
    if not isinstance(raw, dict):
        return None
    try:
        out = {
            "name": str(raw["name"]).strip().lower(),
            "old_pubkey": str(raw["old_pubkey"]).strip().lower(),
            "new_pubkey": str(raw["new_pubkey"]).strip().lower(),
            "issued_at": str(raw["issued_at"]),
            "seq": raw["seq"],
            "prev_hash": str(raw["prev_hash"]).strip().lower(),
            "signature": str(raw["signature"]).strip().lower(),
        }
    except (KeyError, AttributeError, TypeError):
        return None
    if isinstance(out["seq"], bool) or not isinstance(out["seq"], int):
        return None
    if out["seq"] < 1 or out["seq"] >= 2 ** 63:
        return None
    import re
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", out["name"]):
        return None
    for k, n in (("old_pubkey", 64), ("new_pubkey", 64), ("prev_hash", 64),
                 ("signature", 128)):
        if not re.fullmatch(r"[0-9a-f]{%d}" % n, out[k]):
            return None
    if out["old_pubkey"] == out["new_pubkey"]:
        return None
    if len(out["issued_at"]) > 64:
        return None
    try:
        issued = datetime.fromisoformat(out["issued_at"])
    except ValueError:
        return None
    if issued.tzinfo is None:
        return None
    if issued > datetime.now(timezone.utc) + timedelta(minutes=5):
        return None
    return out


def _norm_cert(raw) -> dict | None:
    """Every rotation admission check, in order, before any state is read:
    shape and v2 kind binding, canonical encoding of R, S, old_pub and
    new_pub, strict checkvalid + weak_reason on BOTH keys, then verify.
    cert_hash is computed only after all of that passes."""
    if not isinstance(raw, dict) or not _tag_ok(raw):
        return None
    rec = _shape(raw)
    if rec is None:
        return None
    if not _canonical(rec):
        return None
    if not _keys_ok(rec):
        return None
    if not _verify(rec, _signing_tag(raw)):
        return None
    rec["cert_hash"] = cert_hash(rec)
    return rec


def _wire(rec: dict) -> dict:
    return {"v": VERSION, "kind": KIND, "tag": TAG.decode(),
            "name": rec["name"], "old_pubkey": rec["old_pubkey"],
            "new_pubkey": rec["new_pubkey"], "issued_at": rec["issued_at"],
            "seq": rec["seq"], "prev_hash": rec["prev_hash"],
            "signature": rec["signature"]}


# --------------------------------------------------------------- state

def _latest(conn, name):
    return conn.execute(
        "SELECT id, kind, pubkey, seq, head_hash, source, origin_hash"
        " FROM name_pin_log WHERE name=? AND kind IN ('pin','rotate','unpin')"
        " ORDER BY id DESC LIMIT 1",
        (name,)).fetchone()


def _sync_cache(conn, name) -> None:
    row = _latest(conn, name)
    if row is None or row[1] == "unpin":
        conn.execute("DELETE FROM name_pins WHERE name=?", (name,))
        return
    conn.execute(
        "INSERT INTO name_pins (name, pubkey, seq, updated_at) VALUES (?,?,?,?)"
        " ON CONFLICT(name) DO UPDATE SET pubkey=excluded.pubkey,"
        " seq=excluded.seq, updated_at=excluded.updated_at",
        (name, row[2], row[3], _now()))


def ensure_genesis_pin(conn: sqlite3.Connection) -> None:
    """Genesis is pinned to the out-of-band constant when one is set.
    Source genesis_constant: the startup guard checks it against the
    constant (there is no signed binding behind it)."""
    ensure_schema(conn)
    pin = genesis_pin()
    if not pin:
        return
    if _latest(conn, GENESIS_LABEL) is not None:
        return
    h = genesis_origin_hash(pin)
    conn.execute(
        "INSERT INTO name_pin_log (name, pubkey, seq, prev_pubkey,"
        " cert_signature, recorded_at, kind, source, origin_hash, head_hash)"
        " VALUES (?,?,0,'','',?,'pin','genesis_constant',?,?)",
        (GENESIS_LABEL, pin, _now(), h, h))
    _sync_cache(conn, GENESIS_LABEL)


def current_state(conn, name):
    """(pubkey, seq, head_hash) of the live pin, or None."""
    ensure_schema(conn)
    if name == GENESIS_LABEL:
        ensure_genesis_pin(conn)
    row = _latest(conn, name)
    if row is None or row[1] == "unpin":
        return None
    return str(row[2]).lower(), int(row[3]), str(row[4])


def current_pin(conn: sqlite3.Connection, name: str) -> str | None:
    st = current_state(conn, name)
    return None if st is None else st[0]


def current_seq(conn: sqlite3.Connection, name: str) -> int | None:
    st = current_state(conn, name)
    return None if st is None else st[1]


def head_hash(conn, name) -> str | None:
    st = current_state(conn, name)
    return None if st is None else st[2]


def is_contested(conn: sqlite3.Connection, name: str) -> bool:
    ensure_schema(conn)
    return conn.execute("SELECT 1 FROM name_contested WHERE name=?",
                        (name,)).fetchone() is not None


def is_pin_stale(conn, name) -> bool:
    ensure_schema(conn)
    return conn.execute("SELECT 1 FROM name_pin_stale WHERE name=?",
                        (name,)).fetchone() is not None


def pin_refuses_before_signature(conn: sqlite3.Connection, name: str,
                                 pubkey: str) -> bool:
    if is_contested(conn, name):
        return True
    pin = current_pin(conn, name)
    if pin is None:
        return False
    return str(pubkey or "").strip().lower() != pin


def _pin_count(conn) -> int:
    rows = conn.execute(
        "SELECT name, kind FROM name_pin_log WHERE id IN"
        " (SELECT MAX(id) FROM name_pin_log GROUP BY name)").fetchall()
    return sum(1 for r in rows if r[1] != "unpin")


def pin_initial(conn: sqlite3.Connection, name: str, pubkey: str,
                source: str = "", binding: dict | None = None) -> str:
    """Create a pin generation. Only source claim_gate or oob_allowlist,
    with the exact signed binding behind it, may create a pin. Returns
    'pinned', 'exists', 'refused-source', or 'refused-cap'."""
    ensure_schema(conn)
    if name == GENESIS_LABEL:
        ensure_genesis_pin(conn)
    if current_pin(conn, name) is not None:
        return "exists"
    if source not in SOURCES_THAT_PIN or not isinstance(binding, dict):
        return "refused-source"
    pub = str(pubkey).lower()
    if str(binding.get("node_pubkey", "")).lower() != pub:
        return "refused-source"
    if _pin_count(conn) >= pin_cap():
        return "refused-cap"
    sig = str(binding["signature"]).lower()
    h = origin_hash(name, pub, binding["issued_at"], binding["expires_at"], sig)
    conn.execute(
        "INSERT OR IGNORE INTO name_pin_origins (origin_hash, source, name,"
        " pubkey, issued_at, expires_at, signature, recorded_at)"
        " VALUES (?,?,?,?,?,?,?,?)",
        (h, source, name, pub, binding["issued_at"], binding["expires_at"],
         sig, _now()))
    conn.execute(
        "INSERT INTO name_pin_log (name, pubkey, seq, prev_pubkey,"
        " cert_signature, recorded_at, kind, source, origin_hash, head_hash)"
        " VALUES (?,?,0,'','',?,'pin',?,?,?)",
        (name, pub, _now(), source, h, h))
    conn.execute("DELETE FROM name_pin_stale WHERE name=?", (name,))
    _sync_cache(conn, name)
    return "pinned"


def _chain_links(conn, name) -> dict:
    """prev_hash -> (new_pubkey, cert_hash, seq) for every accepted hop of
    the current pin generation, plus the set of known hashes."""
    gen = conn.execute(
        "SELECT MAX(id) FROM name_pin_log WHERE name=? AND kind IN ('pin','unpin')",
        (name,)).fetchone()[0]
    rows = conn.execute(
        "SELECT kind, pubkey, seq, head_hash, cert FROM name_pin_log"
        " WHERE name=? AND id>=? ORDER BY id", (name, gen or 0)).fetchall()
    links = {}
    known = set()
    for kind, pub, seq, hh, cert in rows:
        known.add(hh)
        if kind == "rotate" and cert:
            c = json.loads(cert)
            links[c["prev_hash"]] = (str(pub).lower(), hh, int(seq))
    return {"links": links, "known": known}


def _mark_contested(conn, name, reason) -> None:
    conn.execute(
        "INSERT INTO name_contested (name, since, reason) VALUES (?,?,?)"
        " ON CONFLICT(name) DO NOTHING", (name, _now(), reason))


def _store_fork(conn, rec) -> str:
    have = conn.execute(
        "SELECT new_pubkey FROM name_fork_evidence WHERE name=? AND prev_hash=?",
        (rec["name"], rec["prev_hash"])).fetchall()
    pubs = [r[0] for r in have]
    if rec["new_pubkey"] in pubs:
        return "duplicate"
    if len(pubs) >= FORK_STORE_PER_LINK:
        conn.execute(
            "INSERT INTO name_fork_overflow (name, prev_hash, overflow_count)"
            " VALUES (?,?,1) ON CONFLICT(name, prev_hash) DO UPDATE SET"
            " overflow_count = overflow_count + 1",
            (rec["name"], rec["prev_hash"]))
        return "overflow"
    conn.execute(
        "INSERT OR IGNORE INTO name_fork_evidence (name, prev_hash, new_pubkey,"
        " cert_hash, cert, recorded_at) VALUES (?,?,?,?,?,?)",
        (rec["name"], rec["prev_hash"], rec["new_pubkey"], rec["cert_hash"],
         json.dumps(_wire(rec), sort_keys=True), _now()))
    return "stored"


def _round_held(conn, name, rnd) -> bool:
    """RATE BOUND: True when this name already moved in this round."""
    row = conn.execute("SELECT last_round FROM name_rotation_round WHERE name=?",
                       (name,)).fetchone()
    return row is not None and int(row[0]) >= rnd and rotations_per_round() <= 1


def _note_round(conn, name, rnd) -> None:
    conn.execute(
        "INSERT INTO name_rotation_round (name, last_round) VALUES (?,?)"
        " ON CONFLICT(name) DO UPDATE SET last_round=excluded.last_round",
        (name, rnd))


def _append_rotation(conn, rec) -> None:
    conn.execute(
        "INSERT INTO name_pin_log (name, pubkey, seq, prev_pubkey,"
        " cert_signature, recorded_at, kind, source, origin_hash, head_hash, cert)"
        " VALUES (?,?,?,?,?,?,'rotate','rotation','',?,?)",
        (rec["name"], rec["new_pubkey"], rec["seq"], rec["old_pubkey"],
         rec["signature"], _now(), rec["cert_hash"],
         json.dumps(_wire(rec), sort_keys=True)))
    _sync_cache(conn, rec["name"])
    try:
        conn.execute(
            "INSERT OR IGNORE INTO name_rotations (name, old_pubkey,"
            " new_pubkey, issued_at, signature, accepted_at)"
            " VALUES (?,?,?,?,?,?)",
            (rec["name"], rec["old_pubkey"], rec["new_pubkey"],
             rec["issued_at"], rec["signature"], _now()))
    except sqlite3.OperationalError:
        pass


# ------------------------------------------------- evidence and pending

def _prune(conn, now) -> None:
    conn.execute("DELETE FROM name_cert_evidence WHERE recorded_ts < ?",
                 (now - EVIDENCE_TTL_SEC,))
    conn.execute("DELETE FROM name_pending WHERE recorded_ts < ?",
                 (now - pending_ttl(),))
    conn.execute("DELETE FROM name_pending_pulls WHERE requested_ts < ?",
                 (now - pending_ttl(),))


def evidence_has_room(conn, name, sender) -> bool:
    """Charge-before-write for the unknown-name evidence store. The belt's
    no-cap mutant returns True."""
    n_name = conn.execute("SELECT COUNT(*) FROM name_cert_evidence WHERE name=?",
                          (name,)).fetchone()[0]
    n_send = conn.execute("SELECT COUNT(*) FROM name_cert_evidence WHERE sender=?",
                          (sender,)).fetchone()[0]
    n_all = conn.execute("SELECT COUNT(*) FROM name_cert_evidence").fetchone()[0]
    return (n_name < EVIDENCE_PER_NAME and n_send < EVIDENCE_PER_SENDER
            and n_all < EVIDENCE_GLOBAL)


def _keep_evidence(conn, rec, sender, now=None) -> str:
    if not evidence_has_room(conn, rec["name"], sender):
        return "evidence-full"
    conn.execute(
        "INSERT OR IGNORE INTO name_cert_evidence (name, sender, cert_hash,"
        " cert, recorded_ts) VALUES (?,?,?,?,?)",
        (rec["name"], sender, rec["cert_hash"],
         json.dumps(_wire(rec), sort_keys=True),
         time.time() if now is None else now))
    return "evidence"


def pending_ttl() -> int:
    """A pending cert must outlive the RATE BOUND wait for the hop before
    it, so it lives at least three rounds."""
    return max(PENDING_TTL_SEC, 3 * round_seconds())


def pending_has_room(conn, name, sender) -> bool:
    """Bounded PENDING. The unbounded-queue mutant returns True."""
    n_name = conn.execute("SELECT COUNT(*) FROM name_pending WHERE name=?",
                          (name,)).fetchone()[0]
    n_send = conn.execute("SELECT COUNT(*) FROM name_pending WHERE sender=?",
                          (sender,)).fetchone()[0]
    return n_name < PENDING_PER_NAME and n_send < PENDING_PER_SENDER


def _hold_pending(conn, rec, sender, pulls: list, now=None) -> str:
    if not pending_has_room(conn, rec["name"], sender):
        return "pending-full"
    now = time.time() if now is None else now
    conn.execute(
        "INSERT OR IGNORE INTO name_pending (name, sender, prev_hash, cert_hash,"
        " cert, recorded_ts) VALUES (?,?,?,?,?,?)",
        (rec["name"], sender, rec["prev_hash"], rec["cert_hash"],
         json.dumps(_wire(rec), sort_keys=True), now))
    # One pull per unknown hash, aimed only at the node that sent it.
    cur = conn.execute(
        "INSERT OR IGNORE INTO name_pending_pulls (prev_hash, name, sender,"
        " requested_ts) VALUES (?,?,?,?)",
        (rec["prev_hash"], rec["name"], sender, now))
    if cur.rowcount:
        pulls.append({"name": rec["name"], "prev_hash": rec["prev_hash"],
                      "sender": sender})
    return "pending"


def pending_count(conn, name=None) -> int:
    ensure_schema(conn)
    if name is None:
        return conn.execute("SELECT COUNT(*) FROM name_pending").fetchone()[0]
    return conn.execute("SELECT COUNT(*) FROM name_pending WHERE name=?",
                        (name,)).fetchone()[0]


def evidence_count(conn) -> int:
    ensure_schema(conn)
    return conn.execute("SELECT COUNT(*) FROM name_cert_evidence").fetchone()[0]


# --------------------------------------------------------------- ingest

def _binding_origin(binding) -> tuple[str, str] | None:
    """(key, origin_hash) of a signed binding dict, or None."""
    try:
        pub = str(binding["node_pubkey"]).lower()
        return pub, origin_hash(str(binding["name"]).lower(), pub,
                                binding["issued_at"], binding["expires_at"],
                                str(binding["signature"]).lower())
    except Exception:
        return None


def _held_binding(conn, name):
    try:
        row = conn.execute(
            "SELECT name, node_pubkey, issued_at, expires_at, signature"
            " FROM name_bindings WHERE name=?", (name,)).fetchone()
    except sqlite3.OperationalError:
        return None
    if row is None:
        return None
    return dict(zip(("name", "node_pubkey", "issued_at", "expires_at",
                     "signature"), row))


def birth_contest_allowed(conn, name, old_pub, round_bindings) -> bool:
    """E1: contested-from-birth only when this node HOLDS, or receives in
    the same round, a binding for the name whose key equals the certs'
    old key. The 'current branch' mutant returns True."""
    held = _held_binding(conn, name)
    cands = [held] if held else []
    cands += [b for b in round_bindings
              if isinstance(b, dict)
              and str(b.get("name", "")).lower() == name]
    for b in cands:
        if str(b.get("node_pubkey", "")).lower() == old_pub:
            return True
    return False


def ingest_rotation_round(conn: sqlite3.Connection, certs: list,
                          sender_pub: str | None,
                          round_bindings: list | None = None,
                          now: float | None = None) -> dict:
    """One gossip call's rotation certificates. The caller has already
    charged every cert against the pre-verify budgets (outside the lock).

    Per certificate: _norm_cert (all key, encoding and signature checks),
    then judged against the LOCAL head only:
      * no pin for the name  -> never a pin; kept as capped evidence
                                (E1 birth contest only with a held key)
      * contested            -> fork evidence only
      * prev_hash == head     -> contiguity (old == pin, seq == head+1),
                                fork check, RATE BOUND, accept
      * prev_hash an earlier link -> replay (same hop) or fork (new key)
      * prev_hash unknown    -> PENDING (bounded), one pull at the sender
    """
    ensure_schema(conn)
    now = time.time() if now is None else now
    _prune(conn, now)
    sender = str(sender_pub or "").strip().lower()
    rnd = current_round(now)
    out = {"accepted": {}, "contested": set(), "pending": 0, "evidence": 0,
           "refused": 0, "overflow_n": 0, "pulls": [], "outcomes": []}
    normalized = []
    rb_names = {str(b.get("name", "")).strip().lower()
                for b in (round_bindings or []) if isinstance(b, dict)}
    for raw in certs or []:
        # Charge-before-write for the evidence store, before any verify: a
        # cert for a name with no pin, no held binding and no binding in
        # this round can only become evidence, so a full store refuses it
        # without spending a checkvalid.
        if isinstance(raw, dict):
            nm = str(raw.get("name", "")).strip().lower()
            if (nm and current_pin(conn, nm) is None and nm not in rb_names
                    and _held_binding(conn, nm) is None
                    and not evidence_has_room(conn, nm, sender)):
                out["refused"] += 1
                out["outcomes"].append("evidence-full")
                continue
        rec = _norm_cert(raw)
        if rec is None:
            out["refused"] += 1
            out["outcomes"].append("refused-invalid")
            continue
        normalized.append(rec)

    # Unknown names: E1 birth contest, else evidence. Never a pin.
    unknown = [r for r in normalized if current_pin(conn, r["name"]) is None]
    groups: dict = {}
    for rec in unknown:
        groups.setdefault((rec["name"], rec["prev_hash"]), []).append(rec)
    for (name, prev), group in groups.items():
        olds = {r["old_pubkey"] for r in group}
        news = {r["new_pubkey"] for r in group}
        birth = False
        if len(news) >= 2 and len(olds) == 1 and not bootstrap_picks_first():
            old = next(iter(olds))
            held = _held_binding(conn, name)
            rb = [b for b in (round_bindings or []) if isinstance(b, dict)]
            origin_ok = any(
                (o := _binding_origin(b)) is not None and o[0] == old
                and o[1] == prev
                for b in ([held] if held else []) + rb
                if str(b.get("name", "")).lower() == name)
            if birth_contest_allowed(conn, name, old, round_bindings or []) and (
                    origin_ok or not birth_contest_needs_origin()):
                birth = True
        for rec in group:
            if birth:
                if _store_fork(conn, rec) == "overflow":
                    out["overflow_n"] += 1
                out["outcomes"].append("contested-birth")
            else:
                out["outcomes"].append(_keep_evidence(conn, rec, sender, now))
                out["evidence"] += 1
        if birth:
            _mark_contested(conn, name, "fork at birth: two certs on the held key")
            out["contested"].add(name)

    for rec in normalized:
        name = rec["name"]
        st = current_state(conn, name)
        if st is None:
            continue
        pin, seq, head = st
        if is_contested(conn, name):
            if _store_fork(conn, rec) == "overflow":
                out["overflow_n"] += 1
            out["outcomes"].append("contested")
            out["contested"].add(name)
            continue
        chain = _chain_links(conn, name)
        if rec["prev_hash"] == head:
            if not contiguous(rec, pin, seq):
                out["refused"] += 1
                out["outcomes"].append("refused-noncontiguous")
                continue
            prior = [r[0] for r in conn.execute(
                "SELECT new_pubkey FROM name_fork_evidence WHERE name=? AND"
                " prev_hash=?", (name, head)).fetchall()
                if r[0] != rec["new_pubkey"]]
            if prior and second_cert_contests(name, head, rec["new_pubkey"]):
                if _store_fork(conn, rec) == "overflow":
                    out["overflow_n"] += 1
                _mark_contested(conn, name, "fork: two certs on one prev_hash")
                out["contested"].add(name)
                out["outcomes"].append("contested")
                continue
            if _round_held(conn, name, rnd) or name in out["accepted"] and rotations_per_round() <= 1:
                # RATE BOUND. The cert is kept as fork evidence for this
                # link so a competing cert still contests the name.
                _store_fork(conn, rec)
                out["refused"] += 1
                out["outcomes"].append("rate-held")
                continue
            _store_fork(conn, rec)
            _append_rotation(conn, rec)
            _note_round(conn, name, rnd)
            out["accepted"][name] = rec["new_pubkey"]
            out["outcomes"].append("accepted")
            continue
        if rec["prev_hash"] in chain["known"]:
            link = chain["links"].get(rec["prev_hash"])
            if is_replay(link, rec):
                out["refused"] += 1
                out["outcomes"].append("refused-replay")
                continue
            if second_cert_contests(name, rec["prev_hash"], rec["new_pubkey"]):
                _store_fork(conn, rec)
                _mark_contested(conn, name, "fork: two certs on one prev_hash")
                out["contested"].add(name)
                out["outcomes"].append("contested")
            else:
                out["outcomes"].append("ignored")
            continue
        # Unknown prev_hash: PENDING, never CONTESTED.
        out["outcomes"].append(_hold_pending(conn, rec, sender, out["pulls"], now))
        out["pending"] += 1
    return out


def is_replay(link, rec) -> bool:
    """A cert on an earlier link of the local chain that repeats the hop
    already taken there (same cert, or same successor) is a replay and is
    refused; the pin does not move. The replay mutant returns False."""
    return (link is None or link[1] == rec["cert_hash"]
            or link[0] == rec["new_pubkey"])


def birth_contest_needs_origin() -> bool:
    return True


def contiguous(rec, pin, seq) -> bool:
    """The signer is the current pin and seq is head+1. The non-contiguous
    mutant returns True."""
    return rec["old_pubkey"] == pin and rec["seq"] == seq + 1


def consider_rotation(conn: sqlite3.Connection, rec: dict,
                      sender_pub: str | None = None) -> str:
    result = ingest_rotation_round(conn, [rec], sender_pub)
    name = str((rec or {}).get("name", "")).strip().lower()
    if name in result["contested"] or is_contested(conn, name):
        return "contested"
    if name in result["accepted"]:
        return "accepted"
    if result["outcomes"] and result["outcomes"][0] == "rate-held":
        return "rate-held"
    if result["outcomes"] and result["outcomes"][0].startswith("pending"):
        return "pending"
    return "refused"


# ------------------------------------------------------------- catch-up

def path_accept_rule(conn, name, path) -> list | None:
    """Catch-up acceptance: the fetched path must link hash by hash to this
    node's own head, its first old_pub must equal the current pin, every
    link passes _norm_cert, and the path is accepted or refused WHOLE.
    Returns the normalized path or None. The internal-chain mutant skips
    the head and pin anchoring."""
    st = current_state(conn, name)
    if st is None or not path:
        return None
    pin, seq, head = st
    recs = []
    for raw in path:
        rec = _norm_cert(raw)
        if rec is None or rec["name"] != name:
            return None
        recs.append(rec)
    if recs[0]["prev_hash"] != head or recs[0]["old_pubkey"] != pin:
        return None
    if recs[0]["seq"] != seq + 1:
        return None
    for a, b in zip(recs, recs[1:]):
        if (b["prev_hash"] != a["cert_hash"] or b["old_pubkey"] != a["new_pubkey"]
                or b["seq"] != a["seq"] + 1):
            return None
    return recs


def accept_catchup(conn, name, path, sender_pub=None,
                   now: float | None = None) -> str:
    """Apply a fetched path whole. Then re-judge pending certs that now
    link. Returns 'accepted', 'refused', 'contested', or 'rate-held'."""
    ensure_schema(conn)
    now = time.time() if now is None else now
    if is_contested(conn, name):
        return "contested"
    recs = path_accept_rule(conn, name, path)
    if recs is None:
        return "refused"
    head = head_hash(conn, name)
    others = [r[0] for r in conn.execute(
        "SELECT new_pubkey FROM name_fork_evidence WHERE name=? AND prev_hash=?",
        (name, head)).fetchall() if r[0] != recs[0]["new_pubkey"]]
    if others:
        # Both branches verify from the real head: the first is stored
        # evidence that passed _norm_cert, this one just did.
        _store_fork(conn, recs[0])
        _mark_contested(conn, name, "fork: two certs on one prev_hash")
        return "contested"
    rnd = current_round(now)
    if _round_held(conn, name, rnd):
        return "rate-held"
    for rec in recs:
        _store_fork(conn, rec)
        _append_rotation(conn, rec)
    # A caught-up path is one rate event: the name moved in this round.
    _note_round(conn, name, rnd)
    conn.execute("DELETE FROM name_pending WHERE name=? AND cert_hash IN (%s)"
                 % ",".join("?" * len(recs)),
                 (name, *[r["cert_hash"] for r in recs]))
    return "accepted"


def drain_pending(conn, name, sender_pub=None, now=None) -> dict:
    """Re-judge pending certs for a name after its head moved."""
    rows = conn.execute("SELECT id, cert, sender FROM name_pending WHERE name=?"
                        " ORDER BY id", (name,)).fetchall()
    res = {"accepted": {}, "contested": set(), "outcomes": []}
    for rid, cert, sender in rows:
        c = json.loads(cert)
        h = head_hash(conn, name)
        if c.get("prev_hash") != h:
            continue
        conn.execute("DELETE FROM name_pending WHERE id=?", (rid,))
        r = ingest_rotation_round(conn, [c], sender, now=now)
        res["accepted"].update(r["accepted"])
        res["contested"] |= r["contested"]
        res["outcomes"] += r["outcomes"]
    return res


def chain_for(conn, name) -> dict | None:
    """The served chain for catch-up: the origin binding hash and every
    accepted v2 cert of the current pin generation, oldest first."""
    ensure_schema(conn)
    st = current_state(conn, name)
    if st is None:
        return None
    gen = conn.execute(
        "SELECT MAX(id) FROM name_pin_log WHERE name=? AND kind='pin'",
        (name,)).fetchone()[0]
    first = conn.execute("SELECT origin_hash FROM name_pin_log WHERE id=?",
                         (gen,)).fetchone()
    certs = [json.loads(r[0]) for r in conn.execute(
        "SELECT cert FROM name_pin_log WHERE name=? AND id>? AND kind='rotate'"
        " ORDER BY id", (name, gen)).fetchall()]
    return {"name": name, "origin_hash": first[0] if first else "",
            "head_hash": st[2], "rotations": certs}


def path_after(chain: dict, from_hash: str) -> list:
    certs = chain.get("rotations") or []
    for i, c in enumerate(certs):
        if c.get("prev_hash") == from_hash:
            return certs[i:]
    return []


# ----------------------------------------------------------- PIN-STALE

def claim_after_lapse(conn, name, new_pubkey, binding_expires_at,
                      now_dt=None) -> str | None:
    """A claim under a different key with no rotation cert. When the held
    binding has expired AND the day-90 release has passed, the name is
    marked PIN-STALE (local, logged) and neither key is served. Returns
    True when the name was marked. Pins are permanent; this never unpins."""
    import core
    now_dt = now_dt or datetime.now(timezone.utc)
    pin = current_pin(conn, name)
    if pin is None or str(new_pubkey).lower() == pin:
        return None
    try:
        exp = core._parse_claim_time(binding_expires_at)
    except Exception:
        return None
    if exp > now_dt or exp + timedelta(days=RELEASE_DAYS) > now_dt:
        return None
    return stale_policy(conn, name, pin, str(new_pubkey).lower())


def stale_policy(conn, name, pin, new_pub) -> str:
    """Production: mark PIN-STALE, log it, serve neither key. The belt's
    mutant returns 'released' after an unpin (the new key gets served)."""
    conn.execute(
        "INSERT INTO name_pin_stale (name, since, pin, refused_pubkey)"
        " VALUES (?,?,?,?) ON CONFLICT(name) DO NOTHING",
        (name, _now(), pin, new_pub))
    conn.execute(
        "INSERT INTO name_pin_log (name, pubkey, seq, prev_pubkey,"
        " cert_signature, recorded_at, kind, source, reason)"
        " SELECT name, pubkey, seq, '', '', ?, 'stale-mark', '', ?"
        " FROM name_pin_log WHERE name=? ORDER BY id DESC LIMIT 1",
        (_now(), f"PIN-STALE: lapse+{RELEASE_DAYS}d claim by {new_pub[:16]}",
         name))
    return "stale"


# -------------------------------------------------------- startup guard

def _verify_binding_sig(name, pub, issued_at, expires_at, sig) -> bool:
    import core
    return core._name_binding_verify(name, pub, issued_at, expires_at, sig)


def guard_check(conn, name) -> str | None:
    """None when the live pin's provenance holds; else the refusal reason.
    The label is never trusted: the stored hash must resolve to the exact
    signed binding, whose bytes re-hash to it, whose signature verifies
    (strict), whose key passes checkvalid and weak_reason, and whose key
    equals the pin generation's first key."""
    gen = conn.execute(
        "SELECT pubkey, source, origin_hash FROM name_pin_log WHERE id=("
        " SELECT MAX(id) FROM name_pin_log WHERE name=? AND kind IN ('pin','unpin'))",
        (name,)).fetchone()
    if gen is None:
        return "no pin generation"
    pub, source, oh = str(gen[0]).lower(), gen[1], gen[2]
    if source == "genesis_constant" and name == GENESIS_LABEL:
        g = genesis_pin()
        if g and g == pub and oh == genesis_origin_hash(g):
            return None
        return "genesis pin does not match the constant"
    if source not in SOURCES_THAT_PIN:
        return f"no provenance (source={source or 'none'})"
    return guard_resolve(conn, name, pub, oh)


def guard_resolve(conn, name, pub, oh) -> str | None:
    row = conn.execute(
        "SELECT name, pubkey, issued_at, expires_at, signature FROM"
        " name_pin_origins WHERE origin_hash=?", (oh,)).fetchone()
    if row is None:
        return "origin hash resolves to no stored binding"
    bname, bpub, iss, exp, sig = row
    try:
        if origin_hash(bname, bpub, iss, exp, sig) != oh:
            return "origin bytes do not hash to the stored hash"
    except Exception:
        return "origin bytes malformed"
    if bname != name:
        return "origin binding is for another name"
    if not guard_sig_ok(bname, bpub, iss, exp, sig):
        return "origin signature does not verify"
    from fed import ed25519 as _ed
    try:
        P = _ed._decodepoint_strict(bytes.fromhex(bpub))
        if _ed._is_small_order(P):
            return "origin key small-order"
    except Exception:
        return "origin key not canonical"
    if _weak(bpub) is not None:
        return "origin key weak"
    if str(bpub).lower() != pub:
        return "origin key is not the pin's first key"
    return None


def guard_sig_ok(name, pub, iss, exp, sig) -> bool:
    return _verify_binding_sig(name, pub, iss, exp, sig)


def unpin(conn, name, reason) -> None:
    """Logged local unpin: a NEW appended entry. Never a delete or update."""
    last = _latest(conn, name)
    old_hash = str(last[4]) if last else ""
    conn.execute(
        "INSERT INTO name_pin_log (name, pubkey, seq, prev_pubkey,"
        " cert_signature, recorded_at, kind, source, origin_hash, head_hash, reason)"
        " VALUES (?,?,?,'','',?,'unpin','startup_guard',?,?,?)",
        (name, last[2] if last else "", last[3] if last else 0, _now(),
         old_hash, old_hash, reason))
    _sync_cache(conn, name)


def startup_guard(conn) -> list:
    """Refuse every live pin whose provenance does not hold. Returns
    [(name, reason)]. Refused pins become UNPINNED (not PIN-STALE) via an
    appended log entry, so the name can be claimed through the gates."""
    ensure_schema(conn)
    names = [r[0] for r in conn.execute(
        "SELECT DISTINCT name FROM name_pin_log").fetchall()]
    refused = []
    for name in names:
        last = _latest(conn, name)
        if last is None or last[1] == "unpin":
            continue
        why = guard_check(conn, name)
        if why:
            unpin(conn, name, why)
            refused.append((name, why))
        else:
            _sync_cache(conn, name)
    # Cache rows with no log behind them are not pins.
    for (n,) in conn.execute("SELECT name FROM name_pins").fetchall():
        if _latest(conn, n) is None:
            conn.execute("DELETE FROM name_pins WHERE name=?", (n,))
            refused.append((n, "cache row with no pin log"))
    return refused


# ------------------------------------------------------------- gossip out

def fork_cert_count(conn, name) -> int:
    ensure_schema(conn)
    return conn.execute("SELECT COUNT(*) FROM name_fork_evidence WHERE name=?",
                        (name,)).fetchone()[0]


def overflow_count(conn, name) -> int:
    ensure_schema(conn)
    return conn.execute(
        "SELECT COALESCE(SUM(overflow_count),0) FROM name_fork_overflow"
        " WHERE name=?", (name,)).fetchone()[0]


def gossip_rotations(conn, names: list) -> list:
    """Accepted v2 hops and stored fork evidence. Contested names repeat
    their fork evidence only (so peers see the split); their bindings are
    not gossiped."""
    ensure_schema(conn)
    out, seen = [], set()
    for name in dict.fromkeys(names or []):
        rows = []
        if not is_contested(conn, name):
            ch = chain_for(conn, name)
            rows += (ch or {}).get("rotations", [])
        rows += [json.loads(r[0]) for r in conn.execute(
            "SELECT cert FROM name_fork_evidence WHERE name=? ORDER BY id",
            (name,)).fetchall()]
        for c in rows:
            key = json.dumps(c, sort_keys=True)
            if key in seen:
                continue
            seen.add(key)
            out.append(c)
    return out
