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

V2 CERTIFICATES (ONE FORMAT with hop_certs.py / KINDS 7b15ca9)
  signed bytes = hop_certs.v2_payload:
    name-rotate/v2|<name>|<seq>|<prev_hash>|<old_pub>|<new_pub>|<issued_at>
  cert_hash    = hop_certs.cert_hash over the FULL cert incl. signature
                 (JSON [v,name,seq,prev_hash,old,new,issued_at,sig])
  Chain anchor for a first v2 hop: hop_certs.claim_anchor(name, pin), OR
  the last FROZEN v1 cert's cert_hash (v1 history under v1_frozen_root;
  ruling 64157549 item 1 (b) — freeze, never drop).
  R, S (S < L), old_pub and new_pub are strict-decoded and must re-encode
  to the input bytes before any hash is computed. libsodium
  is_valid_point + checkvalid_sodium on BOTH keys; fail closed.

FORKS
  Fork evidence is keyed on (name, prev_hash). Two verified certificates
  on the same prev_hash with different new keys mark the name CONTESTED.
  Chain depth is never a tiebreak. An unknown prev_hash is PENDING, never
  CONTESTED. A contested name has no recovery path in this build.

FORK GATE (round pause)
  At most one accepted rotation per name per round, where a round is a
  wall-clock window (CYBERNET_NAME_ROTATION_ROUND_SEC, default the
  announce interval), persisted in name_rotation_round. The round pause
  is a FORK GATE, not just a rate bound: a fast chain A->B->C cannot move
  past B in the round that fork evidence for A->B' can still arrive in,
  so the fork contests the name before C is ever resolved or logged.
  The slot is written only on acceptance, in the same transaction as the
  chain advance and the name_pin_log append.
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

# Canonical v2 format (Villhaze ruling ART-42 64157549, as implemented on
# the KINDS track): name-rotate/v2|name|seq|prev_hash|old_pub|new_pub|
# issued_at, serialized ONLY by hop_certs.v2_payload; prev_hash is
# hop_certs.cert_hash over the full previous cert including its signature.
# The first v2 cert anchors on hop_certs.claim_anchor(name, pin), or on the
# name's last FROZEN v1 cert (v1 is frozen, not refused).
TAG = b"name-rotate/v2"
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
    """FORK GATE (round pause): one accepted hop per name per round."""
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
    try:
        have = {r[1] for r in conn.execute("PRAGMA table_info(name_rotations)")}
        if have:
            # Same columns as KINDS window_open.init_schema (7b15ca9).
            for col, ddl in (("cert_v", "INTEGER NOT NULL DEFAULT 1"),
                             ("cert_seq", "INTEGER"), ("prev_hash", "TEXT")):
                if col not in have:
                    conn.execute(f"ALTER TABLE name_rotations ADD COLUMN {col} {ddl}")
    except sqlite3.OperationalError:
        pass
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
        """CREATE TABLE IF NOT EXISTS name_fork_late (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            sender TEXT NOT NULL,
            prev_hash TEXT NOT NULL,
            seq INTEGER NOT NULL,
            new_pubkey TEXT NOT NULL,
            cert_hash TEXT NOT NULL UNIQUE,
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
    # FORK GATE (round pause): last round a rotation was accepted.
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


_wall = time.time   # patchable wall clock (the paging belt's fake clock)


def _now() -> str:
    return datetime.fromtimestamp(_wall(), timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S+00:00")


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
    """The signed bytes: hop_certs.v2_payload (the one serializer). Any other
    tag (the kind-binding mutant) only swaps the leading field."""
    import hop_certs
    if tag == TAG:
        return hop_certs.v2_payload(name, seq, prev_hash, old_pub, new_pub,
                                    issued_at)
    return "|".join([tag.decode(), name, str(int(seq)), prev_hash, old_pub,
                     new_pub, issued_at]).encode()


def hop_row(rec: dict, i: int = 0) -> dict:
    """A cert as a hop_certs.ROW_FIELDS row (the KINDS leaf encoding)."""
    v = int(rec.get("v", VERSION))
    return {"name": rec["name"], "i": i, "old": rec["old_pubkey"],
            "new": rec["new_pubkey"], "issued_at": rec["issued_at"],
            "sig": rec["signature"], "v": v,
            "seq": rec["seq"] if v == 2 else None,
            "prev_hash": rec["prev_hash"] if v == 2 else None}


def cert_hash(rec: dict) -> str:
    """hop_certs.cert_hash over the full cert, signature included. Callers
    pass only certificates that already passed _canonical."""
    global _hash_calls
    import hop_certs
    _hash_calls += 1
    return hop_certs.cert_hash(hop_row(rec))


def claim_anchor(name: str, pub: str) -> str:
    import hop_certs
    return hop_certs.claim_anchor(name, pub)


def _v1_cert_hash(v1: dict) -> str:
    """Hash of a v1 cert as the first v2 hop's prev_hash: hop_certs.cert_hash
    of the FULL v1 cert (signature included). Patchable (payload-only mutant)."""
    import hop_certs
    return hop_certs.cert_hash(hop_row(dict(v1, v=1)))


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


# Key subgroup check (fast path, Cipher with Bulwark's conditions):
# libsodium crypto_core_ed25519_is_valid_point replaces weak_reason on this
# path. It is equivalent to weak_reason on Cipher's corpus (51-vector keys,
# small-order, identity, non-canonical, mixed-order, honest, random) with
# zero disagreements either way. NO fallback to weak_reason: if libsodium
# is missing, admission is refused. Still charged before the check, and
# run outside _db_lock. Passing keys are cached per sender (bounded); a
# refusal is never cached.
import collections as _collections
import contextvars as _contextvars
WEAK_OK_CACHE_PER_SENDER = 64
WEAK_OK_CACHE_SENDERS = 128
SODIUM_KEY_MISSING = "libsodium (PyNaCl) unavailable: key check refuses"
_weak_ok_cache: "_collections.OrderedDict[str, _collections.OrderedDict]" = \
    _collections.OrderedDict()
_cur_sender = _contextvars.ContextVar("name_fork_sender", default="")
_weak_calls = 0


def _key_check(pub: str) -> str | None:
    """Patchable. None = key passes; otherwise the refusal reason."""
    from fed import ed25519 as _ed
    try:
        raw = bytes.fromhex(pub)
    except (TypeError, ValueError):
        return "not hex"
    if len(raw) != 32:
        return "not 32 bytes"
    ok = _ed.sodium_key_ok(raw)
    if ok is None:
        return SODIUM_KEY_MISSING
    return None if ok else "not a prime-order-subgroup point (libsodium)"


def _weak(pub: str) -> str | None:
    global _weak_calls
    sender = _cur_sender.get()
    per = _weak_ok_cache.get(sender) if sender else None
    if per is not None and pub in per:
        per.move_to_end(pub)
        return None
    _weak_calls += 1
    reason = _key_check(pub)
    if reason is None and sender:
        per = _weak_ok_cache.setdefault(sender, _collections.OrderedDict())
        _weak_ok_cache.move_to_end(sender)
        per[pub] = True
        while len(per) > WEAK_OK_CACHE_PER_SENDER:
            per.popitem(last=False)
        while len(_weak_ok_cache) > WEAK_OK_CACHE_SENDERS:
            _weak_ok_cache.popitem(last=False)
    return reason


def _keys_ok(rec: dict) -> bool:
    """Strict checkvalid on both keys (canonical, not small-order) plus
    the subgroup check (libsodium is_valid_point; mixed-order refused) on BOTH old_pub and new_pub. Before verify."""
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
    # Runtime libsodium gate (Villhaze b9f64f88): binding present AND
    # bundled-library probe passed at startup (no version-number gate).
    if _ed.SODIUM_ERROR is not None or not _ed.bundled_probe_ok():
        import logging
        logging.getLogger("name_fork").error(
            _ed.SODIUM_ERROR or "libsodium version gate refused")
        return False
    return _ed.checkvalid_sodium(bytes.fromhex(rec["signature"]), payload,
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
    if raw.get("prev_v1") is not None:
        g = _graft_v1(rec, raw.get("prev_v1"))
        if g is None:
            return None
        rec["_v1_hash"] = g
    return rec


def _v1_shape(v1, name) -> dict | None:
    import re as _re
    if not isinstance(v1, dict):
        return None
    try:
        out = {"name": str(v1["name"]).strip().lower(),
               "old_pubkey": str(v1["old_pubkey"]).strip().lower(),
               "new_pubkey": str(v1["new_pubkey"]).strip().lower(),
               "issued_at": str(v1["issued_at"]),
               "signature": str(v1["signature"]).strip().lower(), "v": 1}
    except (KeyError, TypeError, AttributeError):
        return None
    if out["name"] != name or len(out["issued_at"]) > 64:
        return None
    for k, n in (("old_pubkey", 64), ("new_pubkey", 64), ("signature", 128)):
        if not _re.fullmatch(r"[0-9a-f]{%d}" % n, out[k]):
            return None
    return out


def _verify_v1(v1: dict) -> bool:
    """libsodium only (strict checks + crypto_sign_open), same as v2."""
    global _verify_calls
    import hop_certs
    from fed import ed25519 as _ed
    _verify_calls += 1
    if _ed.SODIUM_ERROR is not None or not _ed.bundled_probe_ok():
        return False
    return _ed.checkvalid_sodium(
        bytes.fromhex(v1["signature"]),
        hop_certs.v1_payload(v1["name"], v1["old_pubkey"], v1["new_pubkey"],
                             v1["issued_at"]),
        bytes.fromhex(v1["old_pubkey"]))


def _graft_v1(rec: dict, raw_v1) -> str | None:
    """The FROZEN v1 cert a first v2 hop chains onto. Same sequence as v2,
    inside _norm_cert (so: charged first, outside _db_lock): shape,
    canonical decode, key check on both keys, libsodium verify. Returns its
    full-cert hash, which must equal the v2 cert's prev_hash."""
    v1 = _v1_shape(raw_v1, rec["name"])
    if v1 is None:
        return None
    if not _canonical(v1) or not _keys_ok(v1):
        return None
    if v1["new_pubkey"] != rec["old_pubkey"]:
        return None
    if not _verify_v1(v1):
        return None
    h = _v1_cert_hash(v1)
    return h if h == rec["prev_hash"] else None


def v1_frozen_rows(conn, name) -> list:
    """This node's frozen v1 certs for a name (name_rotations, cert_v=1), as
    hop rows in accepted order: the leaves of hop_certs.v1_frozen_root."""
    try:
        rows = conn.execute(
            "SELECT old_pubkey, new_pubkey, issued_at, signature FROM"
            " name_rotations WHERE name=? AND COALESCE(cert_v,1)=1"
            " ORDER BY accepted_at ASC, rowid ASC", (name,)).fetchall()
    except sqlite3.OperationalError:
        return []
    return [hop_row({"name": name, "old_pubkey": o, "new_pubkey": n,
                     "issued_at": i, "signature": sg, "v": 1}, j)
            for j, (o, n, i, sg) in enumerate(rows)]


def v1_member(conn, name, h) -> bool:
    """The grafted v1 cert is the name's LAST frozen v1 cert (a leaf of
    hop_certs.v1_frozen_root). The skip-membership mutant returns True."""
    import hop_certs
    rows = v1_frozen_rows(conn, name)
    return bool(rows) and hop_certs.cert_hash(rows[-1]) == h


def _v1_graft_ok(conn, rec, seq) -> bool:
    return (seq == 0 and rec.get("_v1_hash") is not None
            and rec["prev_hash"] == rec["_v1_hash"]
            and v1_member(conn, rec["name"], rec["_v1_hash"]))


def hop_rows(conn, name) -> list:
    """The name's chain as hop_certs rows (frozen v1, then accepted v2), in
    order, i = position. hops_root over these must equal KINDS import."""
    out = list(v1_frozen_rows(conn, name))
    for (cert,) in conn.execute(
            "SELECT cert FROM name_pin_log WHERE name=? AND kind='rotate'"
            " ORDER BY id", (name,)).fetchall():
        rec = json.loads(cert)
        out.append(hop_row(rec, len(out)))
    return out


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
        (GENESIS_LABEL, pin, _now(), h, claim_anchor(GENESIS_LABEL, pin)))
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
        (name, pub, _now(), source, h, claim_anchor(name, pub)))
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
    """FORK GATE: True when this name already moved in this round."""
    row = conn.execute("SELECT last_round FROM name_rotation_round WHERE name=?",
                       (name,)).fetchone()
    return row is not None and int(row[0]) >= rnd and rotations_per_round() <= 1


def _note_round(conn, name, rnd) -> None:
    conn.execute(
        "INSERT INTO name_rotation_round (name, last_round) VALUES (?,?)"
        " ON CONFLICT(name) DO UPDATE SET last_round=excluded.last_round",
        (name, rnd))


def _accept_hop(conn, rec, rnd) -> bool:
    """Acceptance, after every check has passed (decode, verify, weak_reason
    on both keys, seq/prev_hash, fork checks, FORK GATE). Fork evidence, the
    chain advance, the name_pin_log append and the round slot are one
    transaction (a SAVEPOINT): if any write raises, nothing is kept and the
    slot is still free for a retry in the same round."""
    conn.execute("SAVEPOINT accept_hop")
    try:
        _store_fork(conn, rec)
        _append_rotation(conn, rec)
        _note_round(conn, rec["name"], rnd)
    except sqlite3.Error:
        conn.execute("ROLLBACK TO SAVEPOINT accept_hop")
        conn.execute("RELEASE SAVEPOINT accept_hop")
        return False
    conn.execute("RELEASE SAVEPOINT accept_hop")
    return True


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
            " new_pubkey, issued_at, signature, accepted_at, cert_v,"
            " cert_seq, prev_hash) VALUES (?,?,?,?,?,?,2,?,?)",
            (rec["name"], rec["old_pubkey"], rec["new_pubkey"],
             rec["issued_at"], rec["signature"], _now(), rec["seq"],
             rec["prev_hash"]))
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
    """A pending cert must outlive the FORK GATE wait for the hop before
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
                          now: float | None = None,
                          prenormalized: list | None = None) -> dict:
    """One gossip call's rotation certificates. The caller has already
    charged every cert against the pre-verify budgets (outside the lock).

    Per certificate: _norm_cert (all key, encoding and signature checks),
    then judged against the LOCAL head only:
      * no pin for the name  -> never a pin; kept as capped evidence
                                (E1 birth contest only with a held key)
      * contested            -> fork evidence only
      * prev_hash == head     -> contiguity (old == pin, seq == head+1),
                                fork check, FORK GATE, accept
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
    pre = list(prenormalized) if prenormalized is not None else None
    for i, raw in enumerate(certs or []):
        # v1 is FROZEN, not refused: a standalone v1 cert is never a new
        # hop, and is acknowledged without a state change. A v1 cert enters
        # a chain only as the prev_v1 of a first v2 hop.
        if isinstance(raw, dict) and raw.get("v") == 1:
            out["outcomes"].append("v1-frozen")
            continue
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
        # The caller normalizes OUTSIDE _db_lock (core.normalize_rotation_
        # certs) and passes the results in; only direct callers (tests,
        # drain) normalize here.
        # No inline fallback: a caller that did not normalize (outside the
        # lock) gets a refusal, never a _norm_cert under _db_lock.
        rec = pre[i] if pre is not None and i < len(pre) else None
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
                and claim_anchor(name, o[0]) == prev
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
        if rec["prev_hash"] == head or _v1_graft_ok(conn, rec, seq):
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
                # FORK GATE. The cert is kept as fork evidence for this
                # link so a competing cert still contests the name.
                _store_fork(conn, rec)
                out["refused"] += 1
                out["outcomes"].append("rate-held")
                continue
            if not _accept_hop(conn, rec, rnd):
                out["refused"] += 1
                out["outcomes"].append("refused-log-error")
                continue
            out["accepted"][name] = rec["new_pubkey"]
            out["outcomes"].append("accepted")
            continue
        if rec["prev_hash"] in chain["known"]:
            link = chain["links"].get(rec["prev_hash"])
            if is_replay(link, rec):
                out["refused"] += 1
                out["outcomes"].append("refused-replay")
                continue
            if not fork_window_open(conn, name, rec, now):
                # Late fork (Bulwark/Loom): evidence only, capped per name
                # and per sender; the name stays live.
                out["outcomes"].append(_keep_late_fork(conn, rec, sender, now))
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


class PrenormalizedRequired(RuntimeError):
    """A lock-holding entry point was called without certs normalized
    OUTSIDE _db_lock. Programming error, never a peer-reachable outcome."""


def contiguous(rec, pin, seq) -> bool:
    """The signer is the current pin and seq is head+1. The non-contiguous
    mutant returns True."""
    return rec["old_pubkey"] == pin and rec["seq"] == seq + 1


def consider_rotation(conn: sqlite3.Connection, rec: dict,
                      sender_pub: str | None = None, prenormalized=None) -> str:
    """prenormalized: [_norm_cert(rec)] computed by the caller OUTSIDE
    _db_lock. Without it this RAISES before any read, normalize or verify
    (Examiner/Cipher a8e70392, Bulwark N1): there is no inline fallback."""
    if prenormalized is None:
        raise PrenormalizedRequired("consider_rotation needs prenormalized "
                                    "certs computed outside _db_lock")
    result = ingest_rotation_round(conn, [rec], sender_pub,
                                   prenormalized=prenormalized)
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

def path_accept_rule(conn, name, path, prenormalized=None) -> list | None:
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
    for i, raw in enumerate(path):
        # The caller (core.pull_name_chain) charges and normalizes OUTSIDE
        # _db_lock and passes the results in.
        # No inline fallback (never _norm_cert under _db_lock).
        if prenormalized is None:
            raise PrenormalizedRequired("path_accept_rule needs prenormalized certs")
        rec = prenormalized[i]
        if rec is None or rec["name"] != name:
            return None
        recs.append(rec)
    if not _links_tip(recs[0], pin, head) or recs[0]["old_pubkey"] != pin:
        return None
    if recs[0]["seq"] != seq + 1:
        return None
    for a, b in zip(recs, recs[1:]):
        if (b["prev_hash"] != a["cert_hash"] or b["old_pubkey"] != a["new_pubkey"]
                or b["seq"] != a["seq"] + 1):
            return None
    return recs


def accept_catchup(conn, name, path, sender_pub=None,
                   now: float | None = None, prenormalized=None) -> str:
    """Apply a fetched path whole. Then re-judge pending certs that now
    link. Returns 'accepted', 'refused', 'contested', or 'rate-held'."""
    if prenormalized is None:
        # Examiner/Cipher a8e70392: no inline fallback. Raise before any
        # read, normalize or verify.
        raise PrenormalizedRequired("accept_catchup needs prenormalized "
                                    "certs computed outside _db_lock")
    ensure_schema(conn)
    now = time.time() if now is None else now
    if is_contested(conn, name):
        return "contested"
    if len(prenormalized) != len(path):
        return "refused"
    recs = path_accept_rule(conn, name, path, prenormalized)
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
    # A caught-up path is one gated event: the name moved in this round.
    # Evidence, chain, log and slot are one SAVEPOINT, as in _accept_hop.
    conn.execute("SAVEPOINT accept_path")
    try:
        for rec in recs:
            _store_fork(conn, rec)
            _append_rotation(conn, rec)
        _note_round(conn, name, rnd)
    except sqlite3.Error:
        conn.execute("ROLLBACK TO SAVEPOINT accept_path")
        conn.execute("RELEASE SAVEPOINT accept_path")
        return "refused"
    conn.execute("RELEASE SAVEPOINT accept_path")
    conn.execute("DELETE FROM name_pending WHERE name=? AND cert_hash IN (%s)"
                 % ",".join("?" * len(recs)),
                 (name, *[r["cert_hash"] for r in recs]))
    return "accepted"


def pending_rows(conn, name) -> list:
    """(id, cert dict, sender) for a name's pending certs, oldest first."""
    return [(rid, json.loads(cert), sender) for rid, cert, sender in conn.execute(
        "SELECT id, cert, sender FROM name_pending WHERE name=? ORDER BY id",
        (name,)).fetchall()]


def drain_pending(conn, name, sender_pub=None, now=None,
                  prenormalized: dict | None = None) -> dict:
    """Re-judge pending certs for a name after its head moved.
    prenormalized: {pending id: normalized rec or None}, computed by the
    caller outside _db_lock; ids not in it are skipped (never normalized
    under the lock)."""
    rows = pending_rows(conn, name)
    res = {"accepted": {}, "contested": set(), "outcomes": []}
    for rid, c, sender in rows:
        h = head_hash(conn, name)
        if c.get("prev_hash") != h:
            continue
        if prenormalized is None or rid not in prenormalized:
            continue   # never normalized under the lock
        conn.execute("DELETE FROM name_pending WHERE id=?", (rid,))
        r = ingest_rotation_round(conn, [c], sender, now=now,
                                  prenormalized=[prenormalized[rid]])
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


# ------------------------------------------------- catch-up paging (board)

PIN_SETTLE_DEFAULT = 7 * 24 * 3600   # = core.SETTLE_DAYS
CATCHUP_PAGE = 32           # certs per catch-up page, charged on its own
LATE_FORK_PER_NAME = 8      # late fork evidence rows per name
LATE_FORK_PER_SENDER = 32   # late fork evidence rows per sending peer


def _links_tip(c, pin, head) -> bool:
    """A page links to the committed pin only when its first prev_hash IS
    the cert_hash at the tip. Comparing the key is not enough (A->B->A).
    The belt's key-compare mutant returns old_pubkey == pin."""
    return isinstance(c, dict) and str(c.get("prev_hash", "")) == head


def _committed_seq(conn, name, h):
    """seq of a committed cert (or the pin anchor) of the current
    generation with head_hash h; None if h is not committed. One indexed
    point lookup: constant cost."""
    gen = conn.execute(
        "SELECT MAX(id) FROM name_pin_log WHERE name=? AND kind IN ('pin','unpin')",
        (name,)).fetchone()[0]
    row = conn.execute(
        "SELECT seq FROM name_pin_log WHERE name=? AND id>=? AND head_hash=?"
        " AND kind IN ('pin','rotate') LIMIT 1", (name, gen or 0, h)).fetchone()
    return None if row is None else int(row[0])


def classify_page(conn, name, page) -> str:
    """Before any parse: 'tip' (first prev_hash == tip cert_hash), 'fork'
    (first prev_hash == a committed cert other than the tip), else 'junk'.
    Reads only; stores nothing."""
    st = current_state(conn, name)
    if st is None or not page or not isinstance(page[0], dict):
        return "junk"
    pin, seq, head = st
    if _links_tip(page[0], pin, head):
        return "tip"
    if _committed_seq(conn, name, str(page[0].get("prev_hash", ""))) is not None:
        return "fork"
    return "junk"


def catchup_start(conn, name, certs) -> int:
    """Where a served chain leaves this node's committed chain: the cert
    whose prev_hash is the tip, else the last cert whose prev_hash is a
    committed cert (a fork point). -1 when none links."""
    st = current_state(conn, name)
    if st is None:
        return -1
    best = -1
    for i, c in enumerate(certs):
        if not isinstance(c, dict):
            break
        if _links_tip(c, st[0], st[2]):
            return i
        if _committed_seq(conn, name, str(c.get("prev_hash", ""))) is None:
            break
        best = i
    return best


def settle_seconds() -> int:
    """The pin's cosign/settle window: a fork may contest the name only
    while the current pin is younger than this. Default SETTLE_DAYS (7),
    the node's existing settle period (core.SETTLE_DAYS)."""
    raw = os.environ.get("CYBERNET_NAME_PIN_SETTLE_SEC")
    try:
        return max(1, int(raw)) if raw else PIN_SETTLE_DEFAULT
    except ValueError:
        return PIN_SETTLE_DEFAULT


def _tip_recorded_ts(conn, name):
    row = conn.execute(
        "SELECT recorded_at FROM name_pin_log WHERE name=? AND kind IN"
        " ('pin','rotate','unpin') ORDER BY id DESC LIMIT 1", (name,)).fetchone()
    try:
        return datetime.fromisoformat(row[0]).timestamp() if row else None
    except (TypeError, ValueError):
        return None


def fork_window_open(conn, name, rec, now) -> bool:
    """True while the current pin's settle window is open. The belt's
    mutant drops this and keeps only a key-current-at-fork-seq check."""
    t = _tip_recorded_ts(conn, name)
    return t is not None and now < t + settle_seconds()


def _keep_late_fork(conn, rec, sender, now=None) -> str:
    """Late fork: evidence only, once per cert, capped per name and per
    sender. Owner-readable on GET /api/v1/names/{name}/rotations."""
    if conn.execute("SELECT 1 FROM name_fork_late WHERE cert_hash=?",
                    (rec["cert_hash"],)).fetchone():
        return "late-fork-duplicate"
    n_name = conn.execute("SELECT COUNT(*) FROM name_fork_late WHERE name=?",
                          (rec["name"],)).fetchone()[0]
    n_send = conn.execute("SELECT COUNT(*) FROM name_fork_late WHERE sender=?",
                          (sender,)).fetchone()[0]
    if n_name >= LATE_FORK_PER_NAME or n_send >= LATE_FORK_PER_SENDER:
        return "late-fork-full"
    conn.execute(
        "INSERT INTO name_fork_late (name, sender, prev_hash, seq, new_pubkey,"
        " cert_hash, cert, recorded_at) VALUES (?,?,?,?,?,?,?,?)",
        (rec["name"], sender, rec["prev_hash"], rec["seq"], rec["new_pubkey"],
         rec["cert_hash"], json.dumps(_wire(rec), sort_keys=True), _now()))
    return "late-fork"


def late_forks(conn, name) -> list:
    ensure_schema(conn)
    return [{"seq": r[0], "prev_hash": r[1], "new_pubkey": r[2],
             "cert_hash": r[3], "sender": r[4], "recorded_at": r[5],
             "cert": json.loads(r[6])} for r in conn.execute(
        "SELECT seq, prev_hash, new_pubkey, cert_hash, sender, recorded_at, cert"
        " FROM name_fork_late WHERE name=? ORDER BY id", (name,)).fetchall()]
