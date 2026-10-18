"""Wiring cut (ART-42): legacy_log_observe through head_level.

Locked in the Research Board room. A CLEAR on efe3ab1 covers head_level
only; this module is the wiring and carries its own rows
(test_wok_wiring.py, plus the FC-S scan in test_wok_level.py).

Pipeline for one observe, in this order. Nothing is written until every
check has passed (Bulwark gate row):

  1. verify_legacy: signatures pre-check (cap, malformed, unpinned,
     duplicate witness; typed, 0 verifies), then lw.verify_head (one verify
     per witness). Runs in the route's verify phase, off the DB lock.
  2. level encoding shape (MalformedLevel), incl. the extension transport
     field: at most lw.MAX_EXTENSION skeletons under lw.MAX_EXTENSION_BYTES
     (Villhaze a73a009e). The route runs this before step 1 as well, so a
     capped or oversized body costs 0 hashes and 0 verifies.
  3. proven marks for the log are rebuilt from the mark table only, by
     replaying the stored heads through hl.root_mark / hl.extend_mark, so
     every mark is an hl.VerifiedMark (Examiner row; Bulwark rule 3 and
     item 3). A broken chain is MarkNotRootProven, raised before the new
     head reaches cheap_head.
  4. the mark handed to head_level is the proven mark the head claims as
     its prev, or None when the head claims the root. An observed row is
     never a mark (Lodestar seeding rows): with no proven mark, a head
     claiming a nonzero prev hits FirstContactRefused in cheap_head.
  5. hl.verify_head (all typed refusals, incl. MalformedCosign and
     DuplicateCosign, before any write).
  6. mapping (Lodestar): legacy seq == tree_size, head_hash == root.
  7. extension (Bulwark rule 3; Villhaze ART-42 7e9eb9b5 (b)): a legacy
     head_hash is a hash-chain tip (entry_hash at seq), not an RFC 9162
     root, so a non-root head carries the header skeletons prev+1..seq,
     each linked by prev_hash back to its proven prev mark's tip and ending
     at its own head_hash (hl.extend_mark / lw.verify_extension). The RFC
     9162 path (hl.advance_mark) is not used for legacy logs.
  8. (checked first, before any replay) a contested log is refused.
     Then, in this order (Lodestar b5334563, Villhaze 0ff5838c): a head at
     a STORED (log_id, seq) with the stored head_hash is a no-op; with
     another head_hash it is a fork, whatever the latest mark: exactly one
     contested record, every mark for the log removed, nothing stored for
     the second head. Only a head below the latest mark at an UNSTORED seq
     is StaleHead.
  9. a new seq must chain from the LATEST proven mark (or be the root
     head of a log with no mark). Then: one observed row, one mark row.

There is no refusal cache of any kind (a609764 F-B2): a refused encoding
is forgotten, so a clean encoding of the same head is judged on its own.

Locking (Bulwark 8078a11 BLOCK #1). observe_split(open_conn, ...) never
verifies a signature while holding the DB lock: it reads the mark rows, the
contested flag and the stored hashes at this seq under one short lock,
proves the marks and verifies the new head OFF the lock, then re-takes the
lock and writes only if the mark rows are byte-identical to what it read
(otherwise MarksChanged, nothing written; the caller may retry). How stored
rows become VerifiedMarks is MARK_VERIFIER: Bulwark's replay from the root
is the default; Loom's alternative (trust stored marks, or a per-mark
verified flag) can replace it there once Villhaze rules, without touching
observe. Before any verify, a contested log is refused and a head whose
head_hash is already stored at its seq is a no-op (Bulwark #2); after an
insert the replay cache is extended with the new row, so the next observe
does not replay it.

Tampered-database (Villhaze ART-42 ec88c2fe (a)): MARK_VERIFIER =
replay_marks stays the default — stored marks are re-checked from the root,
never trusted as stored. Loom's trust variant is rejected for this cut.

NoGrowthRootChange (Villhaze ART-42 ec88c2fe (b)): refused in hl.cheap_head
before any verify, AND recorded as refused-heads evidence (presented
head_hash, claimed size, presenter identity, time, stored head contested).
Append-only; read-only to consumers; NEVER feeds marks, levels, or
verification — evidence about an attempt, not trust in it.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import time

import head_level as hl
import legacy_witness as lw
from fed import ed25519 as _ed

MAX_LEVEL_BLOB = max(len(t) for t in hl.TAGS.values()) + hl.BODY.size
PROOF_ROOT = "root"
PROOF_CHAIN = "chain"

SCHEMA = (
    """CREATE TABLE IF NOT EXISTS legacy_observed_heads (
        log_id TEXT NOT NULL,
        seq INTEGER NOT NULL,
        head_hash TEXT NOT NULL,
        seen_at INTEGER NOT NULL,
        PRIMARY KEY (log_id, seq, head_hash))""",
    """CREATE TABLE IF NOT EXISTS legacy_level_marks (
        log_id TEXT NOT NULL,
        tree_size INTEGER NOT NULL,
        root TEXT NOT NULL,
        proof_kind TEXT NOT NULL,
        blob TEXT NOT NULL,
        genesis_sig TEXT NOT NULL,
        cosigns TEXT NOT NULL,
        proof TEXT NOT NULL,
        set_at INTEGER NOT NULL,
        PRIMARY KEY (log_id, tree_size))""",
    """CREATE TABLE IF NOT EXISTS legacy_contested_heads (
        log_id TEXT NOT NULL,
        seq INTEGER NOT NULL,
        head_hash_a TEXT NOT NULL,
        head_hash_b TEXT NOT NULL,
        seen_at INTEGER NOT NULL,
        PRIMARY KEY (log_id, seq))""",
    # Append-only refused-heads evidence (Villhaze ART-42 ec88c2fe (b)).
    # Never read by observe for marks/levels/verification — write on
    # NoGrowthRootChange only; consumers may read via /witnessed.
    """CREATE TABLE IF NOT EXISTS legacy_refused_heads (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        log_id TEXT NOT NULL,
        presented_head_hash TEXT NOT NULL,
        claimed_size INTEGER NOT NULL,
        presenter TEXT NOT NULL,
        seen_at INTEGER NOT NULL,
        contested_head_hash TEXT NOT NULL,
        reason TEXT NOT NULL)""",
    # Bulwark v2: no UNIQUE index on legacy_refused_heads. Dedupe is the
    # re-check under the decision lock (core._db_lock), so an existing DB
    # that already holds duplicate rows still opens (no migration step).
    # Bulwark v2 (ART-42, 1b2ecf8c): ONE fixed-size row per log, never keyed
    # by presenter. overflow = verified forks after the first
    # MAX_REFUSED_PER_LOG rows (keep-first: they are counted, not stored);
    # unverified = NoGrowthRootChange attempts refused by the evidence gate.
    """CREATE TABLE IF NOT EXISTS legacy_refused_counts (
        log_id TEXT PRIMARY KEY,
        overflow INTEGER NOT NULL DEFAULT 0,
        unverified INTEGER NOT NULL DEFAULT 0,
        last_seen INTEGER NOT NULL)""",
)

# Bulwark v2 (ART-42, 1b2ecf8c): keep the FIRST N verified forks per log;
# later verified forks only increment legacy_refused_counts.overflow.
MAX_REFUSED_PER_LOG = 64


class MalformedLevel(hl.Refused):
    """The level part of an observe body is not the fixed shape."""


class LevelNotBound(hl.Refused):
    """The pinned legacy log_id is not SHA-256 of the pinned Genesis pub."""


class MappingMismatch(hl.Refused):
    """Legacy (seq, head_hash) is not head_level's (tree_size, root)."""


ExtensionRefused = hl.ExtensionRefused


class MarkNotRootProven(hl.Refused):
    """A stored mark that does not replay back to a root-verified head."""


class NotFromLatestMark(hl.Refused):
    """A new head that does not chain from the latest proven mark."""


class StaleHead(hl.Refused):
    """Bulwark 8360b0c8 item 2: seq below the latest proven mark, at a seq
    with no stored head (a stored seq is a no-op or a fork)."""


class LogContested(hl.Refused):
    """The log has a contested (forked) seq; no mark moves until ruled."""


class MarksChanged(hl.Refused):
    """The stored marks changed between the read and the write (another
    observe wrote first); nothing written, retry."""


# ---- legacy signatures pre-check (Bulwark/Cipher 8360b0c8 item 1) -------

class TooManyWitnessSigs(lw.WitnessRefused):
    """Backstop: more signature entries than pinned witnesses."""


class MalformedWitnessSig(lw.WitnessRefused):
    """A signatures entry that is not {witness: 64 hex, sig: str}."""


class UnpinnedWitness(lw.WitnessRefused):
    """A signatures entry whose (lowercased) witness is not pinned."""


class DuplicateWitness(lw.WitnessRefused):
    """Two signatures entries for one (lowercased) witness."""


class WeakWitnessSig(lw.WitnessRefused):
    """BW-PV2: a signature or witness key that no strict verifier accepts:
    S >= L, R or A non-canonical, R or A small-order. Refused before the
    pre-verify charge, with 0 verifies (decode + 3 doublings, no scalar mult)."""


def witness_dedupe_key(w: str, sig: str):
    """BW-PV2: the one place the per-witness dedupe key is chosen. Keyed on
    the witness key ONLY (chair-confirmed): a second, distinct signature
    from a witness already in the request is refused, not verified."""
    return w


def strict_encoding_reason(w: str, sig: str) -> str | None:
    """BW-PV2 cheap strictness precheck, reusing fed.ed25519's own strict
    helpers (no re-implementation). None when (A, R, S) can reach a verify."""
    if lw.HEX128_RE.fullmatch(sig) is None:     # same shape checkvalid_ok demands
        return "sig must be 128 lowercase hex chars"
    raw = bytes.fromhex(sig)
    if int.from_bytes(raw[32:], "little") >= _ed._L:
        return "S >= L"
    for name, enc in (("R", raw[:32]), ("A", bytes.fromhex(w))):
        try:
            P = _ed._decodepoint_strict(enc)
        except ValueError:
            return f"{name} non-canonical"
        if _ed._is_small_order(P):
            return f"{name} small-order"
    return None


def precheck_signatures(signed, wset) -> None:
    """Typed refusals before lw.verify_head runs: 0 verifies, 0 key checks.
    BW-PV2 order per entry: shape, witness-set membership, key-only dedupe,
    strict encoding of (A, R, S). The route charges the per-source verify
    budget only after this returns."""
    if not isinstance(signed, dict) or not isinstance(signed.get("head"), dict) \
            or not isinstance(signed.get("signatures"), list):
        raise lw.WitnessRefused("malformed head")
    seq = signed["head"].get("seq")
    if type(seq) is not int or seq < 1:
        raise lw.WitnessRefused("bad head field")
    pubs = set(lw.as_schedule(wset).for_seq(seq).pubs)
    sigs = signed["signatures"]
    if len(sigs) > len(pubs):
        raise TooManyWitnessSigs("more signatures than pinned witnesses")
    seen = set()
    for e in sigs:
        if not isinstance(e, dict) or not isinstance(e.get("witness"), str) \
                or not isinstance(e.get("sig"), str):
            raise MalformedWitnessSig("signatures entry must be {witness: str, sig: str}")
        w = e["witness"].lower()                  # normalize at admission (ART-37 4b97c85b)
        if lw.HEX64_RE.fullmatch(w) is None:      # strict check on the normalized value
            raise MalformedWitnessSig("witness pub must be 64 hex chars")
        if w not in pubs:
            raise UnpinnedWitness("signature from a witness this node does not pin")
        pub = w
        w = witness_dedupe_key(pub, e["sig"])     # BW-PV2: key-only (chair); swap point
        if w in seen:
            raise DuplicateWitness("at most one signature per witness")
        seen.add(w)
        why = strict_encoding_reason(pub, e["sig"])
        if why is not None:
            raise WeakWitnessSig(f"witness signature refused before verify: {why}")


class VerifiedLegacyHead:
    """Only verify_legacy() builds one; observe() takes nothing else."""
    __slots__ = ("head",)
    _token = object()

    def __init__(self, head, _t=None):
        if _t is not VerifiedLegacyHead._token:
            raise TypeError("VerifiedLegacyHead comes from verify_legacy only")
        self.head = dict(head)


def verify_legacy(signed, wset, pinned_log, sig_ok=None) -> VerifiedLegacyHead:
    precheck_signatures(signed, wset)
    return VerifiedLegacyHead(lw.verify_head(signed, wset, pinned_log, sig_ok=sig_ok),
                              VerifiedLegacyHead._token)


def init_schema(conn) -> None:
    for s in SCHEMA:
        conn.execute(s)


# ---- marks: rebuilt ONLY by replaying stored heads (mark build site) ----

def _mark_rows(conn, log_id: str):
    return conn.execute(
        "SELECT tree_size, root, proof_kind, blob, genesis_sig, cosigns, proof"
        " FROM legacy_level_marks WHERE log_id=? ORDER BY tree_size", (log_id,)).fetchall()


# Replay cache: log_id -> (inputs, stored rows, VerifiedMarks). Positive
# only, keyed on the exact stored row bytes: a changed or forged row is a
# miss and replays from that row. Never caches a refusal.
_MARK_CACHE: dict = {}


def _cache_key(genesis_pub, pins, sig_ok):
    return (genesis_pub, repr(pins), sig_ok)


def replay_marks(rows, log_id: str, genesis_pub: str, pins, sig_ok) -> list:
    """Bulwark's mark verifier (the default MARK_VERIFIER): every stored mark
    row for the log as hl.VerifiedMark, replayed from the root: the lowest
    row through hl.root_mark, each later row through hl.extend_mark
    (re-verifying its stored skeletons) from the one below it. Any refusal,
    or a replayed mark that differs from the stored (tree_size, root),
    refuses the whole set (MarkNotRootProven). Pure: takes the rows, holds
    no lock, reads nothing."""
    rows = [tuple(r) for r in rows]
    key = _cache_key(genesis_pub, pins, sig_ok)
    hit = _MARK_CACHE.get(log_id)
    out, prev, start = [], None, 0
    if hit is not None and hit[0] == key and rows[:len(hit[1])] == hit[1]:
        out, start = list(hit[2]), len(hit[1])      # same stored bytes already replayed
        prev = out[-1] if out else None
    for size, root, kind, blob, gsig, cosigns, proof in rows[start:]:
        try:
            b = bytes.fromhex(blob)
            cs = json.loads(cosigns)
            ext = json.loads(proof)
            if prev is None:
                if kind != PROOF_ROOT or ext != []:
                    raise MarkNotRootProven("lowest stored mark is not a root-verified head")
                _, m = hl.root_mark(b, gsig, genesis_pub, cs, pins, sig_ok)
            else:
                if kind != PROOF_CHAIN:
                    raise MarkNotRootProven("stored mark above the root is not a chain-extension step")
                _, m = hl.extend_mark(prev, b, gsig, genesis_pub, cs, pins, sig_ok, ext)
        except MarkNotRootProven:
            raise
        except (hl.Refused, ValueError, TypeError, KeyError, AttributeError):
            raise MarkNotRootProven("stored mark does not replay back to the root") from None
        if (m.size, m.root.hex()) != (size, root):
            raise MarkNotRootProven("replayed mark differs from the stored row")
        prev = m
        out.append(m)
    _MARK_CACHE[log_id] = (key, rows, tuple(out))
    return out


def _remember(log_id, genesis_pub, pins, sig_ok, rows, marks) -> None:
    """Bulwark #2: after an insert, the cache holds the rows as now stored and
    their marks, so the next observe replays nothing it already proved."""
    _MARK_CACHE[log_id] = (_cache_key(genesis_pub, pins, sig_ok), [tuple(r) for r in rows], tuple(marks))


# The mark-verification policy: rows -> [hl.VerifiedMark]. Runs off the DB
# lock. Bulwark (default, safe): replay_marks. Loom's alternative (trust the
# stored marks, or a per-mark verified flag) goes here if Villhaze picks it.
MARK_VERIFIER = replay_marks


def proven_marks(conn, log_id: str, genesis_pub: str, pins, sig_ok) -> list:
    """Every stored mark for the log as hl.VerifiedMark (MARK_VERIFIER over
    the mark table). Reads the mark table only."""
    return MARK_VERIFIER(_mark_rows(conn, log_id), log_id, genesis_pub, pins, sig_ok)


# ---- observe ------------------------------------------------------------

def _level_shape(level):
    if not isinstance(level, dict) or set(level) != {"blob", "genesis_sig", "cosigns", "extension"}:
        raise MalformedLevel("level must be {blob, genesis_sig, cosigns, extension}")
    blob, gsig, ext = level["blob"], level["genesis_sig"], level["extension"]
    if not isinstance(blob, str) or len(blob) > 2 * MAX_LEVEL_BLOB or not isinstance(gsig, str) \
            or len(gsig) != 128 or not isinstance(ext, list):
        raise MalformedLevel("level field shape")
    if len(ext) > lw.MAX_EXTENSION:                       # Villhaze a73a009e: 256 per proof
        raise MalformedLevel("extension over the per-proof skeleton cap")
    if not all(isinstance(e, dict) for e in ext):
        raise MalformedLevel("extension entries must be objects")
    if len(json.dumps(ext).encode()) > lw.MAX_EXTENSION_BYTES:
        raise MalformedLevel("extension over its byte cap")
    try:
        bytes.fromhex(gsig)
        return bytes.fromhex(blob), ext
    except ValueError:
        raise MalformedLevel("level field is not hex") from None


def precheck_level(level) -> None:
    """The level transport shape and caps, run by the route before any
    witness verify (0 hashes, 0 verifies on a refusal)."""
    _level_shape(level)


def _claimed_prev(blob: bytes):
    """prev_size/prev_root as the head claims them, only to pick which
    VerifiedMark (if any) cheap_head is handed. cheap_head re-checks."""
    for tag in hl.TAGS.values():
        if blob.startswith(tag):
            body = blob[len(tag):]
            if len(body) == hl.BODY.size:
                f = hl.BODY.unpack(body)
                return f[4], f[5]
    raise hl.Refused("unknown head tag or body length")


def _mark_contested(conn, log_id, seq, hash_a, hash_b, now):
    conn.execute("INSERT OR IGNORE INTO legacy_contested_heads"
                 " (log_id, seq, head_hash_a, head_hash_b, seen_at) VALUES (?,?,?,?,?)",
                 (log_id, seq, hash_a, hash_b, now))


def _record_refused_nogrowth(conn, log_id, presented_head_hash, claimed_size,
                             presenter, contested_head_hash, now):
    """Append-only evidence for a NoGrowthRootChange refusal. Never consulted
    by observe, proven_marks, or any mark/level/verify path."""
    init_schema(conn)
    # Step 5 (1b2ecf8c), under the decision lock: re-dedupe, then keep-first.
    if _refused_seen(conn, log_id, presented_head_hash):
        return                                  # dedupe: already recorded
    n = conn.execute("SELECT COUNT(*) FROM legacy_refused_heads WHERE log_id=?",
                     (log_id,)).fetchone()[0]
    if n >= MAX_REFUSED_PER_LOG:                # keep-first: count, never evict
        _bump_refused_count(conn, log_id, "overflow", now)
        return
    conn.execute(
        "INSERT INTO legacy_refused_heads"
        " (log_id, presented_head_hash, claimed_size, presenter, seen_at,"
        " contested_head_hash, reason) VALUES (?,?,?,?,?,?,?)",
        (log_id, presented_head_hash, claimed_size, presenter, now,
         contested_head_hash, "NoGrowthRootChange"))


def _refused_seen(conn, log_id, presented_head_hash) -> bool:
    return conn.execute("SELECT 1 FROM legacy_refused_heads WHERE log_id=? AND presented_head_hash=?",
                        (log_id, presented_head_hash)).fetchone() is not None


def _bump_refused_count(conn, log_id, col, now) -> None:
    """The one fixed-size per-log record (never keyed by presenter)."""
    assert col in ("overflow", "unverified")
    conn.execute("INSERT INTO legacy_refused_counts (log_id, last_seen) VALUES (?, ?)"
                 " ON CONFLICT(log_id) DO NOTHING", (log_id, now))
    conn.execute(f"UPDATE legacy_refused_counts SET {col} = {col} + 1, last_seen = ?"
                 " WHERE log_id=?", (now, log_id))


def _evidence_consistent(blob, vmark, seq, head_hash) -> bool:
    """Step 1 (1b2ecf8c): the blob parses, maps to the presented legacy head
    (size == seq, root == head_hash), and is the SAME size as the stored,
    proven head with a DIFFERENT root. No hash, no verify."""
    if vmark is None:
        return False
    for tag in hl.TAGS.values():
        if blob.startswith(tag):
            break
    else:
        return False
    body = blob[len(tag):]
    if len(body) != hl.BODY.size:
        return False
    _mode, _lid, size, root, _ps, _pr, _op, _iss = hl.BODY.unpack(body)
    return (size == seq and root.hex() == head_hash
            and size == vmark.size and root != vmark.root)


def _evidence_cosigns_ok(blob, cosigns, pins, sig_ok) -> bool:
    """Step 4 (1b2ecf8c): every pinned cosign verifies; stop at the first
    failure. Unpinned entries are dropped before any verify, as in
    hl.verify_head (pins=None means no pinned cosigners)."""
    try:
        cs = hl.normalize_cosigns(cosigns)
    except hl.Refused:
        return False
    body = blob[blob.index(b"\n") + 1:]
    size = hl.BODY.unpack(body)[2]
    keys = {k: v for k, v in (pins or {"keys": {}})["keys"].items() if v["from"] <= size <= v["to"]}
    msg = hl.COSIGN_PREFIX + body
    for pub, sig in hl.select_cosigns(cs, keys):
        if not sig_ok(pub, msg, sig):
            return False                        # first failure stops the check
    return True


def _nogrowth_evidence_gate(open_conn, vmark, blob, level, genesis_pub, pins, sig_ok,
                            log_id, seq, head_hash, now) -> bool:
    """1b2ecf8c check order, off the lock except two short reads/writes:
    1 consistency, 2 dedupe, 3 genesis_sig, 4 cosigns (first failure stops).
    A refusal at 1/3/4 bumps the one per-log unverified counter; a dedupe
    hit is a no-op. True means: write in the decision lock (step 5)."""
    ok = _evidence_consistent(blob, vmark, seq, head_hash)
    if ok:
        with open_conn() as conn:
            init_schema(conn)
            if _refused_seen(conn, log_id, head_hash):
                return False                    # step 2: no verify for a known fork
        ok = bool(sig_ok(genesis_pub, blob, level["genesis_sig"])) \
            and _evidence_cosigns_ok(blob, level["cosigns"], pins, sig_ok)
    if not ok:
        with open_conn() as conn:
            init_schema(conn)
            _bump_refused_count(conn, log_id, "unverified", now)
    return ok


def _read_state(conn, log_id, seq) -> dict:
    """Everything observe needs from the DB, in one short read."""
    init_schema(conn)
    return {"rows": [tuple(r) for r in _mark_rows(conn, log_id)],
            "contested": conn.execute("SELECT 1 FROM legacy_contested_heads WHERE log_id=?",
                                      (log_id,)).fetchone() is not None,
            "stored": [r[0] for r in conn.execute(
                "SELECT head_hash FROM legacy_observed_heads WHERE log_id=? AND seq=? ORDER BY seen_at, head_hash",
                (log_id, seq)).fetchall()]}



def _verify_level_mark(vmark, blob, ext, level, genesis_pub, pins, sig_ok):
    """Root or chain-extension verify for one observe. Body lines keep the
    historical observe_split indentation so named mutants still match."""
    if vmark is None:                       # cheap_head: FirstContactRefused unless the root
        hl.cheap_head(blob, hl.log_id_of(genesis_pub), None)    # FirstContactRefused first, no verify
        if ext:
            raise ExtensionRefused("a root head carries no chain extension")
        level_name, new_mark = hl.root_mark(blob, level["genesis_sig"], genesis_pub,
                                            level["cosigns"], pins, sig_ok)
    else:
        level_name, new_mark = hl.extend_mark(vmark, blob, level["genesis_sig"], genesis_pub,
                                              level["cosigns"], pins, sig_ok, ext)
    return level_name, new_mark


def observe(conn, vhead, level, genesis_pub, pins, sig_ok, now=None) -> dict:
    """observe_split over one connection the caller already holds."""
    return observe_split(lambda: contextlib.nullcontext(conn), vhead, level, genesis_pub, pins, sig_ok, now)


def observe_split(open_conn, vhead, level, genesis_pub, pins, sig_ok, now=None) -> dict:
    """open_conn() is a context manager yielding a connection under the DB
    lock. It is entered twice, briefly: read, then (after every verify, off
    the lock) re-check and write."""
    if not isinstance(vhead, VerifiedLegacyHead):
        raise TypeError("observe takes a VerifiedLegacyHead")
    h = vhead.head
    log_id, seq, head_hash = h["log_id"], h["seq"], h["head_hash"]
    blob, ext = _level_shape(level)
    if not isinstance(genesis_pub, str) or len(genesis_pub) != 64 \
            or hl.log_id_of(genesis_pub).hex() != log_id:
        raise LevelNotBound("pinned log_id is not SHA-256 of the pinned Genesis key")
    now = int(time.time()) if now is None else now
    with open_conn() as conn:               # short lock: read only, no verify
        state = _read_state(conn, log_id, seq)
    if state["contested"]:
        raise LogContested("log has a contested seq; no mark moves until ruled")
    if head_hash in state["stored"]:        # Bulwark #2: a replay costs no verify
        return {"status": "already-observed", "log_id": log_id, "seq": seq}
    marks = MARK_VERIFIER(state["rows"], log_id, genesis_pub, pins, sig_ok)   # off the lock, before cheap_head
    claimed = _claimed_prev(blob)
    vmark = None
    if claimed != (0, hl.ZERO32):
        vmark = next((m for m in marks if (m.size, m.root) == claimed), None)
    try:
        level_name, new_mark = _verify_level_mark(
            vmark, blob, ext, level, genesis_pub, pins, sig_ok)
    except hl.NoGrowthRootChange:
        # Villhaze ART-42 ec88c2fe (b): refuse AND record evidence. The
        # evidence write never feeds marks/levels/verification.
        contested = (vmark.root.hex() if vmark is not None
                     else claimed[1].hex())
        if not _nogrowth_evidence_gate(open_conn, vmark, blob, level, genesis_pub, pins, sig_ok,
                                       log_id, seq, head_hash, now):
            raise                               # unverified or already recorded: nothing new stored
        with open_conn() as conn:
            _record_refused_nogrowth(conn, log_id, head_hash, seq, genesis_pub,
                                     contested, now)
        raise
    if new_mark.size != seq:
        raise MappingMismatch("legacy seq is not head_level tree_size")
    if new_mark.root.hex() != head_hash:
        raise MappingMismatch("legacy head_hash is not head_level root")
    # ---- every check passed; re-take the lock, re-check, decide, write ----
    with open_conn() as conn:
        fresh = _read_state(conn, log_id, seq)
        if fresh["rows"] != state["rows"]:
            raise MarksChanged("stored marks changed during verification; retry")
        if fresh["contested"]:
            raise LogContested("log has a contested seq; no mark moves until ruled")
        return _decide_and_write(conn, fresh, marks, vmark, new_mark, level, ext, level_name,
                                 log_id, seq, head_hash, genesis_pub, pins, sig_ok, now)


def _decide_and_write(conn, fresh, marks, vmark, new_mark, level, ext, level_name,
                      log_id, seq, head_hash, genesis_pub, pins, sig_ok, now):
    now = int(time.time()) if now is None else now
    latest = marks[-1] if marks else None
    stored = fresh["stored"]
    if head_hash in stored:
        return {"status": "already-observed", "log_id": log_id, "seq": seq}
    if stored:                              # Lodestar b5334563: fork evidence before StaleHead
        _mark_contested(conn, log_id, seq, stored[0], head_hash, now)
        conn.execute("DELETE FROM legacy_level_marks WHERE log_id=?", (log_id,))
        return {"status": "contested", "log_id": log_id, "seq": seq}
    if latest is not None and seq < latest.size:
        raise StaleHead("head seq is below the latest proven mark (unstored seq)")
    if vmark != latest:
        raise NotFromLatestMark("head does not chain from the latest proven mark")
    row = (new_mark.size, new_mark.root.hex(), PROOF_ROOT if vmark is None else PROOF_CHAIN,
           level["blob"], level["genesis_sig"], json.dumps(hl.normalize_cosigns(level["cosigns"])),
           json.dumps(ext))
    conn.execute("INSERT INTO legacy_observed_heads (log_id, seq, head_hash, seen_at) VALUES (?,?,?,?)",
                 (log_id, seq, head_hash, now))
    conn.execute(
        "INSERT INTO legacy_level_marks (log_id, tree_size, root, proof_kind, blob, genesis_sig,"
        " cosigns, proof, set_at) VALUES (?,?,?,?,?,?,?,?,?)", (log_id,) + row + (now,))
    if MARK_VERIFIER is replay_marks:       # Bulwark #2: refresh the cache after the insert
        _remember(log_id, genesis_pub, pins, sig_ok, fresh["rows"] + [row], list(marks) + [new_mark])
    return {"status": "observed", "log_id": log_id, "seq": seq, "level": level_name}
