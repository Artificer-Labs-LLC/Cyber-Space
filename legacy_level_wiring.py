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

OPEN for Villhaze (current behaviour kept, not decided here):
  1. Tampered DB vs trusted marks: MARK_VERIFIER = replay_marks re-verifies
     every stored mark from the root (defends against a tampered mark
     table); Loom's alternative trusts the stored marks (or a per-mark
     verified flag). Replay stays the default until she rules.
  2. NoGrowthRootChange (same tree_size, different root): refused in
     hl.cheap_head before any verify and leaves NO record (no observed row,
     no contested row). Whether it should leave evidence is open.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import time

import head_level as hl
import legacy_witness as lw

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
)


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


def precheck_signatures(signed, wset) -> None:
    """Typed refusals before lw.verify_head runs: 0 verifies, 0 key checks."""
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
        if w in seen:
            raise DuplicateWitness("at most one signature per witness")
        seen.add(w)


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


def _read_state(conn, log_id, seq) -> dict:
    """Everything observe needs from the DB, in one short read."""
    init_schema(conn)
    return {"rows": [tuple(r) for r in _mark_rows(conn, log_id)],
            "contested": conn.execute("SELECT 1 FROM legacy_contested_heads WHERE log_id=?",
                                      (log_id,)).fetchone() is not None,
            "stored": [r[0] for r in conn.execute(
                "SELECT head_hash FROM legacy_observed_heads WHERE log_id=? AND seq=? ORDER BY seen_at, head_hash",
                (log_id, seq)).fetchall()]}


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
    if vmark is None:                       # cheap_head: FirstContactRefused unless the root
        hl.cheap_head(blob, hl.log_id_of(genesis_pub), None)    # FirstContactRefused first, no verify
        if ext:
            raise ExtensionRefused("a root head carries no chain extension")
        level_name, new_mark = hl.root_mark(blob, level["genesis_sig"], genesis_pub,
                                            level["cosigns"], pins, sig_ok)
    else:
        level_name, new_mark = hl.extend_mark(vmark, blob, level["genesis_sig"], genesis_pub,
                                              level["cosigns"], pins, sig_ok, ext)
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
