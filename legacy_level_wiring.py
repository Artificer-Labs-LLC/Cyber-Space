"""Wiring cut (ART-42): legacy_log_observe through head_level.

Locked in the Research Board room. A CLEAR on efe3ab1 covers head_level
only; this module is the wiring and carries its own rows
(test_wok_wiring.py, plus the FC-S scan in test_wok_level.py).

Pipeline for one observe, in this order. Nothing is written until every
check has passed (Bulwark gate row):

  1. verify_legacy: signatures pre-check (cap, malformed, unpinned,
     duplicate witness; typed, 0 verifies), then lw.verify_head (one verify
     per witness). Runs in the route's verify phase, off the DB lock.
  2. level encoding shape (MalformedLevel).
  3. proven marks for the log are rebuilt from the mark table only, by
     replaying the stored heads through hl.root_mark / hl.advance_mark, so
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
  7. consistency (Bulwark rule 3): a non-root head carries an RFC 9162
     consistency proof from its proven prev mark to its own root.
  8. (checked first, before any replay) a contested log is refused.
     A head below the latest mark is stale; replay
     is a no-op; a second threshold head at a stored (log_id, seq) with
     another head_hash is a fork: exactly one contested record, every mark
     for the log removed, nothing stored for the second head (fork row).
  9. a new seq must chain from the LATEST proven mark (or be the root
     head of a log with no mark). Then: one observed row, one mark row.

There is no refusal cache of any kind (a609764 F-B2): a refused encoding
is forgotten, so a clean encoding of the same head is judged on its own.
"""
from __future__ import annotations

import hashlib
import json
import time

import head_level as hl
import legacy_witness as lw

MAX_LEVEL_BLOB = max(len(t) for t in hl.TAGS.values()) + hl.BODY.size
MAX_CONSISTENCY = 64
PROOF_ROOT = "root"
PROOF_CONSISTENCY = "consistency"

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


ConsistencyRefused = hl.ConsistencyRefused


class MarkNotRootProven(hl.Refused):
    """A stored mark that does not replay back to a root-verified head."""


class NotFromLatestMark(hl.Refused):
    """A new head that does not chain from the latest proven mark."""


class StaleHead(hl.Refused):
    """Bulwark 8360b0c8 item 2: seq below the latest proven mark."""


class LogContested(hl.Refused):
    """The log has a contested (forked) seq; no mark moves until ruled."""


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


def proven_marks(conn, log_id: str, genesis_pub: str, pins, sig_ok) -> list:
    """Every stored mark for the log as hl.VerifiedMark, replayed from the
    root: the lowest row through hl.root_mark, each later row through
    hl.advance_mark from the one below it. Any refusal, or a replayed mark
    that differs from the stored (tree_size, root), refuses the whole set
    (MarkNotRootProven). Reads the mark table only."""
    rows = [tuple(r) for r in _mark_rows(conn, log_id)]
    key = (genesis_pub, repr(pins), sig_ok)
    hit = _MARK_CACHE.get(log_id)
    out, prev, start = [], None, 0
    if hit is not None and hit[0] == key and rows[:len(hit[1])] == hit[1]:
        out, start = list(hit[2]), len(hit[1])      # same stored bytes already replayed
        prev = out[-1] if out else None
    for size, root, kind, blob, gsig, cosigns, proof in rows[start:]:
        try:
            b = bytes.fromhex(blob)
            cs = json.loads(cosigns)
            path = [bytes.fromhex(p) for p in json.loads(proof)]
            if prev is None:
                if kind != PROOF_ROOT or path:
                    raise MarkNotRootProven("lowest stored mark is not a root-verified head")
                _, m = hl.root_mark(b, gsig, genesis_pub, cs, pins, sig_ok)
            else:
                if kind != PROOF_CONSISTENCY:
                    raise MarkNotRootProven("stored mark above the root is not a consistency step")
                _, m = hl.advance_mark(prev, b, gsig, genesis_pub, cs, pins, sig_ok, path)
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


# ---- observe ------------------------------------------------------------

def _level_shape(level):
    if not isinstance(level, dict) or set(level) != {"blob", "genesis_sig", "cosigns", "consistency"}:
        raise MalformedLevel("level must be {blob, genesis_sig, cosigns, consistency}")
    blob, gsig, cons = level["blob"], level["genesis_sig"], level["consistency"]
    if not isinstance(blob, str) or len(blob) > 2 * MAX_LEVEL_BLOB or not isinstance(gsig, str) \
            or len(gsig) != 128 or not isinstance(cons, list) or len(cons) > MAX_CONSISTENCY \
            or not all(isinstance(c, str) and len(c) == 64 for c in cons):
        raise MalformedLevel("level field shape")
    try:
        bytes.fromhex(gsig)
        return bytes.fromhex(blob), [bytes.fromhex(c) for c in cons]
    except ValueError:
        raise MalformedLevel("level field is not hex") from None


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


def observe(conn, vhead, level, genesis_pub, pins, sig_ok, now=None) -> dict:
    if not isinstance(vhead, VerifiedLegacyHead):
        raise TypeError("observe takes a VerifiedLegacyHead")
    h = vhead.head
    log_id, seq, head_hash = h["log_id"], h["seq"], h["head_hash"]
    init_schema(conn)
    blob, path = _level_shape(level)
    if not isinstance(genesis_pub, str) or len(genesis_pub) != 64 \
            or hl.log_id_of(genesis_pub).hex() != log_id:
        raise LevelNotBound("pinned log_id is not SHA-256 of the pinned Genesis key")
    if conn.execute("SELECT 1 FROM legacy_contested_heads WHERE log_id=?", (log_id,)).fetchone():
        raise LogContested("log has a contested seq; no mark moves until ruled")
    marks = proven_marks(conn, log_id, genesis_pub, pins, sig_ok)   # before cheap_head runs
    claimed = _claimed_prev(blob)
    vmark = None
    if claimed != (0, hl.ZERO32):
        vmark = next((m for m in marks if (m.size, m.root) == claimed), None)
    if vmark is None:                       # cheap_head: FirstContactRefused unless the root
        level_name, new_mark = hl.root_mark(blob, level["genesis_sig"], genesis_pub,
                                            level["cosigns"], pins, sig_ok)
        if path:
            raise ConsistencyRefused("a root head carries no consistency proof")
    else:
        level_name, new_mark = hl.advance_mark(vmark, blob, level["genesis_sig"], genesis_pub,
                                               level["cosigns"], pins, sig_ok, path)
    if new_mark.size != seq:
        raise MappingMismatch("legacy seq is not head_level tree_size")
    if new_mark.root.hex() != head_hash:
        raise MappingMismatch("legacy head_hash is not head_level root")
    # ---- every check passed; decide, then write ----
    now = int(time.time()) if now is None else now
    latest = marks[-1] if marks else None
    if latest is not None and seq < latest.size:
        raise StaleHead("head seq is below the latest proven mark")
    stored = [r[0] for r in conn.execute(
        "SELECT head_hash FROM legacy_observed_heads WHERE log_id=? AND seq=? ORDER BY seen_at, head_hash",
        (log_id, seq)).fetchall()]
    if head_hash in stored:
        return {"status": "already-observed", "log_id": log_id, "seq": seq}
    if stored:
        _mark_contested(conn, log_id, seq, stored[0], head_hash, now)
        conn.execute("DELETE FROM legacy_level_marks WHERE log_id=?", (log_id,))
        return {"status": "contested", "log_id": log_id, "seq": seq}
    if vmark != latest:
        raise NotFromLatestMark("head does not chain from the latest proven mark")
    conn.execute("INSERT INTO legacy_observed_heads (log_id, seq, head_hash, seen_at) VALUES (?,?,?,?)",
                 (log_id, seq, head_hash, now))
    conn.execute(
        "INSERT INTO legacy_level_marks (log_id, tree_size, root, proof_kind, blob, genesis_sig,"
        " cosigns, proof, set_at) VALUES (?,?,?,?,?,?,?,?,?)",
        (log_id, new_mark.size, new_mark.root.hex(), PROOF_ROOT if vmark is None else PROOF_CONSISTENCY,
         level["blob"], level["genesis_sig"], json.dumps(hl.normalize_cosigns(level["cosigns"])),
         json.dumps([p.hex() for p in path]), now))
    return {"status": "observed", "log_id": log_id, "seq": seq, "level": level_name}
