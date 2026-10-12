"""Witnessed legacy-migration log: entry format, signed head, and the
node-B verifier (ART-20; Loom addendum 4a, Lodestar §11, Villhaze
fcd4a8c7 / db78304f / 5fe976e8).

Node B accepts a legacy identity only against a witness-signed head at or
after window-close, plus the full span [1, head] for that agent. It never
trusts node A: everything below is checked from the bytes alone, against
a witness set and log id that B pins in its own config.

Entry (one per log position). The signed and hashed part is the HEADER:

    cyberspace-legacy-migration-log/v1
    log_id=<64 hex>          # fixed at log creation, independent of any
                             # signing key (Loom Gate 1 #2), so witnesses
                             # can rotate or grow without a new log
    seq=<int>                # position, from 1, no gaps
    prev_hash=<64 hex|none>  # entry_hash of seq-1
    kind=<kind>
    agent_id=<int|none>      # the writer's local id for the account
    agent_prev_seq=<int|none>  # seq of this agent's previous entry (Loom
                             # Gate 1 #1): the per-agent back-link a later
                             # Merkle index needs, frozen into the format now
    name_sha256=<64 hex|none>  # sha256 of the body name (Loom Gate 1 #3):
                             # B sees every hold for a name, even skeletons
    body_sha256=<64 hex>     # sha256 of the BODY below

    entry_hash = sha256(header bytes)

BODY (hashed into the header, so it can be left out without breaking the
chain):

    name=<name|none>
    migration_id=<int|none>
    k0_pub=<64 hex|none>
    detail=<compact sorted JSON>
    logged_at=<unix s>       # the witness's clock; informational except
                             # for the late 24h rule, which the witness signs

Because kind and agent_id sit in the hashed header, a proof can send other
agents' entries as SKELETONS (header fields only) and B still sees every
position, every kind and every agent_id. So a contest for the agent can't
be left out: dropping the entry breaks the chain, and a skeleton still
says "contest". The span for one agent therefore costs O(log length) small
records, with full bodies only for that agent's entries.

Head (signed by the witness set, k-of-n ready; today k=1, the Genesis key):

    cyberspace-legacy-migration-head/v1
    log_id=<64 hex>
    witness_set=<64 hex>     # WitnessSet.id: sha256 of threshold + sorted keys
    seq=<int>                # log size the head commits to
    head_hash=<64 hex>       # entry_hash at seq
    window_open_seq=<int|none>
    window_close_seq=<int|none>
    window_state=<unopened|open|closed>

    {"head": {...fields...}, "signatures": [{"witness": <hex>, "sig": <hex>}]}

Witness sets change by seq: B pins an ordered WitnessSchedule of
(effective_seq, WitnessSet); a head at seq s must be signed by the set
in effect at s. Adding witnesses or rotating a witness key appends to the
schedule; the log, its id and every old proof stay valid.

FORMAT STATUS: agent_prev_seq, name_sha256, the fixed log_id and the
witness schedule are approved and final (Villhaze, ART-20 04cd1107, R2).

Replay. B keeps a high-water mark per log (HeadStore). An older head is
refused. A same-or-newer head must agree with the stored one at the stored
position (the span carries that entry, so this costs nothing). A conflict
is a fork: refused, and it is evidence against the witness. A stale-but-
valid head after window-close is harmless for identities it covers: a
cutover is final, and nothing can contest it after it.
"""
import base64
import hashlib
import json
import os
import re

from fed import ed25519 as _ed

# Local stand-ins for the agent_identity helpers 73a08c2 imported. This
# branch has no agent_identity module. WitnessSet stays hex-only
# (normalize_pub, not a usability gate) so a small-order key can sit in
# the set and fail at verify time.
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
HEX128_RE = re.compile(r"^[0-9a-f]{128}$")
AGENT_ID_PREFIX = "agt_"
_AGENT_ID_DOMAIN = b"cyberspace-agent-id/v0\x00"
ROTATION_CERT_FORMAT = "cyberspace-key-rotation/v1"


def normalize_pub(pub_hex: str) -> str:
    """Lowercase 64-hex Ed25519 public key, or ValueError."""
    p = (pub_hex or "").strip().lower()
    if not HEX64_RE.fullmatch(p):
        raise ValueError("public key must be 64 hex chars (32-byte Ed25519)")
    return p


def agent_key_id(inception_pub_hex: str) -> str:
    """agt_ + 32 lowercase base32 chars of SHA-256(domain || inception key)."""
    pub = bytes.fromhex(normalize_pub(inception_pub_hex))
    digest = hashlib.sha256(_AGENT_ID_DOMAIN + pub).digest()
    return AGENT_ID_PREFIX + base64.b32encode(digest[:20]).decode().lower()


def witness_key_admitted(pub_hex: str) -> str | None:
    """None when the witness key is prime-order; else window_open.weak_reason.

    checkvalid already rejects a pure small-order point. A mixed-order key
    (honest scalar plus a small-order component) can still satisfy the
    cofactorless equation when the challenge is 0 mod the torsion order, so
    head verification fails closed on that component too (ART-40 belt i).
    Tests replace this with a no-op to show the checkvalid-only mutant
    accepts that head.
    """
    import window_open
    return window_open.weak_reason(pub_hex)


def _sig_ok(pub_hex: str, message: bytes, sig_hex: str) -> bool:
    """Strict checkvalid, then prime-order. Fail-closed on any malformation."""
    try:
        if not isinstance(pub_hex, str) or not isinstance(sig_hex, str) or not isinstance(message, (bytes, bytearray)):
            return False
        if HEX64_RE.fullmatch(pub_hex) is None or HEX128_RE.fullmatch(sig_hex) is None:
            return False
        pk = bytes.fromhex(pub_hex)
        sig = bytes.fromhex(sig_hex)
    except Exception:
        return False
    if not _ed.checkvalid(sig, bytes(message), pk):
        return False
    return witness_key_admitted(pub_hex) is None


def rotation_cert_message(agent_key_id_: str, old_pub: str, new_pub: str) -> bytes:
    return "\n".join([ROTATION_CERT_FORMAT, f"agent_key_id={agent_key_id_}",
                      f"old={normalize_pub(old_pub)}", f"new={normalize_pub(new_pub)}"]).encode()


def verify_rotation_cert(cert, agent_key_id_: str, old_pub: str, new_pub: str) -> bool:
    """Fail-closed: both signatures valid over the step, else False."""
    if not isinstance(cert, dict) or set(cert) != {"old_sig", "new_sig"}:
        return False
    try:
        msg = rotation_cert_message(agent_key_id_, old_pub, new_pub)
    except ValueError:
        return False
    return _sig_ok(normalize_pub(old_pub), msg, cert["old_sig"]) and _sig_ok(
        normalize_pub(new_pub), msg, cert["new_sig"])


LOG_FORMAT = "cyberspace-legacy-migration-log/v1"
HEAD_FORMAT = "cyberspace-legacy-migration-head/v1"
WITNESS_SET_FORMAT = "cyberspace-witness-set/v1"
# Domain tag for a witness record. The kind is an exact KINDS byte string
# with no '|', so it cannot smuggle another field into the tag. Callers
# check the kind BEFORE any signature verification over this tag.
WITNESS_DOMAIN = "cyberspace-witness/v0"
# Ruled in with the writer in window_open.open_window. hold-closure is the
# admission-hold record Villhaze ART-40 49a4fdca authorized once the witness
# port at c259535 was accepted and the witness + weak_reason precondition
# closed. A resolution record stays out.
KINDS = ("window-open", "hold", "binding-hold", "migrate-pending", "late-migrate-pending",
         "withdraw", "contest", "window-close", "cutover", "expire", "activation-refused",
         "reserve-hold", "name-refused", "origin-pin", "origin-handoff", "hold-closure")
WITNESS_KINDS = ("reserve-hold", "name-refused", "origin-pin", "origin-handoff", "hold-closure")
# The basis the hold-closure writer may cite. Exact ASCII, no '|'.
HOLD_CLOSURE_PORT = "c259535"
HOLD_CLOSURE_RULING = "49a4fdca"
HOLD_CLOSURE_PRECONDITION = "witness+weak_reason"
# ART-42 392140b7: per-name admission hop cap (hops up to and including the
# earliest weak hop). Node B applies the same constant to re-derive a
# hop-cap refusal from the witnessed row alone.
PER_NAME_HOP_CAP = 64
HOP_CAP_REASON = "hop-cap"
ROWS_ROOT_DOMAIN = b"cyberspace-rows-root/v0\n"
# ART-42 node B wiring: every name in name_rotations commits hop rows under
# hops_root in the hold-closure. At most PER_NAME_HOP_CAP + 2 rows per
# name (window_open.committed_hop_rows): its first
# PER_NAME_HOP_CAP + 1 hops plus its earliest weak hop at its real index.
HOPS_ROOT_DOMAIN = b"cyberspace-hops-root/v0\n"
HOP_ROWS_PER_NAME = PER_NAME_HOP_CAP + 2
if any((not isinstance(k, str)) or ("|" in k) or (k.encode("ascii") != k.encode()) for k in KINDS):
    raise RuntimeError("KINDS must be exact ASCII byte strings with no '|'")
LATE_CANCEL_SEC = 86400
WINDOW_SEC = 30 * 86400  # db78304f; B checks window-close is no earlier
HOLD_AFTER_CLOSE_SEC = 90 * 86400  # db78304f; a late start must fall inside it
HEADER_FIELDS = ("seq", "prev_hash", "kind", "agent_id", "agent_prev_seq", "name_sha256",
                 "body_sha256")
BODY_FIELDS = ("name", "migration_id", "k0_pub", "detail", "logged_at")


# ------------------------------------------------------------- sizing
# Bulwark Gate 1 #1 / Examiner verdict item 1: the log has a ceiling, and
# both proof caps derive from it. Per legacy account at most: hold, 3
# starts (MAX_STARTS_PER_ACCOUNT, withdrawn and late ones included, from
# window-open to the day-90 release), 3 terminal entries (withdraw /
# activation-refused / contest / cutover), expire -> 8; counted as 9 for
# margin. Per live name binding: binding-hold + expire. Plus the 2 window
# edges. The operator reads both counts at deploy (RUNBOOK_SIZING.md);
# no account count is hardcoded.
MAX_STARTS_PER_ACCOUNT = 3
ENTRIES_PER_ACCOUNT = 9
ENTRIES_PER_BINDING = 2
# One slot each for reserve-hold, name-refused, origin-pin, origin-handoff.
# A name carries at most these four; it does not carry all four at once,
# and the ceiling counts the worst case. Orphans are not in `bindings`
# (the binding row was reaped), so the operator pins that count separately.
# hold-closure is one window-level record, not a fifth per-name slot.
ENTRIES_PER_NAME = 4
HOLD_CLOSURE_ENTRIES = 1
WINDOW_EDGES = 2
MAX_NAME_LEN = 32          # core NAME_RE: 3-32 chars of [a-z0-9_-]
MAX_DETAIL_BYTES = 512     # compact JSON; lm.log refuses anything larger
MAX_WITNESSES = 16
# head fields, then per witness one signature (~221 B) and its key in the
# proof's witness_set listing (~68 B)
HEAD_BUDGET = 1024 + MAX_WITNESSES * (256 + 72)


def max_log_entries(accounts: int, bindings: int, orphans: int = 0) -> int:
    """Ceiling for a log sized by accounts, live bindings, and a pinned
    orphan count. Orphans come from the same name_rotations scan
    snapshot_bindings uses; they are not implied by `bindings`."""
    names = int(bindings) + int(orphans)
    return (ENTRIES_PER_ACCOUNT * int(accounts)
            + ENTRIES_PER_BINDING * int(bindings)
            + ENTRIES_PER_NAME * names
            + WINDOW_EDGES
            + HOLD_CLOSURE_ENTRIES)


def _worst_entry(full_body: bool) -> dict:
    """The widest entry the writer can produce, for byte budgets."""
    e = {"seq": 10 ** 10 - 1, "prev_hash": "f" * 64, "kind": max(KINDS, key=len),
         "agent_id": -(10 ** 18), "agent_prev_seq": 10 ** 10 - 1, "name_sha256": "f" * 64,
         "body_sha256": "f" * 64}
    if full_body:
        # detail is a JSON string inside JSON: every quote escapes to 2 bytes.
        # A name is bounded in characters; an astral character serializes to
        # a 12-byte surrogate pair under ensure_ascii, so budget that.
        e.update(name="\U0001F600" * MAX_NAME_LEN, migration_id=-(10 ** 18), k0_pub="f" * 64,
                 detail='"' * MAX_DETAIL_BYTES, logged_at=10 ** 11 - 1)
    return e


def _json_len(x) -> int:
    # Default separators (", ", ": ") are wider than compact; budget for them
    # so an agent's client re-serializing a proof still fits.
    return len(json.dumps(x).encode())


MAX_SKELETON_BYTES = _json_len(_worst_entry(False)) + 2   # + ", " list separator
MAX_ISSUED_AT = 40
MAX_HOP_ROW_BYTES = _json_len({"name": "\U0001F600" * MAX_NAME_LEN, "i": 10 ** 10 - 1,
                               "old": "f" * 64, "new": "f" * 64,
                               "issued_at": "\U0001F600" * MAX_ISSUED_AT, "sig": "f" * 128,
                               "v": 2, "seq": 10 ** 10 - 1, "prev_hash": "f" * 64}) + 2
MAX_LEAF_BYTES = _json_len(["\U0001F600" * MAX_NAME_LEN, "f" * 64]) + 2


def max_hop_rows(bindings: int, orphans: int = 0) -> int:
    """Ceiling on committed hop rows: HOP_ROWS_PER_NAME per pinned name."""
    return HOP_ROWS_PER_NAME * (int(bindings) + int(orphans))
MAX_FULL_BYTES = _json_len(_worst_entry(True)) + 2
FULL_ENTRIES_PER_PROOF = ENTRIES_PER_ACCOUNT + WINDOW_EDGES  # the agent's own + edges


def proof_max_bytes(accounts: int, bindings: int, orphans: int = 0) -> int:
    """Upper bound on a serialized {head, span} proof for a log sized by
    (accounts, bindings, orphans): every entry as a skeleton, the agent's
    own, the window edges, and the per-name witness kinds full, plus the
    rotation chain and key state (item 7, KEY_STATE_BUDGET: up to
    MAX_ROTATIONS steps)."""
    names = int(bindings) + int(orphans)
    full_slots = FULL_ENTRIES_PER_PROOF + ENTRIES_PER_NAME * names + HOLD_CLOSURE_ENTRIES
    return (HEAD_BUDGET + max_log_entries(accounts, bindings, orphans) * MAX_SKELETON_BYTES
            + full_slots * (MAX_FULL_BYTES - MAX_SKELETON_BYTES) + 64
            + max_hop_rows(bindings, orphans) * MAX_HOP_ROW_BYTES
            + int(bindings) * MAX_LEAF_BYTES + 3 * 96
            + KEY_STATE_BUDGET)


def kind_exact(kind) -> bool:
    """True when kind is an exact KINDS byte string and contains no '|'."""
    return isinstance(kind, str) and "|" not in kind and kind in KINDS


def witness_message(kind: str, fields: dict) -> bytes:
    """cyberspace-witness/v0|<kind> plus sorted key=value lines.

    The caller has already admitted `kind`. This does not verify a signature.
    """
    if not kind_exact(kind):
        raise ValueError("kind is not an exact witness kind")
    lines = [f"{WITNESS_DOMAIN}|{kind}"]
    for key in sorted(fields):
        if not isinstance(key, str) or "|" in key:
            raise ValueError("witness field name")
        lines.append(f"{key}={fields[key]}")
    return "\n".join(lines).encode()


def verify_witness_signature(kind, message: bytes, pub_hex: str, sig_hex: str) -> bool:
    """Admit the kind, then verify. An unknown kind never reaches checkvalid."""
    if not kind_exact(kind):
        return False
    if not isinstance(message, (bytes, bytearray)):
        return False
    prefix = f"{WITNESS_DOMAIN}|{kind}\n".encode()
    if not bytes(message).startswith(prefix) and bytes(message) != f"{WITNESS_DOMAIN}|{kind}".encode():
        return False
    return _sig_ok(pub_hex, bytes(message), sig_hex)


class WitnessRefused(Exception):
    """Node B refuses the head or the span; the message says why."""


def _v(x) -> str:
    return "none" if x is None else str(x)


def body_bytes(e: dict) -> bytes:
    return "\n".join([f"name={_v(e['name'])}", f"migration_id={_v(e['migration_id'])}",
                      f"k0_pub={_v(e['k0_pub'])}", f"detail={e['detail']}",
                      f"logged_at={e['logged_at']}"]).encode()


def body_hash(e: dict) -> str:
    return hashlib.sha256(body_bytes(e)).hexdigest()


def name_hash(name) -> str | None:
    return None if name is None else hashlib.sha256(str(name).encode()).hexdigest()


def header_bytes(e: dict, log_id: str) -> bytes:
    return "\n".join([LOG_FORMAT, f"log_id={log_id}", f"seq={e['seq']}",
                      f"prev_hash={e['prev_hash']}", f"kind={e['kind']}",
                      f"agent_id={_v(e['agent_id'])}",
                      f"agent_prev_seq={_v(e['agent_prev_seq'])}",
                      f"name_sha256={_v(e['name_sha256'])}",
                      f"body_sha256={e['body_sha256']}"]).encode()


def entry_hash(e: dict, log_id: str) -> str:
    return hashlib.sha256(header_bytes(e, log_id)).hexdigest()


def skeleton(e: dict) -> dict:
    return {k: e[k] for k in HEADER_FIELDS}


def full(e: dict) -> dict:
    return {k: e[k] for k in HEADER_FIELDS + BODY_FIELDS}


def is_full(e: dict) -> bool:
    return all(k in e for k in BODY_FIELDS)


class WitnessSet:
    """k-of-n witness keys. Today: WitnessSet(1, [genesis_pub])."""

    def __init__(self, threshold: int, pubs):
        keys = sorted({normalize_pub(p) for p in pubs})
        if isinstance(threshold, bool) or not isinstance(threshold, int) \
                or not 1 <= threshold <= len(keys):
            raise ValueError("threshold must be between 1 and the number of witnesses")
        self.threshold, self.pubs = threshold, keys

    @property
    def id(self) -> str:
        return hashlib.sha256("\n".join([WITNESS_SET_FORMAT, f"threshold={self.threshold}",
                                         *self.pubs]).encode()).hexdigest()


class WitnessSchedule:
    """B's pinned, ordered witness sets: [(effective_seq, WitnessSet), ...],
    first effective at seq 1, strictly increasing. A head at seq s must be
    signed by the set in effect at s (the last one with effective_seq <= s)."""

    def __init__(self, entries):
        es = sorted(((int(q), w) for q, w in entries), key=lambda x: x[0])
        if not es or es[0][0] != 1 or len({q for q, _ in es}) != len(es):
            raise ValueError("witness schedule must start at seq 1 with distinct seqs")
        self.entries = es

    def for_seq(self, seq: int) -> "WitnessSet":
        cur = self.entries[0][1]
        for q, w in self.entries:
            if q <= seq:
                cur = w
        return cur


def as_schedule(w) -> WitnessSchedule:
    return w if isinstance(w, WitnessSchedule) else WitnessSchedule([(1, w)])


# ART-42 hop-row BLOCK: the witnesses sign the three roots node B checks.
# orphans_root: Loom, PENDING Villhaze ratification (see hop_certs).
HEAD_ROOT_FIELDS = ("hops_root", "bound_root", "v1_frozen_root", "orphans_root")


def head_bytes(h: dict) -> bytes:
    return "\n".join([HEAD_FORMAT, f"log_id={h['log_id']}", f"witness_set={h['witness_set']}",
                      f"seq={h['seq']}", f"head_hash={h['head_hash']}",
                      f"window_open_seq={_v(h['window_open_seq'])}",
                      f"window_close_seq={_v(h['window_close_seq'])}",
                      f"window_state={h['window_state']}",
                      *[f"{k}={h[k]}" for k in HEAD_ROOT_FIELDS]]).encode()


def sign_head(h: dict, signers) -> dict:
    """signers: iterable of sign(bytes) -> (witness_pub, sig_hex). Each
    witness signs independently; a k-of-n head is the union."""
    msg = head_bytes(h)
    return {"head": dict(h), "signatures": [dict(zip(("witness", "sig"), s(msg)))
                                            for s in signers]}


# ------------------------------------------------------------- checks

def verify_head(signed: dict, wset, log_id: str, sig_ok=None) -> dict:
    """The head dict, or WitnessRefused. Needs `threshold` distinct valid
    signatures from keys in the set the pinned schedule (or single pinned
    WitnessSet) puts in effect at the head's seq."""
    sched = as_schedule(wset)
    try:
        h, sigs = signed["head"], signed["signatures"]
        fields = ("log_id", "witness_set", "seq", "head_hash", "window_open_seq",
                  "window_close_seq", "window_state") + HEAD_ROOT_FIELDS
        if not isinstance(h, dict) or set(h) != set(fields):
            raise WitnessRefused("head has unexpected fields")
        msg = head_bytes(h)
    except (KeyError, TypeError, AttributeError):
        raise WitnessRefused("malformed head") from None
    if h["log_id"] != log_id:
        raise WitnessRefused("head is for another log")
    if not _int(h["seq"]) or h["seq"] < 1 or not _hex64(h["head_hash"]) \
            or not _int(h["window_open_seq"], True) or not _int(h["window_close_seq"], True) \
            or h["window_state"] not in ("unopened", "open", "closed") \
            or not all(_hex64(h[k]) for k in HEAD_ROOT_FIELDS):
        raise WitnessRefused("bad head field")
    wset = sched.for_seq(h["seq"])
    if h["witness_set"] != wset.id:
        raise WitnessRefused("head names a witness set this node does not pin for its seq")
    eligible = eligible_witnesses(wset.pubs)
    good = set()
    for s in sigs if isinstance(sigs, list) else []:
        w = s.get("witness") if isinstance(s, dict) else None
        sig = s.get("sig") if isinstance(s, dict) else None
        if isinstance(w, str) and isinstance(sig, str) and w in eligible and w not in good \
                and (sig_ok or _sig_ok)(w, msg, sig):
            good.add(w)
    if not head_quorum(len(good), len(eligible)) or len(good) < wset.threshold:
        raise WitnessRefused(
            f"head carries {len(good)} valid witness signature(s) of {len(eligible)} eligible "
            f"(Genesis node key excluded); a strict majority is required")
    return h


def genesis_node_pub() -> str | None:
    """The Genesis node's own key: pinned CYBERNET_GENESIS_NODE_PUB, else
    (on Genesis itself) core._NODE_PUB. It never counts as a witness."""
    pinned = os.environ.get("CYBERNET_GENESIS_NODE_PUB", "").strip().lower()
    if pinned:
        return pinned
    try:
        import core
        return (core._NODE_PUB or "").strip().lower() or None
    except Exception:
        return None


class WitnessConfigRefused(ValueError):
    pass


GENESIS_IN_SET = "refused at config load: the Genesis node key is in the witness set"


def load_witness_set(raw_pubs: str, raw_threshold) -> "WitnessSet":
    """Examiner ART-42 ca4e0404: N independent keys, no Genesis node key,
    threshold pinned (no default) and a strict majority of N (2-of-3 is the
    reference shape). Anything else refuses here, at config load."""
    pubs = [normalize_pub(p.strip()) for p in (raw_pubs or "").split(",") if p.strip()]
    if not pubs:
        raise WitnessConfigRefused("refused at config load: no witness keys")
    if len(set(pubs)) != len(pubs):
        raise WitnessConfigRefused("refused at config load: witness keys are not independent (duplicate)")
    if genesis_in_set(pubs):
        raise WitnessConfigRefused(GENESIS_IN_SET)
    t = (raw_threshold or "").strip() if isinstance(raw_threshold, str) else ""
    if not t.isdigit():
        raise WitnessConfigRefused("refused at config load: witness threshold unset or invalid")
    t = int(t)
    if not 1 <= t <= len(pubs) or 2 * t <= len(pubs):
        raise WitnessConfigRefused(
            f"refused at config load: threshold {t} is not a strict majority of {len(pubs)}")
    return WitnessSet(t, pubs)


def genesis_in_set(pubs) -> bool:
    node = genesis_node_pub()
    return node is not None and node in pubs


def eligible_witnesses(pubs) -> set:
    """Villhaze ART-42 64157549: the set carries over from the legacy-log
    signers; the Genesis node key never counts, even when listed."""
    node = genesis_node_pub()
    return {p for p in pubs if p != node}


def head_quorum(good: int, eligible: int) -> bool:
    """Strict majority of the eligible witness set."""
    return eligible > 0 and 2 * good > eligible


def _int(x, nullable=False) -> bool:
    if x is None:
        return nullable
    return isinstance(x, int) and not isinstance(x, bool)


def _hex64(x) -> bool:
    return isinstance(x, str) and HEX64_RE.fullmatch(x) is not None


def entry_shape_problem(e) -> str | None:
    """Why this entry is not a well-typed skeleton or full entry, or None.
    Every value a hostile proof could send is checked here, so the rules
    below never meet a missing field or a wrong type."""
    if not isinstance(e, dict):
        return "entry is not an object"
    if not _int(e.get("seq")) or not _int(e.get("agent_id"), True):
        return "bad seq or agent_id"
    if e.get("kind") not in KINDS:
        return "unknown kind"
    if not (e.get("prev_hash") == "none" or _hex64(e.get("prev_hash"))) \
            or not _hex64(e.get("body_sha256")):
        return "bad hash field"
    if not _int(e.get("agent_prev_seq"), True) or "agent_prev_seq" not in e \
            or "name_sha256" not in e \
            or not (e["name_sha256"] is None or _hex64(e["name_sha256"])):
        return "bad agent_prev_seq or name_sha256"
    present = [k for k in BODY_FIELDS if k in e]
    if present and len(present) != len(BODY_FIELDS):
        return "partial body"
    if present:
        if not (e["name"] is None or isinstance(e["name"], str)) \
                or not _int(e["migration_id"], True) \
                or not (e["k0_pub"] is None or _hex64(e["k0_pub"])) \
                or not _int(e["logged_at"]) or not isinstance(e["detail"], str):
            return "bad body field"
        try:
            if not isinstance(json.loads(e["detail"]), dict):
                return "detail is not a JSON object"
        except ValueError:
            return "detail is not JSON"
    return None


def verify_chain(entries: list, log_id: str) -> tuple:
    """(True, last entry_hash) when entries are well-typed, seq 1..n, each
    links to the previous, and every full entry's body matches its
    body_sha256. Never raises on hostile input."""
    if not isinstance(entries, list):
        return False, "span is not a list"
    prev = "none"
    last_of = {}      # agent_id -> seq of its latest entry so far
    last_at = None    # logged_at of the latest full body so far
    for i, e in enumerate(entries, 1):
        why = entry_shape_problem(e)
        if why:
            return False, f"malformed entry at seq {i}: {why}"
        try:
            if e["seq"] != i:
                return False, f"gap at seq {i}"
            if e["prev_hash"] != prev:
                return False, f"chain broken at seq {i}"
            want = last_of.get(e["agent_id"]) if e["agent_id"] is not None else None
            if e["agent_prev_seq"] != want:
                return False, f"agent back-link wrong at seq {i}"
            if e["agent_id"] is not None:
                last_of[e["agent_id"]] = i
            if is_full(e):
                if body_hash(e) != e["body_sha256"]:
                    return False, f"body does not match its hash at seq {i}"
                if name_hash(e["name"]) != e["name_sha256"]:
                    return False, f"name does not match name_sha256 at seq {i}"
                if last_at is not None and e["logged_at"] < last_at:
                    return False, f"logged_at decreases at seq {i}"
                last_at = e["logged_at"]
            prev = entry_hash(e, log_id)
            if "entry_hash" in e and e["entry_hash"] != prev:
                return False, f"entry_hash mismatch at seq {i}"
        except (KeyError, TypeError):
            return False, f"malformed entry at seq {i}"
    return True, prev


class HeadStore:
    """Node B's high-water mark per log: refuses replayed (older) heads and
    forks. In-memory here; a node persists it (one row per log_id)."""

    def __init__(self):
        self.marks = {}

    def check(self, h: dict, entries: list) -> None:
        mark = self.marks.get(h["log_id"])
        if mark is None:
            return
        seq, hsh = mark
        if h["seq"] < seq:
            raise WitnessRefused(f"stale head: seq {h['seq']} is older than seq {seq} "
                                 "already accepted (replay or rollback)")
        if entry_hash(entries[seq - 1], h["log_id"]) != hsh:
            raise WitnessRefused(f"fork: this span disagrees with the head accepted at seq {seq}")

    def commit(self, h: dict) -> None:
        cur = self.marks.get(h["log_id"])
        if cur is None or h["seq"] >= cur[0]:
            self.marks[h["log_id"]] = (h["seq"], h["head_hash"])


def accept_legacy_identity(proof: dict, name: str, wset: WitnessSet, log_id: str,
                           store, held_names=None) -> dict:
    """Node B's rule (Loom 4b, Cipher's order; late path per 5fe976e8).
    Returns {name, k0_pub, agent_key_id, ...} or raises WitnessRefused,
    and only WitnessRefused: any other failure on hostile input is turned
    into a clean refusal, never a crash. held_names (ART-42 35e546b9) is
    the set of names B already holds witnessed state for."""
    try:
        return _accept(proof, name, wset, log_id, store, held_names=held_names)
    except WitnessRefused:
        raise
    except (KeyError, TypeError, ValueError, AttributeError, IndexError) as e:
        raise WitnessRefused(f"malformed proof ({type(e).__name__})") from None


def check_identity(proof: dict, name: str, wset: WitnessSet, log_id: str,
                   charge=None, held_names=None, sender="local") -> tuple:
    """The 4a rules without touching any store: -> (head, entries, identity).
    Callers that persist the head (node B's import) use this, then run
    their own store check and commit inside their transaction.
    held_names: see check_held_name_diff (ART-42 35e546b9)."""
    try:
        return _rules(proof, name, wset, log_id, charge=charge, held_names=held_names,
                      sender=sender)
    except WitnessRefused:
        raise
    except (KeyError, TypeError, ValueError, AttributeError, IndexError) as e:
        raise WitnessRefused(f"malformed proof ({type(e).__name__})") from None


def migration_matches_cutover(start: dict, cut: dict) -> bool:
    """The cutover activates this migration only when seq, id, and k0 agree."""
    if start["seq"] > cut["seq"]:
        return False
    if start["migration_id"] != cut["migration_id"]:
        return False
    if start["k0_pub"] != cut["k0_pub"]:
        return False
    return True


def rebuild_window_kinds(entries: list) -> dict:
    """Node B's view of the window kinds from the log span alone.

    No database. reserve-hold carries reserved_for and orphan; name-refused,
    origin-pin, and origin-handoff are returned the same way. hold-closure
    is the one admission-hold record, with its precondition, state, port,
    and ruling.
    """
    out = {k: [] for k in WITNESS_KINDS}
    if not isinstance(entries, list):
        return out
    for e in entries:
        if not isinstance(e, dict) or e.get("kind") not in WITNESS_KINDS or not is_full(e):
            continue
        try:
            detail = json.loads(e["detail"])
        except (TypeError, ValueError):
            continue
        if not isinstance(detail, dict):
            continue
        out[e["kind"]].append({
            "name": e.get("name"),
            "k0_pub": e.get("k0_pub"),
            "detail": detail,
            "reserved_for": detail.get("reserved_for"),
            "orphan": detail.get("orphan"),
            "reason": detail.get("reason"),
            "origin": detail.get("origin"),
            "successor": detail.get("successor"),
            "precondition": detail.get("precondition"),
            "state": detail.get("state"),
            "port": detail.get("port"),
            "ruling": detail.get("ruling"),
        })
    return out


def rows_root(entry_hashes) -> str:
    """Commitment to the window kind entries of one open, in seq order."""
    h = hashlib.sha256(ROWS_ROOT_DOMAIN)
    for eh in entry_hashes:
        h.update(str(eh).encode("ascii") + b"\n")
    return h.hexdigest()


_ROW_KINDS = ("reserve-hold", "name-refused", "origin-pin", "origin-handoff")


def hop_row_hash(row: dict) -> str:
    """Hash of one committed hop row {name, i, old, new}."""
    import hop_certs
    body = json.dumps([row[k] for k in hop_certs.ROW_FIELDS],
                      separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(HOPS_ROOT_DOMAIN + body.encode("ascii")).hexdigest()


def hops_root(rows) -> str:
    """Commitment to the hop rows of one open, in (name, i) order."""
    h = hashlib.sha256(HOPS_ROOT_DOMAIN)
    for r in rows:
        h.update(hop_row_hash(r).encode("ascii") + b"\n")
    return h.hexdigest()


def _hop_row_ok(r) -> bool:
    import hop_certs
    return hop_certs.row_ok(r)


def verify_rows_root(entries: list, hops: list | None = None, log_id: str | None = None) -> tuple:
    """(ok, why). Node B: every row-kind entry in the span is covered by the
    single hold-closure's rows_root, nothing after it is a row kind, and the
    proof's hop rows match the hold-closure's hops_root."""
    if not isinstance(entries, list):
        return False, "no entries"
    hops = [] if hops is None else hops
    if not isinstance(hops, list) or not all(_hop_row_ok(r) for r in hops):
        return False, "hop rows malformed"
    closures = [e for e in entries if isinstance(e, dict) and e.get("kind") == "hold-closure"]
    if len(closures) != 1:
        return False, "expected one hold-closure"
    try:
        d = json.loads(closures[0]["detail"])
    except (TypeError, ValueError, KeyError):
        return False, "hold-closure detail unreadable"
    root = d.get("rows_root") if isinstance(d, dict) else None
    if not isinstance(root, str):
        return False, "hold-closure carries no rows_root"
    cseq = closures[0]["seq"]
    rows = [e for e in entries if e.get("kind") in _ROW_KINDS]
    if any(e["seq"] > cseq for e in rows):
        return False, "row entry outside rows_root (after hold-closure)"
    hashes = [entry_hash(e, log_id) if log_id is not None else e["entry_hash"] for e in rows]
    if rows_root(hashes) != root or d.get("rows_n") != len(rows):
        return False, "rows_root mismatch"
    if d.get("hops_n") != len(hops) or hops_root(hops) != d.get("hops_root"):
        return False, "hops_root mismatch"
    return True, None


def _hops_by_name(hops: list) -> tuple:
    """({name: {i: (old, new)}}, {name: [(old, new), ...] in i order}) or
    raises WitnessRefused when a name's rows are not the committed shape:
    i = 0..k-1 contiguous, then at most one row beyond, only when
    k == PER_NAME_HOP_CAP + 1 (the earliest weak hop at its real index)."""
    by = {}
    for r in hops:
        by.setdefault(r["name"], []).append(r)
    at, seq = {}, {}
    for name, rs in by.items():
        idx = [r["i"] for r in rs]
        k = len(rs)
        if k > HOP_ROWS_PER_NAME:
            raise WitnessRefused(f"hop rows for {name!r} exceed {HOP_ROWS_PER_NAME}")
        if idx != list(range(k)):
            k -= 1
            if k != PER_NAME_HOP_CAP + 1 or idx[:k] != list(range(k)) or idx[-1] <= k - 1:
                raise WitnessRefused(f"hop rows for {name!r} are not the committed shape")
        at[name] = {r["i"]: (r["old"], r["new"]) for r in rs}
        seq[name] = [(r["old"], r["new"]) for r in rs]
    return at, seq


def rederive_refusals(entries: list, hops: list | None = None) -> tuple:
    """(ok, refused). Node B re-derives every hop-cap refusal from the
    witnessed hop rows with the SAME counted_hops the writer uses
    (window_open.counted_hops). A FLAG on a name at or under the cap is
    forged; a name over the cap without a FLAG is a dropped FLAG. Either
    refuses. Every reserve-hold carrying weak-hop evidence must match the
    committed earliest weak hop. refused is {name: hops}."""
    import window_open as wo
    hops = [] if hops is None else hops
    try:
        at, seq = _hops_by_name(hops)
    except WitnessRefused as e:
        return False, {"bad-hops": str(e)}
    counted = {name: wo.counted_hops(h) for name, h in seq.items()}
    over = {name for name, n in counted.items() if n > PER_NAME_HOP_CAP}
    view = rebuild_window_kinds(entries)
    refused = {}
    for r in view["name-refused"]:
        if r["reason"] != HOP_CAP_REASON:
            continue
        n = r["detail"].get("hops")
        if r["name"] not in over or not isinstance(n, int) or n != max(at[r["name"]]) + 1:
            return False, {"forged": r["name"], "hops": n, "counted": counted.get(r["name"])}
        refused[r["name"]] = n
    dropped = sorted(over - set(refused))
    if dropped:
        return False, {"dropped": dropped}
    for r in view["reserve-hold"]:
        d = r["detail"]
        if "weak_index" not in d:
            continue
        if d.get("weak_old") != r["reserved_for"] or wo.weak_reason(d.get("weak_old")) is not None \
                or wo.weak_reason(d.get("weak_new")) is None:
            return False, {"bad-hold": r["name"]}
        wi = d["weak_index"]
        if r["name"] not in at or counted[r["name"]] != (wi + 1 if isinstance(wi, int) else None) \
                or tuple(str(k).strip().lower() for k in at[r["name"]].get(wi, ("", ""))) \
                != (d.get("weak_old"), d.get("weak_new")):
            return False, {"bad-hold-hops": r["name"]}
    return True, refused


def check_hop_certs(proof, h, entries, log_id, pins, charge=None, sender="local") -> None:
    """Fourth check: the head's roots match the shipped rows and leaves,
    then every hop cert re-verifies (hop_certs.verify_hops)."""
    import hop_certs
    hop_rows = proof.get("hops", [])
    leaves = proof.get("bound", [])
    if not all(isinstance(x, list) and len(x) == 2 and all(isinstance(v, str) for v in x)
               for x in leaves):
        raise WitnessRefused("bound leaves malformed")
    if h["hops_root"] != hops_root(hop_rows):
        raise WitnessRefused("head hops_root does not match the hop rows")
    if h["bound_root"] != hop_certs.bound_root(leaves):
        raise WitnessRefused("head bound_root does not match the bound leaves")
    if h["v1_frozen_root"] != hop_certs.v1_frozen_root(hop_rows):
        raise WitnessRefused("head v1_frozen_root does not match the v1 certs")
    orphans = proof.get("orphans", [])
    if not isinstance(orphans, list) or not all(
            isinstance(x, list) and len(x) == 2 and all(isinstance(v, str) for v in x)
            for x in orphans):
        raise WitnessRefused("orphan leaves missing or malformed")
    if h["orphans_root"] != hop_certs.orphans_root(orphans):
        raise WitnessRefused("head orphans_root does not match the orphan leaves")
    view = rebuild_window_kinds(entries)
    exempt = {r["name"] for k in ("reserve-hold", "name-refused") for r in view[k]}
    ok, why = hop_certs.verify_hops(hop_rows, leaves, exempt, pins,
                                    cache_key=(log_id, h["head_hash"], h["hops_root"]),
                                    charge=charge, sender=sender, orphans=orphans)
    if not ok:
        raise WitnessRefused(f"hop certs: {why}")


def pinned_sizing() -> tuple | None:
    """(accounts, bindings, orphans) the operator pinned for this log, or
    None. All three are required (Villhaze ART-42 64157549): an unset
    CYBERNET_GENESIS_ORPHANS refuses; a pinned 0 is a real pin."""
    try:
        a = int(os.environ.get("CYBERNET_GENESIS_LEGACY_ACCOUNTS", ""))
        b = int(os.environ.get("CYBERNET_GENESIS_LIVE_BINDINGS", ""))
        o = int(os.environ.get("CYBERNET_GENESIS_ORPHANS", ""))
    except ValueError:
        return None
    if a < 0 or b < 0 or o < 0:
        return None
    return a, b, o


def proof_name_coverage(entries: list, hops: list | None = None) -> set:
    """Names the closure accounts for: hop rows plus witness kind rows
    (reserve-hold, name-refused / FLAG, origin-pin, origin-handoff)."""
    names = set()
    for r in ([] if hops is None else hops):
        if isinstance(r, dict) and isinstance(r.get("name"), str):
            names.add(r["name"])
    view = rebuild_window_kinds(entries)
    for kind in ("reserve-hold", "name-refused", "origin-pin", "origin-handoff"):
        for r in view.get(kind, []):
            n = r.get("name")
            if isinstance(n, str):
                names.add(n)
    return names


def check_held_name_diff(entries: list, hops: list | None = None,
                         held_names=None) -> None:
    """Villhaze ART-42 35e546b9: proof-vs-local diff for held names.

    B refuses a closure that silently omits a name B already holds
    witnessed state for. A FLAG (name-refused) row for that name covers
    the omission. Names B has never seen remain a known limitation and
    do not refuse."""
    if not held_names:
        return
    held = {n for n in held_names if isinstance(n, str)}
    if not held:
        return
    omitted = sorted(held - proof_name_coverage(entries, hops))
    if omitted:
        if len(omitted) == 1:
            raise WitnessRefused(
                f"held name omitted from closure (no FLAG): {omitted[0]!r}")
        raise WitnessRefused(
            f"held names omitted from closure (no FLAG): {omitted}")


def check_size_limits(proof: dict, pins) -> None:
    """First check (Bulwark): nothing is hashed or counted before the
    proof's span, hop rows and bytes are inside the pinned ceilings."""
    if pins is None:
        raise WitnessRefused("no pinned sizing (accounts / bindings / orphans) on this node")
    accounts, bindings, orphans = pins
    span = proof.get("span")
    if not isinstance(span, list) or len(span) > max_log_entries(accounts, bindings, orphans):
        raise WitnessRefused("span exceeds max_log_entries")
    hop_rows = proof.get("hops", [])
    if not isinstance(hop_rows, list) or len(hop_rows) > max_hop_rows(bindings, orphans):
        raise WitnessRefused("hop rows exceed the pinned ceiling")
    leaves = proof.get("bound", [])
    if not isinstance(leaves, list) or len(leaves) > int(bindings):
        raise WitnessRefused("bound leaves exceed the pinned bindings")
    if len(proof.get("orphans") or []) > int(orphans):
        raise WitnessRefused("orphan leaves exceed the pinned orphans")
    if len(json.dumps(proof).encode()) > proof_max_bytes(accounts, bindings, orphans):
        raise WitnessRefused("proof exceeds proof_max_bytes")


def _accept(proof, name, wset, log_id, store, held_names=None) -> dict:
    h, entries, ident = _rules(proof, name, wset, log_id, held_names=held_names)
    store.check(h, entries)
    store.commit(h)
    return ident


def _rules(proof, name, wset, log_id, pins=None, charge=None, held_names=None,
           sender="local") -> tuple:
    if not isinstance(proof, dict):
        raise WitnessRefused("proof is not an object")
    # ART-42 node B order: size limits, then verify_rows_root, then
    # rederive_refusals, then held-name proof-vs-local (35e546b9), then the
    # hop certs. Size first, before any entry or row is hashed.
    pins = pinned_sizing() if pins is None else pins
    check_size_limits(proof, pins)
    h = verify_head(proof.get("head") or {}, wset, log_id)
    if h["window_state"] != "closed" or h["window_close_seq"] is None:
        raise WitnessRefused("head is before window-close; a legacy identity stays pending")
    entries = proof.get("span")
    if not isinstance(entries, list) or len(entries) != h["seq"]:
        raise WitnessRefused("span does not cover [1, head] (truncated or padded)")
    ok, last = verify_chain(entries, log_id)
    if not ok:
        raise WitnessRefused(f"span does not chain: {last}")
    if last != h["head_hash"]:
        raise WitnessRefused("span does not end at the signed head")
    hop_rows = proof.get("hops", [])
    ok, why = verify_rows_root(entries, hop_rows, log_id)
    if not ok:
        raise WitnessRefused(f"rows_root: {why}")
    ok, why = rederive_refusals(entries, hop_rows)
    if not ok:
        raise WitnessRefused(f"hop-cap refusals do not re-derive: {why}")
    check_held_name_diff(entries, hop_rows, held_names)
    check_hop_certs(proof, h, entries, log_id, pins, charge, sender)
    o, c = h["window_open_seq"], h["window_close_seq"]
    kinds = [e["kind"] for e in entries]
    if kinds.count("window-open") != 1 or kinds.count("window-close") != 1 \
            or not (isinstance(o, int) and isinstance(c, int) and 1 <= o < c <= h["seq"]) \
            or entries[o - 1]["kind"] != "window-open" or entries[c - 1]["kind"] != "window-close":
        raise WitnessRefused("head's window positions do not match the span")
    if not (is_full(entries[o - 1]) and is_full(entries[c - 1])):
        raise WitnessRefused("span withholds the body of a window edge")
    if entries[c - 1]["logged_at"] - entries[o - 1]["logged_at"] < WINDOW_SEC:
        raise WitnessRefused("window-close is earlier than the 30-day window allows")
    nh = name_hash(name)
    if any(e["kind"] == "name-refused" and e.get("name_sha256") == nh for e in entries):
        raise WitnessRefused("name-refused")
    holds = [e for e in entries if e["kind"] == "hold" and e["name_sha256"] == nh]
    if len(holds) != 1 or not o < holds[0]["seq"] < c or not is_full(holds[0]) \
            or holds[0]["name"] != name:
        raise WitnessRefused("no single witnessed hold for this name inside the window")
    x = holds[0]["agent_id"]
    mine = [e for e in entries if e["agent_id"] == x]
    if any(not is_full(e) for e in mine):
        raise WitnessRefused("span withholds the body of an entry for this agent")
    if any(e["kind"] == "contest" for e in mine):
        raise WitnessRefused("contested: the account is frozen")
    cuts = [e for e in mine if e["kind"] == "cutover"]
    if len(cuts) != 1:
        raise WitnessRefused("no single cutover for this agent at or before the head")
    cut = cuts[0]
    if cut["seq"] <= c:
        raise WitnessRefused("cutover before window-close is invalid")
    if any(e["kind"] == "expire" and e["seq"] < cut["seq"] for e in mine):
        raise WitnessRefused("the name was released before this cutover")
    withdrawn = {e["migration_id"] for e in mine if e["kind"] in ("withdraw", "activation-refused")}
    if cut["migration_id"] in withdrawn:
        raise WitnessRefused("the cutover's migration was withdrawn or its activation refused")
    main = [e for e in mine if e["kind"] == "migrate-pending" and o < e["seq"] < c
            and e["migration_id"] not in withdrawn]
    late = [e for e in mine if e["kind"] == "late-migrate-pending" and e["seq"] > c
            and e["migration_id"] not in withdrawn]
    if any(e["kind"] == "migrate-pending" and not o < e["seq"] < c for e in mine) or \
            any(e["kind"] == "late-migrate-pending" and e["seq"] < c for e in mine):
        raise WitnessRefused("a migration entry sits outside its allowed span")
    if main:
        if len(main) != 1 or late:
            raise WitnessRefused("not exactly one non-withdrawn migration in the window")
        start = main[0]
    else:
        if len(late) != 1:
            raise WitnessRefused("no single non-withdrawn migration for this agent")
        start = late[0]
        if start["logged_at"] >= entries[c - 1]["logged_at"] + HOLD_AFTER_CLOSE_SEC:
            raise WitnessRefused("late start after the 90-day hold")
        if cut["logged_at"] - start["logged_at"] < LATE_CANCEL_SEC:
            raise WitnessRefused("late cutover before its 24h cancel window passed")
    if not migration_matches_cutover(start, cut):
        raise WitnessRefused("cutover does not match the migration it activates")
    detail = json.loads(cut["detail"])
    if detail.get("window_close_seq") != c:
        raise WitnessRefused("cutover names another window-close")
    for e in entries:
        if e["kind"] != "reserve-hold" or e.get("name_sha256") != nh:
            continue
        if not is_full(e):
            raise WitnessRefused("span withholds a reserve-hold body")
        reserved_for = json.loads(e["detail"]).get("reserved_for")
        if reserved_for != cut["k0_pub"]:
            raise WitnessRefused("reserve-hold key does not match the cutover")
    return h, entries, {"name": name, "k0_pub": cut["k0_pub"], "agent_key_id": agent_key_id(cut["k0_pub"]),
            "recovery_set_sha256": detail.get("recovery_set_sha256"),
            "late": start["kind"] == "late-migrate-pending", "cutover_seq": cut["seq"],
            "head_seq": h["seq"], "log_id": log_id}


# ------------------------------------------------- key state (item 7)
# Gate 1 item 7 (Examiner 1, Cipher 4, Loom 5): B installs the newest key
# in Genesis's rotation chain, not the cutover's K0. The log fixes K0 and
# the identity; key changes after the cutover live in Genesis's rotation
# log, outside the witness log. A proof therefore also carries:
#   rotations  [{kind, old_pub, new_pub, cert}] in order, K0 first
#   key_state  {"state": {...}, "signatures": [...]}: the witness set in
#              effect at the head attests (log, head, identity, the chain's
#              hash, the current key, attested_at)
# B checks every step's cert from K0 and that the chain ends at the
# attested current key. attested_at bounds how old a chain B accepts
# without a refresh (legacy_import.KEY_STATE_MAX_AGE_SEC). Format v1, ruled
# by Villhaze (ART-20 d09683eb); the log format itself (R2) is unchanged.
# The one place this wire string lives: a rename is a change to this line.
KEY_STATE_FORMAT = "cyberspace-legacy-key-state/v1"
KEY_STATE_FIELDS = ("log_id", "witness_set", "head_seq", "head_hash", "agent_key_id",
                    "inception_pub", "current_pub", "rotations", "rotations_sha256",
                    "attested_at")
ROTATION_FIELDS = ("kind", "old_pub", "new_pub", "cert")
ROTATION_KINDS = ("rotate", "import")
MAX_ROTATIONS = 32
_WORST_ROTATION = {"kind": "rotate", "old_pub": "f" * 64, "new_pub": "f" * 64,
                   "cert": {"old_sig": "f" * 128, "new_sig": "f" * 128}}
KEY_STATE_BUDGET = (1024 + MAX_WITNESSES * 256
                    + MAX_ROTATIONS * (len(json.dumps(_WORST_ROTATION).encode()) + 2) + 64)


def rotations_hash(rotations: list) -> str:
    return hashlib.sha256(json.dumps(
        [{k: r.get(k) for k in ROTATION_FIELDS} for r in rotations],
        sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def key_state_bytes(st: dict) -> bytes:
    return "\n".join([KEY_STATE_FORMAT, *(f"{k}={_v(st[k])}" for k in KEY_STATE_FIELDS)]).encode()


def sign_key_state(st: dict, signers) -> dict:
    msg = key_state_bytes(st)
    return {"state": dict(st), "signatures": [dict(zip(("witness", "sig"), s(msg)))
                                              for s in signers]}


def check_key_state(proof: dict, h: dict, ident: dict, wset, log_id: str) -> tuple:
    """-> (current_pub, rotations) or WitnessRefused. h and ident come from
    check_identity on the same proof."""
    try:
        return _key_state(proof, h, ident, wset, log_id)
    except WitnessRefused:
        raise
    except (KeyError, TypeError, ValueError, AttributeError) as e:
        raise WitnessRefused(f"malformed key state ({type(e).__name__})") from None


def _key_state(proof, h, ident, wset, log_id) -> tuple:
    ks, rots = proof.get("key_state"), proof.get("rotations")
    if not isinstance(ks, dict) or not isinstance(ks.get("state"), dict):
        raise WitnessRefused("proof carries no key state")
    st, sigs = ks["state"], ks.get("signatures")
    if set(st) != set(KEY_STATE_FIELDS):
        raise WitnessRefused("key state has unexpected fields")
    if st["log_id"] != log_id:
        raise WitnessRefused("key state is for another log")
    if st["head_seq"] != h["seq"] or st["head_hash"] != h["head_hash"]:
        raise WitnessRefused("key state is not attested at this proof's head")
    w = as_schedule(wset).for_seq(h["seq"])
    if st["witness_set"] != w.id:
        raise WitnessRefused("key state names a witness set this node does not pin for its seq")
    msg = key_state_bytes(st)
    good = set()
    for s in sigs if isinstance(sigs, list) else []:
        k = s.get("witness") if isinstance(s, dict) else None
        sig = s.get("sig") if isinstance(s, dict) else None
        if isinstance(k, str) and isinstance(sig, str) and k in w.pubs and k not in good \
                and _sig_ok(k, msg, sig):
            good.add(k)
    if len(good) < w.threshold:
        raise WitnessRefused(f"key state carries {len(good)} valid witness signature(s); "
                             f"{w.threshold} required")
    k0 = ident["k0_pub"]
    if st["inception_pub"] != k0 or st["agent_key_id"] != agent_key_id(k0):
        raise WitnessRefused("key state is for another identity")
    if not _int(st["attested_at"]):
        raise WitnessRefused("bad key state field")
    if not isinstance(rots, list) or len(rots) > MAX_ROTATIONS:
        raise WitnessRefused(f"rotation chain missing or longer than {MAX_ROTATIONS} steps")
    if st["rotations"] != len(rots) or rotations_hash(rots) != st["rotations_sha256"]:
        raise WitnessRefused("rotation chain does not match the attested key state")
    cur, seen = k0, {k0}
    for i, r in enumerate(rots, 1):
        if not isinstance(r, dict) or set(r) != set(ROTATION_FIELDS):
            raise WitnessRefused(f"rotation step {i} is malformed")
        if r["kind"] not in ROTATION_KINDS:
            raise WitnessRefused(f"rotation step {i} has kind {r['kind']!r}, not importable")
        if r["old_pub"] != cur:
            raise WitnessRefused(f"rotation step {i} does not start at the previous key")
        if not _hex64(r["new_pub"]) or r["new_pub"] in seen:
            raise WitnessRefused(f"rotation step {i} reuses a key or names a bad key")
        if r["cert"] is None:
            raise WitnessRefused(f"rotation step {i} carries no cert")
        if not verify_rotation_cert(r["cert"], st["agent_key_id"], r["old_pub"], r["new_pub"]):
            raise WitnessRefused(f"rotation step {i}: cert does not verify")
        cur = r["new_pub"]
        seen.add(cur)
    if st["current_pub"] != cur:
        raise WitnessRefused("rotation chain does not end at the attested current key")
    return cur, rots
