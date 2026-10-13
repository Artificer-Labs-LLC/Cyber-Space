"""Witness level of a legacy-log head (Research Board 10:46 PM ET designs;
board conditions 1-4). Everything here is CONDITIONAL on Villhaze's
single-operator ruling and parameterized in RULING / PIN_SIGNERS.

(1) Lodestar head marker: tag || fixed-width big-endian body.
(2) Bulwark: every cheap check runs before any signature verify.
(3) Loom pin file: local path only, signed, rollback-protected.
Pure module except load_pins()/the pin-version state file.
"""
import hashlib
import json
import os
import struct

MODES = ("unwitnessed", "single-operator", "independent")
TAGS = {m: f"cyberspace-head-{m}/v0\n".encode() for m in MODES}
COSIGN_PREFIX = b"cyberspace-witness-cosign/v1\n"
PIN_MAGIC = b"cyberspace-witness-pins/v1\n"
BODY = struct.Struct(">B32sQ32sQ32s32sQ")      # 153 bytes
ZERO32 = b"\x00" * 32
CLASS_FLEET, CLASS_OUTSIDE = 1, 2
MAX_OPS, MAX_KEYS = 16, 4

RULING = {"min_outside_operators": 1}
# Pin-signer public keys: compile-time PLACEHOLDER until Villhaze rules.
# Empty => every pin file is refused (no unsigned pins in production).
PIN_SIGNERS: tuple = ()
PIN_THRESHOLD = 1


class Refused(ValueError):
    pass


class TagModeMismatch(Refused):
    pass


class OperatorMismatch(Refused):
    pass


class SignerIndexOutOfRange(Refused):
    pass


class TooFewSignatures(Refused):
    pass


class FirstContactRefused(Refused):
    pass


# ---- FIRST-CONTACT SWITCH (PENDING VILLHAZE RULING, ART-29 2a078f21) -----
# What cheap_head does with prev_size/prev_root when NO continuity mark is
# stored yet. prev_* is never skipped silently (Lodestar 2bdecf9c, Examiner).
#   "refuse_nonzero_prev" - DEFAULT, fail-closed: a first-contact head must
#                           carry prev_size == 0; anything else is refused
#                           (FirstContactRefused) before any verify.
#   "tofu"                - labelled trust-on-first-use: a first-contact head
#                           with any prev_* is accepted as the first mark and
#                           labelled first_contact=True (cheap_head result and
#                           verify_head(out=...)).
# TODO(Villhaze ART-29 2a078f21): flip only on her written ruling. This is
# the single switch; nothing else reads first-contact policy.
FIRST_CONTACT = "refuse_nonzero_prev"
FIRST_CONTACT_CHOICES = ("refuse_nonzero_prev", "tofu")


def log_id_of(genesis_pub_hex: str) -> bytes:
    return hashlib.sha256(bytes.fromhex(genesis_pub_hex)).digest()


def pack_head(mode, log_id, tree_size, root, prev_size, prev_root, operator_id, issued_at):
    return TAGS[MODES[mode]] + BODY.pack(mode, log_id, tree_size, root, prev_size,
                                         prev_root, operator_id, issued_at)


def cheap_head(blob: bytes, log_id: bytes, mark=None) -> dict:
    """All checks that need no signature verify. mark = (size, root) of the
    stored mark, or None when nothing is stored yet."""
    for m, tag in TAGS.items():
        if blob.startswith(tag):
            break
    else:
        raise Refused("unknown head tag")
    body = blob[len(tag):]
    if len(body) != BODY.size:
        raise Refused("head body length")
    mode, lid, size, root, psize, proot, op, issued = BODY.unpack(body)
    if mode > 2:
        raise Refused("mode out of range")
    if MODES[mode] != m:
        raise TagModeMismatch("tag/mode mismatch")
    if mode != 1 and op != ZERO32:
        raise Refused("operator_id must be zero unless single-operator")
    if mode == 1 and op == ZERO32:
        raise Refused("single-operator head needs operator_id")
    if lid != log_id:
        raise Refused("log_id")
    if mark is not None and (psize, proot) != (mark[0], mark[1]):
        raise Refused("prev_* does not match the stored mark")
    if mark is None:
        if FIRST_CONTACT not in FIRST_CONTACT_CHOICES:
            raise FirstContactRefused("FIRST_CONTACT switch has an unknown value")
        if FIRST_CONTACT == "refuse_nonzero_prev" and psize != 0:
            raise FirstContactRefused("first contact with nonzero prev_size")
    if psize > size:
        raise Refused("prev_size > tree_size")
    return {"mode": mode, "level": m, "body": body, "tree_size": size, "root": root,
            "operator_id": op, "issued_at": issued, "first_contact": mark is None,
            "first_contact_policy": FIRST_CONTACT if mark is None else None}


def select_cosigns(cosigns, keys):
    """Unpinned keys dropped before any verify; one per pinned key; capped
    at the pin-list size."""
    kept, seen = [], set()
    for c in cosigns:
        if len(kept) >= len(keys):
            break
        pub = str(c.get("pub", "")).lower()
        if pub in keys and pub not in seen:
            seen.add(pub)
            kept.append((pub, c.get("sig", "")))
    return kept


def verify_head(blob, genesis_sig, genesis_pub, cosigns, pins, sig_ok, mark=None, ruling=RULING, out=None):
    """pins comes from load_pins() (the shipped file), never a response.
    pins=None (fail closed: placeholder signers / threshold 0) rates every
    head at most unwitnessed. Returns (level, cosign_verify_calls)."""
    if pins is None:
        pins = {"keys": {}}
    h = cheap_head(blob, log_id_of(genesis_pub), mark)            # (2) before any verify
    if out is not None:                     # first-contact label (TOFU path)
        out["first_contact"] = h["first_contact"]
        out["first_contact_policy"] = h["first_contact_policy"]
    keys = {k: v for k, v in pins["keys"].items()
            if v["from"] <= h["tree_size"] <= v["to"]}
    if not sig_ok(genesis_pub, blob, genesis_sig):
        raise Refused("genesis signature")
    msg = COSIGN_PREFIX + h["body"]
    calls, fleet_ops, outside_ops = 0, set(), set()
    for pub, sig in select_cosigns(cosigns, keys):
        calls += 1
        if sig_ok(pub, msg, sig):
            k = keys[pub]
            (outside_ops if k["class"] == CLASS_OUTSIDE else fleet_ops).add(k["op"])
    if len(outside_ops) >= ruling["min_outside_operators"]:
        level = "independent"
    elif fleet_ops:
        level = "single-operator"
    else:
        level = "unwitnessed"
    if level != h["level"]:
        raise Refused(f"marker {h['level']!r} but cosigns give {level!r}")
    # Lodestar BLOCK: operator_id must EQUAL the operator that cosigned.
    if level == "single-operator" and fleet_ops != {h["operator_id"]}:
        raise OperatorMismatch("operator_id is not the cosigning fleet operator")
    return level, calls


# ---- (3) pin file -------------------------------------------------------

def _key_ok(pub: bytes) -> bool:
    import hop_certs
    return hop_certs.key_weak(pub.hex()) is None


def placeholder(signers=None, threshold=None) -> bool:
    signers = PIN_SIGNERS if signers is None else signers
    threshold = PIN_THRESHOLD if threshold is None else threshold
    return not signers or threshold <= 0 or threshold > len(signers)


def parse_pins(data: bytes, genesis_pub: str, sig_ok, signers=None, threshold=None):
    """Structure, sortedness, duplicates, Genesis exclusion, key strength and
    trailing bytes are all refused BEFORE any signature verify.
    signers/threshold overrides are TEST-ONLY: production callers pass
    neither and get the compiled-in PIN_SIGNERS/PIN_THRESHOLD (Cipher
    5157a264; enforced by the AST row in test_wok_level.py)."""
    signers = PIN_SIGNERS if signers is None else signers
    threshold = PIN_THRESHOLD if threshold is None else threshold
    if not data.startswith(PIN_MAGIC):
        raise Refused("pin magic")
    p = len(PIN_MAGIC)

    def take(n):
        nonlocal p
        if p + n > len(data):
            raise Refused("pin file truncated")
        b = data[p:p + n]
        p += n
        return b
    lid = take(32)
    version, issued = struct.unpack(">QQ", take(16))
    n_ops = take(1)[0]
    if n_ops > MAX_OPS:
        raise Refused("too many operators")
    if lid != log_id_of(genesis_pub):
        raise Refused("pin log_id")
    gen = bytes.fromhex(genesis_pub)
    keys, ops, last_op, seen = {}, {}, None, set()
    for _ in range(n_ops):
        op = take(32)
        cls, nk = take(1)[0], take(1)[0]
        if last_op is not None and op <= last_op:
            raise Refused("operators unsorted or duplicate")
        last_op = op
        if cls not in (CLASS_FLEET, CLASS_OUTSIDE):
            raise Refused("operator class")
        if nk == 0 or nk > MAX_KEYS:
            raise Refused("n_keys")
        last_k = None
        for _ in range(nk):
            pub = take(32)
            vf, vt = struct.unpack(">QQ", take(16))
            if last_k is not None and pub <= last_k:
                raise Refused("keys unsorted or duplicate")
            last_k = pub
            if pub in seen:
                raise Refused("duplicate pubkey across operators")
            seen.add(pub)
            if pub == gen:
                raise Refused("Genesis key in pin file")
            if vf > vt:
                raise Refused("validity range")
            if not _key_ok(pub):
                raise Refused("weak key in pin file")
            keys[pub.hex()] = {"op": op, "class": cls, "from": vf, "to": vt}
        ops[op] = cls
    signed = data[:p]                       # tag || body; each signer signs this
    n_sigs = take(1)[0]
    sigs = [(take(1)[0], take(64)) for _ in range(n_sigs)]
    if p != len(data):
        raise Refused("trailing bytes")
    if placeholder(signers, threshold):
        raise Refused("pin signers are a placeholder until Villhaze rules")
    idx = [i for i, _ in sigs]
    # All count/order/range checks run before any key check or verify.
    if len(sigs) < threshold:
        raise TooFewSignatures("too few pin signatures")
    if idx != sorted(set(idx)):
        raise Refused("signer indices unsorted or duplicate")
    if any(i >= len(signers) for i in idx):
        raise SignerIndexOutOfRange("signer index out of range")
    use = sigs[:threshold]                  # at most threshold-many verifies
    for i, _ in use:
        if not _key_ok(bytes.fromhex(signers[i])):
            raise Refused("weak pin-signer key")
    for i, s in use:
        if not sig_ok(signers[i], signed, s.hex()):
            raise Refused("pin file signature")
    return {"log_id": lid, "version": version, "issued_at": issued, "keys": keys, "ops": ops}


def load_pins(path: str, genesis_pub: str, sig_ok, state_path: str, signers=None, threshold=None):
    """Local path only. Highest pin_version seen is stored; rollback refused.
    signers/threshold overrides are TEST-ONLY (see parse_pins)."""
    if placeholder(signers, threshold):
        return None                         # fail closed: load no pin file
    if "://" in str(path):
        raise Refused("pin file loads from a local path only")
    with open(path, "rb") as f:
        pins = parse_pins(f.read(), genesis_pub, sig_ok, signers, threshold)
    seen = 0
    if os.path.exists(state_path):
        with open(state_path) as f:
            seen = json.load(f)["pin_version"]
    if pins["version"] < seen:
        raise Refused("pin_version rollback")
    if pins["version"] > seen:
        tmp = state_path + ".tmp"
        with open(tmp, "w") as f:
            json.dump({"pin_version": pins["version"]}, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, state_path)
    return pins
