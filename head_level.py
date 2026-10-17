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
import re
import struct

MODES = ("unwitnessed", "single-operator", "independent")
TAGS = {m: f"cyberspace-head-{m}/v0\n".encode() for m in MODES}
COSIGN_PREFIX = b"cyberspace-witness-cosign/v1\n"
PIN_MAGIC = b"cyberspace-witness-pins/v1\n"
BODY = struct.Struct(">B32sQ32sQ32s32sQ")      # 153 bytes
ZERO32 = b"\x00" * 32
# One rule on every path (Villhaze ART-37 4b97c85b): a pubkey is lowercased
# at admission, the strict PUB_RE runs on the normalized value, and it is
# compared and stored lowercase from then on. Padded / non-hex is refused.
PUB_RE = re.compile(r"[0-9a-f]{64}")


def normalize_pub(pub: str):
    """Lowercased pub if it is then exactly 64 hex chars, else None."""
    p = pub.lower()
    return p if PUB_RE.fullmatch(p) else None
CLASS_FLEET, CLASS_OUTSIDE = 1, 2
MAX_OPS, MAX_KEYS = 16, 4
# Largest well-formed pin file: magic + log_id + version/issued + n_ops,
# MAX_OPS * (op + class + n_keys + MAX_KEYS * (pub + from/to)), n_sigs,
# 255 * (index + sig).
MAX_PIN_BYTES = (len(b"cyberspace-witness-pins/v1\n") + 32 + 16 + 1
                 + MAX_OPS * (32 + 1 + 1 + MAX_KEYS * (32 + 16)) + 1 + 255 * (1 + 64))

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


class MalformedCosign(Refused):
    """F-B1: a cosign entry that is not {"pub": str, "sig": str}."""


class DuplicateCosign(MalformedCosign):
    """F-B2: more than one cosign for one signer (pub). Parse-time refusal:
    never cached, never recorded as equivocation/contested, no log append."""


class PinFileTooLarge(Refused):
    """F-B3: pin file over MAX_PIN_BYTES; refused before/while bounded read."""


class UnverifiedMark(Refused):
    """Bulwark item 3 / Examiner: a mark that is not a VerifiedMark (a raw
    tuple, a forged (999999, ...)) is refused before cheap_head runs."""


class NoGrowthRootChange(Refused):
    """Bulwark item 4: tree_size == prev_size with root != prev_root."""


class ConsistencyRefused(Refused):
    """No valid RFC 9162 consistency proof from the prev mark to this head."""


class ExtensionRefused(Refused):
    """Legacy chain extension (ART-42 7e9eb9b5 (b)): the header skeletons do
    not carry the prev mark's tip to this head's root."""


class VerifiedMark:
    """Opaque continuity mark (tree_size, root). Only root_mark() (a head
    verified at the root: prev_size 0, prev_root ZERO32), advance_mark()
    (an earlier VerifiedMark plus a verified head and consistency proof) and
    extend_mark() (an earlier VerifiedMark plus a verified head and legacy
    chain extension) build one. cheap_head/verify_head refuse anything else."""
    __slots__ = ("_size", "_root")
    _token = object()

    def __init__(self, size, root, _t=None):
        if _t is not VerifiedMark._token:
            raise UnverifiedMark("VerifiedMark comes from root_mark/advance_mark/extend_mark only")
        object.__setattr__(self, "_size", size)
        object.__setattr__(self, "_root", root)

    def __setattr__(self, k, v):
        raise AttributeError("VerifiedMark is immutable")

    @property
    def size(self):
        return self._size

    @property
    def root(self):
        return self._root

    def __eq__(self, other):
        return isinstance(other, VerifiedMark) and (self._size, self._root) == (other._size, other._root)

    def __hash__(self):
        return hash((self._size, self._root))

    def __reduce__(self):
        raise TypeError("VerifiedMark does not serialize; rebuild it from the root")

    def __repr__(self):
        return f"VerifiedMark({self._size}, {self._root.hex()[:16]}...)"


def _require_verified(mark):
    if mark is not None and type(mark) is not VerifiedMark:
        raise UnverifiedMark("mark is not a VerifiedMark")


# ---- FIRST CONTACT (Villhaze ruling, ART-29 4b2e3f59) --------------------
# With NO continuity mark stored, a head is accepted only at the root:
# prev_size == 0 AND prev_root empty (all-zero). Anything else is a history
# claim and is refused (FirstContactRefused) before any verify; this
# includes Lodestar's rider (ART-42 e802b3a5): prev_size 0 beside a non-empty
# prev_root. Trust-on-first-use is rejected for heads and marks, and no
# policy switch exists here. The only bootstrap for a mark-less box is the
# lost-mark rule (re-establish from a threshold-signed head it verifies
# itself). Any change to this rule goes through the written-ruling path
# (ART-29 1e762099); test_wok_level.py has a row asserting no switch.


def log_id_of(genesis_pub_hex: str) -> bytes:
    return hashlib.sha256(bytes.fromhex(genesis_pub_hex)).digest()


def pack_head(mode, log_id, tree_size, root, prev_size, prev_root, operator_id, issued_at):
    return TAGS[MODES[mode]] + BODY.pack(mode, log_id, tree_size, root, prev_size,
                                         prev_root, operator_id, issued_at)


def cheap_head(blob: bytes, log_id: bytes, mark=None) -> dict:
    """All checks that need no signature verify. mark is a VerifiedMark,
    or None when nothing is stored yet."""
    _require_verified(mark)
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
    if mark is not None and (psize, proot) != (mark.size, mark.root):
        raise Refused("prev_* does not match the stored mark")
    if mark is None:                        # ART-29 4b2e3f59: root only
        if psize != 0:
            raise FirstContactRefused("first contact with nonzero prev_size")
        if proot != ZERO32:
            raise FirstContactRefused("first contact with prev_size 0 but non-empty prev_root")
    if psize > size:
        raise Refused("prev_size > tree_size")
    if psize == size and root != proot:
        raise NoGrowthRootChange("tree_size == prev_size but root != prev_root")
    return {"mode": mode, "level": m, "body": body, "tree_size": size, "root": root,
            "operator_id": op, "issued_at": issued}


def normalize_cosigns(cosigns):
    """F-B1/F-B2 at admission: shape, then every pub lowercased and strictly
    checked (MalformedCosign), then duplicates on the NORMALIZED pub
    (DuplicateCosign: A and A-upper are one signer). Returns new entries
    {pub: lowercase, sig}; callers use and store only these."""
    if not isinstance(cosigns, list) or not all(
            isinstance(c, dict) and isinstance(c.get("pub"), str) and isinstance(c.get("sig"), str)
            for c in cosigns):
        raise MalformedCosign("cosign entries must be {pub: str, sig: str}")
    out = []
    for c in cosigns:
        pub = normalize_pub(c["pub"])
        if pub is None:
            raise MalformedCosign("cosign pub must be 64 hex chars")
        out.append({"pub": pub, "sig": c["sig"]})
    if len({c["pub"] for c in out}) != len(out):
        raise DuplicateCosign("at most one cosign per signer")
    return out


def select_cosigns(cosigns, keys):
    """Unpinned keys dropped before any verify; one per pinned key; capped
    at the pin-list size."""
    kept, seen = [], set()
    for c in cosigns:
        if len(kept) >= len(keys):
            break
        pub = c.get("pub", "")
        if pub in keys and pub not in seen:
            seen.add(pub)
            kept.append((pub, c.get("sig", "")))
    return kept


def verify_head(blob, genesis_sig, genesis_pub, cosigns, pins, sig_ok, mark=None, ruling=RULING):
    """pins comes from load_pins() (the shipped file), never a response.
    pins=None (fail closed: placeholder signers / threshold 0) rates every
    head at most unwitnessed. Returns (level, cosign_verify_calls)."""
    if pins is None:
        pins = {"keys": {}}
    _require_verified(mark)                 # Examiner: refused before cheap_head runs
    h = cheap_head(blob, log_id_of(genesis_pub), mark)            # (2) before any verify
    cosigns = normalize_cosigns(cosigns)
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


# ---- continuity marks (Bulwark rule 3, item 3) -------------------------

def _node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def verify_consistency(first, second, first_hash, second_hash, proof) -> bool:
    """RFC 9162 2.1.4.2. first >= 1; first == second needs an empty proof
    and equal roots."""
    if type(first) is not int or type(second) is not int or first < 1 or first > second:
        return False
    if not isinstance(proof, (list, tuple)) or any(type(p) is not bytes or len(p) != 32 for p in proof):
        return False
    if first == second:
        return len(proof) == 0 and first_hash == second_hash
    path = list(proof)
    if first & (first - 1) == 0:
        path = [first_hash] + path
    if not path:
        return False
    fn, sn = first - 1, second - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = _node(c, fr)
            sr = _node(c, sr)
            if not fn & 1:
                while True:
                    fn >>= 1
                    sn >>= 1
                    if fn & 1 or fn == 0:
                        break
        else:
            sr = _node(sr, c)
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr == first_hash and sr == second_hash


def root_mark(blob, genesis_sig, genesis_pub, cosigns, pins, sig_ok, ruling=RULING):
    """A head verified at the root (mark None: prev_size 0, prev_root
    ZERO32) -> (level, VerifiedMark(tree_size, root))."""
    level, _ = verify_head(blob, genesis_sig, genesis_pub, cosigns, pins, sig_ok, mark=None, ruling=ruling)
    h = cheap_head(blob, log_id_of(genesis_pub), None)
    return level, VerifiedMark(h["tree_size"], h["root"], VerifiedMark._token)


def advance_mark(prev, blob, genesis_sig, genesis_pub, cosigns, pins, sig_ok, proof, ruling=RULING):
    """An earlier VerifiedMark, a head whose prev_* is that mark, and an
    RFC 9162 consistency proof prev -> head -> (level, VerifiedMark)."""
    if type(prev) is not VerifiedMark:
        raise UnverifiedMark("advance_mark needs a VerifiedMark")
    level, _ = verify_head(blob, genesis_sig, genesis_pub, cosigns, pins, sig_ok, mark=prev, ruling=ruling)
    h = cheap_head(blob, log_id_of(genesis_pub), prev)
    if not verify_consistency(prev.size, h["tree_size"], prev.root, h["root"], proof):
        raise ConsistencyRefused("consistency proof from the prev mark does not verify")
    return level, VerifiedMark(h["tree_size"], h["root"], VerifiedMark._token)


def extend_mark(prev, blob, genesis_sig, genesis_pub, cosigns, pins, sig_ok, skeletons, ruling=RULING):
    """Legacy logs (Villhaze ART-42 7e9eb9b5 (b)): their root is a hash-chain
    tip (entry_hash at seq), not an RFC 9162 root, so a mark advances on the
    header skeletons prev.size+1..tree_size, checked by
    legacy_witness.verify_extension, instead of a consistency proof. An
    earlier VerifiedMark, a head whose prev_* is that mark, and the
    skeletons -> (level, VerifiedMark). The extension is checked (hashing
    only) before any signature verify."""
    import legacy_witness as lw
    if type(prev) is not VerifiedMark:
        raise UnverifiedMark("extend_mark needs a VerifiedMark")
    h = cheap_head(blob, log_id_of(genesis_pub), prev)
    ok, why = lw.verify_extension(skeletons, log_id_of(genesis_pub).hex(), prev.size, prev.root.hex(),
                                  h["tree_size"], h["root"].hex())
    if not ok:
        raise ExtensionRefused(f"chain extension from the prev mark refused: {why}")
    level, _ = verify_head(blob, genesis_sig, genesis_pub, cosigns, pins, sig_ok, mark=prev, ruling=ruling)
    return level, VerifiedMark(h["tree_size"], h["root"], VerifiedMark._token)


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
    if os.path.getsize(path) > MAX_PIN_BYTES:
        raise PinFileTooLarge("pin file too large")     # before any read
    with open(path, "rb") as f:
        data = f.read(MAX_PIN_BYTES + 1)                 # bounded even if it grew
    if len(data) > MAX_PIN_BYTES:
        raise PinFileTooLarge("pin file too large")
    pins = parse_pins(data, genesis_pub, sig_ok, signers, threshold)
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
