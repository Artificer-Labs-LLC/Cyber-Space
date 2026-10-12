"""Hop certificates for the witnessed window (ART-42, Examiner hop-row BLOCK).

Board-recommended path; Villhaze may rule otherwise, so everything about the
cert format, roots and node B's per-hop rules lives in this one module.

Rotation certs (name_rotations.issued_at / signature, core_serve.py:699-707):
  v1  name-rotate|<name>|<old_pub>|<new_pub>|<issued_at>          (rotate_name.py:84-89)
  v2  name-rotate/v2|<name>|<seq>|<prev_hash>|<old_pub>|<new_pub>|<issued_at>
Both are signed by the OLD key. prev_hash is cert_hash() of the full previous
cert, signature included. The first cert of a chain that starts in v2 has
prev_hash = claim_anchor(name, first old_pub), which binds the chain's first
old_pub to the claim key. v1 option (b): every v1 cert is frozen under
v1_frozen_root; the first v2 cert's prev_hash must be the last v1 cert's
hash; a v1 cert after any v2 cert in the same chain is refused.

bound_root: Merkle root over (name, bound_pub) leaves sorted by name.

Per-hop verifies go through libsodium (PyNaCl) only, fail closed when it is
missing, are cached on (log_id, head_hash, hops_root), and the caller's
per-source bucket is charged CERT_COST_US (2 key checks + 1 verify) per
cert before the first weak_reason or verify; none of it runs under core._db_lock.
"""
import hashlib
import json
from collections import OrderedDict

LEAF_DOMAIN = b"\x00cyberspace-bound-leaf/v0\n"
NODE_DOMAIN = b"\x01cyberspace-merkle-node/v0\n"
EMPTY_ROOT = hashlib.sha256(b"cyberspace-merkle-empty/v0").hexdigest()
# The v2 serializer lives in hop_cert_format (pure, no verify path); the
# byte format is unchanged and re-exported here.
from hop_cert_format import (CERT_DOMAIN, CLAIM_DOMAIN, ROW_FIELDS, cert_hash,  # noqa: E402,F401
                             claim_anchor, norm, v1_payload, v2_payload)

# Counters a test can read. verifies counts every signature check attempted.
STATS = {"verifies": 0, "weak": 0}

# Pre-verify cost model (Cipher fast path, Bulwark conditions). The key
# check is libsodium crypto_core_ed25519_is_valid_point, equivalent to
# window_open.weak_reason on Cipher's 51 vectors plus the mixed-order,
# small-order, identity and non-canonical rows (0 disagreements; 139 keys
# compared). Box measurement (load ~21): key check 43-67 us, verify 55-129 us.
# Each cert is charged 2 key checks + 1 verify BEFORE either runs.
# Caps follow Examiner's measurements (is_valid_point 0.087 ms,
# checkvalid_sodium 1.9 ms per unit): about 2.7 ms per cert unit.
KEYCHECK_US = 87
VERIFY_US = 1900
CERT_COST_US = 2700                               # >= 2*87 + 1900 = 2074 us
# Pass-only weak_reason cache, bounded per sender. A refusal is never cached.
_KEY_OK: dict = {}
KEY_OK_PER_SENDER = 512


MIN_LIBSODIUM = (1, 0, 18)   # is_valid_point gained its subgroup test in 1.0.18
# 4P for a key P with an order-8 torsion part is not prime order; used as a
# behavioural probe when the library does not export its version string.
_PROBE_MIXED = "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"


def _version_from_symbol():
    import ctypes
    import ctypes.util
    cands = []
    try:
        import nacl._sodium as s
        cands.append(s.__file__)
    except Exception:
        pass
    found = ctypes.util.find_library("sodium")
    if found:
        cands.append(found)
    for c in cands:
        try:
            f = ctypes.CDLL(c).sodium_version_string
            f.restype = ctypes.c_char_p
            return tuple(int(x) for x in f().decode().split(".")[:3])
        except Exception:
            continue
    return None


def libsodium_version() -> tuple:
    """Detected once at startup (see _detect_version); patchable by the belt."""
    return _detect_version()


import functools  # noqa: E402


@functools.lru_cache(maxsize=1)
def _detect_version() -> tuple:
    """Version of the libsodium PyNaCl runs on. PyNaCl's bundled build does not
    export sodium_version_string; then the version is >= 1.0.18 only if
    is_valid_point refuses a small-order point added to a valid key (the
    1.0.18 subgroup test) and PyNaCl is >= 1.4 (bundles 1.0.18+); else (0,0,0)."""
    v = _version_from_symbol()
    if v is not None:
        return v
    try:
        import nacl
        from nacl.bindings import crypto_core_ed25519_is_valid_point as vp
        from nacl.bindings import crypto_core_ed25519_add
        base = bytes.fromhex("5866666666666666666666666666666666666666666666666666666666666666")
        mixed = crypto_core_ed25519_add(base, bytes.fromhex(_PROBE_MIXED))
        pv = tuple(int(x) for x in nacl.__version__.split(".")[:2])
        if pv >= (1, 4) and vp(base) and not vp(mixed):
            return MIN_LIBSODIUM
    except Exception:
        pass
    return (0, 0, 0)


def version_ok() -> bool:
    """Examiner: refuse admission below libsodium 1.0.18. Checked at import
    (startup) and on every admission."""
    return libsodium_version() >= MIN_LIBSODIUM


def sodium_point():
    """libsodium's subgroup/canonical point check, or None (missing, or
    libsodium below 1.0.18). No fallback."""
    if not version_ok():
        return None
    try:
        from nacl.bindings import crypto_core_ed25519_is_valid_point
        return crypto_core_ed25519_is_valid_point
    except Exception:
        return None


def _weak_uncached(pub_hex):
    """None for a canonical, prime-order, non-identity point; else why not.
    libsodium only: with the binding missing this raises, never falls back."""
    STATS["weak"] += 1
    vp = sodium_point()
    if vp is None:
        raise SodiumMissing(LIBSODIUM_MISSING)
    try:
        raw = bytes.fromhex(pub_hex)
    except (TypeError, ValueError):
        return "not hex"
    if len(raw) != 32:
        return "not 32 bytes"
    return None if vp(raw) else "not a canonical prime-order point (libsodium is_valid_point)"


def key_weak(pub_hex, sender="local"):
    """weak_reason with a pass-only cache bounded per sender."""
    ok = _KEY_OK.setdefault(sender, OrderedDict())
    if pub_hex in ok:
        ok.move_to_end(pub_hex)
        return None
    why = _weak_uncached(pub_hex)
    if why is None:
        evict_lru(ok, KEY_OK_PER_SENDER)
        ok[pub_hex] = True
    return why


def evict_lru(d: OrderedDict, cap: int) -> None:
    """Drop least-recently-used entries until there is room for one more.
    Never a wholesale clear (Bulwark)."""
    while len(d) >= cap:
        d.popitem(last=False)


def canonical(r) -> bool:
    """Step 1: canonical decode of old/new (64 lowercase hex) and sig (128)."""
    def hx(v, n):
        return isinstance(v, str) and len(v) == n and v == v.lower() and all(
            c in "0123456789abcdef" for c in v)
    return hx(r["old"], 64) and hx(r["new"], 64) and hx(r["sig"], 128)


PRECHECK = True   # belt mutant flips this off
_CACHE: OrderedDict = OrderedDict()
_CACHE_MAX = 1024


LIBSODIUM_MISSING = ("refused: libsodium is not installed (PyNaCl import failed) or is "
                     "older than 1.0.18; per-hop cert verifies and key checks run through "
                     "libsodium only and never fall back")

# Never True on a node. The belt flips it (with a pure-Python verifier) to
# show the refusal happens before any verify.
ALLOW_FALLBACK = False


class SodiumMissing(Exception):
    pass


def _load_sodium():
    try:
        import nacl.exceptions
        import nacl.signing
        return nacl.signing, nacl.exceptions
    except Exception:
        return None


def sodium():
    """(nacl.signing, nacl.exceptions) or None. Tests stub this out."""
    return _load_sodium()


def _fallback_verify(pub_hex, msg, sig_hex):
    """Pure-Python verifier. Never used by node B: libsodium or refuse."""
    raise SodiumMissing("libsodium (PyNaCl) is required for per-hop verifies")


def verify_sig(pub_hex: str, msg: bytes, sig_hex: str) -> bool:
    lib = sodium()
    if lib is None:
        return _fallback_verify(pub_hex, msg, sig_hex)
    signing, exc = lib
    STATS["verifies"] += 1
    try:
        signing.VerifyKey(bytes.fromhex(pub_hex)).verify(msg, bytes.fromhex(sig_hex))
        return True
    except (exc.BadSignatureError, ValueError, TypeError, exc.CryptoError):
        return False


def _merkle(hashes: list) -> str:
    if not hashes:
        return EMPTY_ROOT
    level = list(hashes)
    while len(level) > 1:
        nxt = []
        for j in range(0, len(level), 2):
            right = level[j + 1] if j + 1 < len(level) else level[j]
            nxt.append(hashlib.sha256(NODE_DOMAIN + bytes.fromhex(level[j])
                                      + bytes.fromhex(right)).hexdigest())
        level = nxt
    return level[0]


def leaf_hash(name: str, pub: str) -> str:
    return hashlib.sha256(LEAF_DOMAIN + json.dumps([name, norm(pub)]).encode()).hexdigest()


def bound_root(leaves) -> str:
    """leaves: [[name, bound_pub], ...]; sorted by name before hashing."""
    return _merkle([leaf_hash(n, p) for n, p in sorted(leaves, key=lambda x: x[0])])


# orphans_root (Loom, ART-42): PENDING Villhaze ratification. The orphan
# leaves (name, chain-end pub) of clean chains with no bound leaf are
# witness-signed in head_bytes, so node B compares leaves, not just the
# CYBERNET_GENESIS_ORPHANS count.
ORPHAN_DOMAIN = b"\x00cyberspace-orphan-leaf/v0\n"


def orphans_root(leaves) -> str:
    return _merkle([hashlib.sha256(ORPHAN_DOMAIN + f"{n}\n{norm(p)}".encode()).hexdigest()
                    for n, p in sorted((n, norm(p)) for n, p in leaves)])


def orphan_leaves(rows, leaves, exempt) -> list:
    """Writer and node B: clean, non-exempt chains with no bound leaf."""
    bound = {n for n, _ in leaves}
    last = {}
    for r in rows:
        last[r["name"]] = norm(r["new"])
    return sorted([n, p] for n, p in last.items() if n not in bound and n not in exempt)


def orphans_match(unbound_leaves, shipped) -> bool:
    """Leaf-for-leaf compare. Separate so a belt mutant can compare counts only."""
    return sorted(map(tuple, unbound_leaves)) == sorted((n, norm(p)) for n, p in shipped)


def v1_member(r, earlier, frozen) -> bool:
    """Loom row 2: a name's first v2 cert either opens a v2-only chain
    (prev_hash = claim_anchor, no v1 cert for the name) or chains onto a
    v1 cert whose full hash (signature included) is a v1_frozen_root leaf.
    Holds at a jump too, where check_prev cannot see the previous row."""
    if not any(e["v"] == 1 for e in earlier):
        return r["prev_hash"] == claim_anchor(r["name"], r["old"]) or r["prev_hash"] in frozen
    return r["prev_hash"] in frozen


def v1_frozen_root(rows) -> str:
    return _merkle([cert_hash(r) for r in rows if r.get("v") == 1])


def row_ok(r) -> bool:
    return (isinstance(r, dict) and set(r) == set(ROW_FIELDS)
            and isinstance(r["name"], str) and type(r["i"]) is int and r["i"] >= 0
            and all(isinstance(r[k], str) for k in ("old", "new", "issued_at", "sig"))
            and r["v"] in (1, 2)
            and ((r["v"] == 1 and r["seq"] is None and r["prev_hash"] is None)
                 or (r["v"] == 2 and type(r["seq"]) is int and isinstance(r["prev_hash"], str))))


def _cert_sig_ok(r) -> bool:
    if r["v"] == 2:
        msg = v2_payload(r["name"], r["seq"], r["prev_hash"], r["old"], r["new"], r["issued_at"])
    else:
        msg = v1_payload(r["name"], r["old"], r["new"], r["issued_at"])
    return verify_sig(norm(r["old"]), msg, r["sig"])


def check_prev(r, prev_row) -> bool:
    """v2 prev_hash rule. Separate so a belt mutant can skip it."""
    want = cert_hash(prev_row) if prev_row is not None else claim_anchor(r["name"], r["old"])
    return r["prev_hash"] == want


def continues(prev_row, r) -> bool:
    return norm(r["old"]) == norm(prev_row["new"])


def bound_ok(bound_pub: str, last_new: str) -> bool:
    return bound_pub == norm(last_new)


def leaf_count_ok(n_leaves: int, bindings: int) -> bool:
    return n_leaves == bindings


def bound_diff(unbound: list, orphans: int) -> str | None:
    """Clean chains with no bound leaf must be exactly the pinned orphans."""
    if len(unbound) != orphans:
        return f"chain names without a bound leaf {sorted(unbound)} != pinned orphans {orphans}"
    return None


def verify_hops(rows, leaves, exempt, pins, cache_key=None, charge=None, sender="local",
                orphans=None):
    """(ok, why). rows: committed hop rows (shape already checked); leaves:
    [[name, pub]]; exempt: names carrying a kind row (reserve-hold or
    name-refused), whose chains are checked only through the earliest weak
    hop and do not prove into bound_root; pins: (accounts, bindings, orphans)."""
    if (sodium() is None or sodium_point() is None) and not ALLOW_FALLBACK:
        return False, LIBSODIUM_MISSING
    if cache_key is not None and cache_key in _CACHE:
        _CACHE.move_to_end(cache_key)
        return _CACHE[cache_key]
    if charge is not None:
        charge(len(rows) * CERT_COST_US)
    out = _verify_uncached(rows, leaves, exempt, pins, lambda k: key_weak(k, sender), orphans)
    if cache_key is not None:
        evict_lru(_CACHE, _CACHE_MAX)
        _CACHE[cache_key] = out
    return out


def _verify_uncached(rows, leaves, exempt, pins, point_bad, orphans=None):
    bound = {}
    for n, p in leaves:
        if n in bound:
            return False, f"duplicate bound leaf {n!r}"
        bound[n] = norm(p)
    if not leaf_count_ok(len(bound), pins[1]):
        return False, f"bound leaves {len(bound)} != pinned bindings {pins[1]}"
    by = {}
    for r in rows:
        by.setdefault(r["name"], []).append(r)
    frozen = {cert_hash(r) for r in rows if r["v"] == 1}   # v1_frozen_root leaves
    unbound = []
    for name, rs in by.items():
        seen_v2 = False
        weak_seen = False
        for j, r in enumerate(rs):
            jump = r["i"] != j
            # Order per hop: canonical decode -> weak_reason(old), weak_reason(new) -> libsodium.
            if not canonical(r):
                return False, f"{name!r}: hop {j} is not canonically encoded"
            w_old = w_new = None
            if PRECHECK:
                w_old = point_bad(r["old"])
                if w_old:
                    if name in exempt:
                        break              # nothing after a weak key is verifiable
                    return False, f"{name!r}: hop {j} old_pub is weak: {w_old}"
                w_new = point_bad(r["new"])
                if w_new and name not in exempt:
                    return False, f"{name!r}: hop {j} new_pub is weak: {w_new}"
            if r["v"] == 1 and seen_v2:
                return False, f"{name!r}: v1 cert after the v2 cutover"
            if j and not jump and not continues(rs[j - 1], r):
                return False, f"{name!r}: hop {j} does not continue hop {j - 1}"
            if r["v"] == 2:
                prev = rs[j - 1] if j else None
                if not jump and not check_prev(r, prev):
                    return False, f"{name!r}: hop {j} prev_hash does not match"
                if not seen_v2 and not v1_member(r, rs[:j], frozen):
                    return False, (f"{name!r}: hop {j} first v2 cert chains onto a v1 cert "
                                   "not in v1_frozen_root")
                seen_v2 = True
            if not _cert_sig_ok(r):
                return False, f"{name!r}: hop {j} cert signature does not verify"
            if w_new:
                weak_seen = True
                break
        if name in exempt or weak_seen:
            continue
        if name in bound:
            if not bound_ok(bound[name], rs[-1]["new"]):
                return False, f"{name!r}: chain does not prove into bound_root"
        else:
            unbound.append(name)
    why = bound_diff(unbound, pins[2])
    if why:
        return False, why
    if orphans is not None:
        if len(orphans) != pins[2]:
            return False, f"orphan leaves {len(orphans)} != pinned orphans {pins[2]}"
        mine = [[n, norm(by[n][-1]["new"])] for n in unbound]
        if not orphans_match(mine, orphans):
            return False, "orphan leaves do not match the unbound chains"
    return True, None


def verify_path(pub_hex, msg: bytes, sig_hex, sender="local") -> bool:
    """One signature through node B's per-hop order: canonical decode, then
    weak_reason(pub), then libsodium. Used by the vector rows."""
    if not (isinstance(pub_hex, str) and isinstance(sig_hex, str)
            and canonical({"old": pub_hex, "new": pub_hex, "sig": sig_hex})):
        return False
    if PRECHECK and key_weak(pub_hex, sender):
        return False
    return verify_sig(pub_hex, msg, sig_hex)


STARTUP_VERSION = libsodium_version()     # startup check (logged by callers)
