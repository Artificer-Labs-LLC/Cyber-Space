"""Hop certificates for the witnessed window (ART-42, Examiner hop-row BLOCK).

COPIED from oracle/window-open-witness-kinds-hopcerts at 7b15ca9 (single
serializer for name_fork.py and rotate_name.py; do not fork the format here).

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
per-source bucket is charged per cert before the first verify.
"""
import hashlib
import json

CERT_DOMAIN = b"cyberspace-rotate-cert/v0\n"
CLAIM_DOMAIN = b"cyberspace-claim-anchor/v0\n"
LEAF_DOMAIN = b"\x00cyberspace-bound-leaf/v0\n"
NODE_DOMAIN = b"\x01cyberspace-merkle-node/v0\n"
EMPTY_ROOT = hashlib.sha256(b"cyberspace-merkle-empty/v0").hexdigest()
ROW_FIELDS = ("name", "i", "old", "new", "issued_at", "sig", "v", "seq", "prev_hash")

# Counters a test can read. verifies counts every signature check attempted.
STATS = {"verifies": 0}
_CACHE: dict = {}
_CACHE_MAX = 1024


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


def norm(k) -> str:
    return k.strip().lower() if isinstance(k, str) else ""


def v1_payload(name, old, new, issued_at) -> bytes:
    return (b"name-rotate|" + name.encode() + b"|" + old.encode() + b"|" + new.encode()
            + b"|" + issued_at.encode())


def v2_payload(name, seq, prev_hash, old, new, issued_at) -> bytes:
    return "|".join(["name-rotate/v2", name, str(int(seq)), prev_hash, old, new,
                     issued_at]).encode()


def claim_anchor(name: str, claim_pub: str) -> str:
    return hashlib.sha256(CLAIM_DOMAIN + f"{name}|{norm(claim_pub)}".encode()).hexdigest()


def cert_hash(row: dict) -> str:
    body = json.dumps([row["v"], row["name"], row.get("seq"), row.get("prev_hash"),
                       row["old"], row["new"], row["issued_at"], row["sig"]],
                      separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(CERT_DOMAIN + body.encode("ascii")).hexdigest()


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


def verify_hops(rows, leaves, exempt, pins, cache_key=None, charge=None):
    """(ok, why). rows: committed hop rows (shape already checked); leaves:
    [[name, pub]]; exempt: names carrying a kind row (reserve-hold or
    name-refused), whose chains are checked only through the earliest weak
    hop and do not prove into bound_root; pins: (accounts, bindings, orphans)."""
    from window_open import is_weak_pubkey
    if sodium() is None and not ALLOW_FALLBACK:
        return False, "libsodium (PyNaCl) is required for per-hop verifies; refusing"
    if cache_key is not None and cache_key in _CACHE:
        return _CACHE[cache_key]
    if charge is not None:
        charge(len(rows))
    out = _verify_uncached(rows, leaves, exempt, pins, is_weak_pubkey)
    if cache_key is not None:
        if len(_CACHE) >= _CACHE_MAX:
            _CACHE.clear()
        _CACHE[cache_key] = out
    return out


def _verify_uncached(rows, leaves, exempt, pins, is_weak):
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
    unbound = []
    for name, rs in by.items():
        seen_v2 = False
        weak_seen = False
        for j, r in enumerate(rs):
            jump = r["i"] != j
            if is_weak(r["old"]):
                break                      # nothing after a weak key is verifiable
            if r["v"] == 1 and seen_v2:
                return False, f"{name!r}: v1 cert after the v2 cutover"
            if j and not jump and not continues(rs[j - 1], r):
                return False, f"{name!r}: hop {j} does not continue hop {j - 1}"
            if r["v"] == 2:
                prev = rs[j - 1] if j else None
                if not jump and not check_prev(r, prev):
                    return False, f"{name!r}: hop {j} prev_hash does not match"
                seen_v2 = True
            if not _cert_sig_ok(r):
                return False, f"{name!r}: hop {j} cert signature does not verify"
            if is_weak(r["new"]):
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
    return True, None


# ---------------------------------------------------------------- hops_root
# Verbatim from legacy_witness.py at 7b15ca9 (KINDS track, :184, :656-671),
# carried here so the rotate path and KINDS import share one root function.
HOPS_ROOT_DOMAIN = b"cyberspace-hops-root/v0\n"


def hop_row_hash(row: dict) -> str:
    """Hash of one committed hop row {name, i, old, new}."""
    body = json.dumps([row[k] for k in ROW_FIELDS],
                      separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(HOPS_ROOT_DOMAIN + body.encode("ascii")).hexdigest()


def hops_root(rows) -> str:
    """Commitment to the hop rows of one open, in (name, i) order."""
    h = hashlib.sha256(HOPS_ROOT_DOMAIN)
    for r in rows:
        h.update(hop_row_hash(r).encode("ascii") + b"\n")
    return h.hexdigest()
