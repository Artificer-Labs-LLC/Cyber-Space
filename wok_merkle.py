"""Test helper: RFC 9162 2.1 Merkle tree hash and consistency proofs
(PROOF / SUBPROOF), used by test_wok_level.py and test_wok_wiring.py to
build real roots for head_level marks. Not imported by production code."""
import hashlib


def _largest_pow2_below(n):
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def mth(leaves):
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return hashlib.sha256(b"\x00" + leaves[0]).digest()
    k = _largest_pow2_below(n)
    return hashlib.sha256(b"\x01" + mth(leaves[:k]) + mth(leaves[k:])).digest()


def _subproof(m, leaves, b):
    n = len(leaves)
    if m == n:
        return [] if b else [mth(leaves)]
    k = _largest_pow2_below(n)
    if m <= k:
        return _subproof(m, leaves[:k], b) + [mth(leaves[k:])]
    return _subproof(m - k, leaves[k:], False) + [mth(leaves[:k])]


def proof(m, leaves):
    """Consistency proof from the first m leaves to all of them (m >= 1)."""
    return _subproof(m, leaves, True)


def leaves(tag, n, share=0, base="a"):
    """n leaves; the first `share` come from `base` (forks share a prefix)."""
    return [f"{base}-{i}".encode() if i < share else f"{tag}-{i}".encode() for i in range(n)]
