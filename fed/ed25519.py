"""Ed25519 signatures (RFC 8032) — minimal reference implementation, stdlib only.

Kept dependency-free so any node can verify messages with zero installs.
Tested against the RFC 8032 known-answer vector in envelope.__main__.
"""

import hashlib

_B = 256
_Q = (1 << 255) - 19
_D = (-121665 * pow(121666, _Q - 2, _Q)) % _Q
_I = pow(2, (_Q - 1) // 4, _Q)
_L = 2**252 + 27742317777372353535851937790883648493


def _H(m: bytes) -> bytes:
    return hashlib.sha512(m).digest()


def _inv(x: int) -> int:
    return pow(x, _Q - 2, _Q)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(_D * y * y + 1)
    x = pow(xx, (_Q + 3) // 8, _Q)
    if (x * x - xx) % _Q != 0:
        x = (x * _I) % _Q
    if x % 2 != 0:
        x = _Q - x
    return x


_BY = (4 * _inv(5)) % _Q
_BX = _xrecover(_BY)
_BPOINT = (_BX % _Q, _BY % _Q)


def _edwards(P, Q):
    # Twisted-Edwards addition law, a = -1 (Ed25519): the y-numerator
    # carries a MINUS a -> PLUS x1*x2. The a=+1 variant here is a classic
    # transcription trap; verified against the RFC 8032 test vector.
    x1, y1 = P
    x2, y2 = Q
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + _D * x1 * x2 * y1 * y2)
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - _D * x1 * x2 * y1 * y2)
    return (x3 % _Q, y3 % _Q)


def _scalarmult(P, e: int):
    if e == 0:
        return (0, 1)
    Q = _scalarmult(P, e // 2)
    Q = _edwards(Q, Q)
    if e & 1:
        Q = _edwards(Q, P)
    return Q


def _encodeint(y: int) -> bytes:
    bits = [(y >> i) & 1 for i in range(_B)]
    return bytes(sum(bits[i * 8 + j] << j for j in range(8)) for i in range(_B // 8))


def _encodepoint(P) -> bytes:
    x, y = P
    bits = [(y >> i) & 1 for i in range(_B - 1)] + [x & 1]
    return bytes(sum(bits[i * 8 + j] << j for j in range(8)) for i in range(_B // 8))


def _bit(h: bytes, i: int) -> int:
    return (h[i // 8] >> (i % 8)) & 1


def publickey(sk: bytes) -> bytes:
    """Derive the 32-byte public key from a 32-byte secret seed."""
    h = _H(sk)
    a = 2 ** (_B - 2) + sum(2**i * _bit(h, i) for i in range(3, _B - 2))
    return _encodepoint(_scalarmult(_BPOINT, a))


def _decodepoint(s: bytes):
    y = sum(2**i * _bit(s, i) for i in range(0, _B - 1))
    sign = _bit(s, _B - 1)
    x = _xrecover(y)
    if x & 1 != sign:
        x = _Q - x
    P = (x, y)
    if (-x * x + y * y - 1 - _D * x * x * y * y) % _Q != 0:
        raise ValueError("point not on curve")
    return P


def sign(m: bytes, sk: bytes, pk: bytes) -> bytes:
    """Sign message bytes; returns the 64-byte signature."""
    h = _H(sk)
    a = 2 ** (_B - 2) + sum(2**i * _bit(h, i) for i in range(3, _B - 2))
    r = int.from_bytes(_H(h[_B // 8:] + m), "little")
    R = _scalarmult(_BPOINT, r)
    S = (r + int.from_bytes(_H(_encodepoint(R) + pk + m), "little") * a) % _L
    return _encodepoint(R) + _encodeint(S)


_IDENT = (0, 1)


def _decodepoint_strict(s: bytes):
    """Canonical-only point decode (RFC 8032 5.1.3, strict): the encoded y
    must be < p, x = 0 with the sign bit set is refused, the point must be
    on the curve, and re-encoding must reproduce the input bytes exactly."""
    if len(s) != _B // 8:
        raise ValueError("bad point length")
    y = int.from_bytes(s, "little") & ((1 << 255) - 1)
    if y >= _Q:
        raise ValueError("non-canonical y")
    sign = s[31] >> 7
    x = _xrecover(y) % _Q
    if x == 0 and sign:
        raise ValueError("non-canonical x sign")
    if x & 1 != sign:
        x = (_Q - x) % _Q
    P = (x, y)
    if (-x * x + y * y - 1 - _D * x * x * y * y) % _Q != 0:
        raise ValueError("point not on curve")
    if _encodepoint(P) != bytes(s):
        raise ValueError("non-canonical encoding")
    return P


def _is_small_order(P) -> bool:
    """True when 8*P is the identity (P lies in the 8-torsion subgroup)."""
    Q = P
    for _ in range(3):
        Q = _edwards(Q, Q)
    return Q == _IDENT


def checkvalid(s: bytes, m: bytes, pk: bytes) -> bool:
    """Verify a signature. Returns False instead of raising on any failure.

    Strict, each step failing closed, in order:
      1. pk and R must be canonical encodings (y < p, decode/re-encode
         round-trips byte-for-byte);
      2. S < L (RFC 8032 5.1.7);
      3. neither A nor R may be small-order (8*P == identity);
      4. the cofactorless verification equation, unchanged.
    """
    try:
        if len(s) != _B // 4 or len(pk) != _B // 8:
            return False
        R = _decodepoint_strict(s[:_B // 8])
        A = _decodepoint_strict(pk)
        S = int.from_bytes(s[_B // 8:_B // 4], "little")
        if S >= _L:
            return False
        if _is_small_order(A) or _is_small_order(R):
            return False
        h = int.from_bytes(_H(_encodepoint(R) + pk + m), "little")
        return _scalarmult(_BPOINT, S) == _edwards(R, _scalarmult(A, h))
    except Exception:
        return False


# --------------------------------------------------------------- libsodium
# The rotation-cert path verifies through libsodium (PyNaCl). The strict
# checks above (canonical R and A, S < L, no small-order R or A) still run
# first in pure Python; only the verification equation moves to libsodium.
# If libsodium is missing, this fails CLOSED and names the cause.
SODIUM_MISSING = "libsodium (PyNaCl) unavailable: rotation-cert verify fails closed"
try:
    from nacl.bindings import crypto_sign_open as _sodium_open

    def _sodium_verify(sig, msg, pk):
        _sodium_open(sig + msg, pk)
    from nacl.exceptions import BadSignatureError as _SodiumBadSig
    SODIUM_ERROR = None
except Exception:  # pragma: no cover - exercised by the fail-closed row
    _sodium_verify = None
    _SodiumBadSig = Exception
    SODIUM_ERROR = SODIUM_MISSING


def checkvalid_sodium(s: bytes, m: bytes, pk: bytes) -> bool:
    """Strict checks (as checkvalid steps 1-3), then libsodium's verify.
    Returns False on any failure, including libsodium being missing."""
    if _sodium_verify is None or not bundled_probe_ok():
        return False
    try:
        if len(s) != _B // 4 or len(pk) != _B // 8:
            return False
        R = _decodepoint_strict(s[:_B // 8])
        A = _decodepoint_strict(pk)
        if int.from_bytes(s[_B // 8:_B // 4], "little") >= _L:
            return False
        if _is_small_order(A) or _is_small_order(R):
            return False
        _sodium_verify(bytes(s), bytes(m), bytes(pk))
        return True
    except _SodiumBadSig:
        return False
    except Exception:
        return False


try:
    from nacl.bindings import crypto_core_ed25519_is_valid_point as _sodium_valid_point
except Exception:  # pragma: no cover - exercised by the fail-closed row
    _sodium_valid_point = None


# Cipher (BLOCK-class on 0dadc92): no version-number gate. A version read
# via ctypes.find_library describes the SYSTEM libsodium, while verify and
# is_valid_point run in PyNaCl's BUNDLED copy. So the gate probes the
# bundled functions themselves, once at startup: is_valid_point must refuse
# a known mixed-order point, and crypto_sign_open must refuse a known
# non-canonical (S + L) signature. No find_library, no fallback.
_PROBE_SEED = bytes(range(32))
_PROBE_MSG = b"cyberspace-sodium-probe/v1"
# Base point + an order-8 torsion point: on the curve, canonical, not in
# the prime-order subgroup.
_PROBE_MIXED_HEX = None


class SodiumProbeFailed(RuntimeError):
    pass


def _probe_vectors():
    """(mixed_point, valid_point, sig, noncanonical_sig, pk, msg)."""
    base = _encodepoint(_BPOINT)
    t8 = _decodepoint_strict(bytes.fromhex(
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"))
    mixed = _encodepoint(_edwards(_BPOINT, t8))
    pk = publickey(_PROBE_SEED)
    sig = sign(_PROBE_MSG, _PROBE_SEED, pk)
    S = int.from_bytes(sig[32:], "little") + _L
    bad = sig[:32] + S.to_bytes(32, "little")
    return mixed, base, sig, bad, pk, _PROBE_MSG


def _run_probe() -> str | None:
    """None when the bundled library behaves; else why not."""
    if _sodium_valid_point is None or _sodium_verify is None:
        return SODIUM_MISSING
    mixed, base, sig, bad, pk, msg = _probe_vectors()
    try:
        if not _sodium_valid_point(base):
            return "bundled is_valid_point refuses the base point"
        if _sodium_valid_point(mixed):
            return "bundled is_valid_point ACCEPTS a mixed-order point"
    except Exception as e:
        return f"bundled is_valid_point raised: {e!r}"
    try:
        _sodium_verify(sig, msg, pk)
    except Exception:
        return "bundled crypto_sign_open refuses a valid signature"
    try:
        _sodium_verify(bad, msg, pk)
        return "bundled crypto_sign_open ACCEPTS a non-canonical (S+L) signature"
    except Exception:
        return None


_PROBE_RESULT: list = []


def bundled_probe() -> str | None:
    """Cached startup probe result (None = OK)."""
    if not _PROBE_RESULT:
        _PROBE_RESULT.append(_run_probe())
    return _PROBE_RESULT[0]


def reset_probe() -> None:
    _PROBE_RESULT.clear()


def bundled_probe_ok() -> bool:
    return bundled_probe() is None


def require_bundled_sodium() -> None:
    """Startup: if the bundled library ACCEPTS either probe vector, refuse to
    start. (Missing PyNaCl is not a start refusal: admission refuses.)"""
    why = bundled_probe()
    if why is not None and why != SODIUM_MISSING:
        raise SodiumProbeFailed(f"refusing to start: {why}")


def sodium_key_ok(pk: bytes):
    """libsodium crypto_core_ed25519_is_valid_point: canonical encoding,
    on the curve, not small order, and in the prime-order subgroup (so
    mixed-order keys refuse). Returns None when libsodium is missing; the
    caller must refuse, never fall back. Equivalent to window_open.
    weak_reason on Cipher's key corpus with zero disagreements (belt row)."""
    if _sodium_valid_point is None or not bundled_probe_ok():
        return None
    try:
        return bool(_sodium_valid_point(bytes(pk)))
    except Exception:
        return False
