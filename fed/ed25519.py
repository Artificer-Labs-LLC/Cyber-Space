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


def _check_seed(sk: bytes) -> bytes:
    # Direct library seat gate, twin of envelope's argument gates
    # (5c5f16c): a non-bytes or non-32-byte seed escaped as TypeError
    # from hashlib/concat — or worse, silently derived/signed, since
    # _H hashes any length (an empty or 31-byte seed produced a key
    # no 32-byte-seed holder can reproduce). Refuse as ValueError.
    if not isinstance(sk, bytes) or len(sk) != _B // 8:
        raise ValueError("secret seed must be 32 bytes")
    return sk


def _check_key(name: str, value: bytes) -> bytes:
    if not isinstance(value, bytes) or len(value) != _B // 8:
        raise ValueError(f"{name} must be 32 bytes")
    return value


def publickey(sk: bytes) -> bytes:
    """Derive the 32-byte public key from a 32-byte secret seed."""
    h = _H(_check_seed(sk))
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
    if not isinstance(m, bytes):
        raise ValueError("message must be bytes")
    _check_seed(sk)
    _check_key("public key", pk)
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
        return _scalarmult(_BPOINT, S) == _edwards(R, _scalarmult(A, h % _L))
    except Exception:
        return False

