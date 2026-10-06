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


def checkvalid(s: bytes, m: bytes, pk: bytes) -> bool:
    """Verify a signature. Returns False instead of raising on any failure."""
    try:
        if len(s) != _B // 4 or len(pk) != _B // 8:
            return False
        R = _decodepoint(s[:_B // 8])
        A = _decodepoint(pk)
        S = int.from_bytes(s[_B // 8:_B // 4], "little")
        h = int.from_bytes(_H(_encodepoint(R) + pk + m), "little")
        return _scalarmult(_BPOINT, S) == _edwards(R, _scalarmult(A, h))
    except Exception:
        return False
