#!/usr/bin/env python3
"""r7 item-7 standalone: pin the STRICT POINT DECODE (non-canonical encodings).

Why this file exists: Controller and Meridian each removed the strict decode
from checkvalid / _decodepoint_strict and found that every earlier test
(including the 91-row three-way) still passed. Nothing pinned it. This file does.

Rows:
  A. decode level (THE PIN). For y in {3,4,5,6,9,10,14,15,16,18} (the y < 19
     values whose y+p still fits in 255 bits and which are curve points), the
     non-canonical encoding (y+p little-endian, sign bit 0 and 1) is REFUSED by
     fed.ed25519._decodepoint_strict; the canonical encoding of the same y is
     ACCEPTED (not vacuous); HQ's original decoder (HQ_SRC below, sha256-checked
     against HQ f377366's file bf1e4f6c...ad54) ACCEPTS the non-canonical form
     (the row differentiates).
  B. extra rows, NOT the pin: y=0 (order 4), identity y=1 (incl. x=0 with the
     sign bit set, RFC 8032 5.1.3), y=p-1 (x=0, order 2) with the sign bit set.
  C. checkvalid level. A differentiating forgery CAN be built, but only from
     small-order points (known discrete log): identity as R, or identity as A,
     each in its non-canonical encoding (y = p+1). HQ's checkvalid accepts them.
     Because checkvalid ALSO refuses small-order A/R, the strict decode is
     shadowed there, so the row is run against a module with ONLY the
     small-order gate neutralised (M-NOSMALL): the forgery in canonical form is
     accepted (the forgery is real), the non-canonical form is refused by the
     strict decode alone.
     NOT built: a differentiating signature with a NON-small-order R or A. Such
     a point needs y < 19 (to have a non-canonical twin) and a known discrete
     log; no such point is known and finding one is a discrete-log problem. An
     honest signature cannot have its R/A swapped for a non-canonical encoding
     of the same point for this reason. So at checkvalid level the decode is
     only pinned through the M-NOSMALL harness; the decode-level rows (A) are
     the primary pin.
  D. named mutants, built from the module source and run against the same rows:
       M-NOSTRICT   all three refusals in _decodepoint_strict neutralised
                    (y>=p, x=0 with sign bit, re-encode round trip): the decode
                    accepts like HQ's. KILLED by rows A and C.
       M-NOSTRICT-CV checkvalid decodes R and A with the OLD _decodepoint
                    (also -R and -A, one field each). This is the WIRING mutant:
                    the strict decoder stays correct but checkvalid stops
                    calling it. With the small-order gate on (as shipped) it is
                    invisible at checkvalid level; KILLED only by row C (gate
                    off harness).
     and the 7-way subset matrix of the three refusals. They are NOT all
     redundant: the y<p check is the ONLY thing that catches y >= p (the
     re-encode round trip does not, because P keeps the unreduced y and
     _encodepoint writes it straight back), so skipping the y check alone is a
     KILLED mutant. The sign check (x=0 with sign bit) and the re-encode round
     trip (which also catches x=0 + sign bit) cover each other, so skipping
     ONLY the sign check or ONLY the re-encode is an EQUIVALENT mutant (survives;
     no test can kill it); skipping both is killed (x=0 + sign bit accepted).
     The matrix asserts exactly: killed iff y-check skipped, or both sign-check
     and re-encode skipped.
"""
import hashlib
import os
import sys
import types

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from fed import ed25519 as ed  # noqa: E402

HQ_SHA256 = "bf1e4f6c542fca3bea1d565a6474212070b941a60c8784348035032c3044ad54"
# Verbatim copy of HQ f377366 fed/ed25519.py (== git show 3f3ab67b:fed/ed25519.py).
HQ_SRC = r'''"""Ed25519 signatures (RFC 8032) — minimal reference implementation, stdlib only.

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

'''

PASS = FAIL = 0


def check(label, cond, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok  {label}")
    else:
        FAIL += 1
        print(f"  FAIL {label} {extra}")


def load(name, src):
    m = types.ModuleType(name)
    m.__file__ = ed.__file__
    exec(compile(src, name, "exec"), m.__dict__)
    return m


def accepts(fn, *a):
    try:
        fn(*a)
        return True
    except Exception:
        return False


check("HQ_SRC sha256 is HQ's file bf1e4f6c...ad54",
      hashlib.sha256(HQ_SRC.encode()).hexdigest() == HQ_SHA256)
hq = load("hq_ed25519_orig", HQ_SRC)
SRC = open(ed.__file__).read()
P = ed._Q
check("p == 2**255-19 in both modules", P == hq._Q == (1 << 255) - 19)

Y_SET = [3, 4, 5, 6, 9, 10, 14, 15, 16, 18]


def enc(y, sign, nc):
    v = (y + P) if nc else y
    b = bytearray(v.to_bytes(32, "little"))
    b[31] |= sign << 7
    return bytes(b)


# Independent curve check (not using either decoder): -x^2+y^2 = 1 + d x^2 y^2
def is_curve_y(y):
    xx = ((y * y - 1) * pow(ed._D * y * y + 1, P - 2, P)) % P
    return pow(xx, (P - 1) // 2, P) in (0, 1)


valid_small_y = [y for y in range(0, 19) if is_curve_y(y)]
print("[vector set]")
check("curve-point y in [3,18] are exactly {3,4,5,6,9,10,14,15,16,18}",
      [y for y in valid_small_y if y >= 3] == Y_SET, str(valid_small_y))
check("y+p fits in 255 bits for y<19 and not for y=19",
      all(y + P < (1 << 255) for y in range(19)) and 19 + P >= (1 << 255))


def pin_rows(dec, tag, expect_nc_refused):
    """Return list of non-canonical encodings (label, bytes) the decoder ACCEPTS."""
    acc = []
    for y in Y_SET:
        for sb in (0, 1):
            e = enc(y, sb, True)
            if accepts(dec, e):
                acc.append((f"{tag} y={y} sign={sb}", e))
    return acc


print("[A. decode level: non-canonical y+p refused by strict, canonical accepted, HQ accepts]")
for y in Y_SET:
    for sb in (0, 1):
        nc, cn = enc(y, sb, True), enc(y, sb, False)
        check(f"y={y} sign={sb}: nc {nc.hex()[:16]}.. strict REFUSES", not accepts(ed._decodepoint_strict, nc))
        pt = None
        try:
            pt = ed._decodepoint_strict(cn)
        except Exception:
            pass
        check(f"y={y} sign={sb}: canonical encoding strict ACCEPTS (non-vacuous)", pt is not None)
        check(f"y={y} sign={sb}: canonical decodes to y={y}, x&1=={sb}",
              pt is not None and pt[1] == y and pt[0] & 1 == sb)
        check(f"y={y} sign={sb}: HQ original decoder ACCEPTS the nc form (row differentiates)",
              accepts(hq._decodepoint, nc))
        a, b = None, None
        try:
            a, b = hq._decodepoint(nc), ed._decodepoint_strict(cn)
        except Exception:
            pass
        check(f"y={y} sign={sb}: HQ's decode of nc == strict decode of canonical (same point, two encodings)",
              a is not None and a[0] == b[0] % P and a[1] % P == b[1] % P)

print("[B. extra rows, not the pin]")
# y=0 (order 4): nc = p
for sb in (0, 1):
    check(f"y=0 sign={sb}: nc (y=p) strict REFUSES, canonical ACCEPTS, HQ ACCEPTS nc",
          not accepts(ed._decodepoint_strict, enc(0, sb, True))
          and accepts(ed._decodepoint_strict, enc(0, sb, False))
          and accepts(hq._decodepoint, enc(0, sb, True)))
# identity y=1: nc = p+1
check("identity: nc (y=p+1, sign 0) strict REFUSES, canonical 01 00.. ACCEPTS, HQ ACCEPTS nc",
      not accepts(ed._decodepoint_strict, enc(1, 0, True))
      and accepts(ed._decodepoint_strict, enc(1, 0, False))
      and accepts(hq._decodepoint, enc(1, 0, True)))
# x = 0 with the sign bit set (RFC 8032 5.1.3: must be rejected)
x0_ident = enc(1, 1, False)
x0_ord2 = enc(P - 1, 1, False)
check("x=0 sign bit set, y=1: strict REFUSES; HQ ACCEPTS", not accepts(ed._decodepoint_strict, x0_ident)
      and accepts(hq._decodepoint, x0_ident))
check("x=0 sign bit set, y=p-1: strict REFUSES; HQ ACCEPTS", not accepts(ed._decodepoint_strict, x0_ord2)
      and accepts(hq._decodepoint, x0_ord2))
check("x=0 sign bit clear, y=p-1 (order 2): canonical, strict ACCEPTS decode",
      accepts(ed._decodepoint_strict, enc(P - 1, 0, False)))
check("x=0 sign bit set with nc y=p+1: strict REFUSES; HQ ACCEPTS",
      not accepts(ed._decodepoint_strict, enc(1, 1, True)) and accepts(hq._decodepoint, enc(1, 1, True)))
check("wrong-length encodings refused by strict", not accepts(ed._decodepoint_strict, enc(3, 0, False)[:31])
      and not accepts(ed._decodepoint_strict, enc(3, 0, False) + b"\x00"))
check("non-curve y (2, 7, 8) refused by strict canonical too",
      not any(accepts(ed._decodepoint_strict, enc(y, s, False)) for y in (2, 7, 8) for s in (0, 1)))
check("basepoint round-trips through strict decode", ed._decodepoint_strict(ed._encodepoint(ed._BPOINT)) == ed._BPOINT)

print("[C. checkvalid level: forgeries from small-order points, non-canonical encoding]")
SEED = bytes(range(32))
PK = ed.publickey(SEED)
hh = ed._H(SEED)
SCAL = 2 ** (ed._B - 2) + sum(2 ** i * ed._bit(hh, i) for i in range(3, ed._B - 2))
MSG = b"item7 non-canonical decode row"
L = ed._L
ID_C, ID_NC = enc(1, 0, False), enc(1, 0, True)


def forge_R(r_enc):
    """R = identity under honest A: S = h*a mod L with h from HQ's own formula."""
    R = hq._decodepoint(r_enc)
    h = int.from_bytes(hq._H(hq._encodepoint(R) + PK + MSG), "little")
    return r_enc + ((h * SCAL) % L).to_bytes(32, "little")


def forge_A(a_enc):
    """A = identity: S = r mod L for any honest R = rB (equation S*B == R + h*0)."""
    r = 12345678901234567890
    return ed._encodepoint(ed._scalarmult(ed._BPOINT, r)) + (r % L).to_bytes(32, "little")


F_R_C, F_R_NC = forge_R(ID_C), forge_R(ID_NC)
F_A = forge_A(ID_C)
check("honest signature verifies in HQ and strict", hq.checkvalid(ed.sign(MSG, SEED, PK), MSG, PK)
      and ed.checkvalid(ed.sign(MSG, SEED, PK), MSG, PK))
check("HQ checkvalid ACCEPTS forgery R=identity (canonical)", hq.checkvalid(F_R_C, MSG, PK) is True)
check("HQ checkvalid ACCEPTS forgery R=identity (non-canonical y=p+1)", hq.checkvalid(F_R_NC, MSG, PK) is True)
check("HQ checkvalid ACCEPTS forgery A=identity canonical, any message",
      hq.checkvalid(F_A, MSG, ID_C) is True and hq.checkvalid(F_A, b"other", ID_C) is True)
check("HQ checkvalid ACCEPTS forgery A=identity non-canonical (y=p+1)",
      hq.checkvalid(F_A, MSG, ID_NC) is True and hq.checkvalid(F_A, b"other", ID_NC) is True)
check("merged checkvalid REFUSES all four forgeries",
      not any([ed.checkvalid(F_R_C, MSG, PK), ed.checkvalid(F_R_NC, MSG, PK),
               ed.checkvalid(F_A, MSG, ID_C), ed.checkvalid(F_A, MSG, ID_NC)]))

SMALL_GATE = "        if _is_small_order(A) or _is_small_order(R):\n            return False\n"
# Mutants are built by tolerant text replacement: if the module under test has
# already been mutated (or edited), a missing anchor is a no-op, and the kill
# assertions below (accepts 26/26, forgeries accepted) fail loudly on a no-op.
nosmall = load("ed_M_NOSMALL", SRC.replace(SMALL_GATE, ""))


def cv_rows(mod):
    """(canonical-forgery accepted?, nc-forgery accepted?) rows for a module."""
    return {
        "R canonical": mod.checkvalid(F_R_C, MSG, PK),
        "R non-canonical": mod.checkvalid(F_R_NC, MSG, PK),
        "A canonical": mod.checkvalid(F_A, MSG, ID_C),
        "A non-canonical": mod.checkvalid(F_A, MSG, ID_NC),
    }


r = cv_rows(nosmall)
check("small-order gate off, strict decode on: canonical forgeries ACCEPTED (forgery math is real)",
      r["R canonical"] is True and r["A canonical"] is True, str(r))
check("small-order gate off, strict decode on: R non-canonical REFUSED (strict decode alone)",
      r["R non-canonical"] is False, str(r))
check("small-order gate off, strict decode on: A non-canonical REFUSED (strict decode alone)",
      r["A non-canonical"] is False, str(r))

print("[D. mutants]")
REFUSALS = {
    "y": 'raise ValueError("non-canonical y")',
    "sign": 'raise ValueError("non-canonical x sign")',
    "reenc": 'raise ValueError("non-canonical encoding")',
}
PRESENT = {k for k, v in REFUSALS.items() if SRC.count(v) == 1}
check("real module carries all three refusals in _decodepoint_strict", PRESENT == set(REFUSALS), str(PRESENT))


def mutate(skip):
    s = SRC
    for k in skip:
        s = s.replace(REFUSALS[k], "pass")
    return s


def nc_accepted(mod):
    n = len(pin_rows(mod._decodepoint_strict, "", True))
    n += sum(accepts(mod._decodepoint_strict, e) for e in
             (enc(0, 0, True), enc(0, 1, True), enc(1, 0, True), enc(1, 1, False),
              enc(P - 1, 1, False), enc(1, 1, True)))
    return n


check("real module: accepts 0 non-canonical encodings (of 26 tried)", nc_accepted(ed) == 0)
hq_n = nc_accepted(types.SimpleNamespace(_decodepoint_strict=hq._decodepoint))
check("HQ decoder accepts all 26 non-canonical encodings tried", hq_n == 26, str(hq_n))

m_nostrict = load("ed_M_NOSTRICT", mutate(("y", "sign", "reenc")))
n = nc_accepted(m_nostrict)
check("M-NOSTRICT (all three refusals neutralised): accepts non-canonical -> row A would FAIL -> KILLED",
      n == 26, str(n))
check("M-NOSTRICT: strict decode still accepts canonical encodings of the same points",
      all(accepts(m_nostrict._decodepoint_strict, enc(y, s, False)) for y in Y_SET for s in (0, 1)))
check("M-NOSTRICT is still honest on the sign/verify path",
      m_nostrict.checkvalid(ed.sign(MSG, SEED, PK), MSG, PK) is True)

# M-NOSTRICT combined with the small-order gate off at checkvalid level (row C)
mm = load("ed_M_NOSTRICT_NOSMALL", mutate(("y", "sign", "reenc")).replace(SMALL_GATE, ""))
rr = cv_rows(mm)
check("M-NOSTRICT + small-order off: non-canonical forgeries ACCEPTED -> row C would FAIL -> KILLED",
      rr["R non-canonical"] is True and rr["A non-canonical"] is True, str(rr))

# M-NOSTRICT-CV: checkvalid uses the OLD decoder for R and A
R_STRICT = "R = _decodepoint_strict(s[:_B // 8])"
A_STRICT = "A = _decodepoint_strict(pk)"
R_OLD = "R = _decodepoint(s[:_B // 8])"
A_OLD = "A = _decodepoint(pk)"
cv_src = SRC.replace(R_STRICT, R_OLD).replace(A_STRICT, A_OLD)
rr = cv_rows(load("ed_M_NOSTRICT_CV", cv_src.replace(SMALL_GATE, "")))
check("M-NOSTRICT-CV (checkvalid wired to the OLD decoder for R and A) + small-order off: "
      "non-canonical forgeries ACCEPTED -> KILLED by row C",
      rr["R non-canonical"] is True and rr["A non-canonical"] is True, str(rr))
rr = cv_rows(load("ed_M_NOSTRICT_CV_R", SRC.replace(R_STRICT, R_OLD).replace(SMALL_GATE, "")))
check("M-NOSTRICT-CV-R (only R wired to old decoder) + small-order off: R non-canonical ACCEPTED, "
      "A non-canonical still refused -> KILLED by row C",
      rr["R non-canonical"] is True and rr["A non-canonical"] is False, str(rr))
rr = cv_rows(load("ed_M_NOSTRICT_CV_A", SRC.replace(A_STRICT, A_OLD).replace(SMALL_GATE, "")))
check("M-NOSTRICT-CV-A (only A wired to old decoder) + small-order off: A non-canonical ACCEPTED, "
      "R non-canonical still refused -> KILLED by row C",
      rr["A non-canonical"] is True and rr["R non-canonical"] is False, str(rr))
# With the small-order gate ON (as shipped) the same wiring mutants are NOT visible at
# checkvalid level: the small-order gate shadows the decode. Record it as a fact.
rr = cv_rows(load("ed_M_NOSTRICT_CV_shadowed", cv_src))
check("M-NOSTRICT-CV with the small-order gate ON as shipped: all four forgeries still refused "
      "(decode shadowed by the small-order gate; this is why only the M-NOSMALL harness can see it)",
      not any(rr.values()), str(rr))

print("[D. subset matrix of the three refusals: killed iff y-check skipped, or sign AND re-encode skipped]")
import itertools
for k in range(1, 4):
    for skip in itertools.combinations(("y", "sign", "reenc"), k):
        acc = nc_accepted(load("ed_M_" + "_".join(skip), mutate(skip)))
        killed = acc > 0
        eff = set(skip) | (set(REFUSALS) - PRESENT)  # refusals already absent from the module under test
        expect = ("y" in eff) or ("sign" in eff and "reenc" in eff)
        check(f"skip {{{', '.join(skip)}}}: {'KILLED' if killed else 'survives (equivalent mutant)'} "
              f"({acc}/26 nc accepted)", killed == expect, f"expected killed={expect}")

print(f"\nSUMMARY: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
