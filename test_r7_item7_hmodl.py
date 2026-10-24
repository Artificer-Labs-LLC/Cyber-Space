#!/usr/bin/env python3
"""r7 item-7: fed/ed25519.checkvalid reduces h mod L (libsodium parity).

Root cause (Cipher, ART-37 478bb16a): checkvalid multiplied A by the full
512-bit SHA-512 hash h, while libsodium reduces h mod L first. For a
mixed-order key A' = aB + T the two accept on unrelated conditions
([h]T == 0 vs [h mod L]T == 0, and L = 5 mod 8), so they split on rows
70-75 and 82 of the shared item-7 set. For prime-order A, [h]A == [h mod L]A,
so honest signatures are unaffected.

Checks:
  1. fixture r7_item7_vectors.json has the pinned sha256 and 91 rows;
  2. checkvalid agrees with the fixture's `nacl` expect column on all 91 rows;
  3. if pynacl is importable, checkvalid agrees with live crypto_sign_open
     on all 91 rows (and the `nacl` column itself matches pynacl);
  4. explicit split rows 70, 71, 72, 73, 74, 75, 82;
  5. the fixed line is present, and in-process mutants are killed:
       M-NOREDUCE      h            (the pre-fix line) -> must fail 70/72/74
       M-REDUCE-WRONG  h % (8*_L)   (wrong modulus)    -> must fail
"""
import hashlib
import json
import os
import sys
import types

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from fed import ed25519 as ed  # noqa: E402

FIXTURE = os.path.join(HERE, "r7_item7_vectors.json")
FIXTURE_SHA256 = "c8d4f4486cd2935e68900c21d85e4c628fe074068f459640efa0e9005bfdc6dd"
FIXED_LINE = "_edwards(R, _scalarmult(A, h % _L))"

PASS = FAIL = 0


def check(label, cond, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok  {label}")
    else:
        FAIL += 1
        print(f"  FAIL {label} {extra}")


def args(x):
    return bytes.fromhex(x["sig"]), bytes.fromhex(x["msg"]), bytes.fromhex(x["pk"])


raw = open(FIXTURE, "rb").read()
check("fixture sha256 pinned", hashlib.sha256(raw).hexdigest() == FIXTURE_SHA256,
      hashlib.sha256(raw).hexdigest())
V = json.loads(raw)["vectors"]
check("fixture has 91 rows", len(V) == 91, str(len(V)))

# 2. agreement with the fixture's nacl expect column.
print("[nacl expect column]")
dis = [i for i, x in enumerate(V) if ed.checkvalid(*args(x)) != x["expect"]["nacl"]]
check(f"agrees with nacl column on {len(V) - len(dis)}/{len(V)} rows", not dis, str(dis))

# 3. live pynacl, when available.
try:
    import nacl.bindings as _nb
except Exception:  # pragma: no cover - environment dependent
    _nb = None


def sodium_open(x):
    sig, msg, pk = args(x)
    try:
        _nb.crypto_sign_open(sig + msg, pk)
        return True
    except Exception:
        return False


if _nb is not None:
    print("[pynacl live]")
    live = [sodium_open(x) for x in V]
    col = [i for i, x in enumerate(V) if live[i] != x["expect"]["nacl"]]
    check("nacl column matches pynacl live on all rows", not col, str(col))
    dis_live = [i for i, x in enumerate(V) if ed.checkvalid(*args(x)) != live[i]]
    check(f"agrees with pynacl live on {len(V) - len(dis_live)}/{len(V)} rows",
          not dis_live, str(dis_live))
else:
    print("[pynacl live] skipped: pynacl not importable")

# 4. explicit split rows: (index, expected checkvalid verdict).
print("[split rows]")
SPLIT = {70: False, 71: True, 72: False, 73: True, 74: False, 75: True, 82: True}
for i, want in SPLIT.items():
    x = V[i]
    got = ed.checkvalid(*args(x))
    check(f"row {i} ({x['name']}) -> {want}", got is want and x["expect"]["nacl"] is want,
          f"got={got} nacl={x['expect']['nacl']}")
check("row 0 honest control accepts", ed.checkvalid(*args(V[0])) is True)

# 5. mutants, built from the module source with the fixed line substituted.
print("[mutants]")
src = open(ed.__file__).read()
check("fixed line present exactly once", src.count(FIXED_LINE) == 1)


def mutant(name, replacement):
    m = types.ModuleType(f"ed25519_{name}")
    m.__file__ = ed.__file__
    exec(compile(src.replace(FIXED_LINE, replacement), ed.__file__, "exec"), m.__dict__)
    return m


MUTANTS = {
    "M-NOREDUCE": ("_edwards(R, _scalarmult(A, h))", {70, 72, 74}),
    "M-REDUCE-WRONG": ("_edwards(R, _scalarmult(A, h % (8 * _L)))", set()),
}
for name, (repl, must_fail) in MUTANTS.items():
    m = mutant(name, repl)
    bad = {i for i, x in enumerate(V) if m.checkvalid(*args(x)) != x["expect"]["nacl"]}
    print(f"  {name}: disagrees on rows {sorted(bad)}")
    check(f"{name} killed (disagrees on >=1 row)", bool(bad))
    if must_fail:
        check(f"{name} fails rows {sorted(must_fail)}", must_fail <= bad, str(sorted(bad)))
    check(f"{name} still accepts honest row 0", m.checkvalid(*args(V[0])) is True)

print(f"\nSUMMARY: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
