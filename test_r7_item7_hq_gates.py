#!/usr/bin/env python3
"""r7 item-7 standalone: HQ's argument gates survive the item-7 merge.

HQ f377366's fed/ed25519.py carries _check_seed / _check_key (used in
publickey and sign) and an isinstance(m, bytes) check in sign. Those are NOT
in the 32d8ecf4 lineage, so a whole-file swap would silently drop them. This
file pins them:

  1. publickey() and sign() raise ValueError on 0-, 31- and 33-byte seeds
     (and on a non-bytes seed);
  2. sign() raises ValueError on a non-bytes message and on a pk that is not
     32 bytes;
  3. 32-byte seeds still work and sign/checkvalid round-trips;
  4. named mutant M-NOGATES (module source with every gate removed) is KILLED:
     under it the same calls no longer raise ValueError.
"""
import os
import sys
import types

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from fed import ed25519 as ed  # noqa: E402

PASS = FAIL = 0


def check(label, cond, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok  {label}")
    else:
        FAIL += 1
        print(f"  FAIL {label} {extra}")


def raises_valueerror(fn, *a):
    try:
        fn(*a)
    except ValueError:
        return True
    except Exception as e:  # wrong exception type is a gate failure too
        return False
    return False


SEED = bytes(range(32))
PK = ed.publickey(SEED)
BAD_SEEDS = {"0-byte": b"", "31-byte": SEED[:31], "33-byte": SEED + b"\x00"}


def gate_rows(mod, tag, expect_gated):
    """Returns list of (label, raised ValueError) rows for a module."""
    pk = PK
    rows = []
    for nm, s in BAD_SEEDS.items():
        rows.append((f"{tag} publickey({nm} seed)", raises_valueerror(mod.publickey, s)))
        rows.append((f"{tag} sign({nm} seed)", raises_valueerror(mod.sign, b"m", s, pk)))
    rows.append((f"{tag} publickey(non-bytes seed)", raises_valueerror(mod.publickey, "x" * 32)))
    rows.append((f"{tag} sign(non-bytes message)", raises_valueerror(mod.sign, "m", SEED, pk)))
    rows.append((f"{tag} sign(31-byte pk)", raises_valueerror(mod.sign, b"m", SEED, pk[:31])))
    return rows


print("[gates on the merged module]")
for label, ok in gate_rows(ed, "merged:", True):
    check(label + " -> ValueError", ok)

print("[honest path unchanged]")
sig = ed.sign(b"hello", SEED, PK)
check("32-byte seed signs; checkvalid accepts", ed.checkvalid(sig, b"hello", PK) is True)
check("checkvalid rejects tampered message", ed.checkvalid(sig, b"hellp", PK) is False)

print("[source carries the gates]")
src = open(ed.__file__).read()
for needle in ("def _check_seed(", "def _check_key(", "_H(_check_seed(sk))",
               "    _check_seed(sk)\n", '_check_key("public key", pk)',
               "if not isinstance(m, bytes):"):
    check(f"source has {needle.strip()!r}", needle in src)

print("[mutant M-NOGATES: every gate removed]")
mut = src
mut = mut.replace('raise ValueError("secret seed must be 32 bytes")', "pass")
mut = mut.replace('raise ValueError(f"{name} must be 32 bytes")', "pass")
mut = mut.replace('raise ValueError("message must be bytes")', "pass")
check("mutant source differs from real source (3 gate raises neutralised)",
      mut != src and mut.count("pass") >= 3)
m = types.ModuleType("ed25519_M_NOGATES")
m.__file__ = ed.__file__
exec(compile(mut, ed.__file__, "exec"), m.__dict__)
survived = [lab for lab, ok in gate_rows(m, "M-NOGATES:", False) if ok]
bad_seed_rows = [lab for lab, ok in gate_rows(m, "M-NOGATES:", False)
                 if ("seed)" in lab and "non-bytes" not in lab) and ok]
check("M-NOGATES killed: no 0/31/33-byte-seed call still raises ValueError",
      not bad_seed_rows, str(bad_seed_rows))
check("M-NOGATES killed: no gate row still raises ValueError", not survived, str(survived))

print(f"\nSUMMARY: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
