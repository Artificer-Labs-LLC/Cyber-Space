#!/usr/bin/env python3
"""Belt test for resolve_chain's untrusted-document shape guards.

The stdin (offline) mode reads a rotations document an operator saved
from anywhere, and main() read doc["name"] BEFORE walk() could give
its shape verdicts: a non-object document ('[]', '"hi"', '123') died
in an uncaught AttributeError traceback, a non-string top-level name
did the same inside _label, and walk()'s own name pre-check crashed
on a non-string hop name before verify_rotation's type guard (which
returns 'field ... is not a string' for every OTHER field) was ever
reached. All three now read as the chain verdicts they are: exit 1,
reason on stderr, no traceback. A real one-hop chain still walks
clean as the control.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/resolve-chain-stdin-shape-belt-test.py
"""

import json
import os
import secrets
import subprocess
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)

import rotate_name  # noqa: E402
from fed import ed25519 as _fed_ed25519  # noqa: E402

PASSED = FAILED = 0


def check(name, cond, extra=""):
    global PASSED, FAILED
    if cond:
        PASSED += 1
        print(f"  ok: {name}")
    else:
        FAILED += 1
        print(f"  FAIL: {name} {extra}")


def _cli(stdin_text):
    p = subprocess.run([sys.executable, "resolve_chain.py", "-"],
                       capture_output=True, text=True, input=stdin_text,
                       cwd=ROOT, timeout=30)
    return p.returncode, p.stdout.strip(), p.stderr.strip()


def _broken_shape(name, stdin_text, needle):
    rc, out, err = _cli(stdin_text)
    check(name, rc == 1 and needle in err and "Traceback" not in err,
          f"rc={rc} err={err!r}")


_broken_shape("array document reads broken (exit 1), no traceback",
              "[]", "not a JSON object")
_broken_shape("string document reads broken (exit 1), no traceback",
              '"hi"', "not a JSON object")
_broken_shape("number document reads broken (exit 1), no traceback",
              "123", "not a JSON object")
_broken_shape("non-string top-level name reads broken, no traceback",
              '{"name": 123, "rotations": []}', "no rotation rows")

_hop = {"name": 123, "old_pubkey": "a" * 64, "new_pubkey": "b" * 64,
        "issued_at": "2026-01-01T00:00:00+00:00", "signature": "c" * 128}
_broken_shape("non-string hop name reads broken, no traceback",
              json.dumps({"name": "x", "rotations": [_hop]}),
              "field 'name' is not a string")

# Control: a real one-hop chain minted offline walks clean (exit 0).
_seed = secrets.token_bytes(32)
_old_priv = _seed
_old_pub = _fed_ed25519.publickey(_seed).hex().lower()
_new_pub = _fed_ed25519.publickey(secrets.token_bytes(32)).hex().lower()
_rec = rotate_name.mint_rotation("shapebelt", _old_priv, _new_pub)
_doc = {"name": "shapebelt", "rotations": [
    {"old_pubkey": _rec["old_pubkey"], "new_pubkey": _rec["new_pubkey"],
     "issued_at": _rec["issued_at"], "signature": _rec["signature"]}]}
rc, out, err = _cli(json.dumps(_doc))
check("real one-hop chain still walks clean (exit 0)",
      rc == 0 and _new_pub[:16] in out, f"rc={rc} out={out!r} err={err!r}")

print(f"\nresolve-chain-stdin-shape belt: {PASSED}/{PASSED + FAILED}")
sys.exit(1 if FAILED else 0)
