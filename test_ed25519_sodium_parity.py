#!/usr/bin/env python3
"""Cipher's 51 strict-checkvalid rows (test_ed25519_strict.py) give the
same outcome on the libsodium path: the file runs twice, once on the
pure-Python checkvalid and once with checkvalid -> checkvalid_sodium, and
every row's outcome line must match."""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SHIM = ("import sys, runpy; sys.path.insert(0, %r); from fed import ed25519 as e;"
        " assert e.SODIUM_ERROR is None, e.SODIUM_ERROR;"
        " e.checkvalid = e.checkvalid_sodium;"
        " sys.argv = ['test_ed25519_strict.py'];"
        " runpy.run_path(%r, run_name='__main__')"
        % (HERE, os.path.join(HERE, "test_ed25519_strict.py")))


def rows(cmd):
    p = subprocess.run(cmd, cwd=HERE, capture_output=True, text=True)
    lines = [ln.strip() for ln in p.stdout.splitlines()
             if ln.strip().startswith(("ok ", "FAIL "))]
    return p.returncode, lines


rc_py, py = rows([sys.executable, "test_ed25519_strict.py"])
rc_na, na = rows([sys.executable, "-c", SHIM])
same = py == na
print(f"pure-Python: rc={rc_py} rows={len(py)}  libsodium: rc={rc_na} rows={len(na)}")
for a, b in zip(py, na):
    if a != b:
        print("  DIFF", a, "|", b)
ok = rc_py == 0 and rc_na == 0 and len(py) == 51 and same
print(f"--- {'1 passed, 0 failed' if ok else '0 passed, 1 failed'} ---")
sys.exit(0 if ok else 1)
