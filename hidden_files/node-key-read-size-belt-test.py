#!/usr/bin/env python3
"""Belt: core._node_keypair reads .node.key under a 1KB bound.

A node key seed is 64 hex chars. Cases run in subprocesses with a
throwaway CYBERNET_DB_DIR because _node_keypair runs at import time.
"""
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SEED = "ab" * 32

CHECKS = 0
FAILURES = []


def check(name, cond, detail=""):
    global CHECKS
    CHECKS += 1
    if not cond:
        FAILURES.append(f"{name}: {detail}")


def import_core(dbdir):
    env = dict(os.environ)
    env["CYBERNET_DB_DIR"] = dbdir
    env.pop("CYBERNET_NODE_PRIVKEY", None)
    code = (
        "import core;"
        "print(core._NODE_PUB)"
    )
    return subprocess.run(
        [sys.executable, "-c", code], cwd=ROOT, env=env,
        capture_output=True, text=True, timeout=60,
    )


def expected_pub():
    sys.path.insert(0, ROOT)
    from fed import ed25519
    return ed25519.publickey(bytes.fromhex(SEED)).hex()


EXP = expected_pub()

# 1. valid seed file imports, pub exact
with tempfile.TemporaryDirectory() as d:
    open(os.path.join(d, ".node.key"), "w").write(SEED)
    r = import_core(d)
    check("valid", r.returncode == 0 and r.stdout.strip() == EXP, r.stderr[-300:])

# 2. padded seed within cap imports byte-exact (after strip)
with tempfile.TemporaryDirectory() as d:
    open(os.path.join(d, ".node.key"), "w").write("  " + SEED + "\n")
    r = import_core(d)
    check("padded", r.returncode == 0 and r.stdout.strip() == EXP, r.stderr[-300:])

# 3. at-cap padded seed (exactly 1024 chars) imports
with tempfile.TemporaryDirectory() as d:
    pad = 1024 - len(SEED)
    open(os.path.join(d, ".node.key"), "w").write(SEED + " " * pad)
    r = import_core(d)
    check("at-cap", r.returncode == 0 and r.stdout.strip() == EXP, r.stderr[-300:])

# 4. oversize padded seed (would strip to a valid seed) is refused
with tempfile.TemporaryDirectory() as d:
    open(os.path.join(d, ".node.key"), "w").write(SEED + " " * 2000)
    r = import_core(d)
    check("oversize-padded-refused", r.returncode != 0 and "node key is not a 32-byte hex seed" in r.stderr, r.stderr[-300:] + r.stdout)

# 5. oversize junk is refused with the same wording
with tempfile.TemporaryDirectory() as d:
    open(os.path.join(d, ".node.key"), "w").write("a" * 2048)
    r = import_core(d)
    check("oversize-junk-refused", r.returncode != 0 and "node key is not a 32-byte hex seed" in r.stderr, r.stderr[-300:])

# 6. missing file still generates and persists a 64-char seed
with tempfile.TemporaryDirectory() as d:
    r = import_core(d)
    p = os.path.join(d, ".node.key")
    ok = r.returncode == 0 and os.path.exists(p) and len(open(p).read().strip()) == 64
    check("missing-generates", ok, r.stderr[-300:])

print(f"{CHECKS - len(FAILURES)}/{CHECKS} checks passed")
for f in FAILURES:
    print("FAIL:", f)
sys.exit(1 if FAILURES else 0)
