"""Seed-file canonical-spelling belt (primitives 4 identity + 3 hosting).

Before: mint_name._read_seed and rotate_name._read_seed handed the
stripped file text straight to bytes.fromhex, which ignores embedded
whitespace -- so a 65-char inserted-space seed, or a seed line-wrapped
at 32 chars, decoded to the TRUE 32 bytes and minted/rotated happily.
But resolver/host._config and _startup_problems gate the hostd seed at
exactly 64 hex chars and refuse those spellings on sight: the minter
accepted a key file the hosting daemon then refused to start with,
leaving the name minted but unhostable -- the desync the host seat's
own comment claims to have closed from its side only.

Checks (both modules): clean 64-hex reads byte-exact; uppercase reads
byte-exact; outer-whitespace padding still strips and reads byte-exact;
inserted-space and line-wrapped spellings raise ValueError; a 62-char
short seed still raises (via the same ValueError contract callers catch).

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/seed-file-spelling-belt-test.py
"""
import os
import sys
import tempfile
from pathlib import Path

os.environ["CYBERNET_DB_DIR"] = tempfile.mkdtemp(prefix="seed-spell-")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import mint_name  # noqa: E402
import rotate_name  # noqa: E402

passed = failed = 0


def check(name, cond):
    global passed, failed
    if cond:
        passed += 1
    else:
        failed += 1
        print(f"FAIL: {name}")


SEED = "ab" * 32
SEED_BYTES = bytes.fromhex(SEED)
SPACED = SEED[:32] + " " + SEED[32:]
WRAPPED = SEED[:32] + "\n" + SEED[32:]
TABBED = SEED[:32] + "\t" + SEED[32:]


def reads(reader, text):
    with tempfile.NamedTemporaryFile("w", delete=False) as f:
        f.write(text)
        p = Path(f.name)
    try:
        return reader(p)
    finally:
        p.unlink(missing_ok=True)


def refuses(reader, text):
    try:
        reads(reader, text)
        return False
    except ValueError:
        return True


for mod_name, reader in (("mint_name", mint_name._read_seed),
                         ("rotate_name", rotate_name._read_seed)):
    check(f"{mod_name}: clean seed byte-exact",
          reads(reader, SEED) == SEED_BYTES)
    check(f"{mod_name}: uppercase seed byte-exact",
          reads(reader, SEED.upper()) == SEED_BYTES)
    check(f"{mod_name}: outer padding strips byte-exact",
          reads(reader, "  " + SEED + "\n") == SEED_BYTES)
    check(f"{mod_name}: inserted-space seed refused",
          refuses(reader, SPACED))
    check(f"{mod_name}: line-wrapped seed refused",
          refuses(reader, WRAPPED))
    check(f"{mod_name}: tab-inserted seed refused",
          refuses(reader, TABBED))
    check(f"{mod_name}: short seed refused",
          refuses(reader, "ab" * 31))

print(f"{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
