#!/usr/bin/env python3
"""Belt test for rotate_name.py bounded key-seed reads.

Before this tick every seed seat in rotate_name (promote x2, submit x2,
main x1) loaded <label>-name.key[.next] via read_text() unbounded before
bytes.fromhex ran; a seed file is 64 hex chars, while every sibling
input in the tool is capped (record 64KB, mirror body 64KB). _read_seed
now reads at most _SEED_MAX+1 chars and an oversize file raises
ValueError into each seat's existing refusal wording.

Checks (library calls, temp home, no network — oversize refuses before
any mirror post or file move):
  oversize .next (valid hex + padding past the cap) -> submit refuses
    with its "no pending new key" wording; promote refuses with its
    "key files do not hold 32-byte hex seeds" wording
  oversize current key (valid .next) -> submit refuses with its
    "current name key missing ... continuity broken" wording
  exactly-at-cap .next/.key (hex padded with spaces to the cap) ->
    promote succeeds byte-exact (padding strips, keys match record)
  small garbage seed -> promote keeps "do not hold 32-byte hex seeds"

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/rotate-seed-size-belt-test.py
"""

import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)

import rotate_name  # noqa: E402
from fed.ed25519 import publickey  # noqa: E402

CAP = rotate_name._SEED_MAX if hasattr(rotate_name, "_SEED_MAX") else 1024
MIRROR = "http://127.0.0.1:8471"
OLD = bytes(range(32))
NEW = bytes(range(32, 64))

PASSED = FAILED = 0


def check(name, cond):
    global PASSED, FAILED
    if cond:
        PASSED += 1
        print(f"  ok: {name}")
    else:
        FAILED += 1
        print(f"  FAIL: {name}")


def home_with(next_text, key_text):
    home = Path(tempfile.mkdtemp())
    rec = rotate_name.mint_rotation(
        "foo", OLD, publickey(NEW).hex())
    (home / "foo-rotate.json").write_text(json.dumps(rec))
    if next_text is not None:
        (home / "foo-name.key.next").write_text(next_text)
    if key_text is not None:
        (home / "foo-name.key").write_text(key_text)
    return home


def padded(seed, total):
    text = seed.hex()
    return text + " " * (total - len(text))


# oversize .next: valid hex padded past the cap must refuse at both seats
big_next = padded(NEW, CAP + 500)
ok, msg = rotate_name.submit_rotation(
    "foo", MIRROR, home_with(big_next, OLD.hex()))
check("submit oversize .next refuses", ok is False)
check("submit oversize .next wording", "no pending new key" in msg)
ok, msg = rotate_name.promote_rotation(
    "foo", home_with(big_next, OLD.hex()))
check("promote oversize .next refuses", ok is False)
check("promote oversize .next wording",
      "key files do not hold 32-byte hex seeds" in msg)

# oversize current key with a valid .next: submit's key-seat wording
ok, msg = rotate_name.submit_rotation(
    "foo", MIRROR, home_with(NEW.hex(), padded(OLD, CAP + 500)))
check("submit oversize key refuses", ok is False)
check("submit oversize key wording",
      "current name key missing" in msg and "continuity broken" in msg)

# exactly at cap: padding strips, both keys match the record, promote runs
home = home_with(padded(NEW, CAP), padded(OLD, CAP))
ok, msg = rotate_name.promote_rotation("foo", home)
check("at-cap seeds promote", ok is True)
check("at-cap promote moved new key",
      (home / "foo-name.key").read_text().strip() == NEW.hex())

# small garbage seed: unchanged refusal wording
ok, msg = rotate_name.promote_rotation(
    "foo", home_with("not hex!!", OLD.hex()))
check("promote garbage seed wording",
      ok is False and "key files do not hold 32-byte hex seeds" in msg)

print(f"---\n{PASSED} passed, {FAILED} failed")
sys.exit(1 if FAILED else 0)
