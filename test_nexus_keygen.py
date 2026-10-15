#!/usr/bin/env python3
"""nexus_keygen belt: generation must be claim-free and loss-proof.

The genesis loss had two halves: a claim broadcast with an unsaved
key, and no second copy. This belt proves the generator writes BOTH
files born-0600 and byte-identical, refuses to overwrite either one
(the name key of the root must be impossible to clobber by re-running
a command), refuses key == backup, and that what it writes passes
nexus_preflight READY in a temp dir — never the real ~/.cyberspace.
"""
import os
import stat
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nexus_keygen as nk  # noqa: E402
import nexus_preflight as np  # noqa: E402

fails = 0


def _check(cond, why):
    global fails
    if not cond:
        print(f"FAIL: {why}")
        fails += 1


ROOT = Path(os.path.dirname(os.path.abspath(__file__)))

with tempfile.TemporaryDirectory() as td:
    td = Path(td)
    key = td / "nexus-name.key"
    bak = td / "nexus-name.key.bak"

    pub, problems = nk.generate(key, bak)
    _check(problems == [], f"fresh generation must verify, got {problems}")
    _check(pub is not None and len(pub) == 64, "pub must be derived")
    for p in (key, bak):
        _check(stat.S_IMODE(p.stat().st_mode) == 0o600,
               f"{p.name} must be born 0600")
    _check(key.read_bytes() == bak.read_bytes(),
           "backup must match the primary byte-for-byte")

    # What the keygen writes must satisfy the preflight outright.
    ready, pub2, blockers = np.preflight("nexus", key, bak, ROOT)
    _check(ready and pub2 == pub and blockers == [],
           f"generated seats must make preflight READY, got {blockers}")

    # Re-running must refuse, never overwrite the root key.
    before = key.read_bytes()
    _check(nk.main(["--key", str(key), "--backup", str(td / "b2")]) == 2,
           "existing key must be refused with exit 2")
    _check(key.read_bytes() == before, "refusal must not touch the key")
    _check(nk.main(["--key", str(td / "k2"), "--backup", str(bak)]) == 2,
           "existing backup must be refused with exit 2")
    _check(not (td / "k2").exists(), "backup refusal must write nothing")

    # Key and backup as one path is no backup at all.
    _check(nk.main(["--key", str(td / "same"),
                    "--backup", str(td / "same")]) == 2,
           "key == backup must be refused")
    _check(not (td / "same").exists(), "same-path refusal writes nothing")

if fails:
    print(f"{fails} FAILURES")
    sys.exit(1)
print("PASS: test_nexus_keygen")
