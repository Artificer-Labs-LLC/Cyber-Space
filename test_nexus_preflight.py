#!/usr/bin/env python3
"""nexus_preflight belt: the root-claim guard must fail closed.

genesis.cyberspace was lost because a claim went out with an unsaved
key. Every seat here proves a blocker is named, never smoothed:
refused label, missing key, loose permissions, malformed seed,
missing/mismatched backup, and a tree that cannot federate or pin.
The READY path uses a throwaway key in a temp dir — never the real
~/.cyberspace — and proves the printed pub derives from that seed.
"""
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nexus_preflight as np  # noqa: E402
from fed.ed25519 import publickey  # noqa: E402

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

    # Missing key: NOT READY, blocker names the absence.
    ready, pub, blockers = np.preflight("nexus", key, bak, ROOT)
    _check(not ready and pub is None, "missing key must not be ready")
    _check(any("missing" in b for b in blockers),
           "missing key blocker must be named")

    # genesis is refused outright, whatever the key state.
    ready, pub, blockers = np.preflight("genesis", key, bak, ROOT)
    _check(not ready and any("refused" in b for b in blockers),
           "genesis label must be refused outright")

    # A non-root label is out of scope, not silently waved through.
    ready, pub, blockers = np.preflight("nexus2", key, bak, ROOT)
    _check(not ready, "non-root label must not be ready")

    # Loose permissions on a real seed: blocker, but pub still derives.
    seed = bytes(range(32))
    key.write_text(seed.hex())
    os.chmod(key, 0o644)
    pub2, problems = np.check_key_file(key)
    _check(pub2 == publickey(seed).hex().lower(),
           "pub must derive from the seed")
    _check(any("0600" in p for p in problems),
           "loose key permissions must be named")

    # Tight key, no backup argument: backup blocker stands.
    os.chmod(key, 0o600)
    ready, pub, blockers = np.preflight("nexus", key, None, ROOT)
    _check(not ready and any("backup" in b for b in blockers),
           "unverified backup must block readiness")

    # Mismatched backup: blocker. Matching tight backup: READY.
    bak.write_text(bytes(reversed(range(32))).hex())
    os.chmod(bak, 0o600)
    _check(np.check_backup(key, bak), "mismatched backup must block")
    bak.write_text(seed.hex())
    ready, pub, blockers = np.preflight("nexus", key, bak, ROOT)
    _check(ready and blockers == [],
           f"kept key + matching backup + this tree must be READY, "
           f"got blockers={blockers}")

    # Malformed seed: no pub, named problem, never a crash.
    key.write_text("not-hex")
    pub3, problems = np.check_key_file(key)
    _check(pub3 is None and problems, "malformed seed must be refused")

    # Tree checks pass on the real tree (gossip route + pin present).
    _check(np.check_tree(ROOT) == [], "real tree must pass tree checks")

if fails:
    print(f"{fails} FAILURES")
    sys.exit(1)
print("PASS: test_nexus_preflight")
