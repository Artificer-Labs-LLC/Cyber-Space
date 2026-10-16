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

    # Same physical file as backup: NOT a second copy — preflight
    # must block READY for the path itself, a sub/../ alias, a
    # symlink, and a hardlink (one file lost is the genesis shape).
    sub = td / "sub"
    sub.mkdir(exist_ok=True)
    link = td / "link.key"
    if not link.exists():
        link.symlink_to(key)
    hard = td / "hard.key"
    if not hard.exists():
        os.link(key, hard)
    for seat in (key, sub / ".." / key.name, link, hard):
        _check(np.check_backup(key, seat),
               f"same-file backup {seat} must block")
        _ready, _pub, _bl = np.preflight("nexus", key, seat, ROOT)
        _check(not _ready and any("same file" in b for b in _bl),
               f"same-file backup {seat} must block READY by name")

    # Oversize backup: blocks by size, named — check_backup must not
    # load either file unbounded (both are copies of a <=_SEED_MAX
    # seed file). Oversize primary via the direct seat blocks too.
    bak.write_bytes(b"A" * (np._SEED_MAX + 1))
    _check(any("oversize" in p for p in np.check_backup(key, bak)),
           "oversize backup must block by size, named")
    bak.write_text(seed.hex())
    big = td / "big.key"
    big.write_bytes(b"B" * (np._SEED_MAX + 1))
    _check(any("oversize" in p for p in np.check_backup(big, bak)),
           "oversize primary must block check_backup by size, named")
    ready, pub, blockers = np.preflight("nexus", key, bak, ROOT)
    _check(ready and blockers == [],
           "bounded backup check must keep a matching pair READY")

    # Malformed seed: no pub, named problem, never a crash.
    key.write_text("not-hex")
    pub3, problems = np.check_key_file(key)
    _check(pub3 is None and problems, "malformed seed must be refused")

    # Non-UTF-8 key bytes: a named problem, never a raised
    # UnicodeDecodeError — check_key_file promises "never raises on
    # bad input", and status/claim call preflight in-process, so a
    # raise would silence all three verdicts at once.
    key.write_bytes(b"\xff\xfe" + b"A" * 62)
    pub4, problems = np.check_key_file(key)
    _check(pub4 is None and problems,
           "non-UTF-8 key must be refused, not raised")
    _ready, _pub, _bl = np.preflight("nexus", key, bak, ROOT)
    _check(not _ready and _bl,
           "non-UTF-8 key must block READY with named blockers")

    # Non-UTF-8 tree file: missing-route blocker, never a crash.
    troot = td / "troot"
    troot.mkdir(exist_ok=True)
    (troot / "federation.py").write_bytes(b"\xff\xfe binary")
    (troot / "verify_name.py").write_text("--expect-pubkey")
    _check(np.check_tree(troot),
           "non-UTF-8 federation.py must block, not raise")

    # Oversize tree files: block by size, named — check_tree must
    # not load either source file unbounded (it only searches for
    # one short marker per file). The marker sits inside the
    # oversize file on purpose: size, not content, is the verdict.
    (troot / "federation.py").write_bytes(
        b'"/fed/names/gossip"' + b"x" * np._TREE_MAX)
    (troot / "verify_name.py").write_text("--expect-pubkey")
    _check(any("oversize" in p and "federation" in p
               for p in np.check_tree(troot)),
           "oversize federation.py must block by size, named")
    (troot / "federation.py").write_text('"/fed/names/gossip"')
    (troot / "verify_name.py").write_bytes(
        b"--expect-pubkey" + b"x" * np._TREE_MAX)
    _check(any("oversize" in p and "verify_name" in p
               for p in np.check_tree(troot)),
           "oversize verify_name.py must block by size, named")

    # Tree checks pass on the real tree (gossip route + pin present).
    _check(np.check_tree(ROOT) == [], "real tree must pass tree checks")

if fails:
    print(f"{fails} FAILURES")
    sys.exit(1)
print("PASS: test_nexus_preflight")
