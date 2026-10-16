#!/usr/bin/env python3
"""nexus_preflight belt: the root-claim guard must fail closed.

genesis.cyberspace was lost because a claim went out with an unsaved
key. Every seat here proves a blocker is named, never smoothed:
refused label, missing key, loose permissions, malformed seed,
missing/mismatched backup, and a tree that cannot federate or pin.
The READY path uses a throwaway key in a temp dir — never the real
~/.cyberspace — and proves the printed pub derives from that seed.
"""
import contextlib
import io
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

    # Loose PARENT directory: the file's own 0600 cannot protect a
    # key whose directory anyone can write (rename the key away,
    # plant a substitute) or read (list it). Both writing tools
    # create these dirs born 0700; preflight must block READY for
    # a loose key dir and for a loose backup dir alike, and a
    # tight dir restores READY.
    loose = td / "loose"
    loose.mkdir()
    lkey = loose / "nexus-name.key"
    lkey.write_text(seed.hex())
    os.chmod(lkey, 0o600)
    lbak = loose / "nexus-name.key.bak"
    lbak.write_text(seed.hex())
    os.chmod(lbak, 0o600)
    os.chmod(loose, 0o777)
    _pub, _probs = np.check_key_file(lkey)
    _check(any("directory" in p for p in _probs),
           "loose key parent dir must be named by check_key_file")
    _check(any("directory" in p for p in np.check_backup(lkey, lbak)),
           "loose backup parent dir must be named by check_backup")
    _ready, _pub, _bl = np.preflight("nexus", lkey, lbak, ROOT)
    _check(not _ready and any("directory" in b for b in _bl),
           "loose parent dir must block READY by name")
    os.chmod(loose, 0o700)
    _ready, _pub, _bl = np.preflight("nexus", lkey, lbak, ROOT)
    _check(_ready and _bl == [],
           f"tight parent dir must restore READY, got {_bl}")

    # Symlinked key: the link sits in a tight dir but the FILE lives
    # in a loose one — the resolved parent is where replacement
    # happens, so it must be named and block READY; tightening the
    # target's dir restores READY.
    tdir = td / "tight"
    tdir.mkdir()
    os.chmod(tdir, 0o700)
    skey = tdir / "nexus-name.key"
    skey.symlink_to(lkey)
    sbak = tdir / "nexus-name.key.bak"
    sbak.write_text(seed.hex())
    os.chmod(sbak, 0o600)
    os.chmod(loose, 0o777)
    _pub, _probs = np.check_key_file(skey)
    _check(any("directory" in p for p in _probs),
           "symlink into a loose dir must be named by check_key_file")
    _ready, _pub, _bl = np.preflight("nexus", skey, sbak, ROOT)
    _check(not _ready and any("directory" in b for b in _bl),
           "symlink into a loose dir must block READY by name")
    os.chmod(loose, 0o700)
    _ready, _pub, _bl = np.preflight("nexus", skey, sbak, ROOT)
    _check(_ready and _bl == [],
           f"tight resolved parent must restore READY, got {_bl}")

    # Non-regular key/backup: a FIFO at either seat must be refused
    # by name WITHOUT being opened — open() on a FIFO blocks until a
    # writer appears, so the unbounded seat hung this fail-closed
    # check forever (probed 2026-10-16). A symlink to a FIFO is the
    # same seat (stat follows the link); a FIFO primary named via
    # check_backup directly blocks too. Matching pair stays READY.
    fifo = td / "fifo.key"
    os.mkfifo(fifo)
    os.chmod(fifo, 0o600)
    pubf, probsf = np.check_key_file(fifo)
    _check(pubf is None and any("not a regular file" in p
                                 for p in probsf),
           "FIFO key must block by name, unopened")
    _check(any("not a regular file" in p
               for p in np.check_backup(key, fifo)),
           "FIFO backup must block by name, unopened")
    _check(any("not a regular file" in p
               for p in np.check_backup(fifo, bak)),
           "FIFO primary must block check_backup by name, unopened")
    flink = td / "fifo-link.key"
    flink.symlink_to(fifo)
    pubf, probsf = np.check_key_file(flink)
    _check(pubf is None and any("not a regular file" in p
                                for p in probsf),
           "symlink to a FIFO key must block by name, unopened")
    _ready, _pub, _bl = np.preflight("nexus", key, bak, ROOT)
    _check(_ready and _bl == [],
           f"regular-file gate must keep a matching pair READY, "
           f"got {_bl}")

    # The equals spelling (--key=PATH) is accepted by main, twin
    # of nexus_keygen's both-spellings parser; an empty equals
    # value is a usage refusal (exit 2), never a silent default.
    _check(np.main([f"--key={key}", f"--backup={bak}"]) == 0,
           "equals spelling must reach READY for a matching pair")
    _check(np.main(["--key=", f"--backup={bak}"]) == 2,
           "empty equals value must be a usage refusal")
    _check(np.main([f"--backup={bak}", "--key"]) == 2,
           "space spelling missing its value must stay a refusal")

    # A following -- flag is not a space-form value: --key --backup
    # swallowed the backup flag as the key path and then blamed the
    # real backup path as unknown, instead of naming --key — twin
    # of nexus_keygen's and nexus_depth_check's space-form gates.
    for _argv, _flag in ((["--key", "--backup", str(bak)], "--key"),
                         (["--backup", "--key", str(key)], "--backup")):
        _err = io.StringIO()
        with contextlib.redirect_stderr(_err):
            _code = np.main(_argv)
        _check(_code == 2 and f"{_flag} needs a value" in _err.getvalue(),
               f"following flag must refuse as {_flag} needs a value")

    # -h is a flag token too, not a space-form value: --key -h
    # swallowed the help flag as the key path and reported on a
    # file named "-h" in the cwd while the operator believed the
    # kept key was checked (probed) -- twin of nexus_status's
    # -h gate (212ea75). Both flags refuse it as a missing value.
    for _argv, _flag in ((["--key", "-h",
                           "--backup", str(bak)], "--key"),
                         (["--backup", "-h",
                           "--key", str(key)], "--backup")):
        _err = io.StringIO()
        with contextlib.redirect_stderr(_err):
            _code = np.main(_argv)
        _check(_code == 2 and f"{_flag} needs a value" in _err.getvalue(),
               f"-h must refuse as {_flag} needs a value")

    # A repeated value flag refuses by name: the parser silently
    # last-won, so --key A --key B checked B while the operator
    # believed it checked A — twin of nexus_keygen's duplicate gate.
    for _argv, _flag in (
            (["--key", str(key), "--key", str(bak)], "--key"),
            ([f"--key={key}", f"--key={bak}"], "--key"),
            (["--backup", str(bak), f"--backup={bak}"], "--backup"),
            ([f"--backup={bak}", "--backup", str(bak)], "--backup")):
        _err = io.StringIO()
        with contextlib.redirect_stderr(_err):
            _code = np.main(_argv)
        _check(_code == 2 and f"{_flag} given more than once"
               in _err.getvalue(),
               f"duplicate {_flag} must refuse by name")

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

    # Non-regular tree files: a FIFO at either seat must be refused
    # by name WITHOUT being opened — open() on a FIFO blocks until a
    # writer appears, so it hung this fail-closed check forever
    # (probed 2026-10-16). A symlink to a FIFO is the same seat.
    (troot / "verify_name.py").write_text("--expect-pubkey")
    tfifo = troot / "federation.py"
    tfifo.unlink()
    os.mkfifo(tfifo)
    _check(any("not a regular file" in p and "federation" in p
               for p in np.check_tree(troot)),
           "FIFO federation.py must block by name, unopened")
    tfifo.unlink()
    tfifo.write_text('"/fed/names/gossip"')
    vfifo = troot / "verify_name.py"
    vfifo.unlink()
    os.mkfifo(vfifo)
    _check(any("not a regular file" in p and "verify_name" in p
               for p in np.check_tree(troot)),
           "FIFO verify_name.py must block by name, unopened")
    vfifo.unlink()
    vlink = troot / "verify_name.py"
    realfifo = troot / "real.fifo"
    os.mkfifo(realfifo)
    vlink.symlink_to(realfifo)
    _check(any("not a regular file" in p and "verify_name" in p
               for p in np.check_tree(troot)),
           "symlink to a FIFO verify_name.py must block by name, "
           "unopened")
    vlink.unlink()
    vlink.write_text("--expect-pubkey")
    _check(np.check_tree(troot) == [],
           "regular tree files must restore a clean check_tree")

    # Tree checks pass on the real tree (gossip route + pin present).
    _check(np.check_tree(ROOT) == [], "real tree must pass tree checks")

if fails:
    print(f"{fails} FAILURES")
    sys.exit(1)
print("PASS: test_nexus_preflight")
