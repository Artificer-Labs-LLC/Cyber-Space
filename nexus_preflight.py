#!/usr/bin/env python3
"""Preflight for the Nexus root claim — fail-closed, offline, never claims.

Root-name ruling (2026-10-15): the founding root name is Nexus
(nexus.cyberspace), not Genesis. genesis.cyberspace was claimed
2026-10-08 with a key that was NOT saved; it is locked until
2027-10-08 and abandoned as a name — never reclaim it. The genesis
loss is the lesson this tool exists to enforce: the Nexus key must be
generated, stored, AND backed up before any claim is broadcast, and
the Depth Test pin must be taken from the key out-of-band, never from
a binding served back by the same node that hosts it.

This tool checks readiness only. It never generates a key, never
touches the network, and never claims. Key generation is a deliberate
supervised step (mint_name.py generates + claims in one run, so the
generation for Nexus must be planned, not improvised by a tick).

Checks (all must pass for READY):
  1. Label is exactly "nexus" ("genesis" is refused outright).
  2. Key file ~/.cyberspace/nexus-name.key (or --key PATH) exists,
     has no group/other permission bits, and holds exactly one
     64-hex-char seed; the derived public key is printed so it can be
     pinned out-of-band (verify_name.py --expect-pubkey).
  3. A backup copy (--backup PATH) exists, is equally tight, and
     matches the primary seed byte-for-byte. No verified backup,
     no broadcast — that is the whole point.
  4. The tree can federate and pin: federation.py carries the
     POST /fed/names/gossip receive route, and verify_name.py
     supports the --expect-pubkey pin.

Exit codes: 0 = READY, 1 = NOT READY (blockers listed), 2 = usage.
Usage: ./venv/bin/python nexus_preflight.py [--key PATH] [--backup PATH]
"""

import os
import stat
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fed.ed25519 import publickey  # noqa: E402

_ROOT_LABEL = "nexus"
_REFUSED_LABEL = "genesis"
_SEED_MAX = 1024
_TREE_MAX = 1_048_576


def _parent_dir_problem(path, what):
    """A secret's parent dir is part of its protection, or none.

    The file's own 0600 cannot protect it inside a loose directory:
    directory write lets anyone who can write there rename the key
    away and plant a substitute (the next read then derives a
    stranger's pub), and read+execute lists it. That is why both
    key-writing tools (nexus_keygen._ensure_parent, mint_name
    ._ensure_dir) create these dirs born 0700 — yet preflight only
    ever statted the FILE (probed 2026-10-16: a tight 0600 key in a
    0777 dir reported READY). Return a named problem, or [].

    A symlinked key has TWO parents that matter: the link's own
    directory (write there repoints the link at a stranger's file)
    and the resolved target's directory (write there replaces the
    file itself). Checking only the literal parent missed the
    second (probed 2026-10-16: a tight-dir symlink into a 0777 dir
    reported READY). Check both, deduped when they coincide."""
    parents = []
    for cand in (Path(path).parent, Path(path).resolve().parent):
        if cand not in parents:
            parents.append(cand)
    problems = []
    for parent in parents:
        try:
            mode = stat.S_IMODE(parent.stat().st_mode)
        except OSError:
            continue
        if mode & 0o077:
            problems.append(
                f"{what} directory {parent} is group/other-accessible "
                f"(mode {mode:04o}); a name key's directory is born "
                f"0700 — directory write would let a stranger "
                f"replace the key, directory read lists it")
    return problems


def check_key_file(path):
    """Return (pub_hex | None, problems). Never raises on bad input."""
    problems = []
    p = Path(path)
    if not p.exists():
        return None, [f"key file missing: {p} — the Nexus key has not "
                      f"been generated yet (supervised step, not a tick)"]
    mode = stat.S_IMODE(p.stat().st_mode)
    if mode & 0o077:
        problems.append(f"key file {p} is group/other-accessible "
                        f"(mode {mode:04o}); name keys are born 0600")
    problems += _parent_dir_problem(p, "key file")
    try:
        with p.open("rb") as f:
            raw_bytes = f.read(_SEED_MAX + 1)
    except OSError as e:
        return None, problems + [f"key file unreadable: {e}"]
    if len(raw_bytes) > _SEED_MAX:
        return None, problems + [f"key file {p} exceeds {_SEED_MAX} chars"]
    try:
        raw = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return None, problems + [f"key file {p} is not UTF-8 text — "
                                 f"a name key is one 64-hex-char seed"]
    seed_hex = raw.strip()
    if len(seed_hex) != 64:
        return None, problems + [f"key file {p} is not a 64-hex-char seed"]
    try:
        seed = bytes.fromhex(seed_hex)
    except ValueError:
        return None, problems + [f"key file {p} is not hex"]
    if len(seed) != 32:
        return None, problems + [f"key file {p} is not a 32-byte seed"]
    return publickey(seed).hex().lower(), problems


def _same_file(a, b):
    """True when two paths name one physical file — resolved-path
    equality (sub/../ detours, symlinked parents, symlinks) or, when
    both exist, the same inode (hardlinks included)."""
    if Path(a).resolve() == Path(b).resolve():
        return True
    try:
        return os.path.samefile(a, b)
    except OSError:
        return False


def check_backup(primary_path, backup_path):
    """Backup must exist, be tight, and match the primary byte-for-byte."""
    if backup_path is None:
        return ["no --backup PATH given — a verified second copy of the "
                "Nexus key must exist before any claim is broadcast "
                "(genesis was lost exactly this way)"]
    b = Path(backup_path)
    if _same_file(primary_path, b):
        return ["backup is the same file as the primary key — a backup "
                "must be a second copy, not the same file (one file "
                "lost is the genesis shape)"]
    if not b.exists():
        return [f"backup key file missing: {b}"]
    mode = stat.S_IMODE(b.stat().st_mode)
    problems = []
    if mode & 0o077:
        problems.append(f"backup {b} is group/other-accessible "
                        f"(mode {mode:04o})")
    problems += _parent_dir_problem(b, "backup")
    # Bounded reads, twin of check_key_file's _SEED_MAX cap above and
    # mint_name._read_seed's: a backup is a copy of a seed file, which
    # is never over _SEED_MAX bytes, yet this seat loaded BOTH files
    # via read_bytes() unbounded before comparing (probed 2026-10-16:
    # a 50 MB backup pulled ~63 MB RSS into a readiness check). Read
    # at most _SEED_MAX + 1 bytes of each; anything larger is not a
    # copy of the seed and blocks by size, never by full comparison.
    try:
        with Path(primary_path).open("rb") as f:
            primary_raw = f.read(_SEED_MAX + 1)
        with b.open("rb") as f:
            backup_raw = f.read(_SEED_MAX + 1)
    except OSError as e:
        return problems + [f"backup comparison unreadable: {e}"]
    if len(primary_raw) > _SEED_MAX or len(backup_raw) > _SEED_MAX:
        return problems + [f"backup comparison oversize: a backup is "
                           f"a copy of the seed file, which never "
                           f"exceeds {_SEED_MAX} bytes — an oversize "
                           f"primary or backup is not a verified copy"]
    if primary_raw.strip() != backup_raw.strip():
        problems.append("backup does not match the primary key — "
                        "a mismatched backup is no backup")
    return problems


def _read_tree_text(path):
    """Return (text, oversize). Bounded twin of the seed caps above:
    check_tree loaded both source files via read_text() unbounded
    (probed 2026-10-16: a 50 MB federation.py pulled ~114 MB peak
    RSS into a readiness check), yet it only searches each file for
    one short marker. Read at most _TREE_MAX + 1 bytes (the real
    files are ~84 KB / ~13 KB); an oversize file is named by the
    caller and blocks fail-closed, never searched in full. An
    unreadable or non-UTF-8 file reads as empty, as before."""
    try:
        with path.open("rb") as f:
            raw = f.read(_TREE_MAX + 1)
    except OSError:
        return "", False
    if len(raw) > _TREE_MAX:
        return "", True
    try:
        return raw.decode("utf-8"), False
    except UnicodeDecodeError:
        return "", False


def check_tree(root):
    """The local tree must carry the gossip receive route and the pin."""
    problems = []
    fed_text, fed_over = _read_tree_text(Path(root) / "federation.py")
    if fed_over:
        problems.append(f"federation.py exceeds {_TREE_MAX} bytes — "
                        f"tree check oversize: the gossip receive "
                        f"route cannot be verified without an "
                        f"unbounded read")
    elif '"/fed/names/gossip"' not in fed_text:
        problems.append("federation.py lacks the /fed/names/gossip "
                        "receive route — names cannot federate")
    verify_text, verify_over = _read_tree_text(Path(root)
                                               / "verify_name.py")
    if verify_over:
        problems.append(f"verify_name.py exceeds {_TREE_MAX} bytes — "
                        f"tree check oversize: the --expect-pubkey "
                        f"pin cannot be verified without an "
                        f"unbounded read")
    elif "--expect-pubkey" not in verify_text:
        problems.append("verify_name.py lacks the --expect-pubkey pin — "
                        "the Depth Test cannot pin the Nexus key out-of-band")
    return problems


def preflight(label, key_path, backup_path, root):
    """Return (ready: bool, pub_hex | None, blockers: list[str])."""
    if label == _REFUSED_LABEL:
        return False, None, ["label 'genesis' is refused: claimed "
                             "2026-10-08 with an unsaved key, locked "
                             "until 2027-10-08, and abandoned as a name "
                             "by the 2026-10-15 root-name ruling"]
    if label != _ROOT_LABEL:
        return False, None, [f"label {label!r} is not the root label "
                             f"{_ROOT_LABEL!r} — this preflight guards "
                             f"the root claim only"]
    blockers = []
    pub_hex, key_problems = check_key_file(key_path)
    blockers += key_problems
    if pub_hex is not None:
        blockers += check_backup(key_path, backup_path)
    else:
        blockers.append("backup check skipped — no primary key to back up")
    blockers += check_tree(root)
    return (not blockers), pub_hex, blockers


def main(argv):
    key_path = Path.home() / ".cyberspace" / f"{_ROOT_LABEL}-name.key"
    backup_path = None
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("-h", "--help"):
            print(__doc__.strip())
            return 0
        if a in ("--key", "--backup"):
            i += 1
            if i >= len(argv):
                print(f"refused: {a} needs a value", file=sys.stderr)
                return 2
            if a == "--key":
                key_path = Path(argv[i])
            else:
                backup_path = Path(argv[i])
        else:
            print(f"refused: unknown argument {a!r}", file=sys.stderr)
            return 2
        i += 1
    root = Path(os.path.dirname(os.path.abspath(__file__)))
    ready, pub_hex, blockers = preflight(_ROOT_LABEL, key_path,
                                         backup_path, root)
    if pub_hex is not None:
        print(f"Nexus name key (pub, pin this out-of-band): {pub_hex}")
    for b in blockers:
        print(f"BLOCKER: {b}")
    if ready:
        print("READY: nexus.cyberspace may be claimed — key kept, "
              "backup verified, tree federates and pins.")
        return 0
    print("NOT READY: nexus.cyberspace must not be claimed yet.")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
