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
    try:
        with p.open(encoding="utf-8") as f:
            raw = f.read(_SEED_MAX + 1)
    except OSError as e:
        return None, problems + [f"key file unreadable: {e}"]
    if len(raw) > _SEED_MAX:
        return None, problems + [f"key file {p} exceeds {_SEED_MAX} chars"]
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
    try:
        primary_raw = Path(primary_path).read_bytes()
        backup_raw = b.read_bytes()
    except OSError as e:
        return problems + [f"backup comparison unreadable: {e}"]
    if primary_raw.strip() != backup_raw.strip():
        problems.append("backup does not match the primary key — "
                        "a mismatched backup is no backup")
    return problems


def check_tree(root):
    """The local tree must carry the gossip receive route and the pin."""
    problems = []
    fed = Path(root) / "federation.py"
    try:
        fed_text = fed.read_text(encoding="utf-8")
    except OSError:
        fed_text = ""
    if '"/fed/names/gossip"' not in fed_text:
        problems.append("federation.py lacks the /fed/names/gossip "
                        "receive route — names cannot federate")
    verify = Path(root) / "verify_name.py"
    try:
        verify_text = verify.read_text(encoding="utf-8")
    except OSError:
        verify_text = ""
    if "--expect-pubkey" not in verify_text:
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
