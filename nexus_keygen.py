#!/usr/bin/env python3
"""Generate the Nexus name key ONLY — never claims, never networks.

nexus_preflight.py guards the root claim fail-closed, but its first
blocker — "the Nexus key has not been generated yet" — had no safe
way to clear: mint_name.py generates a key and broadcasts the claim
in the SAME run, which is precisely the shape that lost
genesis.cyberspace (claimed 2026-10-08, key unsaved, locked until
2027-10-08, abandoned by the 2026-10-15 root-name ruling).

This tool splits generation from claiming:

  1. Mints one Ed25519 seed with os.urandom and writes it born-0600
     (mint_name._write_secret, O_EXCL — an existing key is REFUSED,
     never overwritten) to ~/.cyberspace/nexus-name.key.
  2. Writes the verified second copy the preflight demands, also
     born-0600 and O_EXCL, to the --backup path (default:
     ~/.cyberspace/nexus-name.key.bak).
  3. Re-reads both files through nexus_preflight's own checks and
     prints the derived public key for out-of-band pinning
     (verify_name.py --expect-pubkey).

It sends nothing, claims nothing, and leaves the claim itself to a
separate deliberate step that must first pass nexus_preflight READY.
If step 3 verification fails, the files are LEFT in place (deleting a
key we cannot read is how keys get lost twice) and the exit is 1.

Usage: ./venv/bin/python nexus_keygen.py [--key PATH] [--backup PATH]
(each option also accepted in the --key=PATH / --backup=PATH spelling,
the twin of mint_name's both-spellings parser — an operator typing the
equals form at the supervised step must generate, not be refused)
Exit codes: 0 = key + backup generated and verified, 1 = generated
but verification failed (or the backup write failed AFTER the
primary was written — the primary is left in place, named in the
output, and must not be claimed from), 2 = usage / refused
(nothing written).

The same-file refusal compares RESOLVED paths: --key and --backup
spelled differently for one file (a `sub/../` detour, a symlinked
parent) are the same file. Raw Path equality missed those, the
first O_EXCL write succeeded, the second failed "File exists",
and the run reported a clean refusal (exit 2, nothing written)
while leaving a lone primary with NO backup — the genesis shape.
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nexus_preflight as np  # noqa: E402
from fed.ed25519 import publickey  # noqa: E402
from mint_name import _write_secret  # noqa: E402

_LABEL = "nexus"


def _same_file(a, b):
    """True when two paths name the same file once resolved —
    `sub/../x`, `./x` and symlinked parents included."""
    return Path(a).resolve() == Path(b).resolve()


def _ensure_parent(path):
    """Create path's parent dirs; any dir WE create is born 0700.

    The key file is born 0600, but mkdir's default (0755) left the
    directory holding the root name key world-listable. Only dirs
    this call creates are tightened — a pre-existing dir is the
    operator's own and is left exactly as found.
    """
    parent = Path(path).parent
    missing = []
    p = parent
    while not p.exists():
        missing.append(p)
        if p.parent == p:
            break
        p = p.parent
    parent.mkdir(parents=True, exist_ok=True)
    for d in missing:
        os.chmod(d, 0o700)


def generate(key_path, backup_path):
    """Write key + backup, verify via the preflight's own checks.

    Return (pub_hex | None, problems). Both files are written before
    any verification runs; a refusal (existing file, unwritable dir)
    raises OSError to the caller. Key and backup naming the same
    resolved file raises ValueError before anything is written.
    """
    if _same_file(key_path, backup_path):
        raise ValueError("key and backup resolve to the same file — "
                         "a backup must be a second copy")
    seed = os.urandom(32)
    seed_hex = seed.hex()
    key_path = Path(key_path)
    backup_path = Path(backup_path)
    _ensure_parent(key_path)
    _ensure_parent(backup_path)
    _write_secret(key_path, seed_hex)       # O_EXCL: never overwrite
    _write_secret(backup_path, seed_hex)    # O_EXCL: never overwrite
    pub_hex, problems = np.check_key_file(key_path)
    problems += np.check_backup(key_path, backup_path)
    if pub_hex is not None and pub_hex != publickey(seed).hex().lower():
        problems.append("re-read pub does not match the generated seed")
    return pub_hex, problems


def main(argv):
    home = Path.home() / ".cyberspace"
    key_path = home / f"{_LABEL}-name.key"
    backup_path = home / f"{_LABEL}-name.key.bak"
    seen = set()
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("-h", "--help"):
            print(__doc__.strip())
            return 0
        if a.startswith(("--key=", "--backup=")):
            opt, _, v = a.partition("=")
            if not v:
                print(f"refused: {opt} needs a value", file=sys.stderr)
                return 2
            if opt in seen:
                print(f"refused: {opt} given more than once",
                      file=sys.stderr)
                return 2
            seen.add(opt)
            if opt == "--key":
                key_path = Path(v)
            else:
                backup_path = Path(v)
            i += 1
            continue
        if a in ("--key", "--backup"):
            if a in seen:
                print(f"refused: {a} given more than once", file=sys.stderr)
                return 2
            seen.add(a)
            i += 1
            if i >= len(argv) or argv[i].startswith("--"):
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
    if _same_file(key_path, backup_path):
        print("refused: --key and --backup are the same file — a backup "
              "must be a second copy, not the same file", file=sys.stderr)
        return 2
    for p in (key_path, backup_path):
        if p.exists():
            print(f"refused: {p} already exists — never overwrite a "
                  f"name key; nothing was written", file=sys.stderr)
            return 2
    try:
        pub_hex, problems = generate(key_path, backup_path)
    except OSError as e:
        if key_path.exists() and not backup_path.exists():
            print(f"PARTIAL: the primary key WAS written to {key_path} "
                  f"but the backup failed: {e} — the key is left in "
                  f"place with NO backup; do NOT claim from it, and "
                  f"do not delete it; add a verified backup first",
                  file=sys.stderr)
            return 1
        print(f"refused: key generation failed: {e}", file=sys.stderr)
        return 2
    print(f"Nexus name key written: {key_path} (0600)")
    print(f"Nexus name key backup:  {backup_path} (0600, verified match)")
    if pub_hex is not None:
        print(f"Nexus name key (pub, pin this out-of-band): {pub_hex}")
    for p in problems:
        print(f"PROBLEM: {p}")
    if problems:
        print("GENERATED BUT UNVERIFIED: files left in place — do NOT "
              "claim until nexus_preflight reports READY.")
        return 1
    print("Key seats verified. NOTHING was claimed. Next deliberate "
          "step: nexus_preflight.py must report READY, then the claim "
          "is broadcast separately with this kept key.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
