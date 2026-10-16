#!/usr/bin/env python3
"""nexus_keygen belt: generation must be claim-free and loss-proof.

The genesis loss had two halves: a claim broadcast with an unsaved
key, and no second copy. This belt proves the generator writes BOTH
files born-0600 and byte-identical, refuses to overwrite either one
(the name key of the root must be impossible to clobber by re-running
a command), refuses key == backup, and that what it writes passes
nexus_preflight READY in a temp dir — never the real ~/.cyberspace.
"""
import contextlib
import io
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

    # The same file spelled through a sub/../ detour is still one
    # file: raw Path equality missed it, the primary write landed,
    # the backup write failed "File exists", and the run reported
    # a clean refusal while leaving a lone key with NO backup.
    (td / "sub").mkdir()
    _check(nk.main(["--key", str(td / "alias"),
                    "--backup", str(td / "sub" / ".." / "alias")]) == 2,
           "key == backup via a sub/../ spelling must be refused")
    _check(not (td / "alias").exists(),
           "aliased same-file refusal must write nothing")

    # The equals spelling (--key=PATH) is accepted, twin of
    # mint_name's both-spellings parser; an empty equals value is a
    # usage refusal, and equals spelling honors the overwrite ban.
    eq_key, eq_bak = td / "eq.key", td / "eq.key.bak"
    _check(nk.main([f"--key={eq_key}", f"--backup={eq_bak}"]) == 0,
           "equals spelling must generate")
    _check(eq_key.exists() and eq_bak.exists(),
           "equals generation must write both files")
    _check(nk.main([f"--key={eq_key}", f"--backup={td / 'eq2.bak'}"]) == 2,
           "equals spelling must refuse an existing key")
    _check(nk.main(["--key=", f"--backup={td / 'eq3.bak'}"]) == 2,
           "empty equals value must be refused")
    _check(not (td / "eq3.bak").exists(),
           "empty equals refusal writes nothing")

    # A following -- flag is not a space-form value: --key --backup
    # swallowed the backup flag as the key path and then blamed the
    # real backup path as unknown, instead of naming --key.
    for _argv, _flag in ((["--key", "--backup", str(td / "fv.bak")], "--key"),
                         (["--backup", "--key", str(td / "fv.key")], "--backup")):
        _err = io.StringIO()
        with contextlib.redirect_stderr(_err):
            _code = nk.main(_argv)
        _check(_code == 2 and f"{_flag} needs a value" in _err.getvalue(),
               f"following flag must refuse as {_flag} needs a value")
    _check(not (td / "fv.key").exists() and not (td / "fv.bak").exists(),
           "flag-as-value refusal writes nothing")

    # A repeated value flag must refuse, not silently last-win:
    # --key A --key B wrote the key to B while the operator believed
    # it sat at A (probed). Both spellings, both flags.
    for _argv, _flag in (
            (["--key", str(td / "dup1.key"), "--key", str(td / "dup2.key"),
              "--backup", str(td / "dup.bak")], "--key"),
            ([f"--backup={td / 'dup.bak'}", f"--backup={td / 'dup2.bak'}",
              "--key", str(td / "dup.key")], "--backup")):
        _err = io.StringIO()
        with contextlib.redirect_stderr(_err):
            _code = nk.main(_argv)
        _check(_code == 2 and f"{_flag} given more than once" in _err.getvalue(),
               f"duplicate {_flag} must refuse by name")
    _check(not (td / "dup1.key").exists() and not (td / "dup2.key").exists()
           and not (td / "dup.key").exists() and not (td / "dup.bak").exists(),
           "duplicate-flag refusal writes nothing")

    # A backup write that fails AFTER the primary lands (here: a
    # dangling symlink -- exists() passes it, O_EXCL refuses it)
    # is a PARTIAL generation, exit 1 -- never a clean "nothing
    # written" refusal -- and the primary is left in place, alone,
    # for a backup to be added to.
    lone = td / "lone.key"
    dangling = td / "lone.key.bak"
    dangling.symlink_to(td / "no-such-target")
    _check(nk.main(["--key", str(lone),
                    "--backup", str(dangling)]) == 1,
           "backup failure after the primary write is exit 1 (partial)")
    _check(lone.exists(), "partial generation leaves the primary in place")
    _check(not dangling.exists(),
           "partial generation has no backup copy (dangling link only)")

    # A parent dir keygen itself creates is born 0700 (the key's
    # directory must not be world-listable); a pre-existing dir is
    # left exactly as found.
    nested = td / "vault" / "nexus-name.key"
    pub3, problems3 = nk.generate(nested, td / "vault" / "nexus-name.key.bak")
    _check(problems3 == [], f"nested generation must verify, got {problems3}")
    _check(stat.S_IMODE((td / "vault").stat().st_mode) == 0o700,
           "keygen-created parent dir must be born 0700")
    before_mode = stat.S_IMODE(td.stat().st_mode)
    nk.generate(td / "plain.key", td / "plain.key.bak")
    _check(stat.S_IMODE(td.stat().st_mode) == before_mode,
           "pre-existing parent dir mode must be left unchanged")

if fails:
    print(f"{fails} FAILURES")
    sys.exit(1)
print("PASS: test_nexus_keygen")
