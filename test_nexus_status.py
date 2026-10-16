#!/usr/bin/env python3
"""nexus_status belt: the chase status must never invent depth.

Proves, with throwaway keygen'd keys in a temp dir (no network):
no key names keygen as NEXT and exits 1; a ready key+backup exits
0, prints the pub for pinning, and names claim --dry-run as NEXT;
a key without a backup is NOT READY; and in every seat the claim
and depth states read UNKNOWN (offline) -- never a guessed PASS.
"""
import contextlib
import io
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nexus_keygen as nk  # noqa: E402
import nexus_status as ns  # noqa: E402

fails = 0


def _check(cond, why):
    global fails
    if not cond:
        print(f"FAIL: {why}")
        fails += 1


ROOT = Path(os.path.dirname(os.path.abspath(__file__)))

with tempfile.TemporaryDirectory() as td:
    td = Path(td)
    key, bak = td / "nexus-name.key", td / "nexus-name.key.bak"

    code, lines = ns.status(key, bak, ROOT)
    text = "\n".join(lines)
    _check(code == 1, f"no key must be NOT READY (exit 1), got {code}")
    _check("nexus_keygen.py" in text and "NEXT:" in text,
           "no-key seat must name keygen as NEXT")
    _check("UNKNOWN (offline" in text, "offline seats must say UNKNOWN")
    _check("Independent host: NOT EVALUATED" in text,
           "host bar must read NOT EVALUATED, never silently absent")
    _check("Independent host: ELIGIBLE" not in text,
           "status must never claim an eligible independent host")
    _check("DEPTH PASS" not in text and "Claim state: claimed" not in text,
           "status must never invent a claim or a depth PASS")
    _seq = text.split("Supervised sequence:", 1)[-1]
    _check("nexus_host_check.py" in _seq
           and _seq.index("nexus_host_check.py")
           < _seq.index("nexus_depth_check.py"),
           "sequence must gate depth behind host_check (step 5 before 6)")

    pub, problems = nk.generate(key, bak)
    _check(not problems, f"temp keygen failed: {problems}")

    code, lines = ns.status(key, bak, ROOT)
    text = "\n".join(lines)
    _check(code == 0, f"ready key+backup must exit 0, got {code}: {text}")
    _check(pub in text, "ready seat must print the pub for pinning")
    _check("--dry-run" in text, "ready seat must name claim --dry-run NEXT")
    _check("UNKNOWN (offline" in text,
           "even READY, claim/depth stay UNKNOWN until witnessed live")
    _check("Independent host: NOT EVALUATED" in text
           and "Independent host: ELIGIBLE" not in text,
           "even READY, host stays NOT EVALUATED -- READY is not depth")

    # The equals spelling (--key=PATH) is accepted by main, twin
    # of nexus_preflight's both-spellings parser; an empty equals
    # value is a usage refusal, and the space form missing its
    # value stays refused.
    _check(ns.main([f"--key={key}", f"--backup={bak}"]) == 0,
           "equals spelling must reach READY for a matching pair")
    _check(ns.main(["--key=", f"--backup={bak}"]) == 2,
           "empty equals value must be a usage refusal")
    _check(ns.main([f"--backup={bak}", "--key"]) == 2,
           "space form with a missing value must stay refused")

    # A following -- flag is not a space-form value: --key --backup
    # swallowed the backup flag as the key path and then blamed the
    # real backup path as unknown, instead of naming --key -- twin
    # of nexus_preflight's and nexus_keygen's space-form gates.
    for _argv, _flag in ((["--key", "--backup", str(bak)], "--key"),
                         (["--backup", "--key", str(key)], "--backup")):
        _err = io.StringIO()
        with contextlib.redirect_stderr(_err):
            _code = ns.main(_argv)
        _check(_code == 2 and f"{_flag} needs a value" in _err.getvalue(),
               f"following flag must refuse as {_flag} needs a value")

    # -h is a flag token too, not a space-form value: --key -h
    # swallowed the help flag as the key path and reported on a
    # file named "-h" in the cwd while the operator believed the
    # kept key was checked (probed) -- twin of nexus_keygen's
    # -h gate (c0b00de). Both flags refuse it as a missing value.
    for _argv, _flag in ((["--key", "-h",
                           "--backup", str(bak)], "--key"),
                         (["--backup", "-h",
                           "--key", str(key)], "--backup")):
        _err = io.StringIO()
        with contextlib.redirect_stderr(_err):
            _code = ns.main(_argv)
        _check(_code == 2 and f"{_flag} needs a value" in _err.getvalue(),
               f"-h must refuse as {_flag} needs a value")

    # Any flag-shaped token is not a space-form value: --key -x
    # reported on a file named "-x" while the operator believed
    # the kept key was checked (probed) -- the -h gate left every
    # other single-dash token open, twin of nexus_host_check's
    # flag-shaped gate (88a8a6c). Both flags refuse -x by name.
    for _argv, _flag in ((["--key", "-x",
                           "--backup", str(bak)], "--key"),
                         (["--backup", "-x",
                           "--key", str(key)], "--backup")):
        _err = io.StringIO()
        with contextlib.redirect_stderr(_err):
            _code = ns.main(_argv)
        _check(_code == 2 and f"{_flag} needs a value" in _err.getvalue(),
               f"-x must refuse as {_flag} needs a value")

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
            _code = ns.main(_argv)
        _check(_code == 2 and f"{_flag} given more than once"
               in _err.getvalue(),
               f"duplicate {_flag} must refuse by name")

    bak.unlink()
    code, lines = ns.status(key, bak, ROOT)
    _check(code == 1, "key without backup must be NOT READY")

if fails:
    print(f"test_nexus_status: {fails} FAIL")
    sys.exit(1)
print("test_nexus_status: PASS")
