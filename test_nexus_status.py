#!/usr/bin/env python3
"""nexus_status belt: the chase status must never invent depth.

Proves, with throwaway keygen'd keys in a temp dir (no network):
no key names keygen as NEXT and exits 1; a ready key+backup exits
0, prints the pub for pinning, and names claim --dry-run as NEXT;
a key without a backup is NOT READY; and in every seat the claim
and depth states read UNKNOWN (offline) -- never a guessed PASS.
"""
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

    bak.unlink()
    code, lines = ns.status(key, bak, ROOT)
    _check(code == 1, "key without backup must be NOT READY")

if fails:
    print(f"test_nexus_status: {fails} FAIL")
    sys.exit(1)
print("test_nexus_status: PASS")
