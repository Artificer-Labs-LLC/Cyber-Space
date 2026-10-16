#!/usr/bin/env python3
"""One-command Nexus chase status: where the root claim stands.

Fifth and final split step of the Nexus root claim, after
nexus_keygen.py (generation), nexus_preflight.py (readiness),
nexus_claim.py (claim) and nexus_depth_check.py (independent
verification). Those four are separate on purpose -- generation
must never fuse with claiming, the mistake that lost genesis --
but an executor arriving cold (a board member back after a reset,
a fleet hand taking over) had to run and reconcile all four by
hand to learn one fact: what is the next supervised step?

This aggregator answers that, read-only and offline:

  1. It runs nexus_preflight's own checks (kept key, verified
     backup, tree carries the gossip receive route and the pin)
     -- it re-implements none of them.
  2. It prints the pub for out-of-band pinning when a key exists.
  3. It names the NEXT step in the supervised sequence, and only
     that step: keygen if no key, preflight blockers if a key
     exists but is not READY, claim --dry-run if READY.
  4. Claim and depth state are reported as UNKNOWN (offline):
     whether nexus.cyberspace is claimed, and whether it passes
     from an independent node, cannot be known without the
     network, and this tool touches none. It never guesses a
     PASS -- a status that invents depth is the rigged shape.
  5. Independent-host state is reported as NOT EVALUATED: this
     tool holds no candidate evidence, so step 5's host bar
     (nexus_host_check.py, docs/NEXUS_INDEPENDENT_HOST.md) is
     named as unevaluated, never as cleared. A READY preflight
     does not imply an eligible independent host exists.

It sends nothing, claims nothing, generates nothing, writes
nothing.
Exit codes: 0 = READY (next step is the claim), 1 = NOT READY
(next step named), 2 = usage.
Usage: ./venv/bin/python nexus_status.py [--key PATH] [--backup PATH]
(each option also accepted in the --key=PATH / --backup=PATH spelling,
the twin of nexus_keygen's and nexus_preflight's both-spellings parsers)
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nexus_preflight as np  # noqa: E402

_LABEL = "nexus"

_SEQUENCE = [
    "./venv/bin/python nexus_keygen.py",
    "./venv/bin/python nexus_preflight.py "
    "--backup ~/.cyberspace/nexus-name.key.bak",
    "./venv/bin/python nexus_claim.py <mirror_url> --dry-run",
    "./venv/bin/python nexus_claim.py <mirror_url>",
    "./venv/bin/python nexus_host_check.py "
    "--candidate-machine-id <id> --origin-machine-id <id> "
    "--candidate-operator <name> --origin-operator <name> "
    "--evidence-source machine-itself --feed gossip "
    "--pin-source out-of-band",
    "./venv/bin/python nexus_depth_check.py <independent_url> "
    "--expect-pubkey <pub-from-step-1> --origin-url <mirror_url>",
]


def status(key_path, backup_path, root):
    """Return (exit_code, lines). Offline; preflight is the judge."""
    key_path = Path(key_path)
    if backup_path is None:
        backup_path = Path(str(key_path) + ".bak")
    ready, pub_hex, blockers = np.preflight(_LABEL, key_path,
                                            Path(backup_path), root)
    lines = [f"Nexus root claim -- chase status ({_LABEL}.cyberspace)"]
    if pub_hex is not None:
        lines.append(f"Name key (pub, pin this out-of-band): {pub_hex}")
    else:
        lines.append("Name key: none kept yet")
    for b in blockers:
        lines.append(f"BLOCKER: {b}")
    lines.append("Claim state: UNKNOWN (offline -- nexus_claim.py "
                 "against a live mirror is the only witness)")
    lines.append("Depth state: UNKNOWN (offline -- "
                 "nexus_depth_check.py from an independent node, "
                 "never the claim origin, is the only witness)")
    lines.append("Independent host: NOT EVALUATED (offline -- no "
                 "candidate evidence held here; step 5 needs "
                 "nexus_host_check.py ELIGIBLE on supplied "
                 "evidence, see docs/NEXUS_INDEPENDENT_HOST.md)")
    lines.append("Supervised sequence:")
    for i, step in enumerate(_SEQUENCE, 1):
        lines.append(f"  {i}. {step}")
    if ready:
        lines.append("NEXT: preflight READY -- run step 3 "
                     "(nexus_claim --dry-run) under supervision, "
                     "then step 4, then step 5 (nexus_host_check "
                     "ELIGIBLE), then step 6 from a node that "
                     "did not host the claim.")
        return 0, lines
    if not key_path.exists():
        lines.append("NEXT: step 1 (nexus_keygen.py) under "
                     "supervision -- generation is deliberate, "
                     "never a cron improvisation.")
    else:
        lines.append("NEXT: clear the blockers above, then re-run "
                     "nexus_preflight.py until READY.")
    return 1, lines


def main(argv):
    key_path = Path.home() / ".cyberspace" / f"{_LABEL}-name.key"
    backup_path = None
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
                print(f"refused: {a} given more than once",
                      file=sys.stderr)
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
    root = Path(os.path.dirname(os.path.abspath(__file__)))
    code, lines = status(key_path, backup_path, root)
    for line in lines:
        print(line)
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
