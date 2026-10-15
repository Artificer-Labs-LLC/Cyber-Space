#!/usr/bin/env python3
"""Nexus independent-host check — fail-closed, offline, provisions nothing.

docs/NEXUS_INDEPENDENT_HOST.md defines the eligibility bar for the
Depth Test's independent leg in prose. This tool makes that bar
executable: a candidate is ELIGIBLE only when evidence supplied for
all five bars passes, and NOT ELIGIBLE on any missing, unknown, or
disqualifying value. It names no host, authorizes no provisioning
or spend, touches no network, and writes nothing.

The tool evaluates supplied evidence; it does not create it. Machine
identity must come from the machine itself (--evidence-source
machine-itself): a device list or login registry is not a host
census, and evidence sourced from one fails bar 1 outright.

Bars (all five, no partial credit):
  1. Distinct machine: candidate and origin machine ids are both
     present and unequal, evidenced from the machine itself.
  2. Distinct operator: candidate and origin operators are both
     present and unequal.
  3. Not HQ: neither the candidate nor the claim origin is HQ.
  4. Gossip-fed only: the binding arrived via /fed/names/gossip
     (--feed gossip) and the claim key is not present on the
     candidate.
  5. Pinnable out-of-band: the pin was received out-of-band, never
     read off the served binding or the checking node itself.

Exit codes: 0 = ELIGIBLE, 1 = NOT ELIGIBLE (blockers listed),
2 = usage.
Usage: ./venv/bin/python nexus_host_check.py \
  --candidate-machine-id ID --origin-machine-id ID \
  --candidate-operator NAME --origin-operator NAME \
  --evidence-source machine-itself --feed gossip \
  --pin-source out-of-band [--candidate-is-hq] [--origin-is-hq] \
  [--claim-key-present]
"""

import sys
import unicodedata

_FEEDS = ("gossip", "direct-claim", "file-copy", "db-copy",
          "none-yet", "unknown")
_PIN_SOURCES = ("out-of-band", "served-binding", "checking-node",
                "none", "unknown")
_EVIDENCE = ("machine-itself", "registry", "list", "asserted",
             "unknown")


def _invisible(ch):
    """Characters that render as nothing in an id or a log: format
    (Cf: zero-width spaces, joiners, BOMs, tags), control (Cc: NUL,
    DEL and friends -- invisible and log-truncating), surrogates
    (Cs), and the default-ignorable non-spacing marks -- variation
    selectors (U+FE00-FE0F, U+E0100-E01EF) and the combining
    grapheme joiner (U+034F). Other combining marks stay: an accent
    is part of a name, a variation selector is not."""
    if unicodedata.category(ch) in ("Cf", "Cc", "Cs"):
        return True
    o = ord(ch)
    return o == 0x034F or 0xFE00 <= o <= 0xFE0F \
        or 0xE0100 <= o <= 0xE01EF


# Cross-script look-alikes: Cyrillic and Greek letters whose shape
# duplicates a Latin letter (the well-known UTS #39 confusables for
# Latin). A machine id or operator spelled with one of these renders
# identically to the Latin spelling, so it IS the Latin spelling for
# comparison purposes -- the origin may not pass as its own
# independent host or operator by switching alphabets. Scope is
# these two scripts' single-letter Latin duplicates; within-Latin
# look-alikes (l/1, O/0) are font questions, not script spoofing,
# and are deliberately not folded.
_CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "у": "y", "х": "x", "ѕ": "s", "і": "i", "ј": "j",
    "һ": "h",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M",
    "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T",
    "Х": "X", "І": "I", "Ј": "J", "Ѕ": "S",
    "ο": "o", "ρ": "p", "τ": "t", "υ": "u", "χ": "x",
    "ν": "v",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H",
    "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O",
    "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
})


def _norm(v):
    """Identity evidence compares canonically: NFKC-folded (fullwidth
    and other compatibility spellings become the characters they
    render as), invisible characters removed (see _invisible -- a
    seat respelled with them is the same seat), cross-script
    look-alikes folded to the Latin letters they render as (see
    _CONFUSABLES), whitespace runs collapsed and ends stripped, and
    case folded. A value with nothing visible left is no value
    at all. Evidence that is not text at all is no value either:
    a bytes/int/list seat returned untouched compared UNEQUAL to
    the origin's text spelling (b"machine-a" != "machine-a") and
    counted as present, so a type-confused seat cleared bars 1-2
    as its own origin's 'distinct' host/operator."""
    if not isinstance(v, str):
        return ""
    v = unicodedata.normalize("NFKC", v)
    v = "".join(ch for ch in v if not _invisible(ch))
    v = v.translate(_CONFUSABLES)
    return " ".join(v.split()).casefold()


def evaluate(c):
    """Return (eligible: bool, blockers: list[str]). Pure, no I/O."""
    blockers = []
    cm, om = _norm(c.get("candidate_machine_id")), \
        _norm(c.get("origin_machine_id"))
    if not cm or not om:
        blockers.append("bar 1 (distinct machine): machine ids for "
                        "both candidate and origin are required")
    elif cm == om:
        blockers.append("bar 1 (distinct machine): candidate and "
                        "origin share a machine id — a second process, "
                        "port, or login on one host is not a machine")
    if c.get("evidence_source") != "machine-itself":
        blockers.append("bar 1 (distinct machine): evidence source "
                        f"is {c.get('evidence_source')!r}, not "
                        "'machine-itself' — a registry or list is not "
                        "a host census")
    co, oo = _norm(c.get("candidate_operator")), \
        _norm(c.get("origin_operator"))
    if not co or not oo:
        blockers.append("bar 2 (distinct operator): operators for "
                        "both candidate and origin are required")
    elif co == oo:
        blockers.append("bar 2 (distinct operator): candidate and "
                        "origin share an operator")
    if c.get("candidate_is_hq"):
        blockers.append("bar 3 (not HQ): candidate is HQ")
    if c.get("origin_is_hq"):
        blockers.append("bar 3 (not HQ): claim origin is HQ")
    if c.get("feed") != "gossip":
        blockers.append("bar 4 (gossip-fed only): feed is "
                        f"{c.get('feed')!r}, not 'gossip' — a binding "
                        "handed over directly proves storage, not depth")
    if c.get("claim_key_present"):
        blockers.append("bar 4 (gossip-fed only): the claim key is "
                        "present on the candidate — it must never be")
    if c.get("pin_source") != "out-of-band":
        blockers.append("bar 5 (pinnable out-of-band): pin source is "
                        f"{c.get('pin_source')!r}, not 'out-of-band' — "
                        "a pin read off the served binding is "
                        "integrity, not authenticity")
    return (not blockers), blockers


_VALUE_FLAGS = {
    "--candidate-machine-id": "candidate_machine_id",
    "--origin-machine-id": "origin_machine_id",
    "--candidate-operator": "candidate_operator",
    "--origin-operator": "origin_operator",
    "--evidence-source": "evidence_source",
    "--feed": "feed",
    "--pin-source": "pin_source",
}
_BOOL_FLAGS = {
    "--candidate-is-hq": "candidate_is_hq",
    "--origin-is-hq": "origin_is_hq",
    "--claim-key-present": "claim_key_present",
}


def main(argv):
    c = {"candidate_machine_id": None, "origin_machine_id": None,
         "candidate_operator": None, "origin_operator": None,
         "evidence_source": "unknown", "feed": "unknown",
         "pin_source": "unknown", "candidate_is_hq": False,
         "origin_is_hq": False, "claim_key_present": False}
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("-h", "--help"):
            print(__doc__.strip())
            return 0
        if a in _BOOL_FLAGS:
            c[_BOOL_FLAGS[a]] = True
        elif a in _VALUE_FLAGS:
            i += 1
            if i >= len(argv):
                print(f"refused: {a} needs a value", file=sys.stderr)
                return 2
            c[_VALUE_FLAGS[a]] = argv[i]
        else:
            print(f"refused: unknown argument {a!r}", file=sys.stderr)
            return 2
        i += 1
    if c["feed"] not in _FEEDS or c["pin_source"] not in _PIN_SOURCES \
            or c["evidence_source"] not in _EVIDENCE:
        print("refused: --feed, --pin-source, and --evidence-source "
              "must each be one of their documented values",
              file=sys.stderr)
        return 2
    eligible, blockers = evaluate(c)
    for b in blockers:
        print(f"BLOCKER: {b}")
    if eligible:
        print("ELIGIBLE: candidate clears all five bars of "
              "docs/NEXUS_INDEPENDENT_HOST.md on the evidence "
              "supplied. This evaluates supplied evidence only; "
              "record it at standup.")
        return 0
    print("NOT ELIGIBLE: candidate must not be used for Depth Test "
          "step 5.")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
