"""Unit tests for the names-registry primitives in core.py.

Covers the two halves of the claim gate that the resolver suites don't:
  _valid_name_label  — the first-label grammar (names/claim + names_resolve
                       + resolve_cyberspace step 1 all call it)
  _name_claim_beats  — the deterministic conflict rule: same key re-signing
                       (later issued_at supersedes), different keys (earlier
                       issued_at wins, ties by lower pubkey hex). No votes,
                       no auctions — every mirror computes the same answer.

In-process only: no network, no daemons, no DB.

Run: cd ~/workspace/cybernet && ./venv/bin/python test_name_claim.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core import _name_claim_beats, _valid_name_label  # noqa: E402

CASES = {"passed": 0, "failed": 0}


def check(name, cond, extra=""):
    if cond:
        CASES["passed"] += 1
        print(f"  ok  {name}")
    else:
        CASES["failed"] += 1
        print(f"  FAIL {name} {extra}")


def _b(name, pubkey, issued, expires="2099-01-01T00:00:00+00:00"):
    return {"name": name, "node_pubkey": pubkey,
            "issued_at": issued, "expires_at": expires,
            "signature": "00" * 64}


PUB_A = "aa" + "00" * 31   # 64 hex, lexicographically lower
PUB_B = "bb" + "00" * 31   # 64 hex, lexicographically higher
EARLY = "2026-10-07T20:00:00+00:00"
LATER = "2026-10-07T21:00:00+00:00"


def label_cases():
    print("label grammar:")
    check("plain lowercase label", _valid_name_label("genesis") is True)
    check("digits and hyphens", _valid_name_label("node-42") is True)
    check("single char", _valid_name_label("x") is True)
    check("63 chars", _valid_name_label("a" * 63) is True)
    check("empty", _valid_name_label("") is False)
    check("64 chars too long", _valid_name_label("a" * 64) is False)
    check("uppercase", _valid_name_label("Genesis") is False)
    check("dot splits labels", _valid_name_label("a.b") is False)
    check("leading hyphen", _valid_name_label("-gen") is False)
    check("trailing hyphen", _valid_name_label("gen-") is False)
    check("space", _valid_name_label("ge n") is False)
    check("underscore", _valid_name_label("ge_n") is False)
    # str.isalnum() is unicode-aware: the grammar currently admits
    # non-ascii alnum (nothing on the wire decodes it to bytes yet, but
    # nothing forbids it either). Frozen as observed, not blessed.
    check("unicode alnum admitted (observed)",
          _valid_name_label("génèrïs") is True)


def conflict_cases():
    print("conflict rule:")
    check("same key: later issued_at renews",
          _name_claim_beats(_b("x", PUB_A, LATER), _b("x", PUB_A, EARLY)) is True)
    check("same key: stale replay loses",
          _name_claim_beats(_b("x", PUB_A, EARLY), _b("x", PUB_A, LATER)) is False)
    check("same key+same issued_at: no replace",
          _name_claim_beats(_b("x", PUB_A, EARLY), _b("x", PUB_A, EARLY)) is False)
    check("different keys: earlier issued_at wins",
          _name_claim_beats(_b("x", PUB_B, EARLY), _b("x", PUB_A, LATER)) is True)
    check("different keys: later issued_at loses",
          _name_claim_beats(_b("x", PUB_B, LATER), _b("x", PUB_A, EARLY)) is False)
    check("tie: lower pubkey wins",
          _name_claim_beats(_b("x", PUB_A, EARLY), _b("x", PUB_B, EARLY)) is True)
    check("tie: higher pubkey loses",
          _name_claim_beats(_b("x", PUB_B, EARLY), _b("x", PUB_A, EARLY)) is False)
    check("same key differing only in case: same key",
          _name_claim_beats(_b("x", PUB_A.upper(), LATER),
                            _b("x", PUB_A, EARLY)) is True)


def main():
    print("names-registry primitive tests (core.py):")
    label_cases()
    conflict_cases()
    print(f"  {CASES['passed']} passed, {CASES['failed']} failed")
    sys.exit(1 if CASES["failed"] else 0)


if __name__ == "__main__":
    main()
