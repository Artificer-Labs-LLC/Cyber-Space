#!/usr/bin/env python3
"""Belt: _rendezvous_strategy refuses a NON-STRING kind instead of
str()-aliasing it (primitives 1 naming + 3 hosting).

_rendezvous_strategy (core.py) extracts the dial-side rendezvous
strategy from a caller-verified descriptor's reach list, and it read
kind through str() with no gate — its twin extractor _relay_route was
gated for exactly this, but this seat was left behind: a non-string
kind whose string form is "rendezvous" was ACCEPTED as the rendezvous
strategy (epoch math taken from a member nobody typed as rendezvous),
the SAME alias the binding/descriptor seats refuse on sight.
isinstance gate at the seat (kind compared raw, twin of _relay_route):
a non-string member is skipped like any malformed strategy (never
raises), and a valid string descriptor returns its strategy byte-exact.

Covers: valid string kind -> strategy exact (control); exotic
str()-alias kind -> refused, None; int/list/bool kind -> None;
alias member first + valid string member second -> second wins
(skip, not poison).

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/rendezvous-kind-field-type-belt-test.py
"""
import os
import sys
import tempfile

TMP = tempfile.mkdtemp(prefix="rendezvous-kind-belt-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core  # noqa: E402

CASES = {"passed": 0, "failed": 0}


def check(name, cond, extra=""):
    if cond:
        CASES["passed"] += 1
        print(f"  ok  {name}")
    else:
        CASES["failed"] += 1
        print(f"  FAIL {name} {extra}")


WQ = "/relay/hold_query"
GOOD = {"kind": "rendezvous", "epoch_len": 600, "hold_query": WQ}
GOOD_OUT = {"epoch_len": 600, "hold_query": WQ}


class _AliasKind:
    """A non-string kind whose str() is exactly 'rendezvous'."""

    def __str__(self):
        return "rendezvous"


def strat(member):
    return core._rendezvous_strategy({"reach": [member]})


check("valid string kind -> strategy exact (control)",
      strat(dict(GOOD)) == GOOD_OUT, f"got {strat(dict(GOOD))!r}")

check("str()-alias kind -> refused, None (alias)",
      strat({**GOOD, "kind": _AliasKind()}) is None,
      f"got {strat({**GOOD, 'kind': _AliasKind()})!r}")

for bad in (123, ["rendezvous"], True, None):
    check(f"non-string kind {bad!r} -> None",
          strat({**GOOD, "kind": bad}) is None,
          f"got {strat({**GOOD, 'kind': bad})!r}")

check("alias member first + valid second -> second wins (skip, not poison)",
      core._rendezvous_strategy(
          {"reach": [{**GOOD, "kind": _AliasKind()},
                     {**GOOD, "epoch_len": 3600}]})
      == {"epoch_len": 3600, "hold_query": WQ})

print(f"\n{CASES['passed']} passed, {CASES['failed']} failed")
sys.exit(1 if CASES["failed"] else 0)
