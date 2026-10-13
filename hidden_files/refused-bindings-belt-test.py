#!/usr/bin/env python3
"""Belt for the refused-bindings filter on the window-open snapshot
(allocation rule v0.6.3, section 7.3.9; primitive 1 naming).

Refused bindings (reasons grammar, length, expiry-cap, not-in-manifest)
get NO binding-hold and exactly ONE leaf each in the refused-bindings
structure. This belt drives refused_bindings.snapshot_refused_bindings
directly against a mixed row set:

  valid binding            -> hold-eligible (the ONLY hold)
  grammar-refused label    -> grammar leaf, name=sha256: form
  length-refused (2 B)     -> length leaf
  length-refused (40 B)    -> length leaf
  expiry-cap (naive)       -> expiry-cap leaf
  expiry-cap (NULL)        -> expiry-cap leaf
  expiry-cap (date-only)   -> expiry-cap leaf
  not-in-manifest          -> not-in-manifest leaf
  length+grammar both bad  -> length wins (priority order)

Asserts: holds only on the valid row; exactly one leaf per refused
binding; correct reason on each leaf; canonical leaf bytes byte-exact;
grammar leaves use the sha256 name form; leaf size within bound.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/refused-bindings-belt-test.py
"""
import hashlib
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import refused_bindings as rb  # noqa: E402

PASSED = FAILED = 0


def check(desc, cond, extra=""):
    global PASSED, FAILED
    if cond:
        PASSED += 1
        print(f"  ok  {desc}")
    else:
        FAILED += 1
        print(f"  FAIL {desc} {extra}")


NOW = datetime.now(timezone.utc)
EXP = (NOW + timedelta(days=30)).isoformat(timespec="seconds")
PUB = "ab" * 32


def row(name, expires_at=EXP, pub=PUB):
    return {"name": name, "node_pubkey": pub, "issued_at": EXP,
            "expires_at": expires_at, "signature": "00" * 128}


MANIFEST = {"goodname", "edge-ok-1"}

rows = [
    row("goodname"),                          # 0 valid -> hold
    row("bad_name"),                          # 1 grammar (underscore)
    row("ab"),                                # 2 length (2 B)
    row("x" * 40),                            # 3 length (40 B)
    row("edge-ok-1", (NOW + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%S")),  # 4 expiry-cap naive
    row("edge-ok-1", None),                   # 5 expiry-cap NULL
    row("edge-ok-1", (NOW + timedelta(days=30)).strftime("%Y-%m-%d")),          # 6 expiry-cap date-only
    row("notinmanifest"),                     # 7 not-in-manifest (valid shape)
    row("a_"),                                # 8 length+grammar -> grammar wins (B1: grammar before length, spec §7.3.9)
]

holds, refused = rb.snapshot_refused_bindings(rows, MANIFEST)

print("partition")
check("exactly one hold", len(holds) == 1, f"got {len(holds)}")
check("hold is the valid row",
      len(holds) == 1 and holds[0]["name"] == "goodname")
check("one leaf per refused binding", len(refused) == 8,
      f"got {len(refused)}")

reasons = [r for _, r in refused]
check("reasons in input order",
      reasons == ["grammar", "length", "length", "expiry-cap", "expiry-cap",
                  "expiry-cap", "not-in-manifest", "grammar"],
      f"got {reasons}")

print("leaf bytes")
for (leaf, reason), r in zip(refused, rows[1:]):
    check(f"leaf for {r['name']!r} is bytes", isinstance(leaf, bytes))
    check(f"leaf for {r['name']!r} has no trailing newline",
          not leaf.endswith(b"\n"))
    check(f"leaf for {r['name']!r} carries reason={reason}",
          leaf.endswith(("\nreason=" + reason).encode()))
    check(f"leaf for {r['name']!r} has 64-hex pubkey",
          b"\nnode_pubkey=" + PUB.encode() in leaf)
    check(f"leaf for {r['name']!r} within size bound", len(leaf) <= 206,
          f"len={len(leaf)}")

print("grammar leaf sha256 form")
g_leaf = refused[0][0]
expect_name = "sha256:" + hashlib.sha256("bad_name".encode()).hexdigest()
check("grammar leaf name field is sha256 form",
      f"\nname={expect_name}\n".encode() in g_leaf, g_leaf[:80])
check("grammar leaf does not carry the raw label", b"bad_name" not in g_leaf)

print("direct leaf form (non-grammar)")
l_leaf = refused[1][0]  # length case for "ab"
check("length leaf carries raw label", b"\nname=ab\n" in l_leaf)
e_leaf = refused[3][0]  # expiry-cap naive case for "edge-ok-1"
check("expiry-cap leaf carries raw label", b"\nname=edge-ok-1\n" in e_leaf)
check("expiry-cap leaf reason", e_leaf.endswith(b"\nreason=expiry-cap"))
n_leaf = refused[6][0]  # not-in-manifest
check("not-in-manifest leaf reason",
      n_leaf.endswith(b"\nreason=not-in-manifest"))

print("byte-exact canonical leaf")
expect = (b"cyberspace-refused-binding/v1\nname=ab\nnode_pubkey=" + PUB.encode()
          + b"\nreason=length")
check("length leaf byte-exact", l_leaf == expect, f"got {l_leaf!r}")

print("reason codes are the fixed set")
for _, reason in refused:
    check(f"reason {reason!r} in fixed set", reason in rb.REASONS)

print("determinism")
holds2, refused2 = rb.snapshot_refused_bindings(rows, MANIFEST)
check("same inputs -> same outputs",
      holds2 == holds and refused2 == refused)

print("empty / edge inputs")
h, r = rb.snapshot_refused_bindings([], MANIFEST)
check("empty rows -> empty partition", h == [] and r == [])
h, r = rb.snapshot_refused_bindings([row("goodname")], set())
check("empty manifest -> not-in-manifest",
      h == [] and len(r) == 1 and r[0][1] == "not-in-manifest")

print("non-dict rows refuse as grammar, never crash")
for bad in (123, None, "bare-string", ["x"], 1.5, True):
    check(f"classify non-dict {bad!r} -> grammar",
          rb.classify_binding(bad, MANIFEST) == "grammar")
h, r = rb.snapshot_refused_bindings(
    [123, row("goodname"), None], MANIFEST)
check("snapshot survives non-dict rows: valid row still holds",
      len(h) == 1 and h[0]["name"] == "goodname")
check("snapshot: one grammar leaf per non-dict row",
      len(r) == 2 and all(reason == "grammar" for _, reason in r))
check("non-dict grammar leaf uses the sha256 name form",
      all(leaf.split(b"\n")[1].startswith(b"name=sha256:")
          for leaf, _ in r))

print(f"\n{__file__}: {PASSED} passed, {FAILED} failed")
sys.exit(1 if FAILED else 0)
