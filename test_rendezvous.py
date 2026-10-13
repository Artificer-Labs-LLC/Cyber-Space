#!/usr/bin/env python3
"""rendezvous boundary belt: the module promises every check returns
None or False instead of raising across its boundary, but a non-finite
`now` (inf/NaN) escaped epoch_for() as a raw ValueError from the int
conversion, a bool `now` aliased to epoch 0, and an epoch too wide for
the 8-byte field escaped derive_point_id() as OverflowError — on the
shared KDF both sides of primitive 3 (hosting rendezvous) run."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rendezvous  # noqa: E402

K = "ab" * 32
NOW = 1_700_000_000.0
fails = 0

for bad in (float("inf"), float("-inf"), float("nan"), True, False):
    try:
        got = rendezvous.epoch_for(bad)
    except Exception as e:  # noqa: BLE001
        print(f"FAIL: epoch_for({bad!r}) raised {type(e).__name__}: {e}")
        fails += 1
        continue
    if got is not None:
        print(f"FAIL: epoch_for({bad!r}) -> {got!r}, want None")
        fails += 1
    try:
        pair = rendezvous.derive_points(bad, K)
        cur = rendezvous.point_is_current("00" * 32, bad, K)
    except Exception as e:  # noqa: BLE001
        print(f"FAIL: now={bad!r} downstream raised {type(e).__name__}: {e}")
        fails += 1
        continue
    if pair is not None or cur is not False:
        print(f"FAIL: now={bad!r} -> points {pair!r} / current {cur!r}")
        fails += 1

for bad_epoch in (2**64, 2**100, -1, 1.5, True, "5"):
    try:
        got = rendezvous.derive_point_id(K, bad_epoch)
    except Exception as e:  # noqa: BLE001
        print(f"FAIL: derive_point_id(epoch={bad_epoch!r}) raised "
              f"{type(e).__name__}: {e}")
        fails += 1
        continue
    if got is not None:
        print(f"FAIL: derive_point_id(epoch={bad_epoch!r}) -> {got!r}")
        fails += 1

# Valid math is untouched: the widest encodable epoch still derives,
# and the current/previous pair still brackets `now`.
top = rendezvous.derive_point_id(K, 2**64 - 1)
if not (isinstance(top, str) and len(top) == 64):
    print(f"FAIL: max epoch derive changed: {top!r}")
    fails += 1
pair = rendezvous.derive_points(NOW, K)
if pair is None or pair[0] != rendezvous.derive_point_id(
        K, rendezvous.epoch_for(NOW)):
    print(f"FAIL: valid derive_points changed: {pair!r}")
    fails += 1
elif not rendezvous.point_is_current(pair[1], NOW, K):
    print("FAIL: previous-epoch point no longer current")
    fails += 1
if rendezvous.epoch_for(NOW) != int(NOW // 3600):
    print("FAIL: valid epoch_for changed")
    fails += 1

if fails:
    print(f"test_rendezvous: {fails} FAIL")
    sys.exit(1)
print("test_rendezvous: OK")
