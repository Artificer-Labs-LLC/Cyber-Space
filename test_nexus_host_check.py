#!/usr/bin/env python3
"""nexus_host_check belt: eligibility is all five bars or nothing.

Proves with supplied evidence dicts (no network, no provisioning):
the fully-clearing seat is ELIGIBLE; same machine, registry-sourced
evidence, same operator, an HQ seat on either side, a non-gossip
feed, a present claim key, a binding-sourced pin, and missing
values each read NOT ELIGIBLE.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nexus_host_check as nh  # noqa: E402

fails = 0


def _check(cond, why):
    global fails
    if not cond:
        print(f"FAIL: {why}")
        fails += 1


GOOD = {"candidate_machine_id": "machine-B", "origin_machine_id": "machine-A",
        "candidate_operator": "op-B", "origin_operator": "op-A",
        "evidence_source": "machine-itself", "feed": "gossip",
        "pin_source": "out-of-band", "candidate_is_hq": False,
        "origin_is_hq": False, "claim_key_present": False}

ok, blockers = nh.evaluate(dict(GOOD))
_check(ok and not blockers, f"clearing seat must be ELIGIBLE: {blockers}")

padded = dict(GOOD, candidate_machine_id=" machine-B ",
              candidate_operator=" op-B ")
ok, blockers = nh.evaluate(padded)
_check(ok and not blockers,
       f"padded but distinct seat must stay ELIGIBLE: {blockers}")

for key, bad, why in [
    ("candidate_machine_id", "machine-A", "same machine must fail"),
    ("evidence_source", "registry", "registry evidence must fail"),
    ("evidence_source", "list", "list evidence must fail"),
    ("candidate_operator", "op-A", "same operator must fail"),
    ("candidate_is_hq", True, "HQ candidate must fail"),
    ("origin_is_hq", True, "HQ origin must fail"),
    ("feed", "direct-claim", "direct-claim feed must fail"),
    ("feed", "file-copy", "file-copy feed must fail"),
    ("feed", "none-yet", "unfed candidate must fail"),
    ("claim_key_present", True, "present claim key must fail"),
    ("pin_source", "served-binding", "binding-sourced pin must fail"),
    ("pin_source", "checking-node", "self-sourced pin must fail"),
    ("candidate_machine_id", None, "missing machine id must fail"),
    ("candidate_operator", None, "missing operator must fail"),
    ("candidate_machine_id", " Machine-A ",
     "whitespace-respelled same machine must fail"),
    ("candidate_machine_id", "MACHINE-A",
     "case-respelled same machine must fail"),
    ("candidate_machine_id", "   ",
     "whitespace-only machine id must fail as missing"),
    ("candidate_operator", " op-A",
     "whitespace-respelled same operator must fail"),
    ("candidate_operator", "OP-A",
     "case-respelled same operator must fail"),
    ("candidate_operator", " ",
     "whitespace-only operator must fail as missing"),
    ("candidate_machine_id", "machine-​a",
     "zero-width-respelled same machine must fail"),
    ("candidate_machine_id", "ｍachine-a",
     "fullwidth-respelled same machine must fail"),
    ("candidate_machine_id", "​",
     "zero-width-only machine id must fail as missing"),
    ("candidate_operator", "op-​a",
     "zero-width-respelled same operator must fail"),
    ("candidate_operator", "ｏp-a",
     "fullwidth-respelled same operator must fail"),
]:
    seat = dict(GOOD)
    seat[key] = bad
    ok, blockers = nh.evaluate(seat)
    _check(not ok and blockers, f"{why} (bar blockers: {blockers})")

if fails:
    print(f"test_nexus_host_check: {fails} FAIL")
    sys.exit(1)
print("test_nexus_host_check: PASS")
