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

foreign = dict(GOOD, candidate_machine_id="machine-б")
ok, blockers = nh.evaluate(foreign)
_check(ok and not blockers,
       "a non-look-alike foreign letter is a genuinely distinct "
       f"seat and must stay ELIGIBLE: {blockers}")

dashy = dict(GOOD, candidate_machine_id="machine–b")
ok, blockers = nh.evaluate(dashy)
_check(ok and not blockers,
       "a dash-respelled but genuinely distinct seat must stay "
       f"ELIGIBLE: {blockers}")

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
    ("candidate_machine_id", "machine-a️",
     "variation-selector-respelled same machine must fail"),
    ("candidate_machine_id", "machine-͏a",
     "grapheme-joiner-respelled same machine must fail"),
    ("candidate_machine_id", "machine-a\x00",
     "NUL-suffixed same machine must fail"),
    ("candidate_machine_id", "machine-a\x7f",
     "DEL-suffixed same machine must fail"),
    ("candidate_machine_id", "️",
     "variation-selector-only machine id must fail as missing"),
    ("candidate_machine_id", "͏",
     "grapheme-joiner-only machine id must fail as missing"),
    ("candidate_operator", "op-a️",
     "variation-selector-respelled same operator must fail"),
    ("candidate_operator", "op-a\x00",
     "NUL-suffixed same operator must fail"),
    ("candidate_machine_id", "machine-а",
     "cyrillic-a-respelled same machine must fail"),
    ("candidate_machine_id", "machine-А",
     "cyrillic-capital-a-respelled same machine must fail"),
    ("candidate_operator", "оp-a",
     "cyrillic-o-respelled same operator must fail"),
    ("candidate_operator", "οp-a",
     "greek-omicron-respelled same operator must fail"),
    ("candidate_machine_id", b"machine-a",
     "bytes-spelled same machine must fail as missing"),
    ("candidate_machine_id", b"machine-b",
     "bytes machine id must fail as missing, not pass as distinct"),
    ("candidate_operator", b"op-b",
     "bytes operator must fail as missing, not pass as distinct"),
    ("candidate_machine_id", 123,
     "integer machine id must fail as missing"),
    ("candidate_machine_id", ["machine-b"],
     "list machine id must fail as missing"),
    ("candidate_operator", True,
     "boolean operator must fail as missing"),
    ("candidate_machine_id", "machine‐a",
     "hyphen-respelled same machine must fail"),
    ("candidate_machine_id", "machine‑a",
     "non-breaking-hyphen-respelled same machine must fail"),
    ("candidate_machine_id", "machine−a",
     "minus-sign-respelled same machine must fail"),
    ("candidate_machine_id", "machine–a",
     "en-dash-respelled same machine must fail"),
    ("candidate_machine_id", "machine—a",
     "em-dash-respelled same machine must fail"),
    ("candidate_operator", "op‐a",
     "hyphen-respelled same operator must fail"),
    ("candidate_operator", "op−a",
     "minus-sign-respelled same operator must fail"),
    ("candidate_machine_id", "machine-⠀a",
     "braille-blank-respelled same machine must fail"),
    ("candidate_machine_id", "machine-ᅟa",
     "hangul-choseong-filler-respelled same machine must fail"),
    ("candidate_machine_id", "machine-ᅠa",
     "hangul-filler-respelled same machine must fail"),
    ("candidate_operator", "op-⠀a",
     "braille-blank-respelled same operator must fail"),
    ("candidate_machine_id", "⠀",
     "braille-blank-only machine id must fail as missing"),
    ("candidate_machine_id", "ᅠ",
     "hangul-filler-only machine id must fail as missing"),
    ("candidate_machine_id", "machine-￼a",
     "object-replacement-respelled same machine must fail"),
    ("candidate_machine_id", "mαchine-A",
     "greek-alpha-respelled same machine must fail"),
    ("candidate_machine_id", "machιne-A",
     "greek-iota-respelled same machine must fail"),
    ("candidate_machine_id", "macηine-A",
     "greek-eta-respelled same machine must fail"),
    ("candidate_machine_id", "μachine-A",
     "greek-mu-respelled same machine must fail"),
    ("candidate_machine_id", "мachine-A",
     "cyrillic-em-respelled same machine must fail"),
    ("candidate_machine_id", "macнine-A",
     "cyrillic-en-respelled same machine must fail"),
]:
    seat = dict(GOOD)
    seat[key] = bad
    ok, blockers = nh.evaluate(seat)
    _check(not ok and blockers, f"{why} (bar blockers: {blockers})")

for cand, orig, why in [
    ("op-в", "op-b",
     "cyrillic-ve-respelled same operator must fail"),
    ("op-к", "op-k",
     "cyrillic-ka-respelled same operator must fail"),
    ("op-т", "op-t",
     "cyrillic-te-respelled same operator must fail"),
    ("op-β", "op-b",
     "greek-beta-respelled same operator must fail"),
    ("op-ε", "op-e",
     "greek-epsilon-respelled same operator must fail"),
    ("op-ζ", "op-z",
     "greek-zeta-respelled same operator must fail"),
    ("op-κ", "op-k",
     "greek-kappa-respelled same operator must fail"),
    ("op-π", "op-n",
     "greek-pi-respelled same operator must fail"),
]:
    seat = dict(GOOD, candidate_operator=cand, origin_operator=orig)
    ok, blockers = nh.evaluate(seat)
    _check(not ok and blockers, f"{why} (bar blockers: {blockers})")

if fails:
    print(f"test_nexus_host_check: {fails} FAIL")
    sys.exit(1)
print("test_nexus_host_check: PASS")
