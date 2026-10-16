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

cop = dict(GOOD, candidate_machine_id="machine-ⲑ")
ok, blockers = nh.evaluate(cop)
_check(ok and not blockers,
       "a non-look-alike Coptic letter is a genuinely distinct "
       f"seat and must stay ELIGIBLE: {blockers}")

arm = dict(GOOD, candidate_machine_id="machine-բ")
ok, blockers = nh.evaluate(arm)
_check(ok and not blockers,
       "a non-look-alike Armenian letter is a genuinely distinct "
       f"seat and must stay ELIGIBLE: {blockers}")

chk = dict(GOOD, candidate_machine_id="machine-Ꭶ")
ok, blockers = nh.evaluate(chk)
_check(ok and not blockers,
       "a Cherokee letter with no single-Latin look-alike is a "
       f"genuinely distinct seat and must stay ELIGIBLE: {blockers}")

lis = dict(GOOD, candidate_machine_id="machine-ꓘ")
ok, blockers = nh.evaluate(lis)
_check(ok and not blockers,
       "a Lisu letter with no single-Latin look-alike is a "
       f"genuinely distinct seat and must stay ELIGIBLE: {blockers}")

des = dict(GOOD, candidate_machine_id="machine-𐐨")
ok, blockers = nh.evaluate(des)
_check(ok and not blockers,
       "a Deseret letter with no single-Latin look-alike is a "
       f"genuinely distinct seat and must stay ELIGIBLE: {blockers}")

war = dict(GOOD, candidate_machine_id="machine-𑢥")
ok, blockers = nh.evaluate(war)
_check(ok and not blockers,
       "a Warang Citi letter with no single-Latin look-alike is a "
       f"genuinely distinct seat and must stay ELIGIBLE: {blockers}")

car = dict(GOOD, candidate_machine_id="machine-𐊣")
ok, blockers = nh.evaluate(car)
_check(ok and not blockers,
       "a Carian letter with no single-Latin look-alike is a "
       f"genuinely distinct seat and must stay ELIGIBLE: {blockers}")

lyc = dict(GOOD, candidate_machine_id="machine-𐊅")
ok, blockers = nh.evaluate(lyc)
_check(ok and not blockers,
       "a Lycian letter with no single-Latin look-alike is a "
       f"genuinely distinct seat and must stay ELIGIBLE: {blockers}")

elb = dict(GOOD, candidate_machine_id="machine-𐔏")
ok, blockers = nh.evaluate(elb)
_check(ok and not blockers,
       "an Elbasan letter with no single-Latin look-alike is a "
       f"genuinely distinct seat and must stay ELIGIBLE: {blockers}")

mia = dict(GOOD, candidate_machine_id="machine-𖼇")
ok, blockers = nh.evaluate(mia)
_check(ok and not blockers,
       "a Miao letter with no single-Latin look-alike is a "
       f"genuinely distinct seat and must stay ELIGIBLE: {blockers}")

oit = dict(GOOD, candidate_machine_id="machine-𐌒")
ok, blockers = nh.evaluate(oit)
_check(ok and not blockers,
       "an Old Italic letter with no single-Latin look-alike is a "
       f"genuinely distinct seat and must stay ELIGIBLE: {blockers}")

can = dict(GOOD, candidate_machine_id="machine-ᐊ")
ok, blockers = nh.evaluate(can)
_check(ok and not blockers,
       "a Canadian Syllabics letter with no single-Latin look-alike "
       "is a genuinely distinct seat and must stay ELIGIBLE: "
       f"{blockers}")

run = dict(GOOD, candidate_machine_id="machine-ᚲ")
ok, blockers = nh.evaluate(run)
_check(ok and not blockers,
       "a Runic letter with no single-Latin look-alike is a "
       f"genuinely distinct seat and must stay ELIGIBLE: {blockers}")

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
    ("candidate_operator", "օp-a",
     "armenian-oh-respelled same operator must fail"),
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
    ("candidate_machine_id", "maϲhine-a",
     "greek-lunate-sigma-respelled same machine must fail"),
    ("candidate_machine_id", "maϹhine-A",
     "greek-capital-lunate-sigma-respelled same machine must fail"),
    ("candidate_machine_id", "mᴀchine-a",
     "small-capital-a-respelled same machine must fail"),
    ("candidate_machine_id", "ᴍachine-a",
     "small-capital-m-respelled same machine must fail"),
    ("candidate_machine_id", "mɑchine-a",
     "latin-alpha-respelled same machine must fail"),
    ("candidate_operator", "op-ᴀ",
     "small-capital-a-respelled same operator must fail"),
    ("candidate_machine_id", "mⲁchine-A",
     "coptic-alfa-respelled same machine must fail"),
    ("candidate_machine_id", "machine-Ⲁ",
     "coptic-capital-alfa-respelled same machine must fail"),
    ("candidate_operator", "ⲟp-A",
     "coptic-o-respelled same operator must fail"),
    ("candidate_machine_id", "mᎪchine-a",
     "cherokee-go-respelled same machine must fail"),
    ("candidate_machine_id", "machinᎬ-a",
     "cherokee-gv-respelled same machine must fail"),
    ("candidate_machine_id", "mꭺchine-a",
     "cherokee-small-go-respelled same machine must fail"),
    ("candidate_operator", "op-Ꭺ",
     "cherokee-go-respelled same operator must fail"),
    ("candidate_machine_id", "mꓮchine-a",
     "lisu-a-respelled same machine must fail"),
    ("candidate_machine_id", "machinꓰ-a",
     "lisu-e-respelled same machine must fail"),
    ("candidate_operator", "op-ꓮ",
     "lisu-a-respelled same operator must fail"),
    ("candidate_machine_id", "ma𐐽hine-a",
     "deseret-chee-respelled same machine must fail"),
    ("candidate_machine_id", "ma𐐕hine-a",
     "deseret-capital-chee-respelled same machine must fail"),
    ("candidate_machine_id", "machin𑢦-a",
     "warang-ii-respelled same machine must fail"),
    ("candidate_machine_id", "machin𑢮-a",
     "warang-yuj-respelled same machine must fail"),
    ("candidate_machine_id", "m𐊠chine-a",
     "carian-a-respelled same machine must fail"),
    ("candidate_machine_id", "ma𐊢hine-a",
     "carian-d-respelled same machine must fail"),
    ("candidate_machine_id", "𐊰achine-a",
     "carian-s-respelled same machine must fail"),
    ("candidate_machine_id", "machin𐊆-a",
     "lycian-i-respelled same machine must fail"),
    ("candidate_machine_id", "ma𐔛hine-a",
     "elbasan-se-respelled same machine must fail"),
    ("candidate_machine_id", "machi𐔓e-a",
     "elbasan-ne-respelled same machine must fail"),
    ("candidate_machine_id", "m𖽀chine-a",
     "miao-a-respelled same machine must fail"),
    ("candidate_machine_id", "𐌑achine-a",
     "olditalic-she-respelled same machine must fail"),
    ("candidate_machine_id", "ma𐌂hine-a",
     "olditalic-ke-respelled same machine must fail"),
    ("candidate_machine_id", "mᗅchine-a",
     "canadian-gho-respelled same machine must fail"),
    ("candidate_machine_id", "ᗰachine-a",
     "canadian-carrier-go-respelled same machine must fail"),
    ("candidate_machine_id", "ᛗachine-a",
     "runic-ehwaz-respelled same machine must fail"),
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
    ("op-ϲ", "op-c",
     "greek-lunate-sigma-respelled same operator must fail"),
    ("op-ɡ", "op-g",
     "script-g-respelled same operator must fail"),
    ("op-ⲣ", "op-p",
     "coptic-ro-respelled same operator must fail"),
    ("op-ⲥ", "op-c",
     "coptic-sima-respelled same operator must fail"),
    ("op-ⲡ", "op-n",
     "coptic-pi-respelled same operator must fail"),
    ("op-Ꮟ", "op-b",
     "cherokee-si-respelled same operator must fail"),
    ("op-ꭰ", "op-d",
     "cherokee-small-a-respelled same operator must fail"),
    ("op-ꓒ", "op-d",
     "lisu-pha-respelled same operator must fail"),
    ("op-ꓳ", "op-o",
     "lisu-o-respelled same operator must fail"),
    ("op-𐑈", "op-s",
     "deseret-zhee-respelled same operator must fail"),
    ("op-𐐠", "op-s",
     "deseret-capital-zhee-respelled same operator must fail"),
    ("op-𐐬", "op-o",
     "deseret-long-o-respelled same operator must fail"),
    ("op-𐐄", "op-o",
     "deseret-capital-long-o-respelled same operator must fail"),
    ("op-𐐛", "op-l",
     "deseret-eth-respelled same operator must fail"),
    ("op-𑣁", "op-s",
     "warang-a-respelled same operator must fail"),
    ("op-𑢼", "op-t",
     "warang-har-respelled same operator must fail"),
    ("op-𑢠", "op-v",
     "warang-ngaa-respelled same operator must fail"),
    ("op-𑢩", "op-z",
     "warang-o-respelled same operator must fail"),
    ("op-𑣄", "op-y",
     "warang-ya-respelled same operator must fail"),
    ("op-𐊡", "op-b",
     "carian-p2-respelled same operator must fail"),
    ("op-𐊥", "op-f",
     "carian-r-respelled same operator must fail"),
    ("op-𐊫", "op-o",
     "carian-o-respelled same operator must fail"),
    ("op-𐊱", "op-t",
     "carian-c18-respelled same operator must fail"),
    ("op-𐊴", "op-x",
     "carian-x-respelled same operator must fail"),
    ("op-𐊲", "op-y",
     "carian-u-respelled same operator must fail"),
    ("op-𐊂", "op-b",
     "lycian-b-respelled same operator must fail"),
    ("op-𐊇", "op-f",
     "lycian-w-respelled same operator must fail"),
    ("op-𐊊", "op-l",
     "lycian-j-respelled same operator must fail"),
    ("op-𐊒", "op-o",
     "lycian-u-respelled same operator must fail"),
    ("op-𐊕", "op-p",
     "lycian-r-respelled same operator must fail"),
    ("op-𐊖", "op-s",
     "lycian-s-respelled same operator must fail"),
    ("op-𐊗", "op-t",
     "lycian-t-respelled same operator must fail"),
    ("op-𐊐", "op-x",
     "lycian-mm-respelled same operator must fail"),
    ("op-𐔥", "op-f",
     "elbasan-ghe-respelled same operator must fail"),
    ("op-𐔘", "op-k",
     "elbasan-qe-respelled same operator must fail"),
    ("op-𐔎", "op-l",
     "elbasan-je-respelled same operator must fail"),
    ("op-𐔦", "op-l",
     "elbasan-ghamma-respelled same operator must fail"),
    ("op-𐔓", "op-n",
     "elbasan-ne-respelled same operator must fail"),
    ("op-𐔖", "op-o",
     "elbasan-o-respelled same operator must fail"),
    ("op-𐔝", "op-v",
     "elbasan-te-respelled same operator must fail"),
    ("op-𐔧", "op-x",
     "elbasan-khe-respelled same operator must fail"),
    ("op-𐔇", "op-z",
     "elbasan-ei-respelled same operator must fail"),
    ("op-𖼨", "op-l",
     "miao-l-respelled same operator must fail"),
    ("op-𖼖", "op-l",
     "miao-L-respelled same operator must fail"),
    ("op-𖼵", "op-r",
     "miao-r-respelled same operator must fail"),
    ("op-𖼺", "op-s",
     "miao-s-respelled same operator must fail"),
    ("op-𖼊", "op-t",
     "miao-t-respelled same operator must fail"),
    ("op-𖽂", "op-u",
     "miao-u-respelled same operator must fail"),
    ("op-𖼈", "op-v",
     "miao-v-respelled same operator must fail"),
    ("op-𖽃", "op-y",
     "miao-y-respelled same operator must fail"),
    ("op-𐌁", "op-b",
     "olditalic-be-respelled same operator must fail"),
    ("op-𐌂", "op-c",
     "olditalic-ke-respelled same operator must fail"),
    ("op-𐌜", "op-b",
     "olditalic-che-respelled same operator must fail"),
    ("op-𐌉", "op-l",
     "olditalic-i-respelled same operator must fail"),
    ("op-𐌠", "op-l",
     "olditalic-numeral-one-respelled same operator must fail"),
    ("op-𐌑", "op-m",
     "olditalic-she-respelled same operator must fail"),
    ("op-𐌏", "op-o",
     "olditalic-o-respelled same operator must fail"),
    ("op-𐌕", "op-t",
     "olditalic-te-respelled same operator must fail"),
    ("op-𐌗", "op-x",
     "olditalic-eks-respelled same operator must fail"),
    ("op-𐌢", "op-x",
     "olditalic-numeral-ten-respelled same operator must fail"),
    ("op-ᑲ", "op-b",
     "canadian-ka-respelled same operator must fail"),
    ("op-ᖯ", "op-b",
     "canadian-aivilik-b-respelled same operator must fail"),
    ("op-ᗷ", "op-b",
     "canadian-khe-respelled same operator must fail"),
    ("op-ᑯ", "op-d",
     "canadian-ko-respelled same operator must fail"),
    ("op-ᗞ", "op-d",
     "canadian-the-respelled same operator must fail"),
    ("op-ᗪ", "op-d",
     "canadian-carrier-pe-respelled same operator must fail"),
    ("op-ᖴ", "op-f",
     "canadian-blackfoot-we-respelled same operator must fail"),
    ("op-ᕼ", "op-h",
     "canadian-nunavut-h-respelled same operator must fail"),
    ("op-ᒍ", "op-j",
     "canadian-co-respelled same operator must fail"),
    ("op-ᒪ", "op-l",
     "canadian-ma-respelled same operator must fail"),
    ("op-𑪾", "op-n",
     "canadian-spo-respelled same operator must fail"),
    ("op-ᑭ", "op-p",
     "canadian-ki-respelled same operator must fail"),
    ("op-ᖇ", "op-r",
     "canadian-tlhi-respelled same operator must fail"),
    ("op-ᑌ", "op-u",
     "canadian-te-respelled same operator must fail"),
    ("op-ᐯ", "op-v",
     "canadian-pe-respelled same operator must fail"),
    ("op-ᕁ", "op-x",
     "canadian-sayisi-yi-respelled same operator must fail"),
    ("op-ᕽ", "op-x",
     "canadian-hk-respelled same operator must fail"),
    ("op-𑪼", "op-z",
     "canadian-spe-respelled same operator must fail"),
    ("op-ᛕ", "op-k",
     "runic-open-p-respelled same operator must fail"),
    ("op-ᛁ", "op-l",
     "runic-isaz-respelled same operator must fail"),
    ("op-ᛐ", "op-l",
     "runic-short-twig-tyr-respelled same operator must fail"),
    ("op-ᛷ", "op-x",
     "runic-gebo-respelled same operator must fail"),
]:
    seat = dict(GOOD, candidate_operator=cand, origin_operator=orig)
    ok, blockers = nh.evaluate(seat)
    _check(not ok and blockers, f"{why} (bar blockers: {blockers})")

if fails:
    print(f"test_nexus_host_check: {fails} FAIL")
    sys.exit(1)
print("test_nexus_host_check: PASS")
