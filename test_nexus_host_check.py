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

otu = dict(GOOD, candidate_machine_id="machine-𐰀")
ok, blockers = nh.evaluate(otu)
_check(ok and not blockers,
       "an Old Turkic letter with no UTS #39 entry is a genuinely "
       f"distinct seat and must stay ELIGIBLE: {blockers}")

ohu = dict(GOOD, candidate_machine_id="machine-𐲀")
ok, blockers = nh.evaluate(ohu)
_check(ok and not blockers,
       "an Old Hungarian letter with no UTS #39 entry is a "
       f"genuinely distinct seat and must stay ELIGIBLE: {blockers}")

lyd = dict(GOOD, candidate_machine_id="machine-𐤡")
ok, blockers = nh.evaluate(lyd)
_check(ok and not blockers,
       "a Lydian letter with no single-Latin look-alike is a "
       f"genuinely distinct seat and must stay ELIGIBLE: {blockers}")

lydm = dict(GOOD, candidate_machine_id="machine-𐤦",
            origin_machine_id="machine-l")
ok, blockers = nh.evaluate(lydm)
_check(not ok and blockers,
       "a Lydian-I-respelled same machine must fail "
       f"(bar blockers: {blockers})")

osg = dict(GOOD, candidate_machine_id="machine-𐓘")
ok, blockers = nh.evaluate(osg)
_check(ok and not blockers,
       "an Osage letter with no single-Latin look-alike is a "
       f"genuinely distinct seat and must stay ELIGIBLE: {blockers}")

osgm = dict(GOOD, candidate_machine_id="machine-𐓪",
            origin_machine_id="machine-o")
ok, blockers = nh.evaluate(osgm)
_check(not ok and blockers,
       "an Osage-small-O-respelled same machine must fail "
       f"(bar blockers: {blockers})")

nko = dict(GOOD, candidate_machine_id="machine-ߡ")
ok, blockers = nh.evaluate(nko)
_check(ok and not blockers,
       "an NKo letter with no single-Latin look-alike is a "
       f"genuinely distinct seat and must stay ELIGIBLE: {blockers}")

nkom = dict(GOOD, candidate_machine_id="machine-ߊ",
            origin_machine_id="machine-l")
ok, blockers = nh.evaluate(nkom)
_check(not ok and blockers,
       "an NKo-A-respelled same machine must fail "
       f"(bar blockers: {blockers})")

rnc = dict(GOOD, candidate_machine_id="machine-ᚨ")
ok, blockers = nh.evaluate(rnc)
_check(ok and not blockers,
       "a Runic letter with no single-Latin look-alike is a "
       f"genuinely distinct seat and must stay ELIGIBLE: {blockers}")

rncm = dict(GOOD, candidate_machine_id="ᛖachine-a",
            origin_machine_id="machine-a")
ok, blockers = nh.evaluate(rncm)
_check(not ok and blockers,
       "a Runic-EHWAZ-respelled same machine must fail "
       f"(bar blockers: {blockers})")

heb = dict(GOOD, candidate_machine_id="machine-א")
ok, blockers = nh.evaluate(heb)
_check(ok and not blockers,
       "a Hebrew letter with no single-Latin look-alike is a "
       f"genuinely distinct seat and must stay ELIGIBLE: {blockers}")

hebm = dict(GOOD, candidate_machine_id="machine-ס",
            origin_machine_id="machine-o")
ok, blockers = nh.evaluate(hebm)
_check(not ok and blockers,
       "a Hebrew-SAMEKH-respelled same machine must fail "
       f"(bar blockers: {blockers})")

tif = dict(GOOD, candidate_machine_id="machine-ⴰ")
ok, blockers = nh.evaluate(tif)
_check(ok and not blockers,
       "a Tifinagh letter with no single-Latin look-alike is a "
       f"genuinely distinct seat and must stay ELIGIBLE: {blockers}")

tifm = dict(GOOD, candidate_machine_id="machinⴹ-a",
            origin_machine_id="machine-a")
ok, blockers = nh.evaluate(tifm)
_check(not ok and blockers,
       "a Tifinagh-YADD-respelled same machine must fail "
       f"(bar blockers: {blockers})")

vai = dict(GOOD, candidate_machine_id="machine-ꔀ")
ok, blockers = nh.evaluate(vai)
_check(ok and not blockers,
       "a Vai syllable with no single-Latin look-alike is a "
       f"genuinely distinct seat and must stay ELIGIBLE: {blockers}")

vaim = dict(GOOD, candidate_machine_id="machine-ꕗ",
            origin_machine_id="machine-b")
ok, blockers = nh.evaluate(vaim)
_check(not ok and blockers,
       "a Vai-GBA-respelled same machine must fail "
       f"(bar blockers: {blockers})")

man = dict(GOOD, candidate_machine_id="machine-ࡁ")
ok, blockers = nh.evaluate(man)
_check(ok and not blockers,
       "a Mandaic letter with no single-Latin look-alike is a "
       f"genuinely distinct seat and must stay ELIGIBLE: {blockers}")

manm = dict(GOOD, candidate_machine_id="machine-ࡀ",
            origin_machine_id="machine-o")
ok, blockers = nh.evaluate(manm)
_check(not ok and blockers,
       "a Mandaic-HALQA-respelled same machine must fail "
       f"(bar blockers: {blockers})")

han = dict(GOOD, candidate_machine_id="machine-𐴀")
ok, blockers = nh.evaluate(han)
_check(ok and not blockers,
       "a Hanifi letter with no single-Latin look-alike is a "
       f"genuinely distinct seat and must stay ELIGIBLE: {blockers}")

hanm = dict(GOOD, candidate_machine_id="machine-𐴇",
            origin_machine_id="machine-o")
ok, blockers = nh.evaluate(hanm)
_check(not ok and blockers,
       "a Hanifi-HA-respelled same machine must fail "
       f"(bar blockers: {blockers})")

cha = dict(GOOD, candidate_machine_id="machine-𑄃")
ok, blockers = nh.evaluate(cha)
_check(ok and not blockers,
       "a Chakma letter with no single-Latin look-alike is a "
       f"genuinely distinct seat and must stay ELIGIBLE: {blockers}")

cham = dict(GOOD, candidate_machine_id="machine-𑄤",
            origin_machine_id="machine-o")
ok, blockers = nh.evaluate(cham)
_check(not ok and blockers,
       "a Chakma-WAA-respelled same machine must fail "
       f"(bar blockers: {blockers})")

mya = dict(GOOD, candidate_machine_id="machine-က")
ok, blockers = nh.evaluate(mya)
_check(ok and not blockers,
       "a Myanmar letter with no single-Latin look-alike is a "
       f"genuinely distinct seat and must stay ELIGIBLE: {blockers}")

myam = dict(GOOD, candidate_machine_id="machine-ဝ",
            origin_machine_id="machine-o")
ok, blockers = nh.evaluate(myam)
_check(not ok and blockers,
       "a Myanmar-WA-respelled same machine must fail "
       f"(bar blockers: {blockers})")

tai = dict(GOOD, candidate_machine_id="machine-ᨠ")
ok, blockers = nh.evaluate(tai)
_check(ok and not blockers,
       "a Tai Tham letter with no single-Latin look-alike is a "
       f"genuinely distinct seat and must stay ELIGIBLE: {blockers}")

taim = dict(GOOD, candidate_machine_id="machine-ᩅ",
            origin_machine_id="machine-o")
ok, blockers = nh.evaluate(taim)
_check(not ok and blockers,
       "a Tai-Tham-WA-respelled same machine must fail "
       f"(bar blockers: {blockers})")

han = dict(GOOD, candidate_machine_id="machine-ᄀ")
ok, blockers = nh.evaluate(han)
_check(ok and not blockers,
       "a Hangul letter with no single-Latin look-alike is a "
       f"genuinely distinct seat and must stay ELIGIBLE: {blockers}")

hanm = dict(GOOD, candidate_machine_id="machine-ᄋ",
            origin_machine_id="machine-o")
ok, blockers = nh.evaluate(hanm)
_check(not ok and blockers,
       "a Hangul-choseong-ieung-respelled same machine must fail "
       f"(bar blockers: {blockers})")

hanj = dict(GOOD, candidate_machine_id="machine-ᆼ",
            origin_machine_id="machine-o")
ok, blockers = nh.evaluate(hanj)
_check(not ok and blockers,
       "a Hangul-jongseong-ieung-respelled same machine must fail "
       f"(bar blockers: {blockers})")

tag = dict(GOOD, candidate_machine_id="machine-ᝠ")
ok, blockers = nh.evaluate(tag)
_check(ok and not blockers,
       "a Tagbanwa letter with no single-Latin look-alike is a "
       f"genuinely distinct seat and must stay ELIGIBLE: {blockers}")

tagm = dict(GOOD, candidate_machine_id="machine-ᝣ",
            origin_machine_id="machine-x")
ok, blockers = nh.evaluate(tagm)
_check(not ok and blockers,
       "a Tagbanwa-KA-respelled same machine must fail "
       f"(bar blockers: {blockers})")

bas = dict(GOOD, candidate_machine_id="machine-𖫑")
ok, blockers = nh.evaluate(bas)
_check(ok and not blockers,
       "a Bassa Vah letter with no single-Latin look-alike is a "
       f"genuinely distinct seat and must stay ELIGIBLE: {blockers}")

basg = dict(GOOD, candidate_machine_id="machine-𖫖",
            origin_machine_id="machine-s")
ok, blockers = nh.evaluate(basg)
_check(not ok and blockers,
       "a Bassa-Vah-GAH-respelled same machine must fail "
       f"(bar blockers: {blockers})")

baso = dict(GOOD, candidate_machine_id="machine-𖫩",
            origin_machine_id="machine-o")
ok, blockers = nh.evaluate(baso)
_check(not ok and blockers,
       "a Bassa-Vah-OO-respelled same machine must fail "
       f"(bar blockers: {blockers})")

bam = dict(GOOD, candidate_machine_id="machine-ꚡ")
ok, blockers = nh.evaluate(bam)
_check(ok and not blockers,
       "a Bamum letter with no single-Latin look-alike is a "
       f"genuinely distinct seat and must stay ELIGIBLE: {blockers}")

bamw = dict(GOOD, candidate_machine_id="machine-ꛉ",
            origin_machine_id="machine-z")
ok, blockers = nh.evaluate(bamw)
_check(not ok and blockers,
       "a Bamum-WUE-respelled same machine must fail "
       f"(bar blockers: {blockers})")

bamk = dict(GOOD, candidate_machine_id="machine-ꛟ",
            origin_machine_id="machine-v")
ok, blockers = nh.evaluate(bamk)
_check(not ok and blockers,
       "a Bamum-KO-respelled same machine must fail "
       f"(bar blockers: {blockers})")

bamn = dict(GOOD, candidate_machine_id="machine-𖨙",
            origin_machine_id="machine-r")
ok, blockers = nh.evaluate(bamn)
_check(not ok and blockers,
       "a Bamum-PHASE-F-NU-respelled same machine must fail "
       f"(bar blockers: {blockers})")

aho = dict(GOOD, candidate_machine_id="machine-𑜒")
ok, blockers = nh.evaluate(aho)
_check(ok and not blockers,
       "an Ahom letter with no single-Latin look-alike is a "
       f"genuinely distinct seat and must stay ELIGIBLE: {blockers}")

ahop = dict(GOOD, candidate_machine_id="machine-𑜆",
            origin_machine_id="machine-v")
ok, blockers = nh.evaluate(ahop)
_check(not ok and blockers,
       "an Ahom-PA-respelled same machine must fail "
       f"(bar blockers: {blockers})")

ahoj = dict(GOOD, candidate_machine_id="machine-𑜊",
            origin_machine_id="machine-w")
ok, blockers = nh.evaluate(ahoj)
_check(not ok and blockers,
       "an Ahom-JA-respelled same machine must fail "
       f"(bar blockers: {blockers})")

ahol = dict(GOOD, candidate_machine_id="machine-𑜎",
            origin_machine_id="machine-w")
ok, blockers = nh.evaluate(ahol)
_check(not ok and blockers,
       "an Ahom-LA-respelled same machine must fail "
       f"(bar blockers: {blockers})")

ahos = dict(GOOD, candidate_machine_id="machine-𑜏",
            origin_machine_id="machine-w")
ok, blockers = nh.evaluate(ahos)
_check(not ok and blockers,
       "an Ahom-SA-respelled same machine must fail "
       f"(bar blockers: {blockers})")

mal = dict(GOOD, candidate_machine_id="machine-ക")
ok, blockers = nh.evaluate(mal)
_check(ok and not blockers,
       "a Malayalam letter with no single-Latin look-alike is a "
       f"genuinely distinct seat and must stay ELIGIBLE: {blockers}")

malt = dict(GOOD, candidate_machine_id="machine-ഠ",
            origin_machine_id="machine-o")
ok, blockers = nh.evaluate(malt)
_check(not ok and blockers,
       "a Malayalam-TTHA-respelled same machine must fail "
       f"(bar blockers: {blockers})")

mals = dict(GOOD, candidate_machine_id="machine-ട",
            origin_machine_id="machine-s")
ok, blockers = nh.evaluate(mals)
_check(not ok and blockers,
       "a Malayalam-TTA-respelled same machine must fail "
       f"(bar blockers: {blockers})")

ethc = dict(GOOD, candidate_machine_id="machine-ለ")
ok, blockers = nh.evaluate(ethc)
_check(ok and not blockers,
       "an Ethiopic syllable with no single-Latin look-alike is a "
       f"genuinely distinct seat and must stay ELIGIBLE: {blockers}")

ethp = dict(GOOD, candidate_machine_id="machine-ዐ",
            origin_machine_id="machine-o")
ok, blockers = nh.evaluate(ethp)
_check(not ok and blockers,
       "an Ethiopic-PHARYNGEAL-A-respelled same machine must fail "
       f"(bar blockers: {blockers})")

ethh = dict(GOOD, candidate_machine_id="machine-ሀ",
            origin_machine_id="machine-u")
ok, blockers = nh.evaluate(ethh)
_check(not ok and blockers,
       "an Ethiopic-HA-respelled same machine must fail "
       f"(bar blockers: {blockers})")

bopc = dict(GOOD, candidate_machine_id="machine-ㄑ")
ok, blockers = nh.evaluate(bopc)
_check(ok and not blockers,
       "a Bopomofo letter with no single-Latin look-alike is a "
       f"genuinely distinct seat and must stay ELIGIBLE: {blockers}")

bopx = dict(GOOD, candidate_machine_id="machine-ㄒ",
            origin_machine_id="machine-t")
ok, blockers = nh.evaluate(bopx)
_check(not ok and blockers,
       "a Bopomofo-X-respelled same machine must fail "
       f"(bar blockers: {blockers})")

bopa = dict(GOOD, candidate_machine_id="machine-ㄚ",
            origin_machine_id="machine-y")
ok, blockers = nh.evaluate(bopa)
_check(not ok and blockers,
       "a Bopomofo-A-respelled same machine must fail "
       f"(bar blockers: {blockers})")

cjkc = dict(GOOD, candidate_machine_id="machine-中")
ok, blockers = nh.evaluate(cjkc)
_check(ok and not blockers,
       "a CJK ideograph with no single-Latin look-alike is a "
       f"genuinely distinct seat and must stay ELIGIBLE: {blockers}")

cjkt = dict(GOOD, candidate_machine_id="machine-丅",
            origin_machine_id="machine-t")
ok, blockers = nh.evaluate(cjkt)
_check(not ok and blockers,
       "a CJK-U+4E05-respelled same machine must fail "
       f"(bar blockers: {blockers})")

cjky = dict(GOOD, candidate_machine_id="machine-丫",
            origin_machine_id="machine-y")
ok, blockers = nh.evaluate(cjky)
_check(not ok and blockers,
       "a CJK-U+4E2B-respelled same machine must fail "
       f"(bar blockers: {blockers})")

oriyac = dict(GOOD, candidate_machine_id="machine-କ")
ok, blockers = nh.evaluate(oriyac)
_check(ok and not blockers,
       "an Oriya letter with no single-Latin look-alike is a "
       f"genuinely distinct seat and must stay ELIGIBLE: {blockers}")

oriyat = dict(GOOD, candidate_machine_id="machine-ଠ",
              origin_machine_id="machine-o")
ok, blockers = nh.evaluate(oriyat)
_check(not ok and blockers,
       "an Oriya-TTHA-respelled same machine must fail "
       f"(bar blockers: {blockers})")

georgiac = dict(GOOD, candidate_machine_id="machine-ა")
ok, blockers = nh.evaluate(georgiac)
_check(ok and not blockers,
       "a Georgian letter with no single-Latin look-alike is a "
       f"genuinely distinct seat and must stay ELIGIBLE: {blockers}")

georgias = dict(GOOD, candidate_machine_id="machine-Ⴝ",
                origin_machine_id="machine-s")
ok, blockers = nh.evaluate(georgias)
_check(not ok and blockers,
       "a Georgian-CHAR-respelled same machine must fail "
       f"(bar blockers: {blockers})")

georgiah = dict(GOOD, candidate_machine_id="machine-Ⴙ",
                origin_machine_id="machine-h")
ok, blockers = nh.evaluate(georgiah)
_check(not ok and blockers,
       "a Georgian-CHIN-respelled same machine must fail "
       f"(bar blockers: {blockers})")

georgiao = dict(GOOD, candidate_machine_id="machine-ჿ",
                origin_machine_id="machine-o")
ok, blockers = nh.evaluate(georgiao)
_check(not ok and blockers,
       "a Georgian-LABIAL-SIGN-respelled same machine must fail "
       f"(bar blockers: {blockers})")

cherokeeo = dict(GOOD, candidate_machine_id="machine-Ꭳ")
ok, blockers = nh.evaluate(cherokeeo)
_check(ok and not blockers,
       "a Cherokee letter with no single-Latin look-alike is a "
       f"genuinely distinct seat and must stay ELIGIBLE: {blockers}")

cherokeehu = dict(GOOD, candidate_machine_id="machine-ꮁ",
                  origin_machine_id="machine-r")
ok, blockers = nh.evaluate(cherokeehu)
_check(not ok and blockers,
       "a Cherokee-small-HU-respelled same machine must fail "
       f"(bar blockers: {blockers})")

vedicctl = dict(GOOD, candidate_machine_id="machine-\u1cf6")
ok, blockers = nh.evaluate(vedicctl)
_check(ok and not blockers,
       "a Vedic letter with no single-Latin look-alike is a "
       f"genuinely distinct seat and must stay ELIGIBLE: {blockers}")

vedicx = dict(GOOD, candidate_machine_id="machine-\u1cf5",
              origin_machine_id="machine-x")
ok, blockers = nh.evaluate(vedicx)
_check(not ok and blockers,
       "a Vedic-JIHVAMULIYA-respelled same machine must fail "
       f"(bar blockers: {blockers})")

copticctl = dict(GOOD, candidate_machine_id="machine-\u03e2")
ok, blockers = nh.evaluate(copticctl)
_check(ok and not blockers,
       "a Coptic letter with no single-Latin look-alike is a "
       f"genuinely distinct seat and must stay ELIGIBLE: {blockers}")

coptic_i = dict(GOOD, candidate_machine_id="machine-\u2c92",
                origin_machine_id="machine-l")
ok, blockers = nh.evaluate(coptic_i)
_check(not ok and blockers,
       "a Coptic-IAUDA-respelled same machine must fail "
       f"(bar blockers: {blockers})")

coptic_s = dict(GOOD, candidate_machine_id="machine-\u03ed",
                origin_machine_id="machine-o")
ok, blockers = nh.evaluate(coptic_s)
_check(not ok and blockers,
       "a Coptic-SHIMA-respelled same machine must fail "
       f"(bar blockers: {blockers})")

cyrctl = dict(GOOD, candidate_machine_id="machine-\u0436")
ok, blockers = nh.evaluate(cyrctl)
_check(ok and not blockers,
       "a Cyrillic letter with no single-Latin look-alike is a "
       f"genuinely distinct seat and must stay ELIGIBLE: {blockers}")

cyr_w = dict(GOOD, candidate_machine_id="machine-\u051d",
             origin_machine_id="machine-w")
ok, blockers = nh.evaluate(cyr_w)
_check(not ok and blockers,
       "a Cyrillic-WE-respelled same machine must fail "
       f"(bar blockers: {blockers})")

cyr_y = dict(GOOD, candidate_machine_id="machine-\u04ae",
             origin_machine_id="machine-y")
ok, blockers = nh.evaluate(cyr_y)
_check(not ok and blockers,
       "a Cyrillic-STRAIGHT-U-respelled same machine must fail "
       f"(bar blockers: {blockers})")

cyr_l = dict(GOOD, candidate_machine_id="machine-\u0406",
             origin_machine_id="machine-l")
ok, blockers = nh.evaluate(cyr_l)
_check(not ok and blockers,
       "a Cyrillic-I-respelled same machine must fail "
       f"(bar blockers: {blockers})")

for bad, orig, why in [
    ("\u042c", "b", "SOFT SIGN"), ("\u0501", "d", "KOMI DE"),
    ("\u04bd", "e", "ABKHASIAN CHE"), ("\u050c", "g", "KOMI SJE"),
    ("\u050d", "g", "KOMI SJE small"), ("\ua647", "i", "IOTA"),
    ("\u04cf", "l", "PALOCHKA"), ("\u04c0", "l", "PALOCHKA cap"),
    ("\u051a", "q", "QA"), ("\u051b", "q", "QA small"),
    ("\u0433", "r", "GHE"), ("\u0474", "v", "IZHITSA"),
    ("\u0475", "v", "IZHITSA small"), ("\u0461", "w", "OMEGA"),
    ("\u0448", "w", "SHA"), ("\u051c", "w", "WE cap"),
    ("\u04af", "y", "STRAIGHT U small"),
]:
    cyr = dict(GOOD, candidate_operator="op-" + bad,
               origin_operator="op-" + orig)
    ok, blockers = nh.evaluate(cyr)
    _check(not ok and blockers,
           f"a Cyrillic-{why}-respelled same operator must fail "
           f"(bar blockers: {blockers})")

armctl = dict(GOOD, candidate_machine_id="machine-\u0562")
ok, blockers = nh.evaluate(armctl)
_check(ok and not blockers,
       "an Armenian letter with no single-Latin look-alike is a "
       f"genuinely distinct seat and must stay ELIGIBLE: {blockers}")

arm_w = dict(GOOD, candidate_machine_id="machine-\u0561",
             origin_machine_id="machine-w")
ok, blockers = nh.evaluate(arm_w)
_check(not ok and blockers,
       "an Armenian-AYB-respelled same machine must fail "
       f"(bar blockers: {blockers})")

arm_s = dict(GOOD, candidate_machine_id="machine-\u054f",
             origin_machine_id="machine-s")
ok, blockers = nh.evaluate(arm_s)
_check(not ok and blockers,
       "an Armenian-TIWN-respelled same machine must fail "
       f"(bar blockers: {blockers})")

for bad, orig, why in [
    ("\u0584", "f", "KEH"), ("\u0581", "g", "CO"),
    ("\u0570", "h", "HO"), ("\u0582", "i", "YIWN"),
    ("\u0575", "j", "YI"), ("\u0578", "n", "VO"),
    ("\u057c", "n", "RA"), ("\u0563", "q", "GIM"),
    ("\u0566", "q", "ZA"), ("\u057d", "u", "SEH"),
    ("\u054d", "u", "SEH cap"), ("\u0561", "w", "AYB"),
]:
    arm = dict(GOOD, candidate_operator="op-" + bad,
               origin_operator="op-" + orig)
    ok, blockers = nh.evaluate(arm)
    _check(not ok and blockers,
           f"an Armenian-{why}-respelled same operator must fail "
           f"(bar blockers: {blockers})")

grkctl = dict(GOOD, candidate_machine_id="machine-\u03b8")
ok, blockers = nh.evaluate(grkctl)
_check(ok and not blockers,
       "a Greek letter with no single-Latin look-alike is a "
       f"genuinely distinct seat and must stay ELIGIBLE: {blockers}")

grk_f = dict(GOOD, candidate_machine_id="machine-\u03dc",
             origin_machine_id="machine-f")
ok, blockers = nh.evaluate(grk_f)
_check(not ok and blockers,
       "a Greek-DIGAMMA-respelled same machine must fail "
       f"(bar blockers: {blockers})")

grk_o = dict(GOOD, candidate_machine_id="machine-\u03c3",
             origin_machine_id="machine-o")
ok, blockers = nh.evaluate(grk_o)
_check(not ok and blockers,
       "a Greek-SIGMA-respelled same machine must fail "
       f"(bar blockers: {blockers})")

for bad, orig, why in [
    ("\u03dc", "f", "DIGAMMA"), ("\u03f3", "j", "YOT"),
    ("\u037f", "j", "YOT cap"), ("\u0399", "l", "IOTA cap"),
    ("\u03fa", "m", "SAN"), ("\u03c3", "o", "SIGMA"),
    ("\u03f8", "p", "SHO"), ("\u1d26", "r", "SMALL CAPITAL GAMMA"),
    ("\u03b3", "y", "GAMMA"),
]:
    grk = dict(GOOD, candidate_operator="op-" + bad,
               origin_operator="op-" + orig)
    ok, blockers = nh.evaluate(grk)
    _check(not ok and blockers,
           f"a Greek-{why}-respelled same operator must fail "
           f"(bar blockers: {blockers})")

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
    ("candidate_machine_id", "𐰡achine-a",
     "oldturkic-elt-respelled same machine must fail"),
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
    ("op-𐰾", "op-l",
     "oldturkic-aes-respelled same operator must fail"),
    ("op-𐰡", "op-m",
     "oldturkic-elt-respelled same operator must fail"),
    ("op-𐰗", "op-o",
     "oldturkic-ay-respelled same operator must fail"),
    ("op-𐰟", "op-v",
     "oldturkic-al-respelled same operator must fail"),
    ("op-𐰓", "op-x",
     "oldturkic-aed-respelled same operator must fail"),
    ("op-𐰠", "op-y",
     "oldturkic-ael-respelled same operator must fail"),
    ("op-𐲂", "op-x",
     "oldhungarian-capital-eb-respelled same operator must fail"),
    ("op-𐳂", "op-x",
     "oldhungarian-small-eb-respelled same operator must fail"),
    ("op-𐲥", "op-l",
     "oldhungarian-capital-esz-respelled same operator must fail"),
    ("op-𐳥", "op-l",
     "oldhungarian-small-esz-respelled same operator must fail"),
    ("op-𐳺", "op-l",
     "oldhungarian-number-one-respelled same operator must fail"),
    ("op-𐳼", "op-x",
     "oldhungarian-number-ten-respelled same operator must fail"),
    ("op-𐤦", "op-l",
     "lydian-i-respelled same operator must fail"),
    ("op-𐤬", "op-o",
     "lydian-o-respelled same operator must fail"),
    ("op-𐓂", "op-o",
     "osage-capital-o-respelled same operator must fail"),
    ("op-𐒴", "op-r",
     "osage-capital-bra-respelled same operator must fail"),
    ("op-𐓶", "op-u",
     "osage-small-u-respelled same operator must fail"),
    ("op-𐓎", "op-u",
     "osage-capital-u-respelled same operator must fail"),
    ("op-ߕ", "op-b",
     "nko-ta-respelled same operator must fail"),
    ("op-ߓ", "op-f",
     "nko-ba-respelled same operator must fail"),
    ("op-ߊ", "op-l",
     "nko-a-respelled same operator must fail"),
    ("op-ߋ", "op-o",
     "nko-ee-respelled same operator must fail"),
    ("op-ߠ", "op-t",
     "nko-na-woloso-respelled same operator must fail"),
    ("op-ߌ", "op-y",
     "nko-i-respelled same operator must fail"),
    ("op-ᛖ", "op-m",
     "runic-ehwaz-e-respelled same operator must fail"),
    ("op-ᚷ", "op-x",
     "runic-gebo-g-respelled same operator must fail"),
    ("op-ו", "op-l",
     "hebrew-vav-respelled same operator must fail"),
    ("op-ן", "op-l",
     "hebrew-final-nun-respelled same operator must fail"),
    ("op-ט", "op-v",
     "hebrew-tet-respelled same operator must fail"),
    ("op-ⴹ", "op-e",
     "tifinagh-yadd-respelled same operator must fail"),
    ("op-ⵊ", "op-l",
     "tifinagh-yazh-respelled same operator must fail"),
    ("op-ⵏ", "op-l",
     "tifinagh-yan-respelled same operator must fail"),
    ("op-ⵔ", "op-o",
     "tifinagh-yar-respelled same operator must fail"),
    ("op-ⵕ", "op-q",
     "tifinagh-yarr-respelled same operator must fail"),
    ("op-ⴸ", "op-v",
     "tifinagh-yadh-respelled same operator must fail"),
    ("op-ⵝ", "op-x",
     "tifinagh-yath-respelled same operator must fail"),
    ("op-ꕗ", "op-b",
     "vai-gba-respelled same operator must fail"),
    ("op-ꗋ", "op-e",
     "vai-to-respelled same operator must fail"),
    ("op-ꕯ", "op-l",
     "vai-na-respelled same operator must fail"),
    ("op-ꕶ", "op-s",
     "vai-poo-respelled same operator must fail"),
    ("op-ꔋ", "op-t",
     "vai-gbee-respelled same operator must fail"),
    ("op-ࡀ", "op-o",
     "mandaic-halqa-respelled same operator must fail"),
    ("op-𐴇", "op-o",
     "hanifi-ha-respelled same operator must fail"),
    ("op-𑄤", "op-o",
     "chakma-waa-respelled same operator must fail"),
    ("op-င", "op-c",
     "myanmar-nga-respelled same operator must fail"),
    ("op-ၚ", "op-c",
     "myanmar-mon-nga-respelled same operator must fail"),
    ("op-ဝ", "op-o",
     "myanmar-wa-respelled same operator must fail"),
    ("op-ᩅ", "op-o",
     "tai-tham-wa-respelled same operator must fail"),
    ("op-ᄋ", "op-o",
     "hangul-choseong-ieung-respelled same operator must fail"),
    ("op-ᆼ", "op-o",
     "hangul-jongseong-ieung-respelled same operator must fail"),
    ("op-ㅇ", "op-o",
     "hangul-letter-ieung-respelled same operator must fail"),
    ("op-ﾷ", "op-o",
     "hangul-halfwidth-ieung-respelled same operator must fail"),
    ("op-ᝣ", "op-x",
     "tagbanwa-ka-respelled same operator must fail"),
    ("op-𖫖", "op-s",
     "bassa-vah-gah-respelled same operator must fail"),
    ("op-𖫩", "op-o",
     "bassa-vah-oo-respelled same operator must fail"),
    ("op-ꛉ", "op-z",
     "bamum-wue-respelled same operator must fail"),
    ("op-ꛟ", "op-v",
     "bamum-ko-respelled same operator must fail"),
    ("op-𖨙", "op-r",
     "bamum-phase-f-nu-respelled same operator must fail"),
    ("op-𑜆", "op-v",
     "ahom-pa-respelled same operator must fail"),
    ("op-𑜊", "op-w",
     "ahom-ja-respelled same operator must fail"),
    ("op-𑜎", "op-w",
     "ahom-la-respelled same operator must fail"),
    ("op-𑜏", "op-w",
     "ahom-sa-respelled same operator must fail"),
    ("op-ഠ", "op-o",
     "malayalam-ttha-respelled same operator must fail"),
    ("op-ട", "op-s",
     "malayalam-tta-respelled same operator must fail"),
    ("op-ዐ", "op-o",
     "ethiopic-pharyngeal-a-respelled same operator must fail"),
    ("op-ሀ", "op-u",
     "ethiopic-ha-respelled same operator must fail"),
    ("op-ㄒ", "op-t",
     "bopomofo-x-respelled same operator must fail"),
    ("op-ㄚ", "op-y",
     "bopomofo-a-respelled same operator must fail"),
    ("op-丅", "op-t",
     "cjk-u4e05-respelled same operator must fail"),
    ("op-丫", "op-y",
     "cjk-u4e2b-respelled same operator must fail"),
    ("op-ଠ", "op-o",
     "oriya-ttha-respelled same operator must fail"),
    ("op-Ⴙ", "op-h",
     "georgian-chin-respelled same operator must fail"),
    ("op-ჿ", "op-o",
     "georgian-labial-sign-respelled same operator must fail"),
    ("op-Ჿ", "op-o",
     "georgian-mtavruli-labial-sign-respelled same operator must fail"),
    ("op-Ⴝ", "op-s",
     "georgian-char-respelled same operator must fail"),
    ("op-ჽ", "op-s",
     "georgian-aen-respelled same operator must fail"),
    ("op-Ჽ", "op-s",
     "georgian-mtavruli-aen-respelled same operator must fail"),
    ("op-ყ", "op-y",
     "georgian-qar-respelled same operator must fail"),
    ("op-ⴭ", "op-z",
     "georgian-small-aen-respelled same operator must fail"),
    ("op-Ⴭ", "op-z",
     "georgian-capital-aen-respelled same operator must fail"),
    ("op-ꮁ", "op-r",
     "cherokee-small-hu-respelled same operator must fail"),
    ("op-\u1cf5", "op-x",
     "vedic-jihvamuliya-respelled same operator must fail"),
    ("op-\u2c92", "op-l",
     "coptic-iauda-respelled same operator must fail"),
    ("op-\u2cd0", "op-l",
     "coptic-l-shaped-ha-respelled same operator must fail"),
    ("op-\u03ed", "op-o",
     "coptic-shima-respelled same operator must fail"),
    ("op-\u2ccf", "op-p",
     "coptic-old-coptic-ha-small-respelled same operator must fail"),
    ("op-\u2cce", "op-p",
     "coptic-old-coptic-ha-respelled same operator must fail"),
    ("op-\u2c85", "op-r",
     "coptic-gamma-respelled same operator must fail"),
    ("op-\u2cbd", "op-w",
     "coptic-cryptogrammic-ni-respelled same operator must fail"),
    ("op-\u2ca9", "op-y",
     "coptic-ua-respelled same operator must fail"),
]:
    seat = dict(GOOD, candidate_operator=cand, origin_operator=orig)
    ok, blockers = nh.evaluate(seat)
    _check(not ok and blockers, f"{why} (bar blockers: {blockers})")

if fails:
    print(f"test_nexus_host_check: {fails} FAIL")
    sys.exit(1)
print("test_nexus_host_check: PASS")
