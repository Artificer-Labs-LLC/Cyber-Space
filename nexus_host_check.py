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


# Characters with letter/symbol categories that nonetheless render
# as a blank: the Hangul fillers (U+115F, U+1160, U+3164 and its
# halfwidth twin U+FFA0), the Braille Pattern Blank (U+2800), and
# the Object Replacement Character (U+FFFC). Inserted into the
# origin's spelling they draw nothing in a log or a reviewer's
# eye, so a seat respelled with one is the same seat -- and a
# filler-only id is no id at all.
_BLANK = frozenset({0x115F, 0x1160, 0x2800, 0x3164, 0xFFA0, 0xFFFC})


def _invisible(ch):
    """Characters that render as nothing in an id or a log: format
    (Cf: zero-width spaces, joiners, BOMs, tags), control (Cc: NUL,
    DEL and friends -- invisible and log-truncating), surrogates
    (Cs), the default-ignorable non-spacing marks -- variation
    selectors (U+FE00-FE0F, U+E0100-E01EF) and the combining
    grapheme joiner (U+034F) -- and the blank-rendering fillers in
    _BLANK. Other combining marks stay: an accent is part of a
    name, a variation selector is not."""
    if unicodedata.category(ch) in ("Cf", "Cc", "Cs"):
        return True
    o = ord(ch)
    return o == 0x034F or 0xFE00 <= o <= 0xFE0F \
        or 0xE0100 <= o <= 0xE01EF or o in _BLANK


# Cross-script look-alikes: Cyrillic, Greek, and Armenian letters
# whose shape duplicates a Latin letter (the well-known UTS #39
# confusables for Latin). A machine id or operator spelled with one of these renders
# identically to the Latin spelling, so it IS the Latin spelling for
# comparison purposes -- the origin may not pass as its own
# independent host or operator by switching alphabets. Scope is
# these scripts' single-letter Latin duplicates; within-Latin
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
    "ν": "v", "ϲ": "c",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H",
    "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O",
    "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X", "Ϲ": "C",
    # The dash family UTS #39 lists as confusable with the ASCII
    # hyphen-minus that separates id parts: hyphen, non-breaking
    # hyphen (NFKC first lands it on U+2010), figure dash, en/em
    # dash, horizontal bar, and the mathematical minus. A seat
    # whose separator is one of these renders as the same id in
    # a log or a reviewer's eye, so it IS that id. (NFKC already
    # folds the fullwidth and small hyphen-minus spellings.)
    "‐": "-", "‑": "-", "‒": "-", "–": "-",
    "—": "-", "―": "-", "−": "-",
})

# Lowercase counterparts of the capitals above. _norm translates
# BEFORE it case-folds, and case-folding maps a capital down to
# its lowercase, never the reverse -- so a table holding the
# capitals (plus only the lowercase letters first listed) let a
# seat respelled with a lowercase Cyrillic ve/ka/em/en/te or a
# lowercase Greek alpha/beta/epsilon/zeta/eta/iota/kappa/mu
# compare distinct from the Latin original its capital already
# folded to. Pi joins the Greek set: UTS #39 lists it against
# Latin n, the letter it renders as in common fonts.
_CONFUSABLES.update(str.maketrans({
    "в": "b", "к": "k", "м": "m", "н": "h", "т": "t",
    "α": "a", "β": "b", "ε": "e", "ζ": "z", "η": "h",
    "ι": "i", "κ": "k", "μ": "m", "π": "n",
}))

# Armenian oh: U+0555/U+0585 are perfect circles -- the Latin o/O
# drawn in another alphabet. The Cyrillic/Greek sets held their
# o-duplicates, but a seat respelled with the Armenian oh compared
# distinct and passed as its own origin's independent host/operator.
_CONFUSABLES.update(str.maketrans({
    "օ": "o", "Օ": "O",
}))

# Latin small capitals and the single-story a/g: these are not
# different letters that happen to look alike (the l/1, O/0 scope
# exclusion above) -- a small capital IS its letter in small-cap
# dress (its Unicode name says so), and ɑ/ɡ are the single-story
# printed forms of a/g. NFKC folds neither. A seat respelled with
# one rendered as the origin in a log or a reviewer's eye and
# compared distinct. Only the plain small capitals fold; the
# barred, hooked, reversed and turned variants are genuinely
# different letters and stay distinct.
_CONFUSABLES.update(str.maketrans({
    "ᴀ": "a", "ʙ": "b", "ᴄ": "c", "ᴅ": "d", "ᴇ": "e",
    "ꜰ": "f", "ɢ": "g", "ʜ": "h", "ɪ": "i", "ᴊ": "j",
    "ᴋ": "k", "ʟ": "l", "ᴍ": "m", "ɴ": "n", "ᴏ": "o",
    "ᴘ": "p", "ꞯ": "q", "ʀ": "r", "ꜱ": "s", "ᴛ": "t",
    "ᴜ": "u", "ᴠ": "v", "ᴡ": "w", "ʏ": "y", "ᴢ": "z",
    "ɑ": "a", "ɡ": "g",
}))

# Cherokee: Sequoyah's syllabary was typeset with borrowed Latin
# sorts, and UTS #39 lists a set of its letters as confusable with
# single Latin letters (GO with A, GV with E, MI with H, and so
# on). A seat respelled with one rendered as the origin and
# compared distinct (probed this tick: GO and GV seats returned
# ELIGIBLE). Only the single-Latin-letter mappings fold; the
# digit mappings (SE to 4, WV to 6) stay out under the l/1, O/0
# scope exclusion, and multi-letter or non-Latin targets
# (NA to O + stroke, HU to Gamma) stay distinct. Cherokee small
# letters need no entries of their own: Cherokee case-folding is
# upward (small folds to capital), and _norm folds once more
# after case-folding, below.
_CONFUSABLES.update(str.maketrans({
    "Ꭺ": "A", "Ᏼ": "B", "Ꮯ": "C", "Ꭰ": "D", "Ꭼ": "E",
    "Ꮐ": "G", "Ᏻ": "G", "Ꮋ": "H", "Ꮒ": "h", "Ꮟ": "b",
    "Ꮷ": "d", "Ꭵ": "i", "Ꭻ": "J", "Ꮶ": "K", "Ꮮ": "L",
    "Ꮇ": "M", "Ꮲ": "P", "Ꭱ": "R", "Ꮢ": "R", "Ꮥ": "S",
    "Ꮪ": "S", "Ꭲ": "T", "Ꮩ": "V", "Ꮃ": "W", "Ꮤ": "W",
    "Ꭹ": "Y", "Ꮍ": "Y", "Ꮓ": "Z",
}))

# Coptic: the Coptic alphabet is Greek uncial in another name,
# and the letters whose uncial shape IS a Latin letter duplicate
# it exactly as their Greek cognates above do -- alfa, vida, eie,
# zata, hate, iauda, kapa, mi, ni, o, ro, sima, tau, ua, khi fold
# to the same Latin letters the Greek set folds to (small pi to
# n, per UTS #39, as with pi above; capital pi keeps its gate
# shape and stays distinct). A seat respelled with one rendered
# as the origin and compared distinct (probed this tick: alfa
# and o seats returned ELIGIBLE). The remaining Coptic letters
# (gamma, dalda, sou, thethe, laula, ksi, fi, psi, oou) keep
# glyphs no Latin letter has and stay distinct.
_CONFUSABLES.update(str.maketrans({
    "Ⲁ": "A", "Ⲃ": "B", "Ⲉ": "E", "Ⲍ": "Z", "Ⲏ": "H",
    "Ⲓ": "I", "Ⲕ": "K", "Ⲙ": "M", "Ⲛ": "N", "Ⲟ": "O",
    "Ⲣ": "P", "Ⲥ": "C", "Ⲧ": "T", "Ⲩ": "Y", "Ⲭ": "X",
    "ⲁ": "a", "ⲃ": "b", "ⲉ": "e", "ⲍ": "z", "ⲏ": "h",
    "ⲓ": "i", "ⲕ": "k", "ⲙ": "m", "ⲛ": "n", "ⲟ": "o",
    "ⲡ": "n", "ⲣ": "p", "ⲥ": "c", "ⲧ": "t", "ⲩ": "u",
    "ⲭ": "x",
}))

# Lisu: the Fraser alphabet was built from Latin capitals (some
# rotated or mirrored), and UTS #39 lists 26 of its letters as
# confusable with single Latin letters (A with A, BA with B, CA
# with C, and so on) -- mappings taken from confusables.txt at
# unicode.org fetched this tick, not guessed. A seat respelled
# with one rendered as the origin and compared distinct (probed
# this tick: A and E seats returned ELIGIBLE). Lisu is caseless,
# so single entries suffice; PHA folds to d and DA to D, which
# _norm's case-fold then unites with Latin d, as UTS #39's own
# targets do. Letters UTS #39 lists against no Latin letter
# (KHA, for one) stay distinct.
_CONFUSABLES.update(str.maketrans({
    "ꓮ": "A", "ꓐ": "B", "ꓚ": "C", "ꓒ": "d", "ꓓ": "D",
    "ꓰ": "E", "ꓝ": "F", "ꓖ": "G", "ꓧ": "H", "ꓙ": "J",
    "ꓗ": "K", "ꓲ": "l", "ꓡ": "L", "ꓟ": "M", "ꓠ": "N",
    "ꓳ": "O", "ꓑ": "P", "ꓣ": "R", "ꓢ": "S", "ꓔ": "T",
    "ꓴ": "U", "ꓦ": "V", "ꓪ": "W", "ꓫ": "X", "ꓬ": "Y",
    "ꓜ": "Z",
}))

# Deseret: the phonetic alphabet's letters were cut to simple
# geometric shapes, several of which duplicate Latin letters, and
# UTS #39 lists 7 of them as confusable with single Latin letters
# -- mappings taken from confusables.txt at unicode.org fetched
# this tick, not guessed, and confirmed by a full-table audit of
# _norm against every in-scope UTS #39 mapping (the audit is what
# surfaced Deseret). A seat respelled with one rendered as the
# origin and compared distinct (probed this tick: chee and
# long-o seats returned ELIGIBLE). Both cases are listed, as
# UTS #39 lists both; _norm's case-fold unites them. The other
# Deseret letters have glyphs no Latin letter has (long i, for
# one) and stay distinct.
_CONFUSABLES.update(str.maketrans({
    "𐐽": "c", "𐐕": "C", "𐐛": "L", "𐐬": "o", "𐐄": "O",
    "𐑈": "s", "𐐠": "S",
}))

# Warang Citi: the Ho alphabet's letters are simple geometric
# shapes, several of which duplicate Latin letters, and UTS #39
# lists 20 of them as confusable with single Latin letters --
# mappings taken from confusables.txt at unicode.org fetched
# this tick, not guessed. A seat respelled with one rendered as
# the origin and compared distinct (probed this tick: II, A and
# NGAA operator seats returned ELIGIBLE). Both cases are listed,
# as UTS #39 lists both; _norm's case-fold unites them. The
# other Warang Citi letters have glyphs no Latin letter has
# (YO, for one) and stay distinct.
_CONFUSABLES.update(str.maketrans({
    "𑢦": "E", "𑢮": "E", "𑣂": "F", "𑢢": "F",
    "𑣃": "i", "𑢣": "L", "𑢲": "L", "𑣈": "o",
    "𑣗": "o", "𑢵": "O", "𑣁": "s", "𑢼": "T",
    "𑣘": "u", "𑢸": "U", "𑣀": "v", "𑢠": "V",
    "𑣄": "y", "𑣜": "y", "𑢤": "Y", "𑢩": "Z",
}))

# Carian: the Anatolian alphabet's letters were cut to simple
# shapes, several of which duplicate Latin capitals, and UTS #39
# lists 10 of them as confusable with single Latin letters --
# mappings taken from confusables.txt at unicode.org fetched
# this tick, not guessed, and surfaced by a full-table audit of
# _norm against every in-scope UTS #39 mapping. A seat respelled
# with one rendered as the origin and compared distinct (probed
# this tick: A, D and S seats returned ELIGIBLE). Carian is
# unicameral, so single entries suffice; _norm's case-fold
# unites them with the Latin lowercase. The other Carian letters
# have glyphs no Latin letter has (E, for one) and stay distinct.
_CONFUSABLES.update(str.maketrans({
    "𐊠": "A", "𐊡": "B", "𐊢": "C", "𐊥": "F",
    "𐋏": "H", "𐊰": "M", "𐊫": "O", "𐊱": "T",
    "𐊴": "X", "𐊲": "Y",
}))

# Lycian: Carian's Anatolian sibling alphabet, likewise cut to
# simple shapes that duplicate Latin capitals, and UTS #39 lists
# 9 of its letters as confusable with single Latin letters --
# mappings taken from confusables.txt at unicode.org fetched
# this tick, not guessed, and surfaced by the same full-table
# audit of _norm against every in-scope UTS #39 mapping that
# surfaced Carian. A seat respelled with one rendered as the
# origin and compared distinct (probed this tick: B and I seats
# returned ELIGIBLE). Lycian is unicameral, so single entries
# suffice; _norm's case-fold unites them with the Latin
# lowercase (letter J's own UTS #39 target is small l). The
# other Lycian letters keep glyphs no Latin letter has -- D
# folds only to Greek Delta, H to a plus sign, L to a turned V,
# KK to a runic letter -- and stay distinct.
_CONFUSABLES.update(str.maketrans({
    "𐊂": "B", "𐊆": "E", "𐊇": "F", "𐊊": "l",
    "𐊒": "O", "𐊕": "P", "𐊖": "S", "𐊗": "T",
    "𐊐": "X",
}))

# Elbasan: the Albanian alphabet's letters were likewise cut to
# simple shapes that duplicate Latin capitals, and UTS #39 lists
# 10 of them as confusable with single Latin letters -- mappings
# taken from confusables.txt at unicode.org fetched this tick,
# not guessed, and surfaced by the same full-table audit of
# _norm against every in-scope UTS #39 mapping. A seat respelled
# with one rendered as the origin and compared distinct (probed
# this tick: SE and O seats returned ELIGIBLE). Elbasan is
# unicameral, so single entries suffice; _norm's case-fold
# unites them with the Latin lowercase (letter JE's own UTS #39
# target is small l). The other Elbasan letters keep glyphs no
# Latin letter has -- KE folds only to Greek Gamma, PE only to
# Greek Pi, THE only to O with a stroke overlay -- and stay
# distinct.
_CONFUSABLES.update(str.maketrans({
    "𐔛": "C", "𐔥": "F", "𐔘": "K", "𐔎": "l",
    "𐔦": "L", "𐔓": "N", "𐔖": "O", "𐔝": "V",
    "𐔧": "X", "𐔇": "Z",
}))

# Miao: the Pollard script's letters are likewise simple shapes,
# and UTS #39 lists 9 of them as confusable with single Latin
# letters -- mappings taken from confusables.txt at unicode.org
# fetched this tick, not guessed, and surfaced by the same
# full-table audit of _norm against every in-scope UTS #39
# mapping. A seat respelled with one rendered as the origin
# and compared distinct (probed this tick: an A seat returned
# ELIGIBLE). Miao is unicameral, so single entries suffice;
# _norm's case-fold unites them with the Latin lowercase (one
# letter's own UTS #39 target is small l, another's capital L).
# The other Miao letters keep glyphs no Latin letter has --
# one folds only to Greek Gamma, another only to Greek Delta,
# others to punctuation or digits -- and stay distinct.
_CONFUSABLES.update(str.maketrans({
    "𖽀": "A", "𖼨": "l", "𖼖": "L", "𖼵": "R",
    "𖼺": "S", "𖼊": "T", "𖽂": "U", "𖼈": "V",
    "𖽃": "Y",
}))

# Old Italic: the Etruscan-derived alphabet's letters likewise
# duplicate Latin shapes, and UTS #39 lists 10 of its characters
# as confusable with single Latin letters -- mappings taken from
# confusables.txt at unicode.org fetched this tick, not guessed,
# and surfaced by the same full-table audit of _norm against
# every in-scope UTS #39 mapping; this was the audit's last
# uncovered alphabetic set. A seat respelled with one rendered
# as the origin and compared distinct (probed this tick: B and
# O seats returned ELIGIBLE). Old Italic is unicameral, so
# single entries suffice; _norm's case-fold unites them with
# the Latin lowercase (letter CHE's own UTS #39 target is small
# b, letters I and NUMERAL ONE both target small l). The two
# numeral signs are included because their UTS #39 targets are
# Latin letters, unlike digit-target mappings, which stay out.
# The other Old Italic letters keep glyphs no Latin letter has
# -- KU folds only to Greek Koppa, ESS only to an asterisk, YE
# only to a less-than sign, EF only to a digit -- and stay
# distinct.
_CONFUSABLES.update(str.maketrans({
    "𐌁": "B", "𐌂": "C", "𐌜": "b", "𐌉": "l",
    "𐌠": "l", "𐌑": "M", "𐌏": "O", "𐌕": "T",
    "𐌗": "X", "𐌢": "X",
}))

# Canadian Syllabics: the syllabary's letters are likewise
# simple geometric shapes, and UTS #39 lists 20 of them as
# confusable with single Latin letters -- mappings taken from
# confusables.txt at unicode.org fetched this tick, not guessed,
# and surfaced by a full-table audit of _norm against every
# letter-category UTS #39 mapping. A seat respelled with one
# rendered as the origin and compared distinct (probed this
# tick: a CARRIER GHO seat returned ELIGIBLE as its own origin).
# The syllabary is caseless, so single entries suffice; _norm's
# case-fold unites them with the Latin lowercase (the SAYISI YI
# and HK letters' own UTS #39 target is small x). The two
# non-letter signs (FULL STOP to x, CHI SIGN to X) are
# punctuation/symbol, not letters, and stay out; the other
# syllabics keep glyphs no Latin letter has -- A, for one, folds
# only inside multi-letter mappings -- and stay distinct.
_CONFUSABLES.update(str.maketrans({
    "ᗅ": "A", "ᑲ": "b", "ᖯ": "b", "ᗷ": "B",
    "ᑯ": "d", "ᗞ": "D", "ᗪ": "D", "ᖴ": "F",
    "ᕼ": "H", "ᒍ": "J", "ᒪ": "L", "ᗰ": "M",
    "𑪾": "N", "ᑭ": "P", "ᖇ": "R", "ᑌ": "U",
    "ᐯ": "V", "ᕁ": "x", "ᕽ": "x", "𑪼": "Z",
}))

# Runic: the futhark's letters are likewise simple strokes,
# and UTS #39 lists 5 of them as confusable with single Latin
# letters -- mappings taken from confusables.txt at unicode.org
# fetched this tick, not guessed, and surfaced by a full-table
# audit of _norm against every letter-category UTS #39 mapping.
# A seat respelled with one rendered as the origin and compared
# distinct (probed this tick: an EHWAZ seat and ISAZ, OPEN-P,
# SHORT-TWIG-TYR and GEBO operator spellings each returned
# ELIGIBLE as their own origin). Runic is caseless, so single
# entries suffice. The punctuation runes (SINGLE and MULTIPLE
# PUNCTUATION, CROSS PUNCTUATION) and the letters that fold
# only to non-letters (KAUNA to a less-than sign, SHORT-TWIG-SOL
# to an apostrophe) are not letters-to-letters and stay out;
# the other runes keep glyphs no Latin letter has and stay
# distinct.
_CONFUSABLES.update(str.maketrans({
    "ᛕ": "K", "ᛁ": "l", "ᛐ": "l", "ᛗ": "M",
    "ᛷ": "X",
}))

# Old Turkic: the Orkhon/Yenisei runiform letters are likewise
# simple strokes, and UTS #39 lists 6 of them as confusable with
# single Latin letters -- mappings taken from confusables.txt at
# unicode.org fetched this tick, not guessed, and surfaced by a
# full-table audit of _norm against every letter-category UTS #39
# mapping. A seat respelled with one rendered as the origin and
# compared distinct (probed this tick: an ELT machine seat and an
# AY operator spelling each returned ELIGIBLE as their own
# origin). Old Turkic is caseless, so single entries suffice;
# _norm's case-fold unites them with the Latin lowercase (letter
# AES's own UTS #39 target is small l). These 6 are the script's
# only letter-to-single-Latin-letter mappings in the table; the
# other Old Turkic letters have no UTS #39 entry at all and stay
# distinct.
_CONFUSABLES.update(str.maketrans({
    "𐰾": "l", "𐰡": "M", "𐰗": "O", "𐰟": "V",
    "𐰓": "X", "𐰠": "Y",
}))
# Old Hungarian: the rovás letters are likewise simple
# strokes, and UTS #39 lists 3 of its letters as confusable with
# single Latin letters -- mappings taken from confusables.txt at
# unicode.org (cached copy fetched 2026-10-15), not guessed, and
# surfaced by a full-table audit of _norm against every
# letter-category UTS #39 mapping. A seat respelled with one
# rendered as the origin and compared distinct (probed this
# tick: EB, ESZ, NUMBER ONE and NUMBER TEN operator spellings
# each returned ELIGIBLE as their own origin). Both cases of
# EB are listed, as UTS #39 lists both; for ESZ it lists only
# the capital, so the small letter is added as its lowercase
# counterpart -- _norm case-folds down, never up, so a table
# holding only the capital would strand the small spelling
# (the lowercase-counterpart trap named above). The two number
# signs are included because their UTS #39 targets are Latin
# letters, as with the Old Italic numerals; digit-target
# mappings stay out. The other Old Hungarian letters have no
# UTS #39 entry at all and stay distinct.
_CONFUSABLES.update(str.maketrans({
    "𐲂": "X", "𐳂": "x", "𐲥": "l",
    "𐳥": "l", "𐳺": "l", "𐳼": "X",
}))

# Lydian: the Anatolian sibling of Carian and Lycian, likewise
# cut to simple shapes, and UTS #39 lists 2 of its letters as
# confusable with single Latin letters -- mappings taken from
# confusables.txt at unicode.org (cached copy fetched
# 2026-10-15), not guessed, and surfaced by a full-table audit
# of _norm against every letter-category UTS #39 mapping. A
# seat respelled with one rendered as the origin and compared
# distinct (probed this tick: I and O operator spellings each
# returned ELIGIBLE as their own origin). Lydian is
# unicameral, so single entries suffice; _norm's case-fold
# unites them with the Latin lowercase (both UTS #39 targets
# are small letters). The other Lydian letters stay distinct:
# B folds only to a Canadian Syllabics letter, and the rest
# have no UTS #39 entry at all.
_CONFUSABLES.update(str.maketrans({
    "𐤦": "l", "𐤬": "o",
}))

def _norm(v):
    """Identity evidence compares canonically: NFKC-folded (fullwidth
    and other compatibility spellings become the characters they
    render as), invisible characters removed (see _invisible -- a
    seat respelled with them is the same seat), cross-script
    look-alikes folded to the Latin letters they render as and
    dash look-alikes folded to the hyphen-minus they render as
    (see _CONFUSABLES), whitespace runs collapsed and ends stripped, and
    case folded. A value with nothing visible left is no value
    at all. Evidence that is not text at all is no value either:
    a bytes/int/list seat returned untouched compared UNEQUAL to
    the origin's text spelling (b"machine-a" != "machine-a") and
    counted as present, so a type-confused seat cleared bars 1-2
    as its own origin's 'distinct' host/operator."""
    if not isinstance(v, str):
        return ""
    # Confusables fold on BOTH sides of NFKC: NFKC itself rewrites
    # some of them first (the Greek lunate sigmas, whose shape IS
    # Latin c/C, become ordinary sigmas), so a fold that only ran
    # after NFKC would never see the spelling that was used.
    v = v.translate(_CONFUSABLES)
    v = unicodedata.normalize("NFKC", v)
    v = "".join(ch for ch in v if not _invisible(ch))
    v = v.translate(_CONFUSABLES)
    # One more fold after case-folding: Cherokee case-folds
    # UPWARD (its small letters fold to the capitals), so a
    # small-Cherokee spelling only becomes a character the
    # table knows once case-folding has run -- a fold that
    # ended at case-folding would hand it back unfolded.
    return " ".join(v.split()).casefold() \
        .translate(_CONFUSABLES).casefold()


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
