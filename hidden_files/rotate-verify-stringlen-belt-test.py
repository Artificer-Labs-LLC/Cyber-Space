#!/usr/bin/env python3
"""Belt: rotate_name.verify_rotation refuses a hex field whose STRING
length is not the wanted length, even when its decode is the right byte
count (primitives 1 naming + 4 identity).

verify_rotation gated only the DECODED length (len(raw)*2 == want),
never the string length. bytes.fromhex ignores embedded spaces, so
INSERTING a space (a 65-char pubkey, a 129-char signature) decodes to
exactly the wanted 32/64 bytes and passed. The signature seat was a
false accept: the signature is not part of the signed payload, so a
spaced signature decoded to the TRUE sig bytes and the record VERIFIED
— a record every mirror seat now refuses (the names/rotate route gates
string length first, c128594) and every client seat reads as absent
(len(signature) != 128). The pubkey seats misreported: the payload is
built from the spaced string itself, so a spaced pubkey read as
'signature does not verify' when the field itself was malformed.

Fix: string-length gate in verify_rotation's shape loop alongside the
decoded gate, with the loop's own 'is not {want} hex chars' wording;
the fromhex 'is not hex' verdict and clean/uppercase/padded verdicts
stay byte-exact. Twin of the names/rotate route c128594.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/rotate-verify-stringlen-belt-test.py
"""
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import rotate_name  # noqa: E402
from fed.ed25519 import publickey  # noqa: E402

PASSED = FAILED = 0


def check(desc, cond, extra=""):
    global PASSED, FAILED
    if cond:
        PASSED += 1
        print(f"  ok: {desc}")
    else:
        FAILED += 1
        print(f"  FAIL: {desc} {extra}")


def spaced(s):
    """Insert ONE space: string grows by 1, decode is byte-identical."""
    return s[:10] + " " + s[10:]


def iso_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")


OLD = b"\x11" * 32
NEW_PUB = publickey(b"\x22" * 32).hex()
rec = rotate_name.mint_rotation("testname", OLD, NEW_PUB, iso_now())

# control: valid verifies
check("valid rotation verifies", rotate_name.verify_rotation(rec) is None,
      str(rotate_name.verify_rotation(rec)))

# control: uppercase verifies (normalize lowercases before the gate)
up = dict(rec); up["old_pubkey"] = up["old_pubkey"].upper()
up["new_pubkey"] = up["new_pubkey"].upper(); up["signature"] = up["signature"].upper()
check("uppercase rotation verifies", rotate_name.verify_rotation(up) is None,
      str(rotate_name.verify_rotation(up)))

# control: outer-padded verifies (normalize strips before the gate)
pad = dict(rec); pad["new_pubkey"] = "  " + pad["new_pubkey"] + "  "
check("outer-padded new_pubkey verifies", rotate_name.verify_rotation(pad) is None,
      str(rotate_name.verify_rotation(pad)))

# spaced-inserted signature: FALSE ACCEPT before the fix
bad_sig = dict(rec); bad_sig["signature"] = spaced(rec["signature"])
assert len(bad_sig["signature"]) == 129 and bytes.fromhex(bad_sig["signature"]) == bytes.fromhex(rec["signature"])
check("spaced signature (129ch, true 64B decode) -> is not 128 hex chars",
      rotate_name.verify_rotation(bad_sig) == "signature is not 128 hex chars",
      str(rotate_name.verify_rotation(bad_sig)))

# spaced-inserted old_pubkey: misreported as sig failure before the fix
bad_old = dict(rec); bad_old["old_pubkey"] = spaced(rec["old_pubkey"])
assert len(bad_old["old_pubkey"]) == 65 and bytes.fromhex(bad_old["old_pubkey"]) == bytes.fromhex(rec["old_pubkey"])
check("spaced old_pubkey (65ch, true 32B decode) -> is not 64 hex chars",
      rotate_name.verify_rotation(bad_old) == "old_pubkey is not 64 hex chars",
      str(rotate_name.verify_rotation(bad_old)))

# spaced-inserted new_pubkey
bad_new = dict(rec); bad_new["new_pubkey"] = spaced(rec["new_pubkey"])
assert len(bad_new["new_pubkey"]) == 65
check("spaced new_pubkey (65ch, true 32B decode) -> is not 64 hex chars",
      rotate_name.verify_rotation(bad_new) == "new_pubkey is not 64 hex chars",
      str(rotate_name.verify_rotation(bad_new)))

# non-hex verdict unchanged (string length is exact, decode fails)
nonhex = dict(rec); nonhex["old_pubkey"] = "zz" + rec["old_pubkey"][2:]
check("non-hex 64-char old_pubkey -> is not hex (unchanged)",
      rotate_name.verify_rotation(nonhex) == "old_pubkey is not hex",
      str(rotate_name.verify_rotation(nonhex)))

# within-length spaced pub (64ch, 31B decode) still refused by decoded gate
within = dict(rec); within["new_pubkey"] = rec["new_pubkey"][:30] + "  " + rec["new_pubkey"][32:]
assert len(within["new_pubkey"]) == 64 and len(bytes.fromhex(within["new_pubkey"])) == 31
check("within-64 spaced new_pubkey (31B decode) -> is not 64 hex chars",
      rotate_name.verify_rotation(within) == "new_pubkey is not 64 hex chars",
      str(rotate_name.verify_rotation(within)))

# tampered clean sig still reads as signature failure, not malformed
tamp = dict(rec); tamp["signature"] = "00" * 64
r = rotate_name.verify_rotation(tamp)
check("tampered clean signature -> signature does not verify (unchanged)",
      r is not None and "signature does not verify" in r, str(r))

print(f"\n{PASSED} passed, {FAILED} failed")
sys.exit(1 if FAILED else 0)
