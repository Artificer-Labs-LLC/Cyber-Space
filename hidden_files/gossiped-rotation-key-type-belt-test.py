#!/usr/bin/env python3
"""Belt: _gossiped_rotation_designates / _gossiped_rotation_chain_
designates refuse a NON-STRING stored/new key instead of escaping as
AttributeError (primitive 4 identity).

Both helpers promise "fail-closed on every surprise: a missing,
malformed, or failed proof reads as no proof" — but their key
comparisons called .lower() on the caller-supplied stored_pubkey /
new_pubkey with no seat gate, so an int/list key (a gossip-carried
JSON field can carry 123/true/a list straight in) escaped as
AttributeError past that contract, instead of reading as no proof.
The record's own fields are guarded downstream by verify_rotation;
the two key parameters were not. Seat gate: name / stored_pubkey /
new_pubkey / binding_issued_at must be real strings, else False.
Valid string verdicts are byte-exact.

Covers: valid single-hop -> True (control); valid chain -> True
(control); mismatched stored key -> False (control); int/list
stored or new key on both helpers -> False, no raise.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/gossiped-rotation-key-type-belt-test.py
"""
import os
import secrets
import sys
import tempfile
from datetime import datetime, timedelta, timezone

TMP = tempfile.mkdtemp(prefix="gossiped-rotation-type-belt-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core  # noqa: E402
import rotate_name  # noqa: E402

CASES = {"passed": 0, "failed": 0}


def check(name, cond, extra=""):
    if cond:
        CASES["passed"] += 1
        print(f"  ok  {name}")
    else:
        CASES["failed"] += 1
        print(f"  FAIL {name} {extra}")


def attempt(fn, *args):
    try:
        return fn(*args)
    except Exception as e:  # a raise is a failed check, named
        return f"RAISED {type(e).__name__}: {e}"


NOW = datetime.now(timezone.utc)
ISSUED = (NOW - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S+00:00")
BINDING_ISSUED = (NOW - timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%S+00:00")

SEED_A = secrets.token_hex(32)
PUB_A = core._fed_ed25519.publickey(bytes.fromhex(SEED_A)).hex()
SEED_B = secrets.token_hex(32)
PUB_B = core._fed_ed25519.publickey(bytes.fromhex(SEED_B)).hex()
OTHER = core._fed_ed25519.publickey(secrets.token_bytes(32)).hex()


def mint_record(old_seed, old_pub, new_pub):
    payload = rotate_name._rotate_payload("foo", old_pub, new_pub, ISSUED)
    sig = core._fed_ed25519.sign(
        payload, bytes.fromhex(old_seed), bytes.fromhex(old_pub)).hex()
    return {"name": "foo", "old_pubkey": old_pub, "new_pubkey": new_pub,
            "issued_at": ISSUED, "signature": sig}


REC = mint_record(SEED_A, PUB_A, PUB_B)
REC2 = mint_record(SEED_B, PUB_B, OTHER)
CHAIN = [REC, mint_record(SEED_B, PUB_B, OTHER)]
# second hop's new is OTHER; chain tail check uses OTHER as new_pubkey
CHAIN[1] = REC2

check("control designates valid",
      attempt(core._gossiped_rotation_designates,
              REC, "foo", PUB_A, PUB_B, BINDING_ISSUED) is True)
check("control chain valid",
      attempt(core._gossiped_rotation_chain_designates,
              CHAIN, "foo", PUB_A, OTHER, BINDING_ISSUED) is True)
check("control designates mismatched stored",
      attempt(core._gossiped_rotation_designates,
              REC, "foo", OTHER, PUB_B, BINDING_ISSUED) is False)
check("designates int stored -> False",
      attempt(core._gossiped_rotation_designates,
              REC, "foo", 123, PUB_B, BINDING_ISSUED) is False)
check("designates list new -> False",
      attempt(core._gossiped_rotation_designates,
              REC, "foo", PUB_A, [PUB_B], BINDING_ISSUED) is False)
check("designates int new -> False",
      attempt(core._gossiped_rotation_designates,
              REC, "foo", PUB_A, 123, BINDING_ISSUED) is False)
check("chain int stored -> False",
      attempt(core._gossiped_rotation_chain_designates,
              CHAIN, "foo", 123, OTHER, BINDING_ISSUED) is False)
check("chain list new -> False",
      attempt(core._gossiped_rotation_chain_designates,
              CHAIN, "foo", PUB_A, [OTHER], BINDING_ISSUED) is False)
check("chain int new -> False",
      attempt(core._gossiped_rotation_chain_designates,
              CHAIN, "foo", PUB_A, 123, BINDING_ISSUED) is False)

print(f"\n{CASES['passed']} passed, {CASES['failed']} failed")
sys.exit(1 if CASES["failed"] else 0)
