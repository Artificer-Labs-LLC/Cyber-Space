#!/usr/bin/env python3
"""Belt: _reach_descriptor_verify refuses a signature whose STRING
length is not 128 / whose decode is not 64 bytes (primitives
1 naming + 2 resolution + 3 hosting).

_reach_descriptor_verify (core.py) gated the pubkey's string length
(64) but carried NO signature gate at all before checkvalid, and
bytes.fromhex ignores embedded spaces — so a 129-char signature with
an inserted space decoded to the TRUE 64 bytes and the descriptor
VERIFIED (the signature is not part of the signed canonical form),
and an outer-padded spelling verified the same way. Every binding
seat refuses that spelling on sight (resolve step 2 / dial step 3
gate len(signature) != 128), and verify_rotation's string-length gate
(3fbb38b) is the twin fix. The pubkey seat also gained the decoded-
length gate its twins carry (a spaced 64-char pub decoding to 31
bytes is malformed, not merely unverifiable — bool verdict unchanged
there, checkvalid already refused it).

Covers: valid descriptor verifies (control); uppercase sig verifies
(control); inserted-space 129-char sig refused; outer-padded sig
refused; spaced 128-char sig (63-byte decode) refused; short sig
refused; non-string sig refused; tampered clean sig refused (control);
spaced pubkey refused (control); ingest of a spaced-sig live
descriptor reads dropped-unverifiable, never stored (merge seat
trusts this verify).

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/reach-verify-sig-stringlen-belt-test.py
"""
import os
import secrets
import sys
import tempfile
from datetime import datetime, timedelta, timezone

TMP = tempfile.mkdtemp(prefix="reach-verify-sig-belt-")
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


core.init_db()

PRIV = secrets.token_hex(32)
PUB = core._fed_ed25519.publickey(bytes.fromhex(PRIV)).hex()
NOW = datetime.now(timezone.utc)
ISSUED = (NOW - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
EXPIRES = (NOW + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
REACH = [{"kind": "direct", "url": "https://93.184.216.34"}]

DESC = core._reach_mint(PRIV, PUB, "beltname", REACH, ISSUED, EXPIRES)
SIG = DESC["signature"]
SPACED = SIG[:64] + " " + SIG[64:]
SPACED_SAME_LEN = SIG[:10] + " " + SIG[11:]  # 128 chars, 63-byte decode
SPACED_PUB = PUB[:10] + " " + PUB[11:]       # 64 chars, 31-byte decode
TAMPERED = ("0" if SIG[0] != "0" else "1") + SIG[1:]

check("valid descriptor verifies (control)",
      core._reach_descriptor_verify(dict(DESC)) is True)
check("uppercase signature verifies (control)",
      core._reach_descriptor_verify({**DESC, "signature": SIG.upper()}) is True)
check("inserted-space 129-char signature refused",
      core._reach_descriptor_verify({**DESC, "signature": SPACED}) is False)
check("outer-padded signature refused",
      core._reach_descriptor_verify({**DESC, "signature": " " + SIG + " "}) is False)
check("spaced 128-char signature (63-byte decode) refused",
      core._reach_descriptor_verify({**DESC, "signature": SPACED_SAME_LEN}) is False)
check("short signature refused",
      core._reach_descriptor_verify({**DESC, "signature": SIG[:64]}) is False)
check("non-string signature refused",
      core._reach_descriptor_verify({**DESC, "signature": 123}) is False)
check("tampered clean signature refused (control)",
      core._reach_descriptor_verify({**DESC, "signature": TAMPERED}) is False)
check("spaced pubkey refused (control)",
      core._reach_descriptor_verify({**DESC, "node_pubkey": SPACED_PUB}) is False)
check("ingest spaced-sig descriptor -> dropped-unverifiable",
      core.ingest_reach_descriptor({**DESC, "signature": SPACED})
      == "dropped-unverifiable",
      f"got {core.ingest_reach_descriptor({**DESC, 'signature': SPACED})!r}")

with core._db_lock, core._db() as conn:
    rows = conn.execute(
        "SELECT COUNT(*) c FROM reach_descriptors").fetchone()["c"]
check("no descriptor row stored", rows == 0, f"rows={rows}")

print(f"\n{CASES['passed']} passed, {CASES['failed']} failed")
sys.exit(1 if CASES["failed"] else 0)
