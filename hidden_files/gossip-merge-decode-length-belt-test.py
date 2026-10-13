#!/usr/bin/env python3
"""Belt: ingest_gossiped_binding refuses a non-32/64-byte pub/sig decode
as dropped-malformed, not dropped-unverifiable (primitive 1, naming).

The gossip merge seat gated only the 64/128-char STRING length, but
bytes.fromhex ignores embedded spaces, so a spaced 64-char node_pubkey
decoded to 31 bytes (a spaced 128-char signature to 63), passed the
shape gate, and checkvalid's decoded-length gate read it as merely
unverifiable — yet the merge's return code is exactly how mirrors tell
malformed from unverifiable. Twin of verify_name's binding seats
(69ba6b5). Non-hex still falls through to verify (unverifiable).

Cases:
 1. valid binding -> inserted
 2. uppercase pub/sig -> inserted (byte-exact)
 3. spaced pub (64 chars, 31-byte decode) -> dropped-malformed, no row
 4. spaced sig (128 chars, 63-byte decode) -> dropped-malformed, no row
 5. tampered sig (valid 64-byte hex) -> dropped-unverifiable
 6. non-hex sig -> dropped-unverifiable (unchanged)
Runs against a SCRATCH DB (CYBERNET_DB_DIR=tempdir); never the live DB.
"""
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone

TMP = tempfile.mkdtemp(prefix="gossip-merge-decode-belt-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core  # noqa: E402
core.init_db()
from fed import ed25519 as _ed  # noqa: E402

PASS = FAIL = 0


def check(label, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print(f"  ok: {label}")
    else:
        FAIL += 1
        print(f"FAIL {label}: got {got!r}, want {want!r}")


def iso(dt):
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


NOW = datetime.now(timezone.utc)
ISSUED = iso(NOW - timedelta(minutes=5))
EXPIRES = iso(NOW + timedelta(days=30))


def mint(name):
    priv = os.urandom(32).hex()
    pub = _ed.publickey(bytes.fromhex(priv)).hex()
    sig = _ed.sign(core._name_claim_payload(name, pub, ISSUED, EXPIRES),
                   bytes.fromhex(priv), bytes.fromhex(pub)).hex()
    return {"name": name, "node_pubkey": pub, "issued_at": ISSUED,
            "expires_at": EXPIRES, "signature": sig}


def stored(name):
    with core._db_lock, core._db() as conn:
        return conn.execute(
            "SELECT COUNT(*) FROM name_bindings WHERE name=?",
            (name,)).fetchone()[0]


b = mint("decode-valid")
check("valid inserts", core.ingest_gossiped_binding(b), "inserted")

b = mint("decode-upper")
b["node_pubkey"] = b["node_pubkey"].upper()
b["signature"] = b["signature"].upper()
# The seat lowercases both fields before verify, so the original
# signature still verifies — uppercase stays byte-exact in effect.
check("uppercase inserts (lowercased at seat)",
      core.ingest_gossiped_binding(b), "inserted")

b = mint("decode-spaced-pub")
spaced_pub = b["node_pubkey"][:30] + "  " + b["node_pubkey"][32:]
assert len(spaced_pub) == 64 and len(bytes.fromhex(spaced_pub)) == 31
b["node_pubkey"] = spaced_pub
check("spaced pub dropped-malformed",
      core.ingest_gossiped_binding(b), "dropped-malformed")
check("spaced pub stored no row", stored("decode-spaced-pub"), 0)

b = mint("decode-spaced-sig")
spaced_sig = b["signature"][:60] + "  " + b["signature"][62:]
assert len(spaced_sig) == 128 and len(bytes.fromhex(spaced_sig)) == 63
b["signature"] = spaced_sig
check("spaced sig dropped-malformed",
      core.ingest_gossiped_binding(b), "dropped-malformed")
check("spaced sig stored no row", stored("decode-spaced-sig"), 0)

b = mint("decode-tamper")
b["signature"] = "ab" * 64
check("tampered sig dropped-unverifiable",
      core.ingest_gossiped_binding(b), "dropped-unverifiable")

b = mint("decode-nonhex")
b["signature"] = "zz" * 64
check("non-hex sig dropped-unverifiable (unchanged)",
      core.ingest_gossiped_binding(b), "dropped-unverifiable")

print(f"{PASS}/{PASS + FAIL} PASS")
sys.exit(1 if FAIL else 0)
