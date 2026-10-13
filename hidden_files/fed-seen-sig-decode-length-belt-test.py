"""Belt: _claim_seen_sig refuses a non-64-byte sig decode.

_claim_seen_sig's contract: a malformed sig_hex raises ValueError,
fail-closed, never touches the store. It gated on STRING length only
(128 chars + fromhex parses), but bytes.fromhex ignores embedded
spaces, so a spaced 128-char sig decoded to 63 bytes and was INSERTED
into fed_seen_sigs and returned False (not a replay) — a malformed sig
wrote a row. Worse, the spaced respelling of an already-claimed real
sig is a different store key, so it read as a first sight, not the
replay it is.

Cases:
 1. valid sig -> False (first sight), row written
 2. same valid sig -> True (replay)
 3. spaced sig (128 chars, 63-byte decode) -> ValueError, no row
 4. spaced respelling of the claimed sig -> ValueError, no new row
 5. uppercase valid sig -> False (byte-exact: distinct key, 64-byte decode admitted)
"""
import os
import secrets
import sys
import tempfile

TMP = tempfile.mkdtemp(prefix="cybernet-seen-sig-decode-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core
from core import _db
import federation
from fed import envelope as fenv, ed25519

core.init_db()

passed = []
def check(label, cond):
    assert cond, f"FAIL: {label}"
    passed.append(label)

SK = secrets.token_bytes(32)
PK = ed25519.publickey(SK).hex()
T0 = 1_750_000_000.0

sig = fenv.make_envelope(SK.hex(), PK, core._NODE_PUB, {"ping": 1},
                         ts=1_000_000_000)["sig"]
assert len(sig) == 128 and len(bytes.fromhex(sig)) == 64

# Spaced respelling: two spaces in, two hex chars out — still 128 chars,
# fromhex parses it, but the decode is 63 bytes.
spaced = sig[:62] + "  " + sig[64:]
assert len(spaced) == 128 and len(bytes.fromhex(spaced)) == 63
# A spaced sig unrelated to any real envelope.
spaced_other = ("ab" * 32 + "  " + "cd" * 31)
assert len(spaced_other) == 128 and len(bytes.fromhex(spaced_other)) == 63

def rows(conn):
    return conn.execute("SELECT COUNT(*) FROM fed_seen_sigs").fetchone()[0]

with _db() as conn:
    check("valid sig first claim -> False",
          federation._claim_seen_sig(conn, sig, now=T0) is False)
    conn.commit()
with _db() as conn:
    check("valid sig re-claim -> True (replay)",
          federation._claim_seen_sig(conn, sig, now=T0) is True)
    conn.commit()

with _db() as conn:
    before = rows(conn)
    for bad, label in [(spaced_other, "spaced sig"),
                       (spaced, "spaced respelling of claimed sig")]:
        try:
            federation._claim_seen_sig(conn, bad, now=T0)
        except ValueError:
            passed.append(f"ValueError on {label}")
        else:
            raise AssertionError(f"FAIL: {label} did not raise")
    check("malformed spaced claims never wrote rows", rows(conn) == before)
    conn.commit()

with _db() as conn:
    check("uppercase valid sig -> False (64-byte decode admitted)",
          federation._claim_seen_sig(conn, sig.upper(), now=T0) is False)
    conn.commit()

print(f"SEEN-SIG DECODE-LENGTH BELT: {len(passed)}/{len(passed)} checks pass")
