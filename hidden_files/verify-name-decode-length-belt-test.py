#!/usr/bin/env python3
"""Belt test: verify_name refuses a non-32/64-byte decode as malformed
hex, not as a signature failure (primitive 1 naming, offline verifier).

verify_name's binding pub/sig seats gated only the 64/128-char STRING
length, but bytes.fromhex ignores embedded spaces, so a 64-char
node_pubkey with two spaces decoded to a 31-byte key (a 128-char
signature to 63 bytes), passed the hex checks, and was misreported as
"signature does not verify" — the key/sig itself was malformed. The
file's own --expect-pubkey pin gate (len(bytes.fromhex(exp)) == 32)
and verify_rotation's len(raw)*2 check already gate decoded length;
the binding seats were left behind.

9 checks: spaced pub -> "not 64 hex chars", spaced sig ->
"not 128 hex chars", uppercase pub/sig byte-exact (still verify),
wrong-size-string pub/sig unchanged, non-hex unchanged, good binding
still None, tampered name still "does not verify".
"""
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import verify_name  # noqa: E402
from fed.ed25519 import publickey, sign  # noqa: E402

PASSED = FAILED = 0


def check(desc, cond):
    global PASSED, FAILED
    if cond:
        PASSED += 1
        print(f"  ok: {desc}")
    else:
        FAILED += 1
        print(f"  FAIL: {desc}")


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S+00:00")


def _mint(pub_hex=None):
    priv = os.urandom(32)
    pub = publickey(priv)
    ph = pub.hex().lower() if pub_hex is None else pub_hex
    now = datetime.now(timezone.utc)
    issued = _iso(now - timedelta(hours=1))
    expires = _iso(now + timedelta(days=364))
    payload = (b"name-claim|" + b"testbind" + b"|" + ph.encode()
               + b"|" + issued.encode() + b"|" + expires.encode())
    sig = sign(payload, priv, pub).hex().lower()
    return {"name": "testbind", "node_pubkey": ph, "issued_at": issued,
            "expires_at": expires, "signature": sig}


b = _mint()
good_pub, good_sig = b["node_pubkey"], b["signature"]

check("good binding -> None", verify_name.verify(dict(b)) is None)

sb = dict(b)
sb["node_pubkey"] = good_pub[:10] + "  " + good_pub[12:]
assert len(sb["node_pubkey"]) == 64
check("spaced pub (64ch, 31B decode) -> 'not 64 hex chars'",
      (lambda r: r is not None and r == "node_pubkey is not 64 hex chars")
      (verify_name.verify(sb)))

sb = dict(b)
sb["signature"] = good_sig[:10] + "  " + good_sig[12:]
assert len(sb["signature"]) == 128
check("spaced sig (128ch, 63B decode) -> 'not 128 hex chars'",
      (lambda r: r is not None and r == "signature is not 128 hex chars")
      (verify_name.verify(sb)))

up = dict(b)
up["node_pubkey"] = good_pub.upper()
up["signature"] = good_sig.upper()
# _claim_payload lowercases; mirror normalizes likewise — byte-exact valid.
check("uppercase pub/sig still verify", verify_name.verify(up) is None)

sh = dict(b)
sh["node_pubkey"] = good_pub[:62]
check("short pub (62ch) -> 'not 64 hex chars'",
      verify_name.verify(sh) == "node_pubkey is not 64 hex chars")

sh = dict(b)
sh["signature"] = good_sig[:126]
check("short sig (126ch) -> 'not 128 hex chars'",
      verify_name.verify(sh) == "signature is not 128 hex chars")

nh = dict(b)
nh["node_pubkey"] = "zz" * 32
check("non-hex pub -> 'not hex'",
      (lambda r: r is not None and "not hex" in r)(verify_name.verify(nh)))

nh = dict(b)
nh["signature"] = "zz" * 64
check("non-hex sig -> 'not hex'",
      (lambda r: r is not None and "not hex" in r)(verify_name.verify(nh)))

ta = dict(b)
ta["name"] = "tampered"
check("tampered name still -> 'does not verify'",
      (lambda r: r is not None and "does not verify" in r)
      (verify_name.verify(ta)))

print(f"\n{PASSED} passed, {FAILED} failed")
sys.exit(1 if FAILED else 0)
