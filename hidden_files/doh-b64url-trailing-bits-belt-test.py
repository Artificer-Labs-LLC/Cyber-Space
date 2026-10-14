"""DoH base64url trailing-bit canonical-spelling belt (primitive 2 resolution).

Before: routes_doh._decode_dns_param gated the ?dns= alphabet and
trailing pads (6d8bddd), but urlsafe_b64decode still DISCARDS the
unused low bits of the final character -- so a spelling whose last
character carries non-zero trailing bits ('AB' for byte 0x00, where
canonical is 'AA'; '_x' for 0xff, canonical '_w') decoded to the
TRUE wire bytes and was answered. Two spellings, one message: a
spelling RFC 4648 canonical encoding (and strict DoH peers that
re-encode to compare) refuse on sight -- the alphabet gate's own
contract ('only the canonical spelling is a dns parameter') left
this class open.

Checks: valid unpadded + valid padded base64url decode byte-exact
(controls, incl. lengths covering 0/2/4 unused trailing bits);
non-zero-trailing-bit spellings at each remainder length refuse
with HTTP 400; the canonical twin of each refused spelling still
decodes byte-exact.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/doh-b64url-trailing-bits-belt-test.py
"""
import base64
import os
import sys
import tempfile

os.environ["CYBERNET_DB_DIR"] = tempfile.mkdtemp(prefix="doh-trailbits-")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi import HTTPException  # noqa: E402
import routes_doh  # noqa: E402

passed = failed = 0


def check(name, cond):
    global passed, failed
    if cond:
        passed += 1
    else:
        failed += 1
        print(f"FAIL: {name}")


def refuses(s):
    try:
        routes_doh._decode_dns_param(s)
        return False
    except HTTPException as e:
        return e.status_code == 400


def enc(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


def dirty_last(spelling):
    """Same spelling with the final char's lowest (unused) bit set."""
    i = ALPHABET.index(spelling[-1])
    return spelling[:-1] + ALPHABET[i | 1]


# Controls: canonical spellings at each length class decode byte-exact.
for raw in (b"\x00", b"\xff", b"\x01\x02", b"\xfb\xff\xfe",
            bytes(range(1, 64))):
    s = enc(raw)
    check(f"canonical {s!r} decodes byte-exact",
          routes_doh._decode_dns_param(s) == raw)
    check(f"canonical padded {s!r} decodes byte-exact",
          routes_doh._decode_dns_param(
              base64.urlsafe_b64encode(raw).decode()) == raw)

# Wound class: 1-byte (4 unused bits), 2-byte (2 unused bits), and a
# long message -- the dirty spelling decodes to the same bytes today.
for raw in (b"\x00", b"\xff", b"\x01\x02", bytes(range(1, 64))):
    s = enc(raw)
    d = dirty_last(s)
    if d == s:
        continue  # last char already odd: no distinct dirty twin
    check(f"non-zero trailing bits {d!r} refused", refuses(d))
    check(f"canonical twin {s!r} still decodes",
          routes_doh._decode_dns_param(s) == raw)

print(f"{passed}/{passed + failed} PASS")
sys.exit(1 if failed else 0)
