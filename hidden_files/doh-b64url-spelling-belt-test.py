"""DoH base64url canonical-spelling belt (primitive 2 resolution).

Before: routes_doh._decode_dns_param handed the raw ?dns= string to
base64.urlsafe_b64decode (validate=False), which silently DISCARDS
characters outside the alphabet and accepts standard-base64 '+'/'/'
spellings — a junk-inserted or standard-base64 parameter decoded to
the TRUE wire bytes and was answered, a spelling RFC 8484 and strict
DoH peers refuse on sight (twin of the hex string-length gates).

Checks: valid unpadded + valid padded base64url decode byte-exact;
junk-inserted, standard-base64, mid-padding, excess-padding, and
empty parameters all refuse with HTTP 400.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/doh-b64url-spelling-belt-test.py
"""
import base64
import os
import sys
import tempfile

os.environ["CYBERNET_DB_DIR"] = tempfile.mkdtemp(prefix="doh-b64-home-")
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


RAW = bytes(range(1, 64))
ENC = base64.urlsafe_b64encode(RAW).decode().rstrip("=")
PADDED = base64.urlsafe_b64encode(RAW).decode()

check("valid unpadded decodes byte-exact",
      routes_doh._decode_dns_param(ENC) == RAW)
check("valid padded decodes byte-exact",
      routes_doh._decode_dns_param(PADDED) == RAW)
check("junk-inserted spelling refused",
      refuses(ENC[:4] + "####" + ENC[4:]))
check("whitespace-inserted spelling refused",
      refuses(ENC[:4] + " " + ENC[4:]))
std = base64.b64encode(b"\xfb\xff\xfe").decode().rstrip("=")
check("standard-base64 '+//' spelling refused", refuses(std))
check("mid-string padding refused", refuses(ENC[:4] + "=" + ENC[4:]))
check("excess padding refused", refuses(ENC + "==="))
check("empty refused", refuses(""))

print(f"{passed}/{passed + failed} PASS")
sys.exit(1 if failed else 0)
