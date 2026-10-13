#!/usr/bin/env python3
"""Belt test: dial.plan refuses a non-32/64-byte pub/sig decode as a
malformed binding, not as a signature failure (primitives 2 resolution
+ 6 client daemon).

dial.plan step 3 gated only the 64/128-char STRING length and a bare
fromhex parse, but bytes.fromhex ignores embedded spaces, so a spaced
64-char node_pubkey decoded to 31 bytes (a spaced signature to 63),
passed the shape gate, and _name_binding_verify read it as "binding
signature does not verify" — the key/sig itself was malformed. Twin of
verify_name 69ba6b5 and the gossip merge d422823; dial's step-3 seat was
left behind.

Checks: spaced pub -> malformed, spaced sig -> malformed, good binding
still plans (exit 3, silent host), uppercase pub/sig byte-exact (still
plans), tampered sig still "does not verify", non-hex unchanged.
Fake transport only; all signatures real Ed25519.
"""
import os
import secrets
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import core  # noqa: E402
import dial  # noqa: E402

MIRROR = "http://127.0.0.1:8471"
LABEL = "testbind"
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


priv = secrets.token_hex(32)
pub = core._fed_ed25519.publickey(bytes.fromhex(priv)).hex()
now = datetime.now(timezone.utc)
issued = _iso(now - timedelta(hours=1))
expires = _iso(now + timedelta(days=364))
sig = core._fed_ed25519.sign(
    core._name_claim_payload(LABEL, pub, issued, expires),
    bytes.fromhex(priv), bytes.fromhex(pub)).hex()
GOOD = {"name": LABEL, "node_pubkey": pub, "issued_at": issued,
        "expires_at": expires, "signature": sig}


def _plan(binding):
    routes = {MIRROR + "/api/v1/node": {"ok": True},
              MIRROR + "/api/v1/names/" + LABEL: binding}
    saved = core._resolve_get_json
    core._resolve_get_json = lambda url: routes.get(url)
    try:
        return dial.plan(LABEL + ".cyberspace", MIRROR)
    finally:
        core._resolve_get_json = saved


code, lines = _plan(dict(GOOD))
check("good binding -> exit 3 (bound, no reach)", code == 3)

b = dict(GOOD); b["node_pubkey"] = pub[:10] + "  " + pub[12:]
assert len(b["node_pubkey"]) == 64
code, lines = _plan(b)
check("spaced pub (64ch, 31B) -> malformed binding",
      code == 1 and lines == ["name-side: malformed binding"])

b = dict(GOOD); b["signature"] = sig[:10] + "  " + sig[12:]
assert len(b["signature"]) == 128
code, lines = _plan(b)
check("spaced sig (128ch, 63B) -> malformed binding",
      code == 1 and lines == ["name-side: malformed binding"])

b = dict(GOOD); b["node_pubkey"] = pub.upper(); b["signature"] = sig.upper()
code, lines = _plan(b)
check("uppercase pub/sig byte-exact -> exit 3", code == 3)

b = dict(GOOD); b["signature"] = ("0" if sig[0] != "0" else "1") + sig[1:]
code, lines = _plan(b)
check("tampered sig -> 'binding signature does not verify'",
      code == 1 and lines == ["name-side: binding signature does not verify"])

b = dict(GOOD); b["node_pubkey"] = "zz" + pub[2:]
code, lines = _plan(b)
check("non-hex pub -> malformed binding",
      code == 1 and lines == ["name-side: malformed binding"])

print(f"{PASSED}/{PASSED + FAILED} passed")
sys.exit(1 if FAILED else 0)
