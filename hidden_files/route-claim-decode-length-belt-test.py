#!/usr/bin/env python3
"""Belt test: names/claim refuses a non-32/64-byte pub/sig decode as
malformed, not as a signature failure (primitives 1 naming + 3 hosting).

The claim route gated only the 64/128-char STRING length and a bare
fromhex parse, but bytes.fromhex ignores embedded spaces, so a spaced
64-char node_pubkey decoded to 31 bytes (a spaced signature to 63),
passed the route's own 'Malformed key or signature.' gate, and
_name_binding_verify (checkvalid's decoded-length gate) read it as
'Signature does not verify' — the key/sig itself was malformed. Twin
of verify_name 69ba6b5 / dial.plan 9a67588; the sibling rotate route in
the same file already gates decoded length (len(raw)*2 == want).

Checks: spaced pub -> Malformed, spaced sig -> Malformed, good claim
still 200 claimed, uppercase pub/sig byte-exact (still 200), tampered
sig still 'does not verify', non-hex unchanged (Malformed).
Runs against a SCRATCH DB; the repo's live cybernet.db is never touched.
"""
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone

TMP = tempfile.mkdtemp(prefix="route-claim-decode-belt-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient  # noqa: E402
import core  # noqa: E402
core.init_db()
from fed import ed25519 as _ed  # noqa: E402
import app as appmod  # noqa: E402

client = TestClient(appmod.app)
PASSED = FAILED = 0


def check(desc, cond):
    global PASSED, FAILED
    if cond:
        PASSED += 1
        print(f"  ok: {desc}")
    else:
        FAILED += 1
        print(f"  FAIL: {desc}")


def iso_z(dt):
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


NOW = datetime.now(timezone.utc)
ISSUED = iso_z(NOW - timedelta(minutes=5))
EXPIRES = iso_z(NOW + timedelta(days=30))


def mint_claim(name, priv_hex):
    pub = _ed.publickey(bytes.fromhex(priv_hex)).hex()
    sig = _ed.sign(
        core._name_claim_payload(name, pub, ISSUED, EXPIRES),
        bytes.fromhex(priv_hex), bytes.fromhex(pub)).hex()
    return {"name": name, "node_pubkey": pub, "issued_at": ISSUED,
            "expires_at": EXPIRES, "signature": sig}


def detail(r):
    try:
        return r.json().get("detail", "")
    except Exception:
        return r.text


k = os.urandom(32).hex()
r = client.post("/api/v1/names/claim", data=mint_claim("belt-good", k))
check("good claim -> 200 claimed", r.status_code == 200)

k = os.urandom(32).hex()
c = mint_claim("belt-spaced-pub", k)
c["node_pubkey"] = c["node_pubkey"][:10] + "  " + c["node_pubkey"][12:]
assert len(c["node_pubkey"]) == 64
r = client.post("/api/v1/names/claim", data=c)
check("spaced pub (64ch, 31B) -> 400 Malformed",
      r.status_code == 400 and detail(r) == "Malformed key or signature.")

k = os.urandom(32).hex()
c = mint_claim("belt-spaced-sig", k)
c["signature"] = c["signature"][:10] + "  " + c["signature"][12:]
assert len(c["signature"]) == 128
r = client.post("/api/v1/names/claim", data=c)
check("spaced sig (128ch, 63B) -> 400 Malformed",
      r.status_code == 400 and detail(r) == "Malformed key or signature.")

k = os.urandom(32).hex()
c = mint_claim("belt-upper", k)
c["node_pubkey"] = c["node_pubkey"].upper()
c["signature"] = c["signature"].upper()
r = client.post("/api/v1/names/claim", data=c)
check("uppercase pub/sig byte-exact -> 200", r.status_code == 200)

k = os.urandom(32).hex()
c = mint_claim("belt-tampered", k)
c["signature"] = ("0" if c["signature"][0] != "0" else "1") + c["signature"][1:]
r = client.post("/api/v1/names/claim", data=c)
check("tampered sig -> 400 'Signature does not verify'",
      r.status_code == 400 and "Signature does not verify" in detail(r))

k = os.urandom(32).hex()
c = mint_claim("belt-nonhex", k)
c["node_pubkey"] = "zz" + c["node_pubkey"][2:]
r = client.post("/api/v1/names/claim", data=c)
check("non-hex pub -> 400 Malformed",
      r.status_code == 400 and detail(r) == "Malformed key or signature.")

print(f"{PASSED}/{PASSED + FAILED} passed")
sys.exit(1 if FAILED else 0)
