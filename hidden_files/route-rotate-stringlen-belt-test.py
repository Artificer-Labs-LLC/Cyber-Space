#!/usr/bin/env python3
"""Belt test: names/rotate refuses a hex field whose STRING length is
not the wanted length, even when its decode is the right byte count
(primitives 1 naming + 4 identity).

The rotate route's shape loop gated only the DECODED length
(len(raw)*2 == want) and never the string length. bytes.fromhex
ignores embedded spaces, so INSERTING a space into a field (nothing
removed: a 66-char pubkey, a 130-char signature) decodes to exactly
the wanted 32/64 bytes and passed the gate the claim route's
string-length gate refuses on sight. The binding_signature seat was
the live wound: the spaced sig decoded to the TRUE signature bytes,
_name_binding_verify verified it, and the route stored the spaced
130-char string verbatim into name_bindings — a binding every client
seat (resolve step 2, dial step 3, verify_name: len(signature) != 128
reads as absent) refuses, so the mirror answered "rotated" while the
name went dark. Spaced pubkeys misreported as signature failures
instead of the malformed fields they are.

Fix: the loop also refuses len(val) != want with the loop's own
"must be {want} hex chars." detail; the fromhex "is not hex" verdict
and every clean/uppercase verdict stay byte-exact.

Checks: good rotate -> 200 + stored byte-exact; spaced-inserted
binding_signature -> 400 must-be-128 + binding unmoved; spaced
rotation_signature -> 400 must-be-128; spaced new_pubkey -> 400
must-be-64; spaced old_pubkey -> 400 must-be-64; uppercase rotate
still 200; non-hex 64-char field still "is not hex."
Runs against a SCRATCH DB; the repo's live cybernet.db is never touched.
"""
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone

TMP = tempfile.mkdtemp(prefix="route-rotate-stringlen-belt-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient  # noqa: E402
import core  # noqa: E402
core.init_db()
from fed import ed25519 as _ed  # noqa: E402
import rotate_name  # noqa: E402
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
    return dt.astimezone(timezone.utc).replace(microsecond=0).strftime(
        "%Y-%m-%dT%H:%M:%S+00:00")


def detail(r):
    try:
        return r.json().get("detail", "")
    except Exception:
        return r.text


def mint_binding(name, priv_hex, issued, expires):
    pub = _ed.publickey(bytes.fromhex(priv_hex)).hex()
    sig = _ed.sign(core._name_claim_payload(name, pub, issued, expires),
                   bytes.fromhex(priv_hex), bytes.fromhex(pub)).hex()
    return {"name": name, "node_pubkey": pub, "issued_at": issued,
            "expires_at": expires, "signature": sig}


def spaced(s):
    """Insert ONE space: string grows by 1, decode is byte-identical."""
    return s[:10] + " " + s[10:]


def setup_label(label):
    """Claim under old key; return (old_priv, new_priv, record, binding)."""
    old_priv = os.urandom(32).hex()
    new_priv = os.urandom(32).hex()
    now = datetime.now(timezone.utc)
    claim = mint_binding(label, old_priv, iso_z(now - timedelta(minutes=5)),
                         iso_z(now + timedelta(days=30)))
    r = client.post("/api/v1/names/claim", data=claim)
    assert r.status_code == 200, (label, r.status_code, r.text)
    new_pub = _ed.publickey(bytes.fromhex(new_priv)).hex()
    record = rotate_name.mint_rotation(label, bytes.fromhex(old_priv), new_pub)
    now2 = datetime.now(timezone.utc)
    binding = mint_binding(label, new_priv, iso_z(now2),
                           iso_z(now2 + timedelta(days=30)))
    return old_priv, new_priv, record, binding


def rotate_form(record, binding, **over):
    form = {"name": binding["name"], "old_pubkey": record["old_pubkey"],
            "new_pubkey": record["new_pubkey"],
            "rotation_issued_at": record["issued_at"],
            "rotation_signature": record["signature"],
            "binding_issued_at": binding["issued_at"],
            "binding_expires_at": binding["expires_at"],
            "binding_signature": binding["signature"]}
    form.update(over)
    return form


def stored_pub(label):
    r = client.get(f"/api/v1/names/{label}")
    return r.json().get("node_pubkey") if r.status_code == 200 else None


# --- happy path: clean rotate moves the binding, byte-exact ----------------
_, _, rec, bnd = setup_label("belt-rot-good")
r = client.post("/api/v1/names/rotate", data=rotate_form(rec, bnd))
check("good rotate -> 200 rotated",
      r.status_code == 200 and r.json().get("status") == "rotated")
check("stored binding is the new key, byte-exact",
      stored_pub("belt-rot-good") == bnd["node_pubkey"])

# --- spaced-inserted binding_signature: the live wound ---------------------
old_priv, _, rec, bnd = setup_label("belt-rot-spacedsig")
old_pub = _ed.publickey(bytes.fromhex(old_priv)).hex()
bad = spaced(bnd["signature"])
assert len(bad) == 129 and bytes.fromhex(bad) == bytes.fromhex(bnd["signature"])
r = client.post("/api/v1/names/rotate",
                data=rotate_form(rec, bnd, binding_signature=bad))
check("spaced binding_signature (129ch, true 64B decode) -> 400 must-be-128",
      r.status_code == 400
      and detail(r) == "binding_signature must be 128 hex chars.")
check("binding unmoved (still the old key)",
      stored_pub("belt-rot-spacedsig") == old_pub)

# --- spaced-inserted rotation_signature ------------------------------------
_, _, rec, bnd = setup_label("belt-rot-spacedrot")
bad = spaced(rec["signature"])
assert len(bad) == 129
r = client.post("/api/v1/names/rotate",
                data=rotate_form(rec, bnd, rotation_signature=bad))
check("spaced rotation_signature -> 400 must-be-128",
      r.status_code == 400
      and detail(r) == "rotation_signature must be 128 hex chars.")

# --- spaced-inserted new_pubkey ---------------------------------------------
_, _, rec, bnd = setup_label("belt-rot-spacednew")
bad = spaced(rec["new_pubkey"])
assert len(bad) == 65 and bytes.fromhex(bad) == bytes.fromhex(rec["new_pubkey"])
r = client.post("/api/v1/names/rotate",
                data=rotate_form(rec, bnd, new_pubkey=bad))
check("spaced new_pubkey (65ch, true 32B decode) -> 400 must-be-64",
      r.status_code == 400 and detail(r) == "new_pubkey must be 64 hex chars.")

# --- spaced-inserted old_pubkey ---------------------------------------------
_, _, rec, bnd = setup_label("belt-rot-spacedold")
bad = spaced(rec["old_pubkey"])
assert len(bad) == 65
r = client.post("/api/v1/names/rotate",
                data=rotate_form(rec, bnd, old_pubkey=bad))
check("spaced old_pubkey -> 400 must-be-64",
      r.status_code == 400 and detail(r) == "old_pubkey must be 64 hex chars.")

# --- uppercase rotate still accepted (route lowercases form fields) ---------
_, _, rec, bnd = setup_label("belt-rot-upper")
form = rotate_form(rec, bnd)
form = {k: (v.upper() if k not in ("name", "rotation_issued_at",
                                   "binding_issued_at", "binding_expires_at")
            else v) for k, v in form.items()}
r = client.post("/api/v1/names/rotate", data=form)
check("uppercase rotate -> 200 rotated", r.status_code == 200)

# --- non-hex verdict unchanged ----------------------------------------------
_, _, rec, bnd = setup_label("belt-rot-nonhex")
r = client.post("/api/v1/names/rotate",
                data=rotate_form(rec, bnd, old_pubkey="zz" + rec["old_pubkey"][2:]))
check("non-hex 64-char old_pubkey -> 400 is-not-hex (unchanged)",
      r.status_code == 400 and detail(r) == "old_pubkey is not hex.")

print(f"\n{PASSED} passed, {FAILED} failed")
sys.exit(1 if FAILED else 0)
