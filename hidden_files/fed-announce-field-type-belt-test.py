#!/usr/bin/env python3
"""Belt: fed_announce refuses a NON-STRING body field instead of
str()-aliasing it (primitives 1 naming + 5 discovery).

fed_announce (federation.py) read the roster body through str():
an announce-carried numeric name (12345) stringified to the valid
label "12345" and was STORED as that peer name, and int
network/version were stored as their digit strings -- the same
alias the binding/roster/delta seats refuse on sight. Only real
strings are announce roster fields; absent fields keep defaults.

Covers: int name refused (400, no row); int network refused
(400, no row); int version refused (400, no row);
valid string announce stored exact (control); reach_descriptor
seat: int/bool desc name not echoed aliased; int digit-only desc
pubkey refused 400 at the name-key gate; valid string desc
control echoed exact.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/fed-announce-field-type-belt-test.py
"""
import os
import secrets
import sys
import tempfile

TMP = tempfile.mkdtemp(prefix="fed-announce-field-type-belt-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core  # noqa: E402
from core import _db, _db_lock  # noqa: E402
import federation  # noqa: E402
from fed import envelope as fenv, ed25519  # noqa: E402
from fastapi import HTTPException  # noqa: E402

core.init_db()

CASES = {"passed": 0, "failed": 0}


def check(name, cond, extra=""):
    if cond:
        CASES["passed"] += 1
        print(f"  ok  {name}")
    else:
        CASES["failed"] += 1
        print(f"  FAIL {name} {extra}")


URL = "http://93.184.216.34/"


def attempt(body_extra):
    sk = secrets.token_bytes(32)
    pk = ed25519.publickey(sk).hex()
    body = {"node_pub": pk, "name": "validnode", "node_url": URL,
            "network": "cybernet", "version": "0.1.0"}
    body.update(body_extra)
    # body_extra may override node_pub mismatch; keep node_pub == pk
    body["node_pub"] = pk
    env = fenv.make_envelope(sk.hex(), pk, core._NODE_PUB, body)
    try:
        out = federation.fed_announce(env)
        status, detail = 200, ""
    except HTTPException as e:
        out, status, detail = None, e.status_code, str(e.detail)
    with _db_lock, _db() as conn:
        row = conn.execute(
            "SELECT name, network, version FROM peers WHERE node_pub=?",
            (pk,)).fetchone()
    return status, detail, out, row


# 1. int name: str() alias is a valid label, must be refused.
status, detail, out, row = attempt({"name": 12345})
check("int name refused 400 bad node name, no row",
      status == 400 and detail == "bad node name" and row is None,
      f"{status} {detail} row={row}")

# 2. int network: must be refused, not stored as digit string.
status, detail, out, row = attempt({"network": 12345})
check("int network refused 400, no row",
      status == 400 and row is None, f"{status} {detail} row={row}")

# 3. int version: must be refused, not stored as digit string.
status, detail, out, row = attempt({"version": 1})
check("int version refused 400, no row",
      status == 400 and row is None, f"{status} {detail} row={row}")

# 4. valid string control: stored byte-exact.
status, detail, out, row = attempt({})
check("valid string announce stored exact",
      status == 200 and row is not None and row["name"] == "validnode"
      and row["network"] == "cybernet" and row["version"] == "0.1.0",
      f"{status} {detail} row={row}")


# --- reach_descriptor seat: its gate and echo carry the same shape ---
DESC_BASE = {"reach": [], "issued_at": "2026-01-01T00:00:00+00:00",
             "expires_at": "2027-01-01T00:00:00+00:00",
             "signature": "00" * 32}


def attempt_desc(desc, stub=False, sender=None):
    sk = secrets.token_bytes(32)
    pk = sender or ed25519.publickey(sk).hex()
    body = {"node_pub": pk, "reach_descriptor": desc}
    if stub:
        # A verified envelope always carries a well-formed sig; the stub
        # must present one or the replay-dedupe claim (which sits between
        # verify and the descriptor gate) refuses it as invalid first.
        env = {"sender_pub": pk, "recipient": core._NODE_PUB, "body": body,
               "sig": "ab" * 64}
        orig = fenv.verify_envelope
        fenv.verify_envelope = lambda e: True
    else:
        env = fenv.make_envelope(sk.hex(), pk, core._NODE_PUB, body)
    try:
        out = federation.fed_announce(env)
        return 200, "", out
    except HTTPException as e:
        return e.status_code, str(e.detail), None
    finally:
        if stub:
            fenv.verify_envelope = orig


def desc_for(pk, **kw):
    d = dict(DESC_BASE, node_pubkey=pk, name="somename")
    d.update(kw)
    return d


# 5. int descriptor name: echo must not alias it to its digit string.
#    (ingest drops the descriptor unverifiable either way; the seat's
#    own return is what aliased.)
sk5 = secrets.token_bytes(32)
pk5 = ed25519.publickey(sk5).hex()
env5 = fenv.make_envelope(sk5.hex(), pk5, core._NODE_PUB,
                          {"node_pub": pk5,
                           "reach_descriptor": desc_for(pk5, name=12345)})
try:
    out5 = federation.fed_announce(env5)
    st5, nm5 = 200, out5.get("name")
except HTTPException as e:
    st5, nm5 = e.status_code, None
check("int desc name not echoed as digit string",
      st5 == 200 and nm5 == "", f"{st5} name={nm5!r}")

# 6. bool descriptor name: echo must not alias it to "true".
sk6 = secrets.token_bytes(32)
pk6 = ed25519.publickey(sk6).hex()
env6 = fenv.make_envelope(sk6.hex(), pk6, core._NODE_PUB,
                          {"node_pub": pk6,
                           "reach_descriptor": desc_for(pk6, name=True)})
try:
    out6 = federation.fed_announce(env6)
    st6, nm6 = 200, out6.get("name")
except HTTPException as e:
    st6, nm6 = e.status_code, None
check("bool desc name not echoed as 'true'",
      st6 == 200 and nm6 == "", f"{st6} name={nm6!r}")

# 7. int digit-only descriptor pubkey: str() stringified it to its own
#    hex and it passed the name-key gate (200); must be 400 mismatch.
#    Envelope verify stubbed: no real keypair has a digit-only pubkey
#    on demand, and the gate under test sits past envelope verify.
DIGITS = "1234567890" * 6 + "1234"
status, detail, out = attempt_desc(desc_for(DIGITS, node_pubkey=int(DIGITS)),
                                   stub=True, sender=DIGITS)
check("int digit desc pubkey refused 400 name-key mismatch",
      status == 400 and detail == "name-key mismatch",
      f"{status} {detail} out={out}")

# 8. valid string descriptor control: passes the gate, name echoed
#    lowercased byte-exact.
sk8 = secrets.token_bytes(32)
pk8 = ed25519.publickey(sk8).hex()
env8 = fenv.make_envelope(sk8.hex(), pk8, core._NODE_PUB,
                          {"node_pub": pk8,
                           "reach_descriptor": desc_for(pk8, name="ValidName")})
try:
    out8 = federation.fed_announce(env8)
    st8, nm8 = 200, out8.get("name")
except HTTPException as e:
    st8, nm8 = e.status_code, None
check("valid string desc passes gate, echo exact",
      st8 == 200 and nm8 == "validname", f"{st8} name={nm8!r}")

print(f"{CASES['passed']} passed, {CASES['failed']} failed")
sys.exit(1 if CASES["failed"] else 0)
