#!/usr/bin/env python3
"""Belt: /api/v1/names/{name}/rotations refuses a stored rotation
row whose sig/pubkey STRING length is not 128/64 even when its
decode is the right byte count (primitives 1 naming + 4 identity).

names_rotations served the stored name_rotations rows VERBATIM with
no string-length gate: a legacy/pre-gate row with a 129-char
inserted-space sig (or outer-padded spelling, or a 65-char spaced
pubkey) decoded to the TRUE bytes yet was served in a non-canonical
spelling every consumer refuses on sight (rotate_name's
verify_rotation gates len(old_pubkey/new_pubkey) != 64 /
len(signature) != 128). Only exact 128/64 spellings are served;
non-canonical rows are skipped, and a name whose rows are all
non-canonical reads as absent (404), twin of names_resolve's serve
gate (379568b). Case is left alone (uppercase served before and
still does).

Covers: valid 200 byte-exact + self-verifies; uppercase sig+pubs
200; mixed name (clean + spaced-sig rows) serves only the clean row;
spaced-sig-only 404; padded-sig-only 404; spaced-oldpub-only 404;
spaced-newpub-only 404.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/names-rotations-serve-stringlen-belt-test.py
"""
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone

TMP = tempfile.mkdtemp(prefix="names-rotations-strlen-belt-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core  # noqa: E402
import app as cyber  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from fed import ed25519 as _ed  # noqa: E402
import rotate_name  # noqa: E402

CASES = {"passed": 0, "failed": 0}


def check(name, cond, extra=""):
    if cond:
        CASES["passed"] += 1
        print(f"  ok  {name}")
    else:
        CASES["failed"] += 1
        print(f"  FAIL {name} {extra}")


def _iso(dt):
    return dt.isoformat(timespec="seconds")


now = datetime.now(timezone.utc)
ISSUED = _iso(now - timedelta(days=1))
ACCEPTED = _iso(now)

_old_seed = os.urandom(32)
_old_pub = _ed.publickey(_old_seed).hex()
_new_seed = os.urandom(32)
_new_pub = _ed.publickey(_new_seed).hex()


def _spaced(s):
    return s[:32] + " " + s[32:]


def _padded(s):
    return " " + s


core.init_db()


_new2_seed = os.urandom(32)
_new2_pub = _ed.publickey(_new2_seed).hex()


def _seed_row(lab, old_spell, new_spell, sig_spell, new_pub=None):
    new_pub = new_pub or _new_pub
    good = _ed.sign(
        rotate_name._rotate_payload(lab, _old_pub, new_pub, ISSUED),
        _old_seed, bytes.fromhex(_old_pub)).hex()
    spell = {"clean": lambda s: s, "upper": lambda s: s.upper(),
             "spaced": _spaced, "padded": _padded}
    with core._db_lock, core._db() as conn:
        conn.execute(
            "INSERT INTO name_rotations (name, old_pubkey, new_pubkey,"
            " issued_at, signature, accepted_at) VALUES (?,?,?,?,?,?)",
            (lab, spell[old_spell](_old_pub), spell[new_spell](new_pub),
             ISSUED, spell[sig_spell](good), ACCEPTED))
    return good


_good_valid = _seed_row("rotstrlenvalid", "clean", "clean", "clean")
_seed_row("rotstrlenupper", "upper", "upper", "upper")
_good_mixed = _seed_row("rotstrlenmixed", "clean", "clean", "clean")
_seed_row("rotstrlenmixed", "clean", "clean", "spaced", new_pub=_new2_pub)
_seed_row("rotstrlensigs", "clean", "clean", "spaced")
_seed_row("rotstrlensigp", "clean", "clean", "padded")
_seed_row("rotstrlenoldp", "spaced", "clean", "clean")
_seed_row("rotstrlennewp", "clean", "spaced", "clean")

with TestClient(cyber.app) as c:
    r = c.get("/api/v1/names/rotstrlenvalid/rotations")
    check("valid -> 200", r.status_code == 200, r.status_code)
    if r.status_code == 200:
        rots = r.json().get("rotations", [])
        check("valid one row", len(rots) == 1, repr(rots)[:160])
        if rots:
            check("valid byte-exact", rots[0].get("signature") == _good_valid
                  and rots[0].get("old_pubkey") == _old_pub
                  and rots[0].get("new_pubkey") == _new_pub,
                  repr(rots[0])[:160])
            check("valid self-verifies", rotate_name.verify_rotation(
                {"name": "rotstrlenvalid", **rots[0]}) is None)
    r = c.get("/api/v1/names/rotstrlenupper/rotations")
    check("uppercase sig+pubs -> 200", r.status_code == 200, r.status_code)
    r = c.get("/api/v1/names/rotstrlenmixed/rotations")
    check("mixed -> 200", r.status_code == 200, r.status_code)
    if r.status_code == 200:
        rots = r.json().get("rotations", [])
        check("mixed serves only the clean row",
              len(rots) == 1 and rots[0].get("signature") == _good_mixed,
              repr(rots)[:200])
    for lab in ("rotstrlensigs", "rotstrlensigp",
                "rotstrlenoldp", "rotstrlennewp"):
        r = c.get(f"/api/v1/names/{lab}/rotations")
        check(f"{lab} -> 404", r.status_code == 404,
              f"{r.status_code} {r.text[:120]}")

print(f"---\n{CASES['passed']} passed, {CASES['failed']} failed")
sys.exit(1 if CASES["failed"] else 0)
