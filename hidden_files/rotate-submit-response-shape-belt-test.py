#!/usr/bin/env python3
"""Belt test for rotate_name.submit_rotation's mirror-response shape guards.

Every answer submit_rotation reads after the POST is mirror-controlled:
the rotate response body, the resolve-back binding, and the served
rotation chain. Valid JSON that is not an object ('[]', '123') died in
result.get with an AttributeError traceback; a resolve-back node_pubkey
that is not a string (123, null) died in .lower(); a chain whose
rotations value is not a list, whose hops are not objects, or whose hop
fields are not strings died in .get/.strip — instead of the (False,
reason) refusal submit_rotation's contract promises ("never raises on
input"). All shapes now read refused; a well-formed mirror still
submits clean as the control. The mirror is mocked at the _post_form /
_get_json seam (the shape guards are what is under test, not the wire);
the real-route happy path stays covered by rotate-submit-belt-test.py.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/rotate-submit-response-shape-belt-test.py
"""
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import rotate_name  # noqa: E402
from fed.ed25519 import publickey  # noqa: E402

PASSED = FAILED = 0


def check(name, cond, extra=""):
    global PASSED, FAILED
    if cond:
        PASSED += 1
        print(f"  ok: {name}")
    else:
        FAILED += 1
        print(f"  FAIL: {name} {extra}")


LABEL = "shapehop"
OLD = bytes.fromhex("cc" * 32)
NEW = bytes.fromhex("dd" * 32)
OLD_PUB = publickey(OLD).hex().lower()
NEW_PUB = publickey(NEW).hex().lower()
MIRROR = "http://127.0.0.1:8471"


def _submit(post_body, get_map):
    """Stage a valid pending rotation, mock the mirror, submit.

    Returns (ok, msg) or the string 'CRASH ...' if submit raised."""
    with tempfile.TemporaryDirectory() as td:
        home = Path(td)
        rec = rotate_name.mint_rotation(LABEL, OLD, NEW_PUB)
        (home / f"{LABEL}-name.key").write_text(OLD.hex() + "\n")
        (home / f"{LABEL}-rotate.json").write_text(json.dumps(rec) + "\n")
        (home / f"{LABEL}-name.key.next").write_text(NEW.hex() + "\n")
        rotate_name._post_form = (
            lambda url, fields, timeout=30.0: (200, post_body))

        def _get(url, timeout=30.0):
            for suffix, val in get_map.items():
                if url.endswith(suffix):
                    return val
            return None

        rotate_name._get_json = _get
        try:
            return rotate_name.submit_rotation(LABEL, MIRROR, home), rec
        except Exception as exc:  # a crash is the failure this belt hunts
            return f"CRASH {type(exc).__name__}: {exc}", rec


GOOD_RESOLVE = {"node_pubkey": NEW_PUB}

# 1-2. Non-object rotate response bodies read refused, never a traceback.
for body in ("[]", "123"):
    res, _ = _submit(body, {})
    check(f"rotate body {body!r} reads refused, no crash",
          isinstance(res, tuple) and res[0] is False
          and "unparseable rotate response" in res[1], f"res={res!r}")

# 3-4. Non-string resolve-back node_pubkey reads refused.
for bad in (123, None):
    res, _ = _submit('{"status": "rotated"}',
                     {f"/names/{LABEL}": {"node_pubkey": bad}})
    check(f"resolve-back node_pubkey {bad!r} reads refused, no crash",
          isinstance(res, tuple) and res[0] is False
          and "does not resolve to the new key" in res[1], f"res={res!r}")

# 5-7. Malformed served chains read hop-not-seen refused.
for desc, chain in (
        ("rotations is a string", {"rotations": "abc"}),
        ("hop is not an object", {"rotations": [123]}),
        ("hop field is not a string",
         {"rotations": [{"old_pubkey": 123, "new_pubkey": NEW_PUB,
                         "signature": "ab" * 64}]})):
    res, _ = _submit('{"status": "rotated"}',
                     {f"/names/{LABEL}": GOOD_RESOLVE, "/rotations": chain})
    check(f"chain with {desc} reads refused, no crash",
          isinstance(res, tuple) and res[0] is False
          and "hop is not in the served chain" in res[1], f"res={res!r}")

# 8. Control: well-formed rotate + resolve-back + chain submits (True).
with tempfile.TemporaryDirectory() as td:
    home = Path(td)
    rec = rotate_name.mint_rotation(LABEL, OLD, NEW_PUB)
    (home / f"{LABEL}-name.key").write_text(OLD.hex() + "\n")
    (home / f"{LABEL}-rotate.json").write_text(json.dumps(rec) + "\n")
    (home / f"{LABEL}-name.key.next").write_text(NEW.hex() + "\n")
    rotate_name._post_form = (
        lambda url, fields, timeout=30.0: (200, '{"status": "rotated"}'))
    rotate_name._get_json = lambda url, timeout=30.0: (
        GOOD_RESOLVE if url.endswith(f"/names/{LABEL}") else
        {"rotations": [{"old_pubkey": OLD_PUB, "new_pubkey": NEW_PUB,
                        "signature": rec["signature"]}]})
    try:
        res = rotate_name.submit_rotation(LABEL, MIRROR, home)
    except Exception as exc:
        res = f"CRASH {type(exc).__name__}: {exc}"
    check("well-formed mirror still submits (True), no crash",
          isinstance(res, tuple) and res[0] is True, f"res={res!r}")

print(f"\nrotate-submit-response-shape belt: {PASSED}/{PASSED + FAILED}")
sys.exit(1 if FAILED else 0)
