#!/usr/bin/env python3
"""Belt test for rotate_name.py --promote: the loop-closing half of
primitive 4 identity.

The rotation loop is mint -> verify -> mirror accept -> read -> chain-walk
-> promote. Promotion used to be a manual `cp` the operator was told to
do — promote_rotation makes it deliberate AND re-verified, refusing unless
every link still holds. 11 checks:

happy-path promotion (atomic swap, .prev audit, 0600, .next consumed),
refusals on: no .next, no record, tampered record signature,
future-dated record (not yet in force), .next seed not the record's
new_pubkey, key file swapped (continuity broken), double promotion,
and the CLI --promote exit codes.
"""
import json
import os
import stat
import sys
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from io import StringIO
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import rotate_name  # noqa: E402
from fed.ed25519 import publickey  # noqa: E402

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


OLD_SEED = bytes.fromhex("aa" * 32)
NEW_SEED = bytes.fromhex("bb" * 32)


def _stage(home, label="rotbind", old=OLD_SEED, new=NEW_SEED, issued=None,
           tamper=None):
    """Stage a minted rotation in home: key file, record, .next."""
    rec = rotate_name.mint_rotation(
        label, old, publickey(new).hex().lower(),
        issued or _iso(datetime.now(timezone.utc)))
    if tamper:
        rec = dict(rec)
        rec["signature"] = tamper
    (home / f"{label}-name.key").write_text(old.hex() + "\n")
    (home / f"{label}-rotate.json").write_text(json.dumps(rec) + "\n")
    (home / f"{label}-name.key.next").write_text(new.hex() + "\n")
    return rec


def _mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


# 1-6. happy path
with tempfile.TemporaryDirectory() as td:
    home = Path(td)
    rec = _stage(home)
    ok, msg = rotate_name.promote_rotation("rotbind", home)
    check("happy-path promotes", ok)
    key = (home / "rotbind-name.key").read_text().strip()
    check("name key file is now the NEW seed", key == NEW_SEED.hex())
    prev = (home / "rotbind-name.key.prev").read_text().strip()
    check(".prev keeps the OLD seed for chain-walking",
          prev == OLD_SEED.hex())
    check(".next is consumed (atomic swap)",
          not (home / "rotbind-name.key.next").exists())
    check("promoted key file is 0600", _mode(home / "rotbind-name.key") == 0o600)
    check(".prev is 0600", _mode(home / "rotbind-name.key.prev") == 0o600)

# 7. no .next -> refuse, point at mint
with tempfile.TemporaryDirectory() as td:
    home = Path(td)
    ok, msg = rotate_name.promote_rotation("rotbind", home)
    check("no .next refuses", not ok and "mint" in msg)

# 8. record missing -> refuse
with tempfile.TemporaryDirectory() as td:
    home = Path(td)
    (home / "rotbind-name.key.next").write_text(NEW_SEED.hex() + "\n")
    ok, msg = rotate_name.promote_rotation("rotbind", home)
    check("missing record refuses", not ok)

# 9. tampered record signature -> refuse
with tempfile.TemporaryDirectory() as td:
    home = Path(td)
    _stage(home, tamper="00" * 64)
    ok, msg = rotate_name.promote_rotation("rotbind", home)
    check("tampered record refuses", not ok and "verify" in msg)

# 10. future-dated record -> not yet in force
with tempfile.TemporaryDirectory() as td:
    home = Path(td)
    future = _iso(datetime.now(timezone.utc) + timedelta(hours=2))
    _stage(home, issued=future)
    ok, msg = rotate_name.promote_rotation("rotbind", home)
    check("future-dated record refuses", not ok and "future" in msg)

# 11. .next seed not the record's new_pubkey -> refuse
with tempfile.TemporaryDirectory() as td:
    home = Path(td)
    _stage(home)
    (home / "rotbind-name.key.next").write_text(("cc" * 32) + "\n")
    ok, msg = rotate_name.promote_rotation("rotbind", home)
    check("foreign .next seed refuses", not ok and "new_pubkey" in msg)

# 12. key file swapped (doesn't derive old_pubkey) -> continuity broken
with tempfile.TemporaryDirectory() as td:
    home = Path(td)
    _stage(home)
    (home / "rotbind-name.key").write_text(("dd" * 32) + "\n")
    ok, msg = rotate_name.promote_rotation("rotbind", home)
    check("swapped key file refuses", not ok and "continuity" in msg)

# 13. double promotion -> refuse (no .next left)
with tempfile.TemporaryDirectory() as td:
    home = Path(td)
    _stage(home)
    ok1, _ = rotate_name.promote_rotation("rotbind", home)
    ok2, msg2 = rotate_name.promote_rotation("rotbind", home)
    check("second promote refuses", ok1 and not ok2)

# 14-15. CLI --promote exit codes (mocked HOME)
with tempfile.TemporaryDirectory() as td:
    home = Path(td)
    cy = home / ".cyberspace"
    cy.mkdir()
    _stage(cy)
    with mock.patch.object(Path, "home", return_value=home):
        buf = StringIO()
        with redirect_stdout(buf), redirect_stderr(StringIO()):
            rc = rotate_name.main(["--promote", "rotbind"])
        check("CLI --promote exits 0", rc == 0 and "promoted" in buf.getvalue())
        with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            rc2 = rotate_name.main(["--promote", "rotbind"])
        check("CLI double promote exits 1", rc2 == 1)

print(f"\n{PASSED} passed, {FAILED} failed")
sys.exit(1 if FAILED else 0)
