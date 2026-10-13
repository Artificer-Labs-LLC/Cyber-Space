#!/usr/bin/env python3
"""Belt test for rotate_name.py bounded hostd-env reads.

Before this tick both env seats loaded the hostd env via read_text()
unbounded: promote's staging-env refresh (home/hostd/<label>.env) and
_installed_env_note's read-only check of the installed env. An env file
is a handful of KEY=value lines. _read_env_text now reads at most
_ENV_MAX+1 chars and returns None on oversize; each seat maps that to
its own not-touched warning, never parsing or writing the file.

Checks (library calls, temp home, no network):
  oversize staging env -> promote succeeds, env untouched, note warns
  oversize installed env -> note warns exceeds, never a key verdict
  exactly-at-cap staging env holding old key -> refreshed byte-exact
  valid installed env holding old key -> unchanged OLD-key warning

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/rotate-env-size-belt-test.py
"""
import json, os, sys, tempfile
from pathlib import Path
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)
import rotate_name
from fed.ed25519 import publickey
CAP = rotate_name._ENV_MAX if hasattr(rotate_name, "_ENV_MAX") else 65536
OLD = bytes(range(32)); NEW = bytes(range(32, 64))
PASSED = FAILED = 0
def check(name, cond):
    global PASSED, FAILED
    if cond: PASSED += 1; print(f"  ok: {name}")
    else: FAILED += 1; print(f"  FAIL: {name}")
def home_with(env_text=None):
    home = Path(tempfile.mkdtemp())
    rec = rotate_name.mint_rotation("foo", OLD, publickey(NEW).hex())
    (home / "foo-rotate.json").write_text(json.dumps(rec))
    (home / "foo-name.key.next").write_text(NEW.hex())
    (home / "foo-name.key").write_text(OLD.hex())
    if env_text is not None:
        (home / "hostd").mkdir()
        (home / "hostd" / "foo.env").write_text(env_text)
    return home
def env_body(total=None):
    body = f"CYBERNET_HOSTED_NAME=foo\nCYBERNET_NAME_PRIVKEY={OLD.hex()}\n"
    return body + "#" + "x" * (total - len(body) - 1) if total else body
# oversize staging env
big = env_body(CAP + 500)
home = home_with(big)
ok, msg = rotate_name.promote_rotation("foo", home, installed_env=home / "nope.env")
check("promote oversize staging env succeeds", ok is True)
check("promote oversize staging env warns exceeds", "exceeds" in msg and "NOT touched" in msg)
check("oversize staging env untouched", (home / "hostd" / "foo.env").read_text() == big)
# oversize installed env
p = Path(tempfile.mkdtemp()) / "hostd.env"; p.write_text(big)
note = rotate_name._installed_env_note(p, OLD.hex(), NEW.hex(), "foo")
check("installed oversize warns exceeds", "exceeds" in note and "check its" in note)
check("installed oversize no key verdict", "OLD key" not in note and "already holds" not in note)
# at-cap staging env refreshed
home = home_with(env_body(CAP))
ok, msg = rotate_name.promote_rotation("foo", home, installed_env=home / "nope.env")
check("at-cap staging env promote succeeds", ok is True)
check("at-cap staging env refreshed", NEW.hex() in (home / "hostd" / "foo.env").read_text())
# valid installed env unchanged verdict
p.write_text(env_body())
note = rotate_name._installed_env_note(p, OLD.hex(), NEW.hex(), "foo")
check("valid installed env OLD warning", "still holds the OLD key" in note)
print(f"---\n{PASSED} passed, {FAILED} failed")
sys.exit(1 if FAILED else 0)
