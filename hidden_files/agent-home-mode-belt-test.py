#!/usr/bin/env python3
"""Agent-home dir-mode belt (primitive 4 identity).

The 23:25 tick made name-key FILES born 0600, but mint_name.py created
~/.cyberspace and ~/.cyberspace/hostd with bare mkdir() — 0755 under a
default umask, leaking directory metadata (which names an agent holds)
to every local user. Both dirs must be born 0700, and a 0755 dir left
by an older tick must be REPAIRED, since mkdir(exist_ok=True) silently
keeps the old mode. This belt pins that contract on the real helper.
"""
import inspect
import os
import stat
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import mint_name

PASS = []
FAIL = []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(("PASS " if cond else "FAIL ") + name + (f" — {detail}" if detail and not cond else ""))


old_umask = os.umask(0o022)
try:
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)

        # t1: fresh dir is born 0700 under umask 022
        d1 = td / "home1" / ".cyberspace"
        mint_name._ensure_dir_0700(d1)
        check("fresh dir born 0700", stat.S_IMODE(d1.stat().st_mode) == 0o700,
              oct(stat.S_IMODE(d1.stat().st_mode)))

        # t2: pre-existing 0755 dir (older tick's window) is repaired
        d2 = td / "home2" / ".cyberspace"
        d2.mkdir(parents=True)
        os.chmod(d2, 0o755)
        mint_name._ensure_dir_0700(d2)
        check("pre-existing 0755 dir repaired to 0700",
              stat.S_IMODE(d2.stat().st_mode) == 0o700,
              oct(stat.S_IMODE(d2.stat().st_mode)))

        # t3: repair touches the dir only — contents keep their modes
        d3 = td / "home3" / ".cyberspace"
        d3.mkdir(parents=True)
        os.chmod(d3, 0o755)
        key = d3 / "x-name.key"
        fd = os.open(key, os.O_CREAT | os.O_WRONLY, 0o600)
        os.close(fd)
        mint_name._ensure_dir_0700(d3)
        check("dir chmod does not recurse into files",
              stat.S_IMODE(key.stat().st_mode) == 0o600,
              oct(stat.S_IMODE(key.stat().st_mode)))

        # t4: the parent is the operator's — never touched
        d4 = td / "home4" / ".cyberspace"
        parent = d4.parent
        parent.mkdir(parents=True)
        os.chmod(parent, 0o755)
        mint_name._ensure_dir_0700(d4)
        check("parent mode untouched",
              stat.S_IMODE(parent.stat().st_mode) == 0o755,
              oct(stat.S_IMODE(parent.stat().st_mode)))

        # t5: the hostd env dir (second mint call site) same contract
        d5 = td / "home5" / ".cyberspace"
        mint_name._ensure_dir_0700(d5)
        hd = d5 / "hostd"
        os.chmod(hd.parent, 0o755)  # ensure repair, not inheritance, does the work
        mint_name._ensure_dir_0700(hd)
        check("fresh hostd env dir born 0700", stat.S_IMODE(hd.stat().st_mode) == 0o700,
              oct(stat.S_IMODE(hd.stat().st_mode)))
        os.chmod(hd, 0o755)
        mint_name._ensure_dir_0700(hd)
        check("pre-existing 0755 hostd dir repaired",
              stat.S_IMODE(hd.stat().st_mode) == 0o700,
              oct(stat.S_IMODE(hd.stat().st_mode)))

    # t6: coupling — both mint call sites route through the helper, no bare mkdir remains
    src = inspect.getsource(mint_name)
    check("mint home uses helper", "_ensure_dir_0700(home)" in src)
    check("mint env-dir uses helper", "_ensure_dir_0700(env_dir)" in src)
    check("no bare home.mkdir remains", "home.mkdir(" not in src)
    check("no bare env_dir.mkdir remains", "env_dir.mkdir(" not in src)

    # t7: coupling — the historic genesis script closes the same hole
    gen = (Path(mint_name.__file__).parent / "mint_genesis.py").read_text()
    check("mint_genesis chmods the agent home",
          "os.chmod(KEY_PATH.parent, 0o700)" in gen)
finally:
    os.umask(old_umask)

print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
sys.exit(1 if FAIL else 0)
