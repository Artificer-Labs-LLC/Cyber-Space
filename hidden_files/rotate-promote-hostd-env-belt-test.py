#!/usr/bin/env python3
"""rotate --promote <-> hostd env agreement belt (primitives 4+6).

hostd signs reach announces with CYBERNET_NAME_PRIVKEY from the env file
mint_name wrote (~/.cyberspace/hostd/<label>.env), NOT from the name key
file. rotate_name --promote used to swap only the key file: after a
rotation the mirror binding pointed at the NEW key while hostd kept
signing with the OLD one — announces unverifiable, hosted name dark.
This belt pins the fix with the REAL mint_rotation / promote_rotation /
_hostd_env_text / host._config:

  1. pure refresh: old seed line swapped, every other line byte-exact;
     foreign seed and absent line returned untouched.
  2. end-to-end promote: env refreshed to the new seed (0600), and the
     refreshed env parses through host._config as runnable, its privkey
     deriving the record's new_pubkey.
  3. foreign env: promote still succeeds, env NOT touched, summary warns.
  4. no env: promote succeeds, summary says to update hostd manually.

Run from the repo root:  ./venv/bin/python hidden_files/rotate-promote-hostd-env-belt-test.py
"""
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

import mint_name  # noqa: E402
import rotate_name  # noqa: E402
from fed.ed25519 import publickey  # noqa: E402
from resolver import host  # noqa: E402

LABEL = "beltname"
OLD = bytes.fromhex("11" * 32)
NEW = bytes.fromhex("22" * 32)
FOREIGN = "ff" * 32
MIRROR = "http://185.143.228.228:8471"


def _stage_home(home: Path, env_text=None):
    home.mkdir(parents=True, exist_ok=True)
    (home / f"{LABEL}-name.key").write_text(OLD.hex() + "\n")
    (home / f"{LABEL}-name.key.next").write_text(NEW.hex() + "\n")
    record = rotate_name.mint_rotation(LABEL, OLD, publickey(NEW).hex())
    (home / f"{LABEL}-rotate.json").write_text(json.dumps(record) + "\n")
    if env_text is not None:
        env_dir = home / "hostd"
        env_dir.mkdir(parents=True, exist_ok=True)
        (env_dir / f"{LABEL}.env").write_text(env_text)
    return record


class TestRefreshPure(unittest.TestCase):
    def test_updated_preserves_everything_else(self):
        text = mint_name._hostd_env_text(LABEL, OLD.hex(), MIRROR)
        new_text, status = rotate_name._refresh_hostd_env_text(
            text, OLD.hex(), NEW.hex())
        self.assertEqual(status, "updated")
        self.assertIn(f"CYBERNET_NAME_PRIVKEY={NEW.hex()}\n", new_text)
        self.assertEqual(
            new_text.replace(f"CYBERNET_NAME_PRIVKEY={NEW.hex()}",
                             f"CYBERNET_NAME_PRIVKEY={OLD.hex()}"), text)

    def test_foreign_untouched(self):
        text = mint_name._hostd_env_text(LABEL, FOREIGN, MIRROR)
        new_text, status = rotate_name._refresh_hostd_env_text(
            text, OLD.hex(), NEW.hex())
        self.assertEqual(status, "foreign")
        self.assertEqual(new_text, text)

    def test_absent_untouched(self):
        text = "CYBERNET_HOSTED_NAME=beltname\n"
        new_text, status = rotate_name._refresh_hostd_env_text(
            text, OLD.hex(), NEW.hex())
        self.assertEqual(status, "absent")
        self.assertEqual(new_text, text)


class TestPromoteRefreshesEnv(unittest.TestCase):
    def test_promote_refreshes_env_and_hostd_agrees(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            env_text = mint_name._hostd_env_text(LABEL, OLD.hex(), MIRROR)
            record = _stage_home(home, env_text)
            ok, msg = rotate_name.promote_rotation(LABEL, home)
            self.assertTrue(ok, msg)
            self.assertIn("refreshed to the new key", msg)
            env_path = home / "hostd" / f"{LABEL}.env"
            body = env_path.read_text()
            self.assertIn(f"CYBERNET_NAME_PRIVKEY={NEW.hex()}", body)
            self.assertNotIn(OLD.hex(), body)
            self.assertEqual(stat.S_IMODE(env_path.stat().st_mode), 0o600)
            env = {}
            for line in body.splitlines():
                if line and not line.startswith("#") and "=" in line:
                    k, _, v = line.partition("=")
                    env[k.strip()] = v.strip()
            saved = dict(os.environ)
            try:
                os.environ.update(env)
                name, priv, mirror, _r, runnable = host._config()
            finally:
                os.environ.clear()
                os.environ.update(saved)
            self.assertTrue(runnable)
            self.assertEqual(name, LABEL)
            self.assertEqual(publickey(bytes.fromhex(priv)).hex(),
                             record["new_pubkey"].lower())

    def test_promote_foreign_env_warns_and_leaves_it(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            env_text = mint_name._hostd_env_text(LABEL, FOREIGN, MIRROR)
            _stage_home(home, env_text)
            ok, msg = rotate_name.promote_rotation(LABEL, home)
            self.assertTrue(ok, msg)
            self.assertIn("WARNING", msg)
            self.assertEqual(
                (home / "hostd" / f"{LABEL}.env").read_text(), env_text)

    def test_promote_without_env_notes_manual_update(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            _stage_home(home, env_text=None)
            ok, msg = rotate_name.promote_rotation(LABEL, home)
            self.assertTrue(ok, msg)
            self.assertIn("update its", msg)


class TestInstalledEnvNote(unittest.TestCase):
    """install-agent.sh copies the staging env to the installed path
    hostd.service reads; a stale installed copy must be named, never
    silently left behind a 'restart hostd' instruction."""

    def _promote(self, td, installed_text):
        home = Path(td) / "home"
        home.mkdir()
        _stage_home(home, mint_name._hostd_env_text(LABEL, OLD.hex(), MIRROR))
        installed = Path(td) / "hostd.env"
        if installed_text is not None:
            installed.write_text(installed_text)
        ok, msg = rotate_name.promote_rotation(
            LABEL, home, installed_env=installed)
        self.assertTrue(ok, msg)
        return msg, installed

    def test_installed_stale_warns_reinstall_not_restart(self):
        with tempfile.TemporaryDirectory() as td:
            stale = mint_name._hostd_env_text(LABEL, OLD.hex(), MIRROR)
            msg, installed = self._promote(td, stale)
            self.assertIn("still holds the OLD key", msg)
            self.assertIn("will NOT pick up the new key", msg)
            self.assertEqual(installed.read_text(), stale)  # never written

    def test_installed_current_is_confirmed(self):
        with tempfile.TemporaryDirectory() as td:
            msg, _ = self._promote(
                td, mint_name._hostd_env_text(LABEL, NEW.hex(), MIRROR))
            self.assertIn("already holds the new key", msg)

    def test_installed_absent_adds_no_noise(self):
        with tempfile.TemporaryDirectory() as td:
            msg, _ = self._promote(td, None)
            self.assertNotIn("installed hostd env", msg)


if __name__ == "__main__":
    unittest.main(verbosity=2)
