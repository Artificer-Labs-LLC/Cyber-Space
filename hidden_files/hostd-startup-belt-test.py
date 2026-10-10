#!/usr/bin/env python3
"""hostd startup fail-closed belt — deploy/hostd.service <-> resolver/host.py.

Freezes the startup contract: a hosting daemon without a name, a key,
or a mirror REFUSES TO START (exit 2), never runs half-configured.
Half-filled relay triples degrade to direct-dial LOUDLY (stderr, no
secrets) rather than silently dropping the hold-open intent.

Run from the repo root:  python3 hidden_files/hostd-startup-belt-test.py
"""
import os
import subprocess
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from resolver import host  # noqa: E402


def _clean_env(**overrides):
    env = {k: v for k, v in os.environ.items()
           if not k.startswith("CYBERNET_")}
    env.update(overrides)
    return env


class TestHostdStartup(unittest.TestCase):
    def setUp(self):
        self._old = dict(os.environ)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._old)

    def _config_with(self, **kw):
        os.environ.clear()
        os.environ.update(_clean_env(**kw))
        return host._config()

    def test_empty_env_not_runnable(self):
        name, key, mirror, refresh, ok = self._config_with()
        self.assertFalse(ok)
        self.assertIsNone(mirror)

    def test_bad_label_not_runnable(self):
        os.environ.clear()
        os.environ.update(_clean_env(
            CYBERNET_HOSTED_NAME="BAD LABEL!",
            CYBERNET_NAME_PRIVKEY="ab" * 32))
        self.assertFalse(host._config()[4])

    def test_bad_key_length_not_runnable(self):
        os.environ.clear()
        os.environ.update(_clean_env(
            CYBERNET_HOSTED_NAME="alice",
            CYBERNET_NAME_PRIVKEY="ab" * 16))  # 32 hex chars, not 64
        self.assertFalse(host._config()[4])

    def test_bad_key_nonhex_not_runnable(self):
        os.environ.clear()
        os.environ.update(_clean_env(
            CYBERNET_HOSTED_NAME="alice",
            CYBERNET_NAME_PRIVKEY="zz" * 32))
        self.assertFalse(host._config()[4])

    def test_bad_mirror_not_runnable(self):
        os.environ.clear()
        os.environ.update(_clean_env(
            CYBERNET_HOSTED_NAME="alice",
            CYBERNET_NAME_PRIVKEY="ab" * 32,
            CYBERNET_MIRROR_URL="not a url"))
        name, key, mirror, refresh, ok = host._config()
        self.assertFalse(ok)
        self.assertIsNone(mirror)

    def test_good_config_runnable(self):
        name, key, mirror, refresh, ok = self._config_with(
            CYBERNET_HOSTED_NAME="Alice",  # normalized to lowercase
            CYBERNET_NAME_PRIVKEY="ab" * 32,
            CYBERNET_MIRROR_URL="https://8.8.8.8:8471")
        self.assertTrue(ok)
        self.assertEqual(name, "alice")
        self.assertIsNotNone(mirror)

    def test_config_never_raises_on_garbage(self):
        os.environ.clear()
        os.environ.update(_clean_env(
            CYBERNET_HOSTED_NAME="\x01\x02\x7f",
            CYBERNET_NAME_PRIVKEY="",
            CYBERNET_MIRROR_URL="\x01\x02",
            CYBERNET_HOSTD_REFRESH="banana"))
        try:
            out = host._config()
        except Exception as exc:  # noqa: BLE001
            self.fail(f"_config raised: {exc!r}")
        self.assertEqual(len(out), 5)
        self.assertFalse(out[4])
        # _env_int falls back to the default, never crashes
        self.assertEqual(out[3], 600)

    def test_half_relay_degrades_to_none_with_warnings(self):
        os.environ.clear()
        os.environ.update(_clean_env(
            CYBERNET_RELAY_URL="https://relay.example/",
            CYBERNET_RELAY_TOKEN="demo-token-abc",
        ))
        self.assertIsNone(host._relay_cfg())
        warnings = host._relay_warnings()
        self.assertTrue(warnings)
        # no secret values echoed in the loud warnings
        blob = "\n".join(warnings)
        self.assertNotIn("demo-token-abc", blob)

    def test_relay_token_cap_gates_cfg(self):
        os.environ.clear()
        os.environ.update(_clean_env(
            CYBERNET_RELAY_URL="https://relay.example/",
            CYBERNET_RELAY_PUBKEY="cd" * 32,
            CYBERNET_RELAY_TOKEN="x" * 2000))  # beyond _RELAY_TOKEN_CAP
        self.assertIsNone(host._relay_cfg())

    def test_misconfigured_daemon_exits_2(self):
        p = subprocess.run(
            [sys.executable, "-m", "resolver.host"],
            cwd=REPO, env=_clean_env(),
            capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 2)

    def test_unset_mirror_is_loud(self):
        p = subprocess.run(
            [sys.executable, "-m", "resolver.host"],
            cwd=REPO, env=_clean_env(
                CYBERNET_HOSTED_NAME="alice",
                CYBERNET_NAME_PRIVKEY="ab" * 32),
            capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 2)
        self.assertIn("CYBERNET_MIRROR_URL", p.stderr)

    def test_missing_key_env_file_exits_2(self):
        # the systemd unit's contract: no env file values -> refuse, loud
        p = subprocess.run(
            [sys.executable, "-m", "resolver.host"],
            cwd=REPO, env=_clean_env(CYBERNET_HOSTED_NAME="alice"),
            capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
