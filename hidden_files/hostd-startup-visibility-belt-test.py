#!/usr/bin/env python3
"""hostd startup-visibility belt — resolver/host.py _startup_problems.

Freezes: a refused start is never silent. run() used to speak only
when CYBERNET_MIRROR_URL was unset; a malformed mirror, bad label, or
bad/missing name key (mirror set) exited 2 with zero output. Every
refusal now names the var and the reason — never a secret value.

Run from the repo root:  python3 hidden_files/hostd-startup-visibility-belt-test.py
"""
import os
import subprocess
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from resolver import host  # noqa: E402

GOOD = dict(CYBERNET_HOSTED_NAME="alice",
            CYBERNET_NAME_PRIVKEY="ab" * 32,
            CYBERNET_MIRROR_URL="https://8.8.8.8:8471")


def _clean_env(**overrides):
    env = {k: v for k, v in os.environ.items()
           if not k.startswith("CYBERNET_")}
    env.update(overrides)
    return env


class TestStartupVisibility(unittest.TestCase):
    def setUp(self):
        self._old = dict(os.environ)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._old)

    def _problems(self, **kw):
        os.environ.clear()
        os.environ.update(_clean_env(**kw))
        return host._startup_problems()

    def _run(self, **kw):
        return subprocess.run(
            [sys.executable, "-m", "resolver.host"], cwd=REPO,
            env=_clean_env(**kw), capture_output=True, text=True,
            timeout=60)

    def test_good_config_no_problems(self):
        self.assertEqual(self._problems(**GOOD), [])

    def test_bad_mirror_named(self):
        p = self._problems(**{**GOOD, "CYBERNET_MIRROR_URL": "not a url"})
        self.assertTrue(any("CYBERNET_MIRROR_URL" in x for x in p))

    def test_bad_label_named(self):
        p = self._problems(**{**GOOD, "CYBERNET_HOSTED_NAME": "BAD LABEL!"})
        self.assertTrue(any("CYBERNET_HOSTED_NAME" in x for x in p))

    def test_short_key_named_no_secret_echo(self):
        secret = "cd" * 16
        p = self._problems(**{**GOOD, "CYBERNET_NAME_PRIVKEY": secret})
        self.assertTrue(any("CYBERNET_NAME_PRIVKEY" in x for x in p))
        self.assertNotIn(secret, "\n".join(p))

    def test_missing_key_with_mirror_set_is_loud(self):
        kw = {k: v for k, v in GOOD.items()
              if k != "CYBERNET_NAME_PRIVKEY"}
        r = self._run(**kw)
        self.assertEqual(r.returncode, 2)
        self.assertIn("CYBERNET_NAME_PRIVKEY", r.stderr)

    def test_malformed_mirror_process_is_loud(self):
        r = self._run(**{**GOOD, "CYBERNET_MIRROR_URL": "not a url"})
        self.assertEqual(r.returncode, 2)
        self.assertIn("CYBERNET_MIRROR_URL", r.stderr)

    def test_unset_mirror_wording_kept(self):
        kw = {k: v for k, v in GOOD.items()
              if k != "CYBERNET_MIRROR_URL"}
        r = self._run(**kw)
        self.assertEqual(r.returncode, 2)
        self.assertIn("CYBERNET_MIRROR_URL", r.stderr)

    def test_empty_env_reports_all_three(self):
        p = self._problems()
        self.assertEqual(len(p), 3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
