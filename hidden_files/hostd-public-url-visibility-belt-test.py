#!/usr/bin/env python3
"""hostd public-URL visibility belt (primitives 3+6).

core._reach_build silently drops a malformed CYBERNET_PUBLIC_URL: the
direct strategy vanishes, the descriptor carries relay only (or no
honest reach and announce fails generically), and the operator who set
the var believes direct hosting is on. _public_url_warnings names the
mistake at startup, mirroring _relay_warnings: unset is silent (a
choice), valid is silent, set-but-invalid warns and never echoes the
value itself.

Run from the repo root:  ./venv/bin/python hidden_files/hostd-public-url-visibility-belt-test.py
"""
import os
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from resolver import host  # noqa: E402


class TestPublicUrlWarnings(unittest.TestCase):
    def setUp(self):
        self._old = dict(os.environ)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._old)

    def _warns(self, value):
        if value is None:
            os.environ.pop("CYBERNET_PUBLIC_URL", None)
        else:
            os.environ["CYBERNET_PUBLIC_URL"] = value
        return host._public_url_warnings()

    def test_unset_is_silent(self):
        self.assertEqual(self._warns(None), [])

    def test_empty_is_silent(self):
        self.assertEqual(self._warns(""), [])

    def test_valid_public_url_is_silent(self):
        self.assertEqual(self._warns("https://8.8.8.8:8471"), [])

    def test_malformed_url_warns_and_names_var(self):
        warns = self._warns("not a url")
        self.assertEqual(len(warns), 1)
        self.assertIn("CYBERNET_PUBLIC_URL", warns[0])

    def test_loopback_url_warns(self):
        warns = self._warns("http://127.0.0.1:8471")
        self.assertEqual(len(warns), 1)
        self.assertIn("CYBERNET_PUBLIC_URL", warns[0])

    def test_warning_never_echoes_the_value(self):
        secret = "https://user: hunter2-token.example.invalid:9999"
        warns = self._warns(secret)
        self.assertEqual(len(warns), 1)
        self.assertNotIn(secret, warns[0])
        self.assertNotIn("hunter2-token", warns[0])

    def test_run_wires_the_warning(self):
        src = open(os.path.join(REPO, "resolver", "host.py")).read()
        self.assertIn("_public_url_warnings()", src)
        self.assertIn("hostd: direct disabled:", src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
