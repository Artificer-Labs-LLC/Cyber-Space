#!/usr/bin/env python3
"""hostd refresh-cadence visibility belt (primitives 3+6).

_config parses CYBERNET_HOSTD_REFRESH via _env_int(..., 600) as
max(1, int(...)), falling back to 600 on a non-integer — both
silently. An operator who set 0 believing re-announce was disabled
instead gets a 1-second announce loop; one who typed a unit suffix
gets 600. _hostd_refresh_warnings names each mistake at startup:
unset/empty and any integer >= 1 are silent, and no warning echoes
the value.

Run from the repo root:  ./venv/bin/python hidden_files/hostd-refresh-visibility-belt-test.py
"""
import os
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from resolver import host  # noqa: E402

_VAR = "CYBERNET_HOSTD_REFRESH"


class TestHostdRefreshWarnings(unittest.TestCase):
    def setUp(self):
        self._old = dict(os.environ)
        os.environ.pop(_VAR, None)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._old)

    def _warns(self, value=None):
        os.environ.pop(_VAR, None)
        if value is not None:
            os.environ[_VAR] = value
        return host._hostd_refresh_warnings()

    def test_unset_is_silent(self):
        self.assertEqual(self._warns(), [])

    def test_empty_is_silent_default_by_choice(self):
        self.assertEqual(self._warns(""), [])

    def test_default_value_is_silent(self):
        self.assertEqual(self._warns("600"), [])

    def test_floor_value_is_silent(self):
        self.assertEqual(self._warns("1"), [])

    def test_valid_value_is_silent(self):
        self.assertEqual(self._warns("60"), [])

    def test_zero_warns_clamped(self):
        warns = self._warns("0")
        self.assertEqual(len(warns), 1)
        self.assertIn("CYBERNET_HOSTD_REFRESH", warns[0])
        self.assertIn("1", warns[0])

    def test_negative_warns_clamped(self):
        warns = self._warns("-30")
        self.assertEqual(len(warns), 1)
        self.assertIn("below the 1 floor", warns[0])

    def test_non_integer_warns_default(self):
        warns = self._warns("banana")
        self.assertEqual(len(warns), 1)
        self.assertIn("CYBERNET_HOSTD_REFRESH", warns[0])
        self.assertIn("600", warns[0])

    def test_unit_suffix_warns_default(self):
        warns = self._warns("10m")
        self.assertEqual(len(warns), 1)
        self.assertIn("600", warns[0])

    def test_run_wires_the_warning(self):
        src = open(os.path.join(REPO, "resolver", "host.py")).read()
        self.assertIn("_hostd_refresh_warnings()", src)
        self.assertIn("hostd: refresh:", src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
