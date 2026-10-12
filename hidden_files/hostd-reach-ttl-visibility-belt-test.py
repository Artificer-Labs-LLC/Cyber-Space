#!/usr/bin/env python3
"""hostd reach-TTL visibility belt (primitives 3+6).

core._reach_build parses CYBERNET_REACH_TTL as max(600, int(...)),
falling back to 86400 on a non-integer — both silently. An operator
who set 60, or "1h", believes the descriptor lifetime is what they
typed when a different lifetime is signed and advertised.
_reach_ttl_warnings names each mistake at startup: unset/empty and
any integer >= 600 are silent, and no warning echoes the value.

Run from the repo root:  ./venv/bin/python hidden_files/hostd-reach-ttl-visibility-belt-test.py
"""
import os
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from resolver import host  # noqa: E402

_VAR = "CYBERNET_REACH_TTL"


class TestReachTtlWarnings(unittest.TestCase):
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
        return host._reach_ttl_warnings()

    def test_unset_is_silent(self):
        self.assertEqual(self._warns(), [])

    def test_empty_is_silent_default_by_choice(self):
        self.assertEqual(self._warns(""), [])

    def test_default_value_is_silent(self):
        self.assertEqual(self._warns("86400"), [])

    def test_floor_value_is_silent(self):
        self.assertEqual(self._warns("600"), [])

    def test_valid_value_is_silent(self):
        self.assertEqual(self._warns("3600"), [])

    def test_below_floor_warns_clamped(self):
        warns = self._warns("60")
        self.assertEqual(len(warns), 1)
        self.assertIn("CYBERNET_REACH_TTL", warns[0])
        self.assertIn("600", warns[0])

    def test_negative_warns_clamped(self):
        warns = self._warns("-5")
        self.assertEqual(len(warns), 1)
        self.assertIn("600", warns[0])

    def test_over_cap_warns_clamped(self):
        warns = self._warns(str(400 * 86400))
        self.assertEqual(len(warns), 1)
        self.assertIn("CYBERNET_REACH_TTL", warns[0])
        self.assertIn("31536000", warns[0])

    def test_at_cap_is_silent(self):
        self.assertEqual(self._warns(str(365 * 86400)), [])

    def test_non_integer_warns_default(self):
        warns = self._warns("banana")
        self.assertEqual(len(warns), 1)
        self.assertIn("CYBERNET_REACH_TTL", warns[0])
        self.assertIn("86400", warns[0])

    def test_unit_suffix_warns_default(self):
        warns = self._warns("1h")
        self.assertEqual(len(warns), 1)
        self.assertIn("86400", warns[0])

    def test_run_wires_the_warning(self):
        src = open(os.path.join(REPO, "resolver", "host.py")).read()
        self.assertIn("_reach_ttl_warnings()", src)
        self.assertIn("hostd: reach ttl:", src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
