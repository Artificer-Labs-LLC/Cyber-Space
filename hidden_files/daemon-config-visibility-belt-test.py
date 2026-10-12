#!/usr/bin/env python3
"""resolver daemon config visibility belt (primitives 2+6).

daemon._config parses CYBERNET_RESOLVER_PORT / CYBERNET_TTL_CAP via
_env_int and CYBERNET_UPSTREAM_DNS via _parse_upstream — every bad
value falls back silently: a typo'd port listens on 5353, a malformed
upstream forwards all non-zone queries to 1.1.1.1:53 unchosen, a
port above 65535 is honored and the bind fails with no hint why.
_daemon_config_warnings names each mistake at startup: unset/empty
and valid values are silent, and no warning echoes the value.

Run from the repo root:  ./venv/bin/python hidden_files/daemon-config-visibility-belt-test.py
"""
import os
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from resolver import daemon  # noqa: E402

_VARS = ("CYBERNET_RESOLVER_PORT", "CYBERNET_TTL_CAP", "CYBERNET_UPSTREAM_DNS")


class TestDaemonConfigWarnings(unittest.TestCase):
    def setUp(self):
        self._old = dict(os.environ)
        for v in _VARS:
            os.environ.pop(v, None)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._old)

    def _warns(self, **kw):
        for v in _VARS:
            os.environ.pop(v, None)
        os.environ.update(kw)
        return daemon._daemon_config_warnings()

    def test_unset_is_silent(self):
        self.assertEqual(self._warns(), [])

    def test_valid_values_are_silent(self):
        self.assertEqual(self._warns(
            CYBERNET_RESOLVER_PORT="5354",
            CYBERNET_TTL_CAP="60",
            CYBERNET_UPSTREAM_DNS="9.9.9.9:53"), [])

    def test_explicit_defaults_are_silent(self):
        self.assertEqual(self._warns(
            CYBERNET_RESOLVER_PORT="5353",
            CYBERNET_TTL_CAP="300",
            CYBERNET_UPSTREAM_DNS="1.1.1.1:53"), [])

    def test_port_non_integer_warns_default(self):
        warns = self._warns(CYBERNET_RESOLVER_PORT="banana")
        self.assertEqual(len(warns), 1)
        self.assertIn("CYBERNET_RESOLVER_PORT", warns[0])
        self.assertIn("5353", warns[0])
        self.assertNotIn("banana", warns[0])

    def test_port_zero_warns_floor(self):
        warns = self._warns(CYBERNET_RESOLVER_PORT="0")
        self.assertEqual(len(warns), 1)
        self.assertIn("below the 1 floor", warns[0])

    def test_port_above_65535_warns_bind_will_fail(self):
        warns = self._warns(CYBERNET_RESOLVER_PORT="99999")
        self.assertEqual(len(warns), 1)
        self.assertIn("above 65535", warns[0])

    def test_ttl_non_integer_warns_default(self):
        warns = self._warns(CYBERNET_TTL_CAP="10m")
        self.assertEqual(len(warns), 1)
        self.assertIn("CYBERNET_TTL_CAP", warns[0])
        self.assertIn("300", warns[0])

    def test_ttl_negative_warns_floor(self):
        warns = self._warns(CYBERNET_TTL_CAP="-5")
        self.assertEqual(len(warns), 1)
        self.assertIn("below the 0 floor", warns[0])

    def test_ttl_zero_is_silent(self):
        self.assertEqual(self._warns(CYBERNET_TTL_CAP="0"), [])

    def test_upstream_malformed_warns_default(self):
        warns = self._warns(CYBERNET_UPSTREAM_DNS="notanupstream")
        self.assertEqual(len(warns), 1)
        self.assertIn("CYBERNET_UPSTREAM_DNS", warns[0])
        self.assertIn("1.1.1.1:53", warns[0])
        self.assertNotIn("notanupstream", warns[0])

    def test_upstream_bad_port_warns(self):
        warns = self._warns(CYBERNET_UPSTREAM_DNS="10.0.0.7:dns")
        self.assertEqual(len(warns), 1)
        self.assertIn("CYBERNET_UPSTREAM_DNS", warns[0])

    def test_upstream_whitespace_padded_valid_is_silent(self):
        self.assertEqual(
            self._warns(CYBERNET_UPSTREAM_DNS=" 10.0.0.3 : 5354 "), [])

    def test_run_wires_the_warning(self):
        src = open(os.path.join(REPO, "resolver", "daemon.py")).read()
        self.assertIn("_daemon_config_warnings()", src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
