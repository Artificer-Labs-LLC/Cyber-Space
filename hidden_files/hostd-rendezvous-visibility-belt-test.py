#!/usr/bin/env python3
"""hostd rendezvous visibility belt (primitives 3+6).

core._reach_build enables rendezvous only on exactly
CYBERNET_RENDEZVOUS=1, advertises the entry only when a relay strategy
is present, and falls back to the frozen epoch_len default on a bad
CYBERNET_RENDEZVOUS_EPOCH_LEN — all silently. An operator who set
"true", or set "1" with no usable relay, or set a custom epoch_len
that is out of bounds, believes derived-point rendezvous is live when
it is not (or not as configured). _rendezvous_warnings names each
mistake at startup: unset and "0" are silent (off by choice), a valid
"1" with a usable relay and an in-bounds epoch_len is silent, and no
warning ever echoes a secret value. An epoch_len set while rendezvous
is off also warns: hold_open derives points under it unconditionally,
but the descriptor never advertises it, so a dialer deriving with
the frozen default never meets the held points.

Run from the repo root:  ./venv/bin/python hidden_files/hostd-rendezvous-visibility-belt-test.py
"""
import os
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from resolver import host  # noqa: E402

_VARS = ("CYBERNET_RENDEZVOUS", "CYBERNET_RENDEZVOUS_EPOCH_LEN",
         "CYBERNET_RELAY_URL", "CYBERNET_RELAY_PUBKEY",
         "CYBERNET_RELAY_TOKEN")

_RELAY = dict(CYBERNET_RELAY_URL="https://8.8.8.8:8471",
              CYBERNET_RELAY_PUBKEY="cd" * 32,
              CYBERNET_RELAY_TOKEN="demo-token-abc")


class TestRendezvousWarnings(unittest.TestCase):
    def setUp(self):
        self._old = dict(os.environ)
        for var in _VARS:
            os.environ.pop(var, None)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._old)

    def _warns(self, **kw):
        for var in _VARS:
            os.environ.pop(var, None)
        os.environ.update(kw)
        return host._rendezvous_warnings()

    def test_unset_is_silent(self):
        self.assertEqual(self._warns(), [])

    def test_zero_is_silent_off_by_choice(self):
        self.assertEqual(self._warns(CYBERNET_RENDEZVOUS="0"), [])

    def test_non_one_value_warns_not_enabled(self):
        warns = self._warns(CYBERNET_RENDEZVOUS="true")
        self.assertEqual(len(warns), 1)
        self.assertIn("CYBERNET_RENDEZVOUS", warns[0])
        self.assertIn("NOT enabled", warns[0])

    def test_enabled_with_usable_relay_is_silent(self):
        self.assertEqual(
            self._warns(CYBERNET_RENDEZVOUS="1", **_RELAY), [])

    def test_enabled_without_relay_warns(self):
        warns = self._warns(CYBERNET_RENDEZVOUS="1")
        self.assertEqual(len(warns), 1)
        self.assertIn("CYBERNET_RENDEZVOUS=1", warns[0])
        self.assertIn("relay", warns[0])
        self.assertIn("will not be advertised", warns[0])

    def test_enabled_with_half_relay_warns(self):
        warns = self._warns(
            CYBERNET_RENDEZVOUS="1",
            CYBERNET_RELAY_URL="https://8.8.8.8:8471")
        self.assertEqual(len(warns), 1)
        self.assertIn("will not be advertised", warns[0])

    def test_valid_epoch_len_is_silent(self):
        self.assertEqual(self._warns(
            CYBERNET_RENDEZVOUS="1", CYBERNET_RENDEZVOUS_EPOCH_LEN="600",
            **_RELAY), [])

    def test_out_of_bounds_epoch_len_warns(self):
        warns = self._warns(
            CYBERNET_RENDEZVOUS="1", CYBERNET_RENDEZVOUS_EPOCH_LEN="30",
            **_RELAY)
        self.assertEqual(len(warns), 1)
        self.assertIn("CYBERNET_RENDEZVOUS_EPOCH_LEN", warns[0])
        self.assertIn("3600", warns[0])

    def test_non_integer_epoch_len_warns(self):
        warns = self._warns(
            CYBERNET_RENDEZVOUS="1",
            CYBERNET_RENDEZVOUS_EPOCH_LEN="banana", **_RELAY)
        self.assertEqual(len(warns), 1)
        self.assertIn("CYBERNET_RENDEZVOUS_EPOCH_LEN", warns[0])

    def test_epoch_len_set_while_unset_warns_not_advertised(self):
        warns = self._warns(CYBERNET_RENDEZVOUS_EPOCH_LEN="600")
        self.assertEqual(len(warns), 1)
        self.assertIn("CYBERNET_RENDEZVOUS_EPOCH_LEN", warns[0])
        self.assertIn("NOT be advertised", warns[0])
        self.assertIn("3600", warns[0])

    def test_epoch_len_set_while_zero_warns_not_advertised(self):
        warns = self._warns(CYBERNET_RENDEZVOUS="0",
                            CYBERNET_RENDEZVOUS_EPOCH_LEN="600")
        self.assertEqual(len(warns), 1)
        self.assertIn("NOT be advertised", warns[0])

    def test_epoch_len_set_with_non_one_warns_twice(self):
        warns = self._warns(CYBERNET_RENDEZVOUS="true",
                            CYBERNET_RENDEZVOUS_EPOCH_LEN="600")
        self.assertEqual(len(warns), 2)
        self.assertIn("NOT enabled", warns[0])
        self.assertIn("NOT be advertised", warns[1])

    def test_bad_epoch_len_while_off_warns_once_not_advertised(self):
        warns = self._warns(CYBERNET_RENDEZVOUS_EPOCH_LEN="30")
        self.assertEqual(len(warns), 1)
        self.assertIn("NOT be advertised", warns[0])

    def test_no_relay_and_bad_epoch_warns_twice(self):
        warns = self._warns(
            CYBERNET_RENDEZVOUS="1", CYBERNET_RENDEZVOUS_EPOCH_LEN="30")
        self.assertEqual(len(warns), 2)

    def test_warnings_never_echo_the_relay_token(self):
        warns = self._warns(
            CYBERNET_RENDEZVOUS="1",
            CYBERNET_RENDEZVOUS_EPOCH_LEN="banana", **_RELAY)
        self.assertEqual(len(warns), 1)
        self.assertNotIn("demo-token-abc", "\n".join(warns))

    def test_run_wires_the_warning(self):
        src = open(os.path.join(REPO, "resolver", "host.py")).read()
        self.assertIn("_rendezvous_warnings()", src)
        self.assertIn("hostd: rendezvous:", src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
