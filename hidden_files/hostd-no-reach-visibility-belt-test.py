#!/usr/bin/env python3
"""hostd no-reach visibility belt (primitives 3+6).

Direct and relay are each optional if the other is set, so a config
with neither usable — a minted env installed as-is (mint_name.py
writes neither), an invalid public URL with no relay, a half-filled
relay triple with no public URL — gives core._reach_build no strategy:
it returns None, announce_once fails forever, and startup said
nothing (the first announce note blamed 'no honest reach' among
three causes). _no_reach_warnings names the real cause at startup:
either strategy usable is silent, neither warns once and names both
options, and no secret value is ever echoed.

Run from the repo root:  ./venv/bin/python hidden_files/hostd-no-reach-visibility-belt-test.py
"""
import os
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from resolver import host  # noqa: E402

REACH_KEYS = (
    "CYBERNET_PUBLIC_URL",
    "CYBERNET_RELAY_URL",
    "CYBERNET_RELAY_PUBKEY",
    "CYBERNET_RELAY_TOKEN",
)
VALID_URL = "https://8.8.8.8:8471"
VALID_PUB = "ab" * 32


class TestNoReachWarnings(unittest.TestCase):
    def setUp(self):
        self._old = dict(os.environ)
        for key in REACH_KEYS:
            os.environ.pop(key, None)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._old)

    def _set_relay(self):
        os.environ["CYBERNET_RELAY_URL"] = VALID_URL
        os.environ["CYBERNET_RELAY_PUBKEY"] = VALID_PUB
        os.environ["CYBERNET_RELAY_TOKEN"] = "tok"

    def test_neither_configured_warns_once(self):
        warns = host._no_reach_warnings()
        self.assertEqual(len(warns), 1)
        self.assertIn("CYBERNET_PUBLIC_URL", warns[0])
        self.assertIn("CYBERNET_RELAY_URL", warns[0])

    def test_valid_direct_is_silent(self):
        os.environ["CYBERNET_PUBLIC_URL"] = VALID_URL
        self.assertEqual(host._no_reach_warnings(), [])
        self.assertTrue(host._direct_strategy_present())

    def test_valid_relay_is_silent(self):
        self._set_relay()
        self.assertEqual(host._no_reach_warnings(), [])

    def test_invalid_direct_and_no_relay_warns(self):
        os.environ["CYBERNET_PUBLIC_URL"] = "http://127.0.0.1:8471"
        self.assertEqual(len(host._no_reach_warnings()), 1)
        self.assertFalse(host._direct_strategy_present())

    def test_half_filled_relay_and_no_direct_warns(self):
        os.environ["CYBERNET_RELAY_URL"] = VALID_URL
        self.assertEqual(len(host._no_reach_warnings()), 1)

    def test_warning_never_echoes_the_token(self):
        os.environ["CYBERNET_RELAY_URL"] = VALID_URL
        os.environ["CYBERNET_RELAY_PUBKEY"] = "not-hex"
        os.environ["CYBERNET_RELAY_TOKEN"] = "hunter2-token"
        warns = host._no_reach_warnings()
        self.assertEqual(len(warns), 1)
        self.assertNotIn("hunter2-token", warns[0])

    def test_run_wires_the_warning(self):
        src = open(os.path.join(REPO, "resolver", "host.py")).read()
        self.assertIn("_no_reach_warnings()", src)
        self.assertIn("hostd: reach:", src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
