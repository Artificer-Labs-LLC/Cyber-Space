#!/usr/bin/env python3
"""resolver client port agreement + visibility belt (primitives 2+6).

client._default_port used isdigit(): " 5354 " -> 5353 while the daemon
listened on 5354, "0" -> 0 while the daemon clamped to 1, "-5" -> 5353
while the daemon clamped to 1 — the client queried a port no daemon
was on, in silence. _default_port now mirrors daemon._env_int exactly
(this belt asserts agreement over a corpus, never a copied expectation)
and _client_port_warnings names set-but-ineffective values in main().

Run from the repo root:  ./venv/bin/python hidden_files/client-port-visibility-belt-test.py
"""
import os
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from resolver import client, daemon  # noqa: E402

_VAR = "CYBERNET_RESOLVER_PORT"
_CORPUS = ["", "5353", "5354", " 5354 ", "0", "-5", "1", "65535",
           "99999", "banana", "0x35", "53.53", "+5354"]


class TestClientPort(unittest.TestCase):
    def setUp(self):
        self._old = os.environ.get(_VAR)

    def tearDown(self):
        if self._old is None:
            os.environ.pop(_VAR, None)
        else:
            os.environ[_VAR] = self._old

    def _set(self, value):
        if value is None:
            os.environ.pop(_VAR, None)
        else:
            os.environ[_VAR] = value
        return client._default_port(), client._client_port_warnings()

    def test_agrees_with_daemon_over_corpus(self):
        for raw in _CORPUS:
            port, _ = self._set(raw)
            self.assertEqual(
                port, daemon._env_int(_VAR, 5353, floor=1), raw)

    def test_unset_and_valid_are_silent(self):
        self.assertEqual(self._set(None), (5353, []))
        self.assertEqual(self._set("5354"), (5354, []))
        self.assertEqual(self._set(" 5354 "), (5354, []))

    def test_non_integer_warns_without_echoing_value(self):
        port, warns = self._set("banana")
        self.assertEqual(port, 5353)
        self.assertEqual(len(warns), 1)
        self.assertIn(_VAR, warns[0])
        self.assertNotIn("banana", warns[0])

    def test_below_floor_warns_and_clamps(self):
        for raw in ("0", "-5"):
            port, warns = self._set(raw)
            self.assertEqual(port, 1)
            self.assertEqual(len(warns), 1)
            self.assertIn("below the 1 floor", warns[0])

    def test_above_65535_warns(self):
        port, warns = self._set("99999")
        self.assertEqual(port, 99999)
        self.assertEqual(len(warns), 1)
        self.assertIn("above 65535", warns[0])

    def test_main_wires_the_warning(self):
        src = open(os.path.join(REPO, "resolver", "client.py")).read()
        self.assertIn("_client_port_warnings()", src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
