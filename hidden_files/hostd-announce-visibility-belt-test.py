#!/usr/bin/env python3
"""hostd announce-visibility belt (primitives 3+6).

resolver/host.py run() discarded announce_once's bool: a hostd whose
env key does not control the hosted name (wrong-name env, stale
pre-rotation installed env) announced into the void forever — systemd
"active", name dark, zero output. _announce_note speaks on TRANSITIONS
only: first result and every change; steady states stay silent so the
log is a signal, not a heartbeat.

Run from the repo root:  ./venv/bin/python hidden_files/hostd-announce-visibility-belt-test.py
"""
import os
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from resolver import host  # noqa: E402


class TestAnnounceNote(unittest.TestCase):
    def test_first_success_speaks_accepted(self):
        note = host._announce_note(None, True, "alice")
        self.assertIn("alice.cyberspace accepted", note)
        self.assertIn("reachable", note)

    def test_first_failure_warns_not_reachable(self):
        note = host._announce_note(None, False, "alice")
        self.assertIn("WARNING", note)
        self.assertIn("alice.cyberspace NOT accepted", note)
        self.assertIn("NOT reachable", note)
        # never pins one cause — the bool cannot distinguish them
        self.assertIn("does not control this name", note)

    def test_success_to_failure_warns_going_dark(self):
        note = host._announce_note(True, False, "alice")
        self.assertIn("WARNING", note)
        self.assertIn("going dark", note)

    def test_failure_to_success_speaks_recovery(self):
        note = host._announce_note(False, True, "alice")
        self.assertIn("accepted again", note)
        self.assertNotIn("WARNING", note)

    def test_steady_success_is_silent(self):
        self.assertIsNone(host._announce_note(True, True, "alice"))

    def test_steady_failure_is_silent(self):
        self.assertIsNone(host._announce_note(False, False, "alice"))

    def test_note_names_the_label(self):
        note = host._announce_note(None, False, "willowmint")
        self.assertIn("willowmint.cyberspace", note)

    def test_run_loop_wires_the_note(self):
        src = open(os.path.join(REPO, "resolver", "host.py")).read()
        self.assertIn("_announce_note(last_ok, ok_now, name)", src)
        self.assertIn("last_ok = ok_now", src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
