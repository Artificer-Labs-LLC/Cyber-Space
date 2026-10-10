"""Tests for the dry-run dial planner (dial.py).

Drives the REAL plan(): the REAL core binding re-verification
(_name_binding_verify with real Ed25519 checkvalid), the REAL
descriptor re-verification (_reach_descriptor_verify, descriptors
minted by the REAL core._reach_mint), and a scripted fake mirror that
only stands in for the network (core._resolve_get_json is
monkeypatched — it never raises, only returns None). The exit-code
contract is the contract the agent's seat will run on.

Run: cd ~/workspace/cybernet && ./venv/bin/python -m unittest test_dial
"""

import os
import secrets
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import core  # noqa: E402
import dial  # noqa: E402

MIRROR = "http://127.0.0.1:8471"
LABEL = "dialplan"
ADDR = LABEL + ".cyberspace"


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S+00:00")


def _name_key():
    priv = secrets.token_hex(32)
    pub = core._fed_ed25519.publickey(bytes.fromhex(priv)).hex()
    return priv, pub


class FakeMirror:
    """Scripted mirror: route table of full-URL -> JSON body (None = silent)."""

    def __init__(self, routes: dict):
        self.routes = routes
        self.saved = core._resolve_get_json

    def __enter__(self):
        def fake(url: str):
            return self.routes.get(url)
        core._resolve_get_json = fake
        return self

    def __exit__(self, *exc):
        core._resolve_get_json = self.saved


def _live_times():
    now = datetime.now(timezone.utc)
    return _iso(now - timedelta(hours=1)), _iso(now + timedelta(days=365))


def _fixture(binding=None, desc=None, directory=None, alive=True):
    routes = {}
    if alive:
        routes[MIRROR + "/api/v1/node"] = {"ok": True}
    if binding is not None:
        routes[MIRROR + "/api/v1/names/" + LABEL] = binding
    if desc is not None:
        routes[MIRROR + "/api/v1/names/" + LABEL + "/reach"] = desc
    if directory is not None:
        routes[MIRROR + "/api/v1/directory"] = directory
    return FakeMirror(routes)


def _signed_binding(label, priv, pub, issued_at, expires_at):
    sig = core._fed_ed25519.sign(
        core._name_claim_payload(label, pub, issued_at, expires_at),
        bytes.fromhex(priv), bytes.fromhex(pub)).hex()
    return {"name": label, "node_pubkey": pub, "issued_at": issued_at,
            "expires_at": expires_at, "signature": sig}


class DialPlanTests(unittest.TestCase):
    def test_invalid_label_never_touches_network(self):
        code, lines = dial.plan("bad..label.cyberspace", MIRROR)
        self.assertEqual(code, 1)
        self.assertTrue(lines[0].startswith("name-side:"))

    def test_not_cyberspace_address(self):
        code, _ = dial.plan("example.com", MIRROR)
        self.assertEqual(code, 1)

    def test_silent_mirror_is_exit_2(self):
        with _fixture(alive=False):
            code, lines = dial.plan(ADDR, MIRROR)
        self.assertEqual(code, 2)
        self.assertTrue(lines[0].startswith("mirror:"))

    def test_no_binding_is_name_side(self):
        with _fixture():
            code, lines = dial.plan(ADDR, MIRROR)
        self.assertEqual(code, 1)
        self.assertIn("no binding", lines[0])

    def test_bad_signature_is_refused(self):
        priv, pub = _name_key()
        issued, expires = _live_times()
        binding = _signed_binding(LABEL, priv, pub, issued, expires)
        binding["signature"] = "ff" * 64  # corrupted after signing
        with _fixture(binding=binding):
            code, lines = dial.plan(ADDR, MIRROR)
        self.assertEqual(code, 1)
        self.assertIn("does not verify", lines[0])

    def test_wrong_key_signature_is_refused(self):
        priv, pub = _name_key()
        other_priv, _ = _name_key()
        issued, expires = _live_times()
        binding = _signed_binding(LABEL, other_priv, pub, issued, expires)
        with _fixture(binding=binding):
            code, _ = dial.plan(ADDR, MIRROR)
        self.assertEqual(code, 1)  # signed by a key that is not the named one

    def test_expired_binding_is_absent(self):
        priv, pub = _name_key()
        now = datetime.now(timezone.utc)
        binding = _signed_binding(
            LABEL, priv, pub,
            _iso(now - timedelta(days=400)),
            _iso(now - timedelta(days=365)))
        with _fixture(binding=binding):
            code, lines = dial.plan(ADDR, MIRROR)
        self.assertEqual(code, 1)
        self.assertIn("expired", lines[0])

    def test_direct_plan_from_descriptor(self):
        priv, pub = _name_key()
        issued, expires = _live_times()
        binding = _signed_binding(LABEL, priv, pub, issued, expires)
        desc = core._reach_mint(
            priv, pub, LABEL, [{"kind": "direct", "url": "https://93.184.216.34/"}],
            issued, expires)
        with _fixture(binding=binding, desc=desc):
            code, lines = dial.plan(ADDR, MIRROR)
        self.assertEqual(code, 0)
        self.assertTrue(any(l == "plan: direct https://93.184.216.34"
                            for l in lines), lines)
        self.assertTrue(any(l.startswith("via: name-key-signed") for l in lines))

    def test_malformed_direct_skipped_for_relay(self):
        priv, pub = _name_key()
        issued, expires = _live_times()
        binding = _signed_binding(LABEL, priv, pub, issued, expires)
        relay_pub = secrets.token_hex(32)
        desc = core._reach_mint(
            priv, pub, LABEL,
            [{"kind": "direct", "url": "http://127.0.0.1:9/"},  # loopback: invalid node URL
             {"kind": "relay", "relay": relay_pub,
              "url": "https://93.184.216.35/", "token": "sess-tok-1"}],
            issued, expires)
        with _fixture(binding=binding, desc=desc):
            code, lines = dial.plan(ADDR, MIRROR)
        self.assertEqual(code, 0)
        self.assertTrue(any(l.startswith(f"plan: relay {relay_pub}")
                            for l in lines), lines)
        # the dial credential itself is never printed
        self.assertFalse(any("sess-tok-1" in l for l in lines))

    def test_rendezvous_plan(self):
        priv, pub = _name_key()
        issued, expires = _live_times()
        binding = _signed_binding(LABEL, priv, pub, issued, expires)
        desc = core._reach_mint(
            priv, pub, LABEL,
            [{"kind": "rendezvous", "epoch_len": 600,
              "hold_query": "/relay/hold_query"}],
            issued, expires)
        with _fixture(binding=binding, desc=desc):
            code, lines = dial.plan(ADDR, MIRROR)
        self.assertEqual(code, 0)
        self.assertTrue(any(l.startswith("plan: rendezvous epoch_len=600")
                            for l in lines), lines)

    def test_descriptor_naming_other_key_is_refused(self):
        priv, pub = _name_key()
        other_priv, other_pub = _name_key()
        issued, expires = _live_times()
        binding = _signed_binding(LABEL, priv, pub, issued, expires)
        desc = core._reach_mint(
            other_priv, other_pub, LABEL,
            [{"kind": "direct", "url": "https://evil.example/"}],
            issued, expires)
        with _fixture(binding=binding, desc=desc):
            code, _ = dial.plan(ADDR, MIRROR)
        self.assertEqual(code, 1)

    def test_legacy_directory_fallback(self):
        priv, pub = _name_key()
        issued, expires = _live_times()
        binding = _signed_binding(LABEL, priv, pub, issued, expires)
        directory = {"nodes": [{"node_pub": pub,
                                "node_url": "https://93.184.216.36/"}]}
        with _fixture(binding=binding, directory=directory):
            code, lines = dial.plan(ADDR, MIRROR)
        self.assertEqual(code, 0)
        self.assertTrue(any(l == "plan: direct https://93.184.216.36"
                            for l in lines), lines)
        self.assertTrue(any("legacy directory" in l for l in lines))

    def test_bound_but_silent_host_is_exit_3(self):
        priv, pub = _name_key()
        issued, expires = _live_times()
        binding = _signed_binding(LABEL, priv, pub, issued, expires)
        with _fixture(binding=binding, directory={"nodes": []}):
            code, lines = dial.plan(ADDR, MIRROR)
        self.assertEqual(code, 3)
        self.assertTrue(any("no reach" in l for l in lines), lines)

    def test_malformed_descriptor_reads_as_silent(self):
        priv, pub = _name_key()
        issued, expires = _live_times()
        binding = _signed_binding(LABEL, priv, pub, issued, expires)
        with _fixture(binding=binding, desc={"garbage": True},
                      directory={"nodes": []}):
            code, _ = dial.plan(ADDR, MIRROR)
        self.assertEqual(code, 3)  # no reach, never a guess


if __name__ == "__main__":
    unittest.main()
