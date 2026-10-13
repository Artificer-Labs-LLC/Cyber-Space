"""dial.plan / resolve_cyberspace agreement belt (primitive 2/3 preview contract).

dial.py is the agent's seat for "how would this name be dialed" — its docstring
promises the daemon dials only what the plan describes. That promise is only
true if the planner's step-5 fallback semantics match the resolver's step 5.
This belt drives BOTH the REAL dial.plan() and the REAL
core.resolve_cyberspace() against the same scripted mirror (fake transport
only; all signatures real Ed25519) and demands agreement.

The two divergences this belt locks:
  1. mismatched-key descriptor: the daemon (resolve_cyberspace step 5) SKIPS
     a descriptor whose node_pubkey != the binding's key and falls to the
     directory scan. The planner must preview that, not veto it with a
     hard exit 1.
  2. directory shape: the real mirror serves {"entries": [...]}; the planner
     must read "entries" like the resolver does, not dead "nodes"/"agents"
     keys that never fire against a real mirror.
  3. cross-name descriptor: a descriptor signed by the RIGHT key but for a
     DIFFERENT name (the name is inside the signed canonical form) must be
     skipped by both seats — a mirror cross-serving it would otherwise
     redirect the dial to the other name's reach.

Step 6 (live verification) is monkeypatched at the transport edge only
(_resolve_peer_get_json + _fed_env.verify_envelope) — the belt's subject is
step-5 strategy/fallback agreement, and the reach-serve-dial belt already
proves resolve_cyberspace's own step-5 fallbacks against real signatures.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/dial-plan-resolve-agreement-belt-test.py
"""
import os
import secrets
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.expanduser("~/workspace/cybernet"))

import core  # noqa: E402
import dial  # noqa: E402

MIRROR = "http://127.0.0.1:8471"


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S+00:00")


def _name_key():
    priv = secrets.token_hex(32)
    pub = core._fed_ed25519.publickey(bytes.fromhex(priv)).hex()
    return priv, pub


def _live_times():
    now = datetime.now(timezone.utc)
    # Lifetime under the 365-day cap: 1h ago + 365d would be 365d1h.
    return _iso(now - timedelta(hours=1)), _iso(now + timedelta(days=364))


def _binding(label, priv, pub):
    issued, expires = _live_times()
    sig = core._fed_ed25519.sign(
        core._name_claim_payload(label, pub, issued, expires),
        bytes.fromhex(priv), bytes.fromhex(pub)).hex()
    return {"name": label, "node_pubkey": pub, "issued_at": issued,
            "expires_at": expires, "signature": sig}


def _descriptor(label, priv, pub, strategies):
    issued, expires = _live_times()
    return core._reach_mint(priv, pub, label, strategies, issued, expires)


class ScriptedNet:
    """Fake transport for mirror + peer URLs. Real signatures, no network."""

    def __init__(self, mirror_routes, peer_routes):
        self.mirror_routes = mirror_routes
        self.peer_routes = peer_routes
        self.saved_get = core._resolve_get_json
        self.saved_peer = core._resolve_peer_get_json
        self.saved_env = core._fed_env.verify_envelope

    def __enter__(self):
        core._resolve_get_json = lambda url: self.mirror_routes.get(url)
        core._resolve_peer_get_json = lambda url: self.peer_routes.get(url)
        core._fed_env.verify_envelope = lambda env: True
        return self

    def __exit__(self, *exc):
        core._resolve_get_json = self.saved_get
        core._resolve_peer_get_json = self.saved_peer
        core._fed_env.verify_envelope = self.saved_env


def _routes(label, binding=None, desc=None, entries=()):
    m = {MIRROR + "/api/v1/node": {"ok": True}}
    if binding is not None:
        m[MIRROR + "/api/v1/names/" + label] = binding
    if desc is not None:
        m[MIRROR + "/api/v1/names/" + label + "/reach"] = desc
    m[MIRROR + "/api/v1/directory"] = {"entries": list(entries), "count": len(entries),
                                       "limit": 200, "cap": None}
    m[MIRROR + "/api/v1/directory?limit=200"] = m[MIRROR + "/api/v1/directory"]
    return m


def _peer_routes(binding):
    # Step-6 live verification answers for the scripted node URLs.
    p = {}
    for host in ("8.8.4.4", "8.8.8.8", "1.1.1.1", "9.9.9.9"):
        base = f"http://{host}:8471"
        p[base + "/fed/ping"] = {"ok": True}
        p[base + "/api/v1/names/" + binding["name"]] = binding
    return p


def _dir_entry(pub, url):
    return {"node_pub": pub, "node_url": url, "direct": True}


class AgreementBelt(unittest.TestCase):
    def setUp(self):
        core._resolve_memo.clear()

    def tearDown(self):
        core._resolve_memo.clear()

    def _both(self, label, mirror_routes, peer_routes):
        with ScriptedNet(mirror_routes, peer_routes):
            code, lines = dial.plan(label + ".cyberspace", MIRROR)
            result = core.resolve_cyberspace(label + ".cyberspace", MIRROR)
        return code, lines, result

    def test_descriptor_direct_agrees(self):
        label = "agreea"
        priv, pub = _name_key()
        b = _binding(label, priv, pub)
        d = _descriptor(label, priv, pub,
                        [{"kind": "direct", "url": "http://8.8.4.4:8471"}])
        code, lines, result = self._both(label, _routes(label, b, d), _peer_routes(b))
        self.assertEqual(code, 0)
        self.assertTrue(any(l.startswith("plan: direct http://8.8.4.4:8471")
                            for l in lines), lines)
        self.assertIsNotNone(result)
        self.assertEqual(result["node_url"], "http://8.8.4.4:8471")
        self.assertNotIn("via_relay", result)

    def test_fqdn_root_dot_resolves_both_seats(self):
        # The resolver client accepts one trailing FQDN root dot; dial
        # learned to strip it (af3bce0) but resolve_cyberspace did not,
        # so the canonical fully-qualified form read as not-in-zone
        # (None, before any fetch) in the daemon while the planner
        # previewed a dial for it. Both seats must resolve it.
        label = "agreefqdn"
        priv, pub = _name_key()
        b = _binding(label, priv, pub)
        d = _descriptor(label, priv, pub,
                        [{"kind": "direct", "url": "http://8.8.4.4:8471"}])
        with ScriptedNet(_routes(label, b, d), _peer_routes(b)):
            code, lines = dial.plan(label + ".cyberspace.", MIRROR)
            result = core.resolve_cyberspace(label + ".cyberspace.", MIRROR)
        self.assertEqual(code, 0, lines)
        self.assertIsNotNone(result)
        self.assertEqual(result["name"], label)
        self.assertEqual(result["node_url"], "http://8.8.4.4:8471")

    def test_double_root_dot_is_silence_both_seats(self):
        # Only one root dot is stripped; a second leaves a trailing
        # dot, so the address is still not in .cyberspace.
        label = "agreeddot"
        priv, pub = _name_key()
        b = _binding(label, priv, pub)
        d = _descriptor(label, priv, pub,
                        [{"kind": "direct", "url": "http://8.8.4.4:8471"}])
        with ScriptedNet(_routes(label, b, d), _peer_routes(b)):
            code, _lines = dial.plan(label + ".cyberspace..", MIRROR)
            result = core.resolve_cyberspace(label + ".cyberspace..", MIRROR)
        self.assertEqual(code, 1)
        self.assertIsNone(result)

    def test_mismatched_descriptor_falls_to_directory(self):
        # Descriptor signed by a STRANGER key (valid signature, live): the
        # daemon skips it and scans the directory; the plan must say the
        # same instead of vetoing with exit 1.
        label = "agreeb"
        k1p, k1 = _name_key()
        k2p, k2 = _name_key()
        b = _binding(label, k1p, k1)
        d = _descriptor(label, k2p, k2,
                        [{"kind": "direct", "url": "http://8.8.8.8:8471"}])
        entries = [_dir_entry(k1, "http://1.1.1.1:8471")]
        code, lines, result = self._both(label, _routes(label, b, d, entries),
                                         _peer_routes(b))
        self.assertEqual(code, 0, lines)
        self.assertTrue(any("plan: direct http://1.1.1.1:8471" in l
                            for l in lines), lines)
        self.assertTrue(any("different key" in l for l in lines), lines)
        self.assertIsNotNone(result)
        self.assertEqual(result["node_url"], "http://1.1.1.1:8471")

    def test_mismatched_descriptor_no_directory_is_silence(self):
        label = "agreec"
        k1p, k1 = _name_key()
        k2p, k2 = _name_key()
        b = _binding(label, k1p, k1)
        d = _descriptor(label, k2p, k2,
                        [{"kind": "direct", "url": "http://8.8.8.8:8471"}])
        code, lines, result = self._both(label, _routes(label, b, d), _peer_routes(b))
        self.assertEqual(code, 3, lines)  # silent host, never a guess
        self.assertIsNone(result)

    def test_cross_name_descriptor_is_silence_both_seats(self):
        # Descriptor signed by the binding's own key but for a different
        # name: both seats skip it; with no directory entry the name is
        # a silent host (dial exit 3, resolver None), never a redirect
        # to the other name's direct URL.
        label = "agreef"
        priv, pub = _name_key()
        b = _binding(label, priv, pub)
        d = _descriptor("othername", priv, pub,
                        [{"kind": "direct", "url": "http://8.8.4.4:8471"}])
        code, lines, result = self._both(label, _routes(label, b, d), _peer_routes(b))
        self.assertEqual(code, 3, lines)
        self.assertTrue(any("different name" in l for l in lines), lines)
        self.assertIsNone(result)

    def test_unparseable_issued_at_agrees_absent(self):
        # A signer can sign a garbage issued_at and pass signature
        # verification; the resolver's step 4 parses issued_at and reads
        # the row as absent. The planner must agree (exit 1), not
        # preview a direct dial the resolver would never make.
        label = "agreee"
        priv, pub = _name_key()
        _, expires = _live_times()
        sig = core._fed_ed25519.sign(
            core._name_claim_payload(label, pub, "not-a-time", expires),
            bytes.fromhex(priv), bytes.fromhex(pub)).hex()
        b = {"name": label, "node_pubkey": pub, "issued_at": "not-a-time",
             "expires_at": expires, "signature": sig}
        d = _descriptor(label, priv, pub,
                        [{"kind": "direct", "url": "http://8.8.4.4:8471"}])
        code, lines, result = self._both(label, _routes(label, b, d), _peer_routes(b))
        self.assertEqual(code, 1, lines)
        self.assertIsNone(result)

    def test_directory_entries_shape_resolves(self):
        # No descriptor at all; the directory carries the name-key entry in
        # the REAL "entries" shape. The planner must read it.
        label = "agreed"
        priv, pub = _name_key()
        b = _binding(label, priv, pub)
        entries = [_dir_entry(pub, "http://9.9.9.9:8471")]
        code, lines, result = self._both(label, _routes(label, b, None, entries),
                                         _peer_routes(b))
        self.assertEqual(code, 0, lines)
        self.assertTrue(any("plan: direct http://9.9.9.9:8471" in l
                            for l in lines), lines)
        self.assertTrue(any("legacy directory entry" in l for l in lines), lines)
        self.assertIsNotNone(result)
        self.assertEqual(result["node_url"], "http://9.9.9.9:8471")


if __name__ == "__main__":
    unittest.main(verbosity=2)
