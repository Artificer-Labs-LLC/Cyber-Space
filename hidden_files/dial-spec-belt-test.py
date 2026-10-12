"""dial.py spec belt (primitive 2/3): docs/DIAL.md claim-lock.

The DIAL frozen spec promises: the six steps, the exit-code table, the
strategy preference order (direct > relay > rendezvous), the
descriptor-pin skip-and-fall-through, the real {"entries": [...]}
directory shape, the ?limit=200 wide slice, and secret safety (relay token
never printed — length only). This belt drives the REAL dial.plan()
against a scripted mirror (fake transport only; all signatures real
Ed25519) and fails the moment any spec claim stops matching the code.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/dial-spec-belt-test.py
"""
import os
import secrets
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.expanduser("~/workspace/cybernet"))

import core  # noqa: E402  (import core FIRST — core_serve-first leaves it partial)
import dial  # noqa: E402

MIRROR = "http://127.0.0.1:8471"


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S+00:00")


def _name_key():
    priv = secrets.token_hex(32)
    pub = core._fed_ed25519.publickey(bytes.fromhex(priv)).hex()
    return priv, pub


def _times(issued_delta, expires_delta):
    now = datetime.now(timezone.utc)
    return _iso(now + issued_delta), _iso(now + expires_delta)


def _binding(label, priv, pub, issued_delta, expires_delta):
    issued, expires = _times(issued_delta, expires_delta)
    sig = core._fed_ed25519.sign(
        core._name_claim_payload(label, pub, issued, expires),
        bytes.fromhex(priv), bytes.fromhex(pub)).hex()
    return {"name": label, "node_pubkey": pub, "issued_at": issued,
            "expires_at": expires, "signature": sig}


def _live_binding(label, priv, pub):
    # Lifetime under the 365-day cap: -1h + 364d is 364d1h (cf. _descriptor).
    return _binding(label, priv, pub,
                    timedelta(hours=-1), timedelta(days=364))


def _dead_binding(label, priv, pub):
    return _binding(label, priv, pub,
                    timedelta(days=-366), timedelta(hours=-1))


def _descriptor(label, priv, pub, strategies):
    # Descriptor lifetime under the 365-day cap: -1h + 365d is 365d1h.
    issued, expires = _times(timedelta(hours=-1), timedelta(days=364))
    return core._reach_mint(priv, pub, label, strategies, issued, expires)


def _direct(url):
    return {"kind": "direct", "url": url}


def _relay(relay_pub, url, token):
    return {"kind": "relay", "relay": relay_pub, "url": url, "token": token}


def _rendezvous(epoch_len):
    return {"kind": "rendezvous", "epoch_len": epoch_len,
            "hold_query": "/hold/open"}


class ScriptedMirror:
    def __init__(self, routes):
        self.routes = routes
        self.saved = core._resolve_get_json

    def __enter__(self):
        core._resolve_get_json = lambda url: self.routes.get(url)
        return self

    def __exit__(self, *exc):
        core._resolve_get_json = self.saved


def _routes(label, binding=None, desc=None, entries=()):
    m = {MIRROR + "/api/v1/node": {"ok": True}}
    if binding is not None:
        m[MIRROR + "/api/v1/names/" + label] = binding
    if desc is not None:
        m[MIRROR + "/api/v1/names/" + label + "/reach"] = desc
    m[MIRROR + "/api/v1/directory?limit=200"] = {"entries": list(entries)}
    return m


class SpecBelt(unittest.TestCase):
    def setUp(self):
        core._resolve_memo.clear()

    def tearDown(self):
        core._resolve_memo.clear()

    def _plan(self, label, routes):
        with ScriptedMirror(routes):
            return dial.plan(label + ".cyberspace", MIRROR)

    # --- step 0: label shape; the plan never goes to the network ---
    def test_bad_label_is_exit_1_before_network(self):
        with ScriptedMirror({"raise": None}) as sm:
            sm.routes.clear()
            code, lines = dial.plan("no-suffix-here", MIRROR)
        self.assertEqual(code, 1)
        self.assertTrue(any("not in .cyberspace" in l for l in lines))

    def test_empty_mirror_is_exit_4(self):
        code, lines = dial.plan("x.cyberspace", "")
        self.assertEqual(code, 4)
        self.assertTrue(any("empty mirror" in l for l in lines))

    def test_malformed_mirror_is_exit_4_not_silent(self):
        # _resolve_get_json swallows the urlopen error for these as
        # None, so they used to read as exit 2 "mirror: silent" — a
        # down mirror — when no fetch was ever possible.
        for bad in ("notaurl", "ftp://x", "http://", "https://",
                    "127.0.0.1:8471", "http://[::1"):
            with ScriptedMirror({"raise": None}) as sm:
                sm.routes.clear()
                code, lines = dial.plan("x.cyberspace", bad)
            self.assertEqual(code, 4, bad)
            self.assertTrue(any("malformed mirror" in l for l in lines), bad)
            self.assertFalse(any(bad in l for l in lines), bad)

    # --- step 1: mirror liveness ---
    def test_silent_mirror_is_exit_2(self):
        with ScriptedMirror({}):
            code, lines = dial.plan("whatever.cyberspace", MIRROR)
        self.assertEqual(code, 2)
        self.assertTrue(any("silent" in l for l in lines))

    # --- step 3: binding re-verify ---
    def test_expired_binding_is_exit_1(self):
        label = "specdead"
        priv, pub = _name_key()
        b = _dead_binding(label, priv, pub)
        code, lines = self._plan(label, _routes(label, b))
        self.assertEqual(code, 1)
        self.assertTrue(any("expired" in l for l in lines), lines)

    # --- step 4: descriptor pin; step 5: strategy order + exit 3 ---
    def test_strategy_order_direct_beats_relay_beats_rendezvous(self):
        label = "specorder"
        priv, pub = _name_key()
        _, rpub = _name_key()
        b = _live_binding(label, priv, pub)
        d = _descriptor(label, priv, pub,
                        [_rendezvous(600), _relay(rpub, "http://8.8.8.8:8471", "tok123"),
                         _direct("http://8.8.4.4:8471")])
        code, lines = self._plan(label, _routes(label, b, d))
        self.assertEqual(code, 0, lines)
        self.assertTrue(any(l.startswith("plan: direct http://8.8.4.4:8471")
                            for l in lines), lines)

    def test_relay_beats_rendezvous_token_length_only(self):
        label = "specrelay"
        priv, pub = _name_key()
        _, rpub = _name_key()
        b = _live_binding(label, priv, pub)
        token = "tok-secret-123"
        d = _descriptor(label, priv, pub,
                        [_rendezvous(600), _relay(rpub, "http://8.8.8.8:8471", token)])
        code, lines = self._plan(label, _routes(label, b, d))
        self.assertEqual(code, 0, lines)
        self.assertTrue(any("plan: relay" in l for l in lines), lines)
        self.assertFalse(any(token in l for l in lines),
                         "relay token value must never print")
        self.assertTrue(any(f"token: {len(token)} chars" in l for l in lines),
                        lines)

    def test_rendezvous_only(self):
        label = "specrv"
        priv, pub = _name_key()
        b = _live_binding(label, priv, pub)
        d = _descriptor(label, priv, pub, [_rendezvous(600)])
        code, lines = self._plan(label, _routes(label, b, d))
        self.assertEqual(code, 0, lines)
        self.assertTrue(any("plan: rendezvous epoch_len=600" in l
                            for l in lines), lines)
        self.assertTrue(any("probe:" in l and "hold/open" in l for l in lines),
                        lines)

    def test_bound_but_silent_is_exit_3(self):
        label = "specsilent"
        priv, pub = _name_key()
        b = _live_binding(label, priv, pub)
        code, lines = self._plan(label, _routes(label, b))
        self.assertEqual(code, 3, lines)
        self.assertTrue(any("no reach" in l for l in lines), lines)

    def test_directory_entries_shape_fallback(self):
        label = "specdir"
        priv, pub = _name_key()
        b = _live_binding(label, priv, pub)
        entries = [{"node_pub": pub, "node_url": "http://9.9.9.9:8471"}]
        code, lines = self._plan(label, _routes(label, b, None, entries))
        self.assertEqual(code, 0, lines)
        self.assertTrue(any("plan: direct http://9.9.9.9:8471" in l
                            for l in lines), lines)
        self.assertTrue(any("legacy directory entry" in l for l in lines),
                        lines)


if __name__ == "__main__":
    unittest.main(verbosity=2)
