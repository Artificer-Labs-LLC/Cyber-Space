#!/usr/bin/env python3
"""mint_name env <-> resolver.host agreement belt (primitive 6, one-command node).

mint_name.py is the front door: it claims a name and writes the hostd env
file an agent installs as /etc/cybernet-hostd/hostd.env. resolver.host
REFUSES TO START without an active CYBERNET_MIRROR_URL (required, public,
no default). Until this belt, mint wrote that line COMMENTED OUT — a
minted env installed as-is could never start hostd. This belt pins the
agreement using the REAL mint _hostd_env_text and the REAL host._config:

  1. public mirror: the env mint writes parses to exactly three active
     keys (name, name key, mirror), host._config accepts them verbatim
     (runnable, mirror/name/key round-trip).
  2. loopback mirror: written faithfully, host._config still refuses
     (fail-closed public-URL gate — the fix must not weaken hostd).
  3. optional relay/public-URL lines stay commented (never half-filled).

Run from the repo root:  ./venv/bin/python hidden_files/mint-env-hostd-agreement-belt-test.py
"""
import os
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

import mint_name  # noqa: E402
from resolver import host  # noqa: E402

LABEL = "beltname"
PRIV = "ab" * 32
PUBLIC_MIRROR = "http://185.143.228.228:8471"
LOOPBACK_MIRROR = "http://127.0.0.1:8471"


def _parse_active_env(text):
    """systemd EnvironmentFile semantics for our shape: KEY=VALUE lines
    that are not comments."""
    env = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        env[k.strip()] = v.strip()
    return env


class TestMintEnvHostdAgreement(unittest.TestCase):
    def setUp(self):
        self._old = dict(os.environ)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._old)

    def _config_from_env_text(self, text):
        for k in [k for k in os.environ if k.startswith("CYBERNET_")]:
            del os.environ[k]
        os.environ.update(_parse_active_env(text))
        return host._config()

    def test_public_mirror_env_starts_hostd(self):
        text = mint_name._hostd_env_text(LABEL, PRIV, PUBLIC_MIRROR)
        env = _parse_active_env(text)
        self.assertEqual(
            set(env),
            {"CYBERNET_HOSTED_NAME", "CYBERNET_NAME_PRIVKEY",
             "CYBERNET_MIRROR_URL"})
        name, priv, mirror, _refresh, runnable = self._config_from_env_text(text)
        self.assertTrue(runnable)
        self.assertEqual(name, LABEL)
        self.assertEqual(priv, PRIV)
        self.assertEqual(mirror, PUBLIC_MIRROR)

    def test_trailing_slash_mirror_normalised(self):
        text = mint_name._hostd_env_text(LABEL, PRIV, PUBLIC_MIRROR + "/")
        _n, _p, mirror, _r, runnable = self._config_from_env_text(text)
        self.assertTrue(runnable)
        self.assertEqual(mirror, PUBLIC_MIRROR)

    def test_loopback_mirror_still_refused_by_hostd(self):
        text = mint_name._hostd_env_text(LABEL, PRIV, LOOPBACK_MIRROR)
        self.assertEqual(_parse_active_env(text)["CYBERNET_MIRROR_URL"],
                         LOOPBACK_MIRROR)
        _n, _p, _m, _r, runnable = self._config_from_env_text(text)
        self.assertFalse(runnable)

    def test_optional_lines_stay_commented(self):
        text = mint_name._hostd_env_text(LABEL, PRIV, PUBLIC_MIRROR)
        env = _parse_active_env(text)
        for opt in ("CYBERNET_RELAY_URL", "CYBERNET_RELAY_PUBKEY",
                    "CYBERNET_RELAY_TOKEN", "CYBERNET_PUBLIC_URL"):
            self.assertNotIn(opt, env)
            self.assertIn(f"# {opt}=", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
