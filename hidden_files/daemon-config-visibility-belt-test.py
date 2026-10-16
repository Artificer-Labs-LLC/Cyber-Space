#!/usr/bin/env python3
"""resolver daemon config visibility belt (primitives 2+6).

daemon._config parses CYBERNET_RESOLVER_PORT / CYBERNET_TTL_CAP via
_env_int and CYBERNET_UPSTREAM_DNS via _parse_upstream — every bad
value falls back silently: a typo'd port listens on 5353, a malformed
upstream forwards all non-zone queries to 1.1.1.1:53 unchosen, a
port above 65535 is honored and the bind fails with no hint why.
CYBERNET_MIRROR_URL is worse: _env_str passes it through verbatim,
so a scheme-less or host-less mirror is never fetched and every
.cyberspace query answers NXDOMAIN while the daemon looks healthy.
CYBERNET_RESOLVER_BIND is passed through the same way, and an
unbindable value raises in run() before the daemon serves anything.
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

_VARS = ("CYBERNET_RESOLVER_PORT", "CYBERNET_TTL_CAP", "CYBERNET_UPSTREAM_DNS",
         "CYBERNET_MIRROR_URL", "CYBERNET_RESOLVER_BIND")


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

    def test_upstream_bracketed_v6_is_silent(self):
        self.assertEqual(
            self._warns(CYBERNET_UPSTREAM_DNS="[::1]:5353"), [])

    def test_upstream_bracketed_v6_bad_port_warns(self):
        warns = self._warns(CYBERNET_UPSTREAM_DNS="[::1]:dns")
        self.assertEqual(len(warns), 1)
        self.assertIn("CYBERNET_UPSTREAM_DNS", warns[0])

    def test_upstream_whitespace_padded_valid_is_silent(self):
        self.assertEqual(
            self._warns(CYBERNET_UPSTREAM_DNS=" 10.0.0.3 : 5354 "), [])

    def test_mirror_loopback_default_is_silent(self):
        self.assertEqual(
            self._warns(CYBERNET_MIRROR_URL="http://127.0.0.1:8471"), [])

    def test_mirror_https_with_host_is_silent(self):
        self.assertEqual(
            self._warns(CYBERNET_MIRROR_URL="https://mirror.example:8443"), [])

    def test_mirror_bare_word_warns_no_echo(self):
        warns = self._warns(CYBERNET_MIRROR_URL="notaurl")
        self.assertEqual(len(warns), 1)
        self.assertIn("CYBERNET_MIRROR_URL", warns[0])
        self.assertIn("NXDOMAIN", warns[0])
        self.assertNotIn("notaurl", warns[0])

    def test_mirror_no_scheme_warns(self):
        warns = self._warns(CYBERNET_MIRROR_URL="127.0.0.1:8471")
        self.assertEqual(len(warns), 1)
        self.assertIn("CYBERNET_MIRROR_URL", warns[0])

    def test_mirror_non_http_scheme_warns(self):
        warns = self._warns(CYBERNET_MIRROR_URL="ftp://mirror.example")
        self.assertEqual(len(warns), 1)
        self.assertIn("CYBERNET_MIRROR_URL", warns[0])

    def test_mirror_undialable_ports_warn(self):
        for bad in ("http://mirror.example:99999", "http://mirror.example:0",
                    "http://mirror.example:abc"):
            warns = self._warns(CYBERNET_MIRROR_URL=bad)
            self.assertEqual(len(warns), 1, bad)
            self.assertIn("CYBERNET_MIRROR_URL", warns[0])
        self.assertEqual(
            self._warns(CYBERNET_MIRROR_URL="http://mirror.example:65535"), [])

    def test_mirror_scheme_without_host_warns(self):
        warns = self._warns(CYBERNET_MIRROR_URL="http://")
        self.assertEqual(len(warns), 1)
        self.assertIn("CYBERNET_MIRROR_URL", warns[0])

    def test_mirror_misspellings_warn(self):
        # Twin of mint_name._valid_mirror / dial.plan: userinfo dials
        # the host after the "@", query/fragment mangles the appended
        # fetch, and an out-of-class host is undialable as written —
        # each warned silent before, while queries NXDOMAINed.
        for bad in ("http://127.0.0.1@evil.example:8471",
                    "http://mirror.example:8471?x=1",
                    "http://mirror.example:8471#frag",
                    "http://x%40evil.example:8471",
                    "http://x\\evil.example:8471",
                    "http://é.example:8471"):
            warns = self._warns(CYBERNET_MIRROR_URL=bad)
            self.assertEqual(len(warns), 1, bad)
            self.assertIn("CYBERNET_MIRROR_URL", warns[0])
            self.assertNotIn(bad, warns[0])
        self.assertEqual(
            self._warns(CYBERNET_MIRROR_URL="http://[::1]:8471"), [])
        self.assertEqual(
            self._warns(CYBERNET_MIRROR_URL="http://mirror.example:8471/prefix"), [])

    def test_mirror_whitespace_control_warns(self):
        # Twin of dial.plan's raw-string gate (ac61d04): interior
        # whitespace/control surviving the outer strip — urlsplit
        # silently strips \t\r\n, a space or \x01 in the path is
        # never fetchable as written — warned silent before.
        for bad in ("http://mirror.example:8471/a b",
                    "http://mirror.example:8471/a\nb",
                    "http://mirror.example:8471/a\tb",
                    "http://mirror.example:8471/\x01x",
                    "http://mirror.example:8471/\x7fx"):
            warns = self._warns(CYBERNET_MIRROR_URL=bad)
            self.assertEqual(len(warns), 1, bad)
            self.assertIn("CYBERNET_MIRROR_URL", warns[0])
            self.assertNotIn(bad, warns[0])
        self.assertEqual(
            self._warns(CYBERNET_MIRROR_URL="http://mirror.example:8471/prefix"), [])

    def test_bind_ipv4_and_wildcard_are_silent(self):
        self.assertEqual(self._warns(CYBERNET_RESOLVER_BIND="127.0.0.1"), [])
        self.assertEqual(self._warns(CYBERNET_RESOLVER_BIND="0.0.0.0"), [])

    def test_bind_hostnames_are_silent(self):
        self.assertEqual(self._warns(CYBERNET_RESOLVER_BIND="localhost"), [])
        self.assertEqual(
            self._warns(CYBERNET_RESOLVER_BIND="resolver-1.example"), [])

    def test_bind_bad_hostname_warns_no_echo(self):
        warns = self._warns(CYBERNET_RESOLVER_BIND="bad host!")
        self.assertEqual(len(warns), 1)
        self.assertIn("CYBERNET_RESOLVER_BIND", warns[0])
        self.assertIn("bind will fail", warns[0])
        self.assertNotIn("bad host!", warns[0])

    def test_bind_invalid_dotted_quad_warns(self):
        warns = self._warns(CYBERNET_RESOLVER_BIND="999.999.1.1")
        self.assertEqual(len(warns), 1)
        self.assertIn("CYBERNET_RESOLVER_BIND", warns[0])
        self.assertNotIn("999.999.1.1", warns[0])

    def test_bind_ipv6_is_silent(self):
        # daemon._bind_family binds AF_INET6 for a v6 literal (bare or
        # bracketed), so a v6 bind is a working configuration now, not
        # the old AF_INET death this belt used to demand a warning for.
        self.assertEqual(self._warns(CYBERNET_RESOLVER_BIND="::1"), [])
        self.assertEqual(self._warns(CYBERNET_RESOLVER_BIND="[::1]"), [])

    def test_bind_bracketed_garbage_warns(self):
        warns = self._warns(CYBERNET_RESOLVER_BIND="[not-an-ip]")
        self.assertEqual(len(warns), 1)
        self.assertIn("CYBERNET_RESOLVER_BIND", warns[0])

    def test_bind_underscore_warns(self):
        warns = self._warns(CYBERNET_RESOLVER_BIND="bad_host")
        self.assertEqual(len(warns), 1)
        self.assertIn("CYBERNET_RESOLVER_BIND", warns[0])

    def test_run_wires_the_warning(self):
        src = open(os.path.join(REPO, "resolver", "daemon.py")).read()
        self.assertIn("_daemon_config_warnings()", src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
