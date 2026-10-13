"""Unit tests for the resolver daemon's env config (see docs/RESOLVER.md).

daemon.py's _config() was smoke-tested in prose at the 19:30 tick and never
frozen as a file; the daemon stands on this parsing and bad env must never
crash the zone. All in-process, no sockets — the sandbox blocks UDP sends
and _config() never touches the wire. Importing resolver.daemon pulls in
core.py (clean import, threads only spawn on demand — proven at 19:25).

Frozen behaviors recorded, not all blessed:
  * _parse_upstream() accepts bracketed IPv6 upstreams ("[::1]:5353" ->
    ("::1", 5353), stored unbracketed so answer._forward picks AF_INET6);
    a bare IPv6 literal ("::1") has no unambiguous port split and still
    falls back to 1.1.1.1:53 — the wired-in default, never a silent
    half-parse.

Run: cd ~/workspace/cybernet && ./venv/bin/python resolver/test_daemon_config.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from resolver import daemon  # noqa: E402

CASES = {"passed": 0, "failed": 0}

SAVED = {k: os.environ.get(k) for k in (
    "CYBERNET_MIRROR_URL", "CYBERNET_UPSTREAM_DNS", "CYBERNET_RESOLVER_BIND",
    "CYBERNET_RESOLVER_PORT", "CYBERNET_TTL_CAP")}


def check(name, cond, extra=""):
    if cond:
        CASES["passed"] += 1
        print(f"  ok  {name}")
    else:
        CASES["failed"] += 1
        print(f"  FAIL {name} {extra}")


def scrub():
    for k in SAVED:
        os.environ.pop(k, None)


# --- _env_str: unset -> default, set -> stripped, blank -> default ---

scrub()
check("str: unset -> default", daemon._env_str("CYBERNET_MIRROR_URL", "D") == "D")
os.environ["CYBERNET_MIRROR_URL"] = "  http://10.0.0.2:8471  "
check("str: set -> stripped",
      daemon._env_str("CYBERNET_MIRROR_URL", "D") == "http://10.0.0.2:8471")
os.environ["CYBERNET_MIRROR_URL"] = "   "
check("str: blank -> default", daemon._env_str("CYBERNET_MIRROR_URL", "D") == "D")

# --- _env_int: unset -> default, valid -> parsed, floor wins, garbage -> default ---

scrub()
check("int: unset -> default", daemon._env_int("CYBERNET_TTL_CAP", 300) == 300)
os.environ["CYBERNET_TTL_CAP"] = "60"
check("int: valid -> parsed", daemon._env_int("CYBERNET_TTL_CAP", 300) == 60)
os.environ["CYBERNET_TTL_CAP"] = "-5"
check("int: negative -> floor 0", daemon._env_int("CYBERNET_TTL_CAP", 300) == 0)
os.environ["CYBERNET_TTL_CAP"] = "junk"
check("int: garbage -> default", daemon._env_int("CYBERNET_TTL_CAP", 300) == 300)
os.environ["CYBERNET_TTL_CAP"] = ""
check("int: empty -> default", daemon._env_int("CYBERNET_TTL_CAP", 300) == 300)
os.environ["CYBERNET_RESOLVER_PORT"] = "0"
check("int: port 0 -> floor 1", daemon._env_int("CYBERNET_RESOLVER_PORT", 5353, floor=1) == 1)
os.environ["CYBERNET_RESOLVER_PORT"] = "99999"
check("int: port honored high", daemon._env_int("CYBERNET_RESOLVER_PORT", 5353, floor=1) == 99999)
os.environ["CYBERNET_RESOLVER_PORT"] = "0x35"
check("int: hex string -> default", daemon._env_int("CYBERNET_RESOLVER_PORT", 5353, floor=1) == 5353)

# --- _parse_upstream: malformed -> the documented default, never a half-parse ---

_p = daemon._parse_upstream
D = ("1.1.1.1", 53)
check("upstream: '' -> default", _p("") == D)
check("upstream: no port -> default", _p("10.0.0.1") == D)
check("upstream: host:port parsed", _p("10.0.0.2:5353") == ("10.0.0.2", 5353))
check("upstream: whitespace tolerated", _p("  10.0.0.3 : 5354 ") == ("10.0.0.3", 5354))
check("upstream: empty host -> default", _p(":5353") == D)
check("upstream: empty port -> default", _p("10.0.0.4:") == D)
check("upstream: port 0 -> default", _p("10.0.0.5:0") == D)
check("upstream: port 99999 -> default", _p("10.0.0.6:99999") == D)
check("upstream: non-digit port -> default", _p("10.0.0.7:dns") == D)
check("upstream: bracketed v6 parsed, unbracketed", _p("[::1]:5353") == ("::1", 5353))
check("upstream: bracketed v6 no port -> default", _p("[::1]") == D)
check("upstream: bracketed v6 bad port -> default", _p("[::1]:dns") == D)
check("upstream: bracketed v4 -> default", _p("[10.0.0.1]:53") == D)
check("upstream: bracketed garbage -> default", _p("[nope]:53") == D)
check("upstream: bare v6 -> default (no port split)", _p("::1") == D)
for _bad in (None, 123, 1.5, True, b"1.1.1.1:53", ["x"]):
    check(f"upstream: non-str {type(_bad).__name__} -> default", _p(_bad) == D)

# --- _config: full pass — defaults, overrides, malformed all fall back ---

scrub()
check("config: all defaults",
      daemon._config() == ("127.0.0.1", 5353, "http://127.0.0.1:8471", ("1.1.1.1", 53), 300))

os.environ["CYBERNET_MIRROR_URL"] = "http://192.168.1.2:8471"
os.environ["CYBERNET_UPSTREAM_DNS"] = "9.9.9.9:53"
os.environ["CYBERNET_RESOLVER_BIND"] = "0.0.0.0"
os.environ["CYBERNET_RESOLVER_PORT"] = "5354"
os.environ["CYBERNET_TTL_CAP"] = "60"
check("config: overrides honored",
      daemon._config() == ("0.0.0.0", 5354, "http://192.168.1.2:8471", ("9.9.9.9", 53), 60))

os.environ["CYBERNET_MIRROR_URL"] = "  "
os.environ["CYBERNET_UPSTREAM_DNS"] = "notanupstream"
os.environ["CYBERNET_RESOLVER_BIND"] = ""
os.environ["CYBERNET_RESOLVER_PORT"] = "bogus"
os.environ["CYBERNET_TTL_CAP"] = "-10"
check("config: malformed all -> defaults",
      daemon._config() == ("127.0.0.1", 5353, "http://127.0.0.1:8471", ("1.1.1.1", 53), 0))
scrub()

# --- _bind_family: v4/hostname -> AF_INET unchanged, v6 -> AF_INET6 ---

import socket as _socket  # noqa: E402

check("bind_family: ipv4 -> AF_INET",
      daemon._bind_family("127.0.0.1") == (_socket.AF_INET, "127.0.0.1"))
check("bind_family: hostname -> AF_INET",
      daemon._bind_family("localhost") == (_socket.AF_INET, "localhost"))
check("bind_family: bare v6 -> AF_INET6",
      daemon._bind_family("::1") == (_socket.AF_INET6, "::1"))
check("bind_family: bracketed v6 -> AF_INET6 unbracketed",
      daemon._bind_family("[::1]") == (_socket.AF_INET6, "::1"))
check("bind_family: malformed -> AF_INET passthrough",
      daemon._bind_family("bad host!") == (_socket.AF_INET, "bad host!"))
for _bad in (None, 123, 1.5, True, b"::1", ["x"]):
    try:
        daemon._bind_family(_bad)
        check(f"bind_family: non-str {type(_bad).__name__} -> ValueError", False)
    except ValueError:
        check(f"bind_family: non-str {type(_bad).__name__} -> ValueError", True)
    try:
        daemon._bind_target(_bad, 5353)
        check(f"bind_target: non-str {type(_bad).__name__} -> ValueError", False)
    except ValueError:
        check(f"bind_target: non-str {type(_bad).__name__} -> ValueError", True)

# --- _bind_target: literals keep family/target, hostnames resolve ---

from unittest import mock as _mock  # noqa: E402

check("bind_target: ipv4 literal -> AF_INET + literal target",
      daemon._bind_target("127.0.0.1", 5353)
      == (_socket.AF_INET, ("127.0.0.1", 5353)))
check("bind_target: bare v6 literal -> AF_INET6 + literal target",
      daemon._bind_target("::1", 5353)
      == (_socket.AF_INET6, ("::1", 5353)))
check("bind_target: bracketed v6 literal -> AF_INET6 unbracketed",
      daemon._bind_target("[::1]", 5353)
      == (_socket.AF_INET6, ("::1", 5353)))
for _bad_port in (True, False, "5353", 5353.0, None, 0, -1, 65536, b"5353"):
    try:
        daemon._bind_target("127.0.0.1", _bad_port)
        check(f"bind_target: bad port {_bad_port!r} -> ValueError", False)
    except ValueError:
        check(f"bind_target: bad port {_bad_port!r} -> ValueError", True)


def _fake_gai_v6(host, port, family=0, type=0, *a, **k):
    return [(_socket.AF_INET6, _socket.SOCK_DGRAM, 17, "",
             ("::1", port, 0, 0))]


def _fake_gai_v4(host, port, family=0, type=0, *a, **k):
    return [(_socket.AF_INET, _socket.SOCK_DGRAM, 17, "",
             ("127.0.0.1", port))]


with _mock.patch.object(_socket, "getaddrinfo", _fake_gai_v6):
    check("bind_target: v6-only hostname -> AF_INET6 + resolved sockaddr",
          daemon._bind_target("v6only.example", 5353)
          == (_socket.AF_INET6, ("::1", 5353, 0, 0)))
with _mock.patch.object(_socket, "getaddrinfo", _fake_gai_v4):
    check("bind_target: v4 hostname -> AF_INET + resolved sockaddr",
          daemon._bind_target("daemon.example", 5353)
          == (_socket.AF_INET, ("127.0.0.1", 5353)))


def _bad_gai(host, port, family=0, type=0, *a, **k):
    raise _socket.gaierror("no such host")


with _mock.patch.object(_socket, "getaddrinfo", _bad_gai):
    try:
        daemon._bind_target("nope.example", 5353)
        check("bind_target: unresolvable hostname -> gaierror", False)
    except _socket.gaierror:
        check("bind_target: unresolvable hostname -> gaierror", True)

# --- restore caller's env ---

for k, v in SAVED.items():
    if v is None:
        os.environ.pop(k, None)
    else:
        os.environ[k] = v

print(f"\n{CASES['passed']} passed, {CASES['failed']} failed")
sys.exit(1 if CASES["failed"] else 0)
