"""Unit tests for the resolver daemon's env config (see docs/RESOLVER.md).

daemon.py's _config() was smoke-tested in prose at the 19:30 tick and never
frozen as a file; the daemon stands on this parsing and bad env must never
crash the zone. All in-process, no sockets — the sandbox blocks UDP sends
and _config() never touches the wire. Importing resolver.daemon pulls in
core.py (clean import, threads only spawn on demand — proven at 19:25).

Frozen behaviors recorded, not all blessed:
  * _parse_upstream() splits on the FIRST colon, so bracketed IPv6 upstreams
    ("[::1]:5353") fall back to 1.1.1.1:53 — the wired-in default, never a
    silent half-parse. If IPv6 upstream is ever wanted, this parser is the
    seam to fix, not the loop.

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
check("upstream: bracketed v6 -> default (documented gap, not silent)",
      _p("[::1]:5353") == D)
check("upstream: bare v6 -> default (documented gap, not silent)", _p("::1") == D)

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

# --- restore caller's env ---

for k, v in SAVED.items():
    if v is None:
        os.environ.pop(k, None)
    else:
        os.environ[k] = v

print(f"\n{CASES['passed']} passed, {CASES['failed']} failed")
sys.exit(1 if CASES["failed"] else 0)
