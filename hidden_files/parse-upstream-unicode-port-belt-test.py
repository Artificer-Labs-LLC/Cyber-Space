#!/usr/bin/env python3
"""Belt: resolver.daemon._parse_upstream refuses a port spelled in
Unicode digits instead of aliasing it -- and never raises on an
isdigit-but-not-int spelling (primitives 2 resolution + 6 client
daemon).

_parse_upstream gated the port with str.isdigit() and parsed it with
int(): on str, isdigit() matches Unicode decimal digits and int()
parses them, so an Arabic-Indic or fullwidth spelling of 5353 was
accepted as a second spelling of the same upstream port (twin of the
B1 rule: character classes are [0-9], NOT \\d -- core._NODE_URL_RE
b65258c). Worse, isdigit() also accepts characters int() refuses
(superscripts: '²'.isdigit() is True, int('²') raises), so a
superscript port escaped _parse_upstream as a raw ValueError --
through _daemon_config_warnings and _config, both documented
never-crash seats (run() calls _config before serving anything, so
the daemon died on a config value whose documented fate is the
1.1.1.1:53 fallback). Fix: ASCII-only digit gate at the port seat;
valid ASCII ports byte-exact, every non-ASCII spelling falls back.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/parse-upstream-unicode-port-belt-test.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from resolver import daemon  # noqa: E402

CASES = {"passed": 0, "failed": 0}


def check(name, cond, extra=""):
    if cond:
        CASES["passed"] += 1
        print(f"  ok  {name}")
    else:
        CASES["failed"] += 1
        print(f"  FAIL {name} {extra}")


def parses(raw):
    try:
        return daemon._parse_upstream(raw)
    except Exception:
        return None


D = ("1.1.1.1", 53)

check("ascii port parsed byte-exact", parses("10.0.0.2:5353") == ("10.0.0.2", 5353))
check("bracketed v6 ascii port parsed", parses("[::1]:5353") == ("::1", 5353))
check("whitespace-tolerated ascii port parsed",
      parses("  10.0.0.3 : 5354 ") == ("10.0.0.3", 5354))

ARABIC = "٥٣٥٣"      # Arabic-Indic 5353: isdigit() and int() both accept
FULLWIDTH = "５３５３"  # fullwidth 5353: isdigit() and int() both accept
SUPER = "²"          # superscript two: isdigit() True, int() raises
assert int(ARABIC) == 5353 and int(FULLWIDTH) == 5353 and SUPER.isdigit()
check("arabic-indic port -> default", parses(f"10.0.0.1:{ARABIC}") == D)
check("fullwidth port -> default", parses(f"10.0.0.1:{FULLWIDTH}") == D)
check("mixed ascii+unicode port -> default", parses("10.0.0.1:53٥٣") == D)
check("superscript port -> default, no raise", parses(f"10.0.0.1:{SUPER}") == D)
check("bracketed v6 superscript port -> default, no raise",
      parses(f"[::1]:{SUPER}") == D)

# The crash reached the daemon's front door: warnings and _config
# must survive the same spelling and report/fall back, never raise.
os.environ["CYBERNET_UPSTREAM_DNS"] = f"10.0.0.1:{SUPER}"
try:
    warns = daemon._daemon_config_warnings()
    cfg = daemon._config()
    survived = any("CYBERNET_UPSTREAM_DNS" in w for w in warns) and cfg[3] == D
except Exception:
    survived = False
finally:
    os.environ.pop("CYBERNET_UPSTREAM_DNS", None)
check("config warnings + _config survive superscript upstream", survived)

# Controls: existing malformed refusals unchanged.
check("port 0 -> default", parses("10.0.0.5:0") == D)
check("port 99999 -> default", parses("10.0.0.6:99999") == D)

print(f"{CASES['passed']}/{CASES['passed'] + CASES['failed']} passed")
sys.exit(1 if CASES["failed"] else 0)
