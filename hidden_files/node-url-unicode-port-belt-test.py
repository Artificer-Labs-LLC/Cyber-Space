#!/usr/bin/env python3
"""Belt: core._valid_node_url refuses a port spelled in Unicode digits
instead of blessing a URL the dialer cannot dial (primitives 3 hosting
+ 5 discovery).

_NODE_URL_RE gated the port with (\\d{1,5}) and the range check below
it parses the group with int() -- on str patterns \\d matches Unicode
decimal digits and int() parses them, so an Arabic-Indic or fullwidth
spelling of 5353 passed both gates and the URL was stored/forwarded
VERBATIM as a peer's node_url, while urllib's own port parser (the
dialer: urlsplit().port, _post_to_peer_path, gossip, directory joins)
refuses that exact string ("Port could not be cast to integer value")
-- blessed-but-undialable, a second spelling of port 5353 no dial
seat can use. Twin of the B1 rule the timestamp seats already carry
(core_serve._canonical_ts_pattern / verify_name: character classes are
[0-9], NOT \\d, exactly because \\d matches Unicode digits). Fix:
([0-9]{1,5}) at the regex seat; valid ASCII ports byte-exact, the
range gate unchanged.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/node-url-unicode-port-belt-test.py
"""
import os
import sys
import tempfile

os.environ["CYBERNET_DB_DIR"] = tempfile.mkdtemp(prefix="node-url-uniport-")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core  # noqa: E402

CASES = {"passed": 0, "failed": 0}


def check(name, cond, extra=""):
    if cond:
        CASES["passed"] += 1
        print(f"  ok  {name}")
    else:
        CASES["failed"] += 1
        print(f"  FAIL {name} {extra}")


def accepts(url):
    try:
        return core._valid_node_url(url)
    except Exception:
        return None


HOST = "http://185.143.228.228"  # global literal: no DNS in the SSRF gate

check("ascii port accepted byte-exact",
      accepts(f"{HOST}:5353/") == f"{HOST}:5353")
check("no port accepted byte-exact", accepts(f"{HOST}/") == HOST)
check("port 1 accepted", accepts(f"{HOST}:1/") == f"{HOST}:1")
check("port 65535 accepted", accepts(f"{HOST}:65535/") == f"{HOST}:65535")

# Unicode-digit spellings of 5353: int() parses them, \d matches them,
# urllib's port parser refuses the stored string on sight.
ARABIC = "٥٣٥٣"      # Arabic-Indic 5353
FULLWIDTH = "５３５３"  # fullwidth 5353
assert int(ARABIC) == 5353 and int(FULLWIDTH) == 5353
check("arabic-indic port refused", accepts(f"{HOST}:{ARABIC}/") is None)
check("fullwidth port refused", accepts(f"{HOST}:{FULLWIDTH}/") is None)
check("mixed ascii+unicode port refused",
      accepts(f"{HOST}:53٥٣/") is None)

# Controls: the range gate's existing refusals are unchanged.
check("port 99999 refused", accepts(f"{HOST}:99999/") is None)
check("port 0 refused", accepts(f"{HOST}:0/") is None)

print(f"{CASES['passed']}/{CASES['passed'] + CASES['failed']} passed")
sys.exit(1 if CASES["failed"] else 0)
