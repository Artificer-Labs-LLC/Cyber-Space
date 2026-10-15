#!/usr/bin/env python3
"""Depth-check nexus.cyberspace from an INDEPENDENT node, pin-first.

Fourth split step of the Nexus root claim, after nexus_keygen.py
(generation), nexus_preflight.py (readiness) and nexus_claim.py
(claim). nexus_claim verifies the claim by resolving back at the
SAME mirror that accepted it — that proves the mirror stored the
binding, nothing more. Asking a node about itself is the rigged
shape Her Grace named and struck down (2026-10-12): a Depth Test
PASS requires the binding to be fetched from a node that did not
host the claim, and verified against a pubkey pinned OUT-OF-BAND.

This tool enforces that shape:
  1. --expect-pubkey is REQUIRED and must be 64 hex chars. There is
     no default and it is never taken from the fetched binding —
     a pin read off the answer is integrity, not authenticity.
  2. --origin-url (where the claim was hosted) is REQUIRED, like
     the pin: without it the checked node cannot be compared
     against the claim origin, so independence would be asserted
     but never established (exit 2, no verdict). It must be a
     dialable http(s) URL like the node — an unparseable origin
     compares unequal to everything, which is no comparison.
     The comparison is CANONICAL, not raw-string: scheme/host
     case, a trailing host dot, a default port spelled or omitted,
     and the loopback spellings (localhost / 127.0.0.1 / ::1) all
     name the same node. When the canonical origin equals the
     canonical node, the check refuses: same-node is not depth
     (exit 1).
  3. The binding served by the independent node must pass
     verify_name.verify with expect_name="nexus" and the pin:
     self-authenticating signature, live window, pinned key.

It sends nothing, claims nothing, and writes nothing.
Exit codes: 0 = DEPTH PASS, 1 = refused / not verified,
            2 = usage / bad argument (no verdict).
Usage: ./venv/bin/python nexus_depth_check.py <independent_url> \
         --expect-pubkey <64hex> --origin-url <claim_host_url>
"""

import os
import sys
import urllib.parse
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mint_name as mn  # noqa: E402
import verify_name as vn  # noqa: E402

_LABEL = "nexus"


def _base(url):
    return url.rstrip("/").lower() if isinstance(url, str) else ""


_LOOPBACK = {"localhost", "127.0.0.1", "::1"}


def _canonical(url):
    """Canonical base for the same-node comparison ONLY (the fetch
    still uses _base). Raw-string equality let one node wear two
    spellings — localhost vs 127.0.0.1, :80 vs no port, case, a
    trailing host dot — and pass as its own 'independent' checker.
    Unparseable input falls back to its raw base; the caller has
    already validated both URLs, so this only shapes the compare."""
    if not isinstance(url, str):
        return ""
    try:
        parts = urllib.parse.urlsplit(url.strip())
        port = parts.port
    except ValueError:
        return _base(url)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").rstrip(".").lower()
    if host in _LOOPBACK:
        host = "loopback"
    if port is None or (scheme, port) in (("http", 80), ("https", 443)):
        port_part = ""
    else:
        port_part = f":{port}"
    return f"{scheme}://{host}{port_part}{parts.path.rstrip('/')}"


def depth_check(node_url, expect_pubkey, origin_url=None, get=None):
    """Return (exit_code, notes). Fetches ONLY from node_url."""
    get = mn._get_json if get is None else get
    if not mn._valid_mirror(node_url):
        return 2, ["node URL is not a dialable http(s) URL"]
    pin = vn._normalize_expected(expect_pubkey)
    try:
        pin_ok = len(pin) == 64 and len(bytes.fromhex(pin)) == 32
    except ValueError:
        pin_ok = False
    if not pin_ok:
        return 2, ["--expect-pubkey is not a 64-hex name key — "
                   "the pin must come out-of-band, never from the "
                   "binding being checked"]
    if not origin_url:
        return 2, ["refused: --origin-url is required — without the "
                   "claim origin, the checked node cannot be shown "
                   "independent of it, so no verdict is possible"]
    if not mn._valid_mirror(origin_url):
        return 2, ["refused: --origin-url is not a dialable http(s) "
                   "URL — an unparseable origin compares unequal to "
                   "every node, so independence is not established"]
    if _canonical(origin_url) == _canonical(node_url):
        return 1, ["REFUSED: checked node is the claim origin — "
                   "asking a node about itself is not a Depth Test"]
    binding = get(_base(node_url) + f"/api/v1/names/{_LABEL}")
    if not isinstance(binding, dict):
        return 1, [f"independent node serves no binding for "
                   f"{_LABEL}.cyberspace"]
    reason = vn.verify(binding, expect_name=_LABEL, expect_pubkey=pin)
    if reason is not None:
        return 1, [f"DEPTH FAIL: {reason}"]
    return 0, [f"DEPTH PASS: {_LABEL}.cyberspace served by an "
               f"independent node verifies against the pinned key "
               f"{pin[:16]}... (signature, name and live window)"]


def main(argv):
    node_url = None
    expect_pubkey = None
    origin_url = None
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("-h", "--help"):
            print(__doc__.strip())
            return 0
        if a in ("--expect-pubkey", "--origin-url"):
            i += 1
            if i >= len(argv):
                print(f"refused: {a} needs a value", file=sys.stderr)
                return 2
            if a == "--expect-pubkey":
                expect_pubkey = argv[i]
            else:
                origin_url = argv[i]
        elif a.startswith("--"):
            print(f"refused: unknown argument {a!r}", file=sys.stderr)
            return 2
        elif node_url is None:
            node_url = a
        else:
            print("usage: nexus_depth_check.py <independent_url> "
                  "--expect-pubkey <64hex> --origin-url URL",
                  file=sys.stderr)
            return 2
        i += 1
    if node_url is None:
        print("usage: nexus_depth_check.py <independent_url> "
              "--expect-pubkey <64hex> --origin-url URL",
              file=sys.stderr)
        return 2
    if expect_pubkey is None:
        print("refused: --expect-pubkey is required — a depth check "
              "without an out-of-band pin is no check", file=sys.stderr)
        return 2
    if origin_url is None:
        print("refused: --origin-url is required — a depth check "
              "that cannot compare the checked node against the "
              "claim origin cannot establish independence",
              file=sys.stderr)
        return 2
    code, notes = depth_check(node_url, expect_pubkey, origin_url)
    for n in notes:
        print(n, file=sys.stderr if code else sys.stdout)
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
