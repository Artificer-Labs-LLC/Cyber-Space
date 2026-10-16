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
     the loopback spellings (localhost, the whole 127.0.0.0/8
     range, ::1, and the unspecified 0.0.0.0 / ::) all name the
     same node, the inet_aton spellings of an IPv4 address
     (127.1, 2130706433, 0x7f000001, 0177.0.0.1) dial the same
     address as its dotted quad, the IPv4-mapped IPv6 spellings
     ([::ffff:10.0.0.9], [::ffff:0a00:0009]) dial the same IPv4
     address too, and a URL path never does — a node is its
     scheme/host/port, so the same host wearing a path suffix is
     still the claim origin, not a second node. When the
     canonical origin equals the canonical node, the check
     refuses: same-node is not depth (exit 1).
  3. The binding served by the independent node must pass
     verify_name.verify with expect_name="nexus" and the pin:
     self-authenticating signature, live window, pinned key.
  4. The fetch itself must not be redirected. urllib's default
     opener follows 3xx silently, so a node that answers
     /api/v1/names/nexus with a redirect to the claim origin
     would have the ORIGIN's binding verified as if the checked
     node served it — independence lost at the transport layer,
     below every URL comparison. The real fetch therefore uses
     a no-redirect opener: any 3xx is an HTTP error, reads as
     "serves no binding", and the check fails (exit 1).
  5. Independence is judged on the endpoint actually DIALED,
     not only on the spelling: a DNS name is not canonicalized
     by the comparisons above, so a name that resolves to the
     claim origin's address (or to loopback, when the origin
     is loopback) would pass as a foreign node while reaching
     the origin's machine. Both URLs' hosts are therefore
     resolved and their (address, port) endpoint sets compared;
     any intersection refuses (exit 1). A host that does not
     resolve contributes no endpoints — an unresolvable checked
     node then fails at the fetch, as before.

It sends nothing, claims nothing, and writes nothing.
Exit codes: 0 = DEPTH PASS, 1 = refused / not verified,
            2 = usage / bad argument (no verdict).
Usage: ./venv/bin/python nexus_depth_check.py <independent_url> \
         --expect-pubkey <64hex> --origin-url <claim_host_url>
"""

import ipaddress
import json
import os
import socket
import sys
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mint_name as mn  # noqa: E402
import verify_name as vn  # noqa: E402

_LABEL = "nexus"


def _base(url):
    return url.rstrip("/").lower() if isinstance(url, str) else ""


_LOOPBACK_NAMES = {"localhost"}


def _aton_ipv4(host):
    """The IPv4 address a host string DIALS as, or None.

    ipaddress only accepts the dotted-quad spelling, but the
    resolver (getaddrinfo/inet_aton) also accepts the shorthand,
    integer, hex and octal spellings -- 127.1, 2130706433,
    0x7f000001, 0177.0.0.1 all dial 127.0.0.1. inet_aton parses
    exactly those numeric forms and refuses names, so a successful
    parse is the address the fetch would actually reach."""
    try:
        return ipaddress.IPv4Address(socket.inet_aton(host))
    except (OSError, ValueError):
        return None


def _is_loopback_host(host):
    """localhost, any 127.0.0.0/8 address, ::1, an IPv4-mapped form
    of one of those, and the unspecified 0.0.0.0 / :: (which dial
    the local host) all reach the SAME node's machine."""
    if host in _LOOPBACK_NAMES:
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = _aton_ipv4(host)
        if ip is None:
            return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return bool(ip.is_loopback or ip.is_unspecified)


def _canonical(url):
    """Canonical base for the same-node comparison ONLY (the fetch
    still uses _base). Raw-string equality let one node wear two
    spellings — localhost vs 127.0.0.1, :80 vs no port, case, a
    trailing host dot — and pass as its own 'independent' checker.
    Two spellings survived that pass: any other 127/8 address (or
    0.0.0.0) is the same loopback machine as localhost, and the
    path was part of the compare, so the origin wearing a path
    suffix compared unequal to the bare node. A third family
    survived both passes: inet_aton spellings (127.1, 2130706433,
    0x7f000001) are not dotted quads, so ipaddress rejected them
    and they compared as foreign hosts while dialing loopback --
    any aton-parseable host is normalized to the address it
    dials. A fourth family survived all three: an IPv4-mapped
    IPv6 host ([::ffff:10.0.0.9], or its hex form
    [::ffff:0a00:0009]) is not loopback when the mapped address
    is remote, inet_aton refuses it, and it compared as a foreign
    IPv6 host while dialing the plain IPv4 address -- a mapped
    host is normalized to the IPv4 address it dials. A node is
    its scheme/host/port; the path is dropped here entirely.
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
    if _is_loopback_host(host):
        host = "loopback"
    else:
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            ip = None
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            host = str(ip.ipv4_mapped)
        else:
            aton = _aton_ipv4(host)
            if aton is not None:
                host = str(aton)
    if port is None or (scheme, port) in (("http", 80), ("https", 443)):
        port_part = ""
    else:
        port_part = f":{port}"
    return f"{scheme}://{host}{port_part}"


def _resolve(host, port):
    """The addresses a host actually DIALS to, normalized:
    IPv4-mapped forms fold to the IPv4 address, and loopback /
    unspecified addresses fold to one 'loopback' endpoint host
    (the same folding _canonical applies to spellings). Empty
    set when the host does not resolve."""
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except (OSError, UnicodeError):
        return set()
    out = set()
    for info in infos:
        raw = info[4][0]
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError:
            continue
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        out.add("loopback" if ip.is_loopback or ip.is_unspecified
                else str(ip))
    return out


def _endpoints(url, resolve):
    """{(address, effective port)} a URL dials; empty if the URL
    has no host or its host does not resolve."""
    if not isinstance(url, str):
        return set()
    try:
        parts = urllib.parse.urlsplit(url.strip())
        port = parts.port
    except ValueError:
        return set()
    host = (parts.hostname or "").rstrip(".").lower()
    if not host:
        return set()
    if port is None:
        port = 443 if parts.scheme.lower() == "https" else 80
    return {(addr, port) for addr in resolve(host, port)}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect: returning None makes urllib raise
    HTTPError for the 3xx instead of following it. A depth check
    that follows a redirect to the claim origin verifies the
    origin's own answer under the checked node's name."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect())


def _get_json_no_redirect(url, timeout=30.0):
    """mn._get_json's shape (bounded read, dict-or-None) over the
    no-redirect opener, so a 3xx reads as no binding served."""
    try:
        with _OPENER.open(url, timeout=timeout) as resp:
            raw = mn._read_bounded(resp)
            if raw is None:
                return None
            data = json.loads(raw.decode("utf-8"))
            return data if isinstance(data, dict) else None
    except Exception:
        return None


def depth_check(node_url, expect_pubkey, origin_url=None, get=None,
                resolve=None):
    """Return (exit_code, notes). Fetches ONLY from node_url."""
    get = _get_json_no_redirect if get is None else get
    resolve = _resolve if resolve is None else resolve
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
    if _endpoints(origin_url, resolve) & _endpoints(node_url, resolve):
        return 1, ["REFUSED: checked node resolves to the claim "
                   "origin's endpoint — a name that dials the "
                   "origin is not an independent node"]
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
            if i >= len(argv) or argv[i].startswith("--"):
                print(f"refused: {a} needs a value", file=sys.stderr)
                return 2
            if a == "--expect-pubkey":
                expect_pubkey = argv[i]
            else:
                origin_url = argv[i]
        elif a.startswith("--") and "=" in a:
            opt, _, v = a.partition("=")
            if opt not in ("--expect-pubkey", "--origin-url"):
                print(f"refused: unknown argument {a!r}", file=sys.stderr)
                return 2
            if not v:
                print(f"refused: {opt} needs a value", file=sys.stderr)
                return 2
            if opt == "--expect-pubkey":
                expect_pubkey = v
            else:
                origin_url = v
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
