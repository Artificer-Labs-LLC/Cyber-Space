#!/usr/bin/env python3
"""nexus_depth_check belt: a PASS must be independent and pinned.

Proves, with a throwaway keygen'd key and fake node functions (no
network): a good binding from an independent node passes against
the out-of-band pin; the same node as the claim origin refuses;
a wrong pin, a tampered binding, and a missing binding each fail;
a malformed pin is a usage refusal (exit 2), never a verdict --
and so is a missing or empty claim origin, without which the
checked node's independence was never established at all.
"""
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nexus_claim as nc  # noqa: E402
import nexus_depth_check as nd  # noqa: E402
import nexus_keygen as nk  # noqa: E402
from fed.ed25519 import publickey  # noqa: E402

fails = 0


def _check(cond, why):
    global fails
    if not cond:
        print(f"FAIL: {why}")
        fails += 1


with tempfile.TemporaryDirectory() as td:
    td = Path(td)
    key, bak = td / "nexus-name.key", td / "nexus-name.key.bak"
    _pub, _problems = nk.generate(key, bak)
    _check(not _problems, f"temp keygen failed: {_problems}")
    priv = bytes.fromhex(key.read_text().strip())
    pub = publickey(priv).hex().lower()
    binding = nc.build_binding(priv, 30)
    other = nc.build_binding(bytes.fromhex("11" * 32), 30)

    def serve(b):
        return lambda url: b

    node = "http://10.0.0.9:8471"
    origin = "http://10.0.0.1:8471"

    code, _ = nd.depth_check(node, pub, origin, get=serve(binding))
    _check(code == 0, f"independent + pinned good binding must PASS, got {code}")

    code, _ = nd.depth_check(node, pub, node, get=serve(binding))
    _check(code == 1, "same node as origin must refuse (not depth)")

    code, _ = nd.depth_check(node, pub, None, get=serve(binding))
    _check(code == 2, "missing origin is usage (exit 2): independence "
                      "cannot be established, so a good binding must "
                      "not PASS on an uncompared node")

    code, _ = nd.depth_check(node, pub, "", get=serve(binding))
    _check(code == 2, "empty origin is usage (exit 2), not a verdict")

    code, _ = nd.depth_check(node, pub, "not-a-url", get=serve(binding))
    _check(code == 2, "unparseable origin is usage (exit 2): it "
                      "compares unequal to everything, so a good "
                      "binding must not PASS on an uncompared node")

    code, _ = nd.depth_check("http://127.0.0.1:8471", pub,
                             "http://localhost:8471", get=serve(binding))
    _check(code == 1, "localhost vs 127.0.0.1 is the same node "
                      "(exit 1), not an independent checker")

    code, _ = nd.depth_check("http://10.0.0.9", pub,
                             "http://10.0.0.9:80", get=serve(binding))
    _check(code == 1, "default port spelled vs omitted is the same "
                      "node (exit 1)")

    code, _ = nd.depth_check("http://LOCALHOST.:8471", pub,
                             "http://127.0.0.1:8471", get=serve(binding))
    _check(code == 1, "case + trailing host dot do not make a "
                      "second node (exit 1)")

    code, _ = nd.depth_check("http://127.0.0.1:8472", pub,
                             "http://localhost:8471", get=serve(binding))
    _check(code == 0, "loopback on a DIFFERENT port is a different "
                      "node and must still PASS")

    code, _ = nd.depth_check("http://127.0.0.2:8471", pub,
                             "http://localhost:8471", get=serve(binding))
    _check(code == 1, "any 127/8 address is the same loopback "
                      "machine as localhost (exit 1)")

    code, _ = nd.depth_check("http://0.0.0.0:8471", pub,
                             "http://127.0.0.1:8471", get=serve(binding))
    _check(code == 1, "0.0.0.0 dials the local host: same node "
                      "as 127.0.0.1 (exit 1)")

    code, _ = nd.depth_check("http://127.1:8471", pub,
                             "http://localhost:8471", get=serve(binding))
    _check(code == 1, "127.1 dials 127.0.0.1: inet_aton shorthand "
                      "is the same loopback machine (exit 1)")

    code, _ = nd.depth_check("http://2130706433:8471", pub,
                             "http://127.0.0.1:8471", get=serve(binding))
    _check(code == 1, "2130706433 dials 127.0.0.1: integer form is "
                      "the same loopback machine (exit 1)")

    code, _ = nd.depth_check("http://0x7f000001:8471", pub,
                             "http://localhost:8471", get=serve(binding))
    _check(code == 1, "0x7f000001 dials 127.0.0.1: hex form is the "
                      "same loopback machine (exit 1)")

    code, _ = nd.depth_check("http://167772169:8471", pub,
                             "http://10.0.0.9:8471", get=serve(binding))
    _check(code == 1, "167772169 dials 10.0.0.9: integer form of a "
                      "remote address is that same node (exit 1)")

    code, _ = nd.depth_check("http://127.1:8472", pub,
                             "http://localhost:8471", get=serve(binding))
    _check(code == 0, "inet_aton loopback on a DIFFERENT port is a "
                      "different node and must still PASS")

    code, _ = nd.depth_check("http://[::ffff:10.0.0.9]:8471", pub,
                             "http://10.0.0.9:8471", get=serve(binding))
    _check(code == 1, "[::ffff:10.0.0.9] dials 10.0.0.9: IPv4-mapped "
                      "form is that same node (exit 1)")

    code, _ = nd.depth_check("http://[::ffff:0a00:0009]:8471", pub,
                             "http://10.0.0.9:8471", get=serve(binding))
    _check(code == 1, "[::ffff:0a00:0009] dials 10.0.0.9: hex-mapped "
                      "form is that same node (exit 1)")

    code, _ = nd.depth_check("http://[::ffff:10.0.0.9]:8472", pub,
                             "http://10.0.0.9:8471", get=serve(binding))
    _check(code == 0, "IPv4-mapped form on a DIFFERENT port is a "
                      "different node and must still PASS")

    code, _ = nd.depth_check(node, pub, node + "/claimed",
                             get=serve(binding))
    _check(code == 1, "origin wearing a path suffix is still the "
                      "same node (exit 1): a node is scheme/host/port")

    code, _ = nd.depth_check(node + "/mirror", pub, origin,
                             get=serve(binding))
    _check(code == 0, "a path suffix on a genuinely different host "
                      "must still PASS")

    code, _ = nd.depth_check(node, "00" * 32, origin, get=serve(binding))
    _check(code == 1, "wrong pin must fail")

    tampered = dict(binding, node_pubkey=other["node_pubkey"])
    code, _ = nd.depth_check(node, pub, origin, get=serve(tampered))
    _check(code == 1, "tampered pub must fail the pin")

    bad_sig = dict(binding, signature="00" * 64)
    code, _ = nd.depth_check(node, pub, origin, get=serve(bad_sig))
    _check(code == 1, "bad signature must fail")

    code, _ = nd.depth_check(node, pub, origin, get=serve(None))
    _check(code == 1, "no binding served must fail, not pass")

    code, _ = nd.depth_check(node, "not-hex", origin, get=serve(binding))
    _check(code == 2, "malformed pin is usage (exit 2), not a verdict")

    code, _ = nd.depth_check("ftp://x", pub, origin, get=serve(binding))
    _check(code == 2, "non-http node URL is usage (exit 2)")

    # Resolved endpoints: a DNS name is not canonicalized by the
    # spelling comparisons, so a name that DIALS the origin (or
    # loopback, when the origin is loopback) must still refuse.
    _dns = {"10.0.0.1": {"10.0.0.1"}, "127.0.0.1": {"loopback"},
            "alias.example": {"10.0.0.1"},
            "far.example": {"10.0.0.44"},
            "home.example": {"loopback"}}

    def fake_resolve(host, port):
        return set(_dns.get(host, set()))

    code, _ = nd.depth_check("http://alias.example:8471", pub,
                             "http://10.0.0.1:8471",
                             get=serve(binding), resolve=fake_resolve)
    _check(code == 1, "a DNS name resolving to the origin's address "
                      "is the origin (exit 1), not an independent node")

    code, _ = nd.depth_check("http://home.example:8471", pub,
                             "http://127.0.0.1:8471",
                             get=serve(binding), resolve=fake_resolve)
    _check(code == 1, "a DNS name resolving to loopback is the "
                      "loopback origin (exit 1)")

    code, _ = nd.depth_check("http://far.example:8471", pub,
                             "http://10.0.0.1:8471",
                             get=serve(binding), resolve=fake_resolve)
    _check(code == 0, "a DNS name resolving elsewhere must still PASS")

    code, _ = nd.depth_check("http://alias.example:8472", pub,
                             "http://10.0.0.1:8471",
                             get=serve(binding), resolve=fake_resolve)
    _check(code == 0, "the origin's address on a DIFFERENT port is "
                      "a different endpoint and must still PASS")

    # Real fetch (get=None), loopback servers: the default urllib
    # opener follows 3xx silently, so a node redirecting the name
    # path to the claim origin would pass the origin's own binding
    # off as independently served. The depth fetch must refuse.
    import http.server
    import json as _json
    import threading

    body = _json.dumps(binding).encode()

    class _Direct(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    direct = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Direct)
    direct_url = f"http://127.0.0.1:{direct.server_address[1]}"

    class _Redirect(_Direct):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location",
                             direct_url + "/api/v1/names/nexus")
            self.end_headers()

    redir = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Redirect)
    redir_url = f"http://127.0.0.1:{redir.server_address[1]}"
    for srv in (direct, redir):
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        code, _ = nd.depth_check(direct_url, pub, redir_url)
        _check(code == 0, "real fetch: direct-served binding on an "
                          f"independent node must PASS, got {code}")
        code, _ = nd.depth_check(redir_url, pub, direct_url)
        _check(code == 1, "real fetch: a node that REDIRECTS to the "
                          "claim origin serves no binding of its own "
                          f"(exit 1), got {code}")
    finally:
        direct.shutdown()
        redir.shutdown()

# The equals spelling (--expect-pubkey=<64hex>) is accepted by
# main, twin of the both-spellings parsers nexus_keygen /
# nexus_preflight / nexus_status / nexus_claim / nexus_host_check
# already carry; an empty equals value is a usage refusal, and
# the space form missing its value stays refused. The equals
# case uses node == origin, which refuses (exit 1) before any
# fetch, so it proves the parse without touching the network.
_check(nd.main([node, f"--expect-pubkey={pub}",
                f"--origin-url={node}"]) == 1,
       "equals spelling must be accepted and reach the "
       "same-node refusal (exit 1)")
_check(nd.main([node, "--expect-pubkey=",
                f"--origin-url={origin}"]) == 2,
       "empty equals value must be a usage refusal")
_check(nd.main([node, "--expect-pubkey"]) == 2,
       "space form with a missing value must stay refused")

# A space-form value flag followed by another flag has a missing
# value, not a flag-shaped value: before, --expect-pubkey swallowed
# --origin-url as the pin (and --origin-url swallowed --expect-pubkey
# as the origin), so the refusal blamed the flag's own value as an
# unknown/extra argument instead of naming the flag that needs a
# value (twin of mint_name's space-form gate). The refusal message
# is the proof, so capture stderr.
import contextlib  # noqa: E402
import io  # noqa: E402

_err = io.StringIO()
with contextlib.redirect_stderr(_err):
    _code = nd.main([node, "--expect-pubkey", "--origin-url", origin])
_check(_code == 2 and "--expect-pubkey needs a value" in _err.getvalue(),
       "space form followed by another flag must refuse the pin "
       f"flag by name, got {_code}: {_err.getvalue()!r}")
_err = io.StringIO()
with contextlib.redirect_stderr(_err):
    _code = nd.main([node, "--expect-pubkey", pub,
                     "--origin-url", "--expect-pubkey", pub])
_check(_code == 2 and "--origin-url needs a value" in _err.getvalue(),
       "space form followed by another flag must refuse the origin "
       f"flag by name, got {_code}: {_err.getvalue()!r}")

if fails:
    print(f"test_nexus_depth_check: {fails} FAIL")
    sys.exit(1)
print("test_nexus_depth_check: PASS")
