"""Redirect-through SSRF gate harness (2026-10-09 dev tick).

_peer_urlopen's SSRF gate ran on the URL dialed, but urllib's default
opener follows 3xx redirects without consulting anyone — a hostile peer
whose public node_url passed the gate could 302 us onto
169.254.169.254 / loopback / the tailnet. The new
_GatedRedirectHandler re-runs the same gate on every redirect target.

Fixture: a local HTTP server whose /redirect endpoint 302s to a
/secret endpoint on the same loopback address; /secret increments a
counter so we can prove the gated opener never fetched it.

Note on scope isolation: the harness drives core._peer_opener.open()
directly (NOT _peer_urlopen) for the redirect cases, because
_peer_urlopen's own initial-URL gate would reject the loopback fixture
URL itself — a different, already-tested control (case 5 re-checks it).
"""
import os
import sys
import tempfile
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TMP = tempfile.mkdtemp(prefix="cybernet-redirect-gate-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core
from core import _peer_opener

HITS = {"secret": 0, "ok": 0}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location",
                             f"http://127.0.0.1:{self.server.server_port}/secret")
            self.end_headers()
        elif self.path == "/secret":
            HITS["secret"] += 1
            body = b"INTERNAL REACHED"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/ok":
            HITS["ok"] += 1
            body = b"fine"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()


server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
port = server.server_port
threading.Thread(target=server.serve_forever, daemon=True).start()

passed = []


def check(name, cond):
    passed.append(cond)
    print(("PASS " if cond else "FAIL ") + name)


# 1. Gated opener refuses the redirect to an internal address: 403,
#    and the /secret endpoint is never fetched.
try:
    _peer_opener.open(f"http://127.0.0.1:{port}/redirect", timeout=5)
    check("1. gated redirect to loopback refused", False)
except urllib.error.HTTPError as e:
    check("1. gated redirect to loopback refused",
          e.code == 403 and "peer redirect target rejected" in str(e)
          and HITS["secret"] == 0)

# 2. Non-redirect fetch through the same opener still works.
try:
    with _peer_opener.open(f"http://127.0.0.1:{port}/ok", timeout=5) as r:
        check("2. non-redirect fetch unaffected",
              r.status == 200 and r.read() == b"fine" and HITS["ok"] == 1)
except Exception:
    check("2. non-redirect fetch unaffected", False)

# 3. Legitimate (gate-fail-open) redirect targets are still followed:
#    the gate fails OPEN on DNS errors, so a redirect to a name that
#    cannot resolve must return a Request, not raise. (The sandbox DNS
#    answers even .invalid with a wildcard non-global address, so the
#    harness forces the DNS-error path with a wrapper — the gate's
#    documented fail-open contract, narrowly scoped to one hostname.)
import socket as _sock

_real_getaddrinfo = _sock.getaddrinfo


def _boom_getaddrinfo(host, *a, **k):
    if host == "unresolvable-xyz.example":
        raise _sock.gaierror(-2, "Name or service not known")
    return _real_getaddrinfo(host, *a, **k)


_sock.getaddrinfo = _boom_getaddrinfo
req = urllib.request.Request(f"http://127.0.0.1:{port}/redirect")
try:
    out = core._GatedRedirectHandler().redirect_request(
        req, None, 302, "Found", {},
        "http://unresolvable-xyz.example/x")
    check("3. fail-open redirect target still followed",
          isinstance(out, urllib.request.Request))
except Exception as e:
    print("   (case 3 raised: %r)" % e)
    check("3. fail-open redirect target still followed", False)
finally:
    _sock.getaddrinfo = _real_getaddrinfo

# 4. Negative control: the DEFAULT opener follows the same redirect onto
#    the internal target — proves the fixture's redirect path works, so
#    case 1's refusal is the handler's doing, not a broken fixture.
try:
    urllib.request.urlopen(f"http://127.0.0.1:{port}/redirect", timeout=5)
    check("4. negative control: default opener reaches /secret",
          HITS["secret"] == 1)
except Exception:
    check("4. negative control: default opener reaches /secret", False)

# 5. The initial-URL gate is untouched: _peer_urlopen still rejects the
#    loopback target itself with ValueError (no node-surface behavior
#    change on legal peers).
try:
    core._peer_urlopen(f"http://127.0.0.1:{port}/ok", timeout=5)
    check("5. initial-URL loopback gate still rejects", False)
except ValueError as e:
    check("5. initial-URL loopback gate still rejects",
          "peer node_url rejected at fetch time" in str(e))

server.shutdown()
print(f"\n{sum(passed)}/{len(passed)} passed")
sys.exit(0 if all(passed) else 1)
