"""IP-pin dial regression pin: the fetch-time SSRF gate approves an address,
but urllib re-resolves the hostname at connect() — a hostile name owner can
flip their A record in that window (residual micro-TOCTOU). The pinned
connection classes must dial exactly the gate-approved IP while keeping the
original hostname for TLS SNI and cert verification.

Drives the REAL connection classes in core.py against a local TCP/HTTP
server; the bogus hostname 'pin-probe.invalid' can never resolve, so any
successful dial proves the pin (not fresh DNS) chose the address.
"""
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import core
from fastapi import HTTPException

PASS, FAIL = 0, 0


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name}")


def run():
    global PASS, FAIL

    # 1. gate returns the approved IP for a literal global address
    pin = core._reject_nonpublic_node_url("http://93.184.216.0/x")
    check("gate returns pin for literal global IP", pin == "93.184.216.0")

    # 2. gate still rejects non-global literals and hostnames (unchanged)
    for bad in ("http://127.0.0.1/x", "http://[::1]/x", "http://localhost/x"):
        try:
            core._reject_nonpublic_node_url(bad)
            check(f"gate rejects {bad}", False)
        except HTTPException:
            check(f"gate rejects {bad}", True)

    # 3. DNS fail-open preserved: unresolvable name -> no pin, no raise.
    # The sandbox DNS wildcard-answers everything, so simulate NXDOMAIN with
    # a getaddrinfo wrapper that fails only for the probe hostname.
    real_getaddrinfo = socket.getaddrinfo

    def nxdomain(host, *a, **k):
        if host == "pin-probe.invalid":
            raise socket.gaierror(-2, "Name or service not known")
        return real_getaddrinfo(host, *a, **k)

    socket.getaddrinfo = nxdomain
    try:
        check("gate fail-open returns None",
              core._reject_nonpublic_node_url("http://pin-probe.invalid/x") is None)
    finally:
        socket.getaddrinfo = real_getaddrinfo

    # 4. dial binds to the pin, not to fresh DNS
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"pinned-ok"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]

    # negative control: no pin, bogus hostname -> DNS must fail (real dial
    # code; name resolution stubbed to NXDOMAIN as above)
    socket.getaddrinfo = nxdomain
    try:
        c = core._PinnedHTTPConnection("pin-probe.invalid", port=port, timeout=5)
        c.request("GET", "/")
        c.getresponse()
        check("no-pin dial to .invalid fails (negative control)", False)
    except (socket.gaierror, OSError, ConnectionError):
        check("no-pin dial to .invalid fails (negative control)", True)
    finally:
        socket.getaddrinfo = real_getaddrinfo

    # pinned dial: bogus hostname + pin 127.0.0.1 -> reaches local server
    core._peer_pin.pin = ("127.0.0.1", "pin-probe.invalid")
    try:
        c = core._PinnedHTTPConnection("pin-probe.invalid", port=port, timeout=5)
        c.connect()
        peer = c.sock.getpeername()[0]
        c.request("GET", "/")
        resp = c.getresponse()
        body = resp.read()
        check("pinned dial reaches server despite unresolvable host",
              resp.status == 200 and body == b"pinned-ok")
        # peer address of the socket is the pin, not a DNS answer
        check("dialed address is the pinned IP", peer == "127.0.0.1")
    finally:
        core._peer_pin.pin = None
    srv.shutdown()

    # 5. HTTPS: SNI/cert identity binds to the hostname, never the pinned IP
    captured = {}

    class FakeCtx:
        def wrap_socket(self, sock, server_hostname=None):
            captured["server_hostname"] = server_hostname
            return sock

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    tport = listener.getsockname()[1]

    accepted = []

    def accept_one():
        conn, _ = listener.accept()
        accepted.append(conn)

    threading.Thread(target=accept_one, daemon=True).start()
    core._peer_pin.pin = ("127.0.0.1", "peer.example")
    try:
        c = core._PinnedHTTPSConnection("peer.example", port=tport, timeout=5)
        c._context = FakeCtx()
        c.connect()
        check("pinned TLS dial connects to pin",
              c.sock.getpeername()[0] == "127.0.0.1")
        check("SNI/cert hostname is original name, not IP",
              captured.get("server_hostname") == "peer.example")
    finally:
        core._peer_pin.pin = None
        for s in accepted:
            s.close()
        listener.close()

    # 6. redirect handler re-pins to the redirect target, not the origin
    class FakeFP:
        pass

    seen = {}
    orig_req = core.urllib.request.Request("http://93.184.216.0/a")
    core._peer_pin.pin = ("93.184.216.0", "93.184.216.0")
    try:
        h = core._GatedRedirectHandler()
        new_req = h.redirect_request(orig_req, FakeFP(), 302, "Found", {},
                                    "http://93.184.216.1/b")
        check("redirect re-pins to target IP",
              getattr(core._peer_pin, "pin", None) == ("93.184.216.1", "93.184.216.1"))
        check("redirect target passes gate (no 403)",
              new_req.full_url == "http://93.184.216.1/b")
    finally:
        core._peer_pin.pin = None

    print(f"\n{PASS} passed, {FAIL} failed")
    return FAIL == 0


if __name__ == "__main__":
    raise SystemExit(0 if run() else 1)
