"""Fail-closed plumbing tests for resolver/wiring/smoke.py.

No daemon, no network: monkeypatch smoke._query / smoke._query_tcp to fake
transport and DNS answers in-process, and assert main()'s exit codes — the
fail-closed contract the wiring README promises ("Exit 0 only if all pass")
is real.

Checks:
  daemon down on the wire -> _query raises (transport failure is loud)
  _query raising -> main() exits 1 ("unreachable" is said, not swallowed)
  good NOERROR+A then junk NXDOMAIN -> main() exits 0 (PASS path)
  junk not NXDOMAIN -> main() exits 1 (fail-closed answer refuses)
  --tcp routes both checks through _query_tcp (UDP never touched)
  A NODATA on the registered name -> AAAA leg asked (v6-only node passes);
  NODATA on both families -> main() exits 1
  UDP wire dials a server hostname at its resolved family (fake-socket
  seam: a v6-only hostname creates an AF_INET6 socket aimed at ::1)
  packet shape: _build_query header parses, qname encodes

Run: cd ~/workspace/cybernet && ./venv/bin/python resolver/wiring/test_smoke.py
"""

import contextlib
import io
import os
import random
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import smoke  # noqa: E402

CASES = {"passed": 0, "failed": 0}


def check(name, cond, extra=""):
    if cond:
        CASES["passed"] += 1
        print(f"  ok  {name}")
    else:
        CASES["failed"] += 1
        print(f"  FAIL {name} {extra}")


def _run_main_with_fake(fake_query, argv_extra=()):
    real = smoke._query
    smoke._query = fake_query
    old_argv = sys.argv
    sys.argv = ["smoke.py", "--server", "127.0.0.1", "--port", "53599"] + list(argv_extra)
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            rc = smoke.main()
    finally:
        smoke._query = real
        sys.argv = old_argv
    return rc, buf.getvalue()


# 1. transport failure is loud: _query raises, never answers
def _test_transport_raises():
    raised = False
    try:
        # closed localhost UDP port: ECONNREFUSED (fast) or timeout;
        # either way it must RAISE, never return a fake answer
        smoke._query("genesis.cyberspace", 1, "127.0.0.1", 53599, timeout=0.5)
    except Exception as exc:
        raised = True
        print(f"       (_query raised {type(exc).__name__})")
    check("daemon down -> _query raises", raised)


# 2. raised transport -> main() exits 1 and says unreachable
def _test_fail_closed_unreachable():
    def _down(name, qtype, server, port, timeout=3.0):
        raise OSError("connection refused")

    rc, out = _run_main_with_fake(_down)
    check("unreachable daemon -> exit 1", rc == 1, f"got {rc}")
    check("unreachable is said aloud", "unreachable" in out, repr(out[:80]))


# 3. happy path: registered NOERROR+A, junk NXDOMAIN -> exit 0
def _test_happy_path():
    def _good(name, qtype, server, port, timeout=3.0):
        return (3, 0, 0) if name.startswith("zz-") else (0, 1, 0)

    rc, out = _run_main_with_fake(_good)
    check("good daemon -> exit 0", rc == 0, f"got {rc}")
    check("PASS lines printed", "registered name resolves" in out
          and "NXDOMAIN (fail-closed)" in out, repr(out[:120]))
    check("default wire says udp", "[udp]" in out, repr(out[:120]))


# 4. daemon that answers junk -> exit 1, not trusted
def _test_junk_not_nxdomain():
    def _lying(name, qtype, server, port, timeout=3.0):
        return (0, 1, 0)  # answers everything — not fail-closed

    rc, out = _run_main_with_fake(_lying)
    check("non-NXDOMAIN junk -> exit 1", rc == 1, f"got {rc}")
    check("fail-closed refusal said", "not fail-closed" in out, repr(out[:80]))


# 5b. --tcp routes the checks through _query_tcp, not _query
def _test_tcp_flag_routes():
    calls = {"tcp": 0, "udp": 0}

    def _good_tcp(name, qtype, server, port, timeout=3.0):
        calls["tcp"] += 1
        return (3, 0, 0) if name.startswith("zz-") else (0, 1, 0)

    def _never_udp(name, qtype, server, port, timeout=3.0):
        calls["udp"] += 1
        raise AssertionError("UDP transport must not be used under --tcp")

    real_query, real_tcp = smoke._query, smoke._query_tcp
    smoke._query, smoke._query_tcp = _never_udp, _good_tcp
    old_argv = sys.argv
    sys.argv = ["smoke.py", "--server", "127.0.0.1", "--port", "53599",
                "--tcp"]
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            rc = smoke.main()
    finally:
        smoke._query, smoke._query_tcp = real_query, real_tcp
        sys.argv = old_argv
    out = buf.getvalue()
    check("--tcp happy path -> exit 0", rc == 0, f"got {rc}")
    check("--tcp uses TCP transport only",
          calls["tcp"] == 2 and calls["udp"] == 0, repr(calls))
    check("--tcp wire is labeled", "[tcp]" in out, repr(out[:120]))


# 5c. IPv6 server forms: brackets stripped, family follows the literal,
#     and the bracketed form actually completes a TCP wire to ::1
def _test_ipv6_server_forms():
    check("bracketed v6 host stripped", smoke._server_host("[::1]") == "::1")
    check("bare v6 host unchanged", smoke._server_host("::1") == "::1")
    check("v4 host unchanged", smoke._server_host("127.0.0.1") == "127.0.0.1")
    check("hostname unchanged", smoke._server_host("localhost") == "localhost")
    import socket as _socket
    check("v6 literal -> AF_INET6", smoke._server_family("::1") == _socket.AF_INET6)
    check("v4 literal -> AF_INET", smoke._server_family("127.0.0.1") == _socket.AF_INET)
    check("hostname -> AF_INET", smoke._server_family("localhost") == _socket.AF_INET)

    # live wire: a one-shot TCP DNS server on ::1 answering NXDOMAIN;
    # before the fix the bracketed form died in create_connection
    import threading
    srv = _socket.socket(_socket.AF_INET6, _socket.SOCK_STREAM)
    srv.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
    srv.bind(("::1", 0))
    port = srv.getsockname()[1]
    srv.listen(1)

    def _serve_once():
        conn, _ = srv.accept()
        with conn:
            head = conn.recv(2)
            (ln,) = struct.unpack(">H", head)
            q = b""
            while len(q) < ln:
                q += conn.recv(ln - len(q))
            (txid,) = struct.unpack(">H", q[:2])
            resp = struct.pack(">HHHHHH", txid, 0x8503, 0, 0, 0, 0)
            conn.sendall(struct.pack(">H", len(resp)) + resp)
        srv.close()

    threading.Thread(target=_serve_once, daemon=True).start()
    try:
        rcode, an, _ = smoke._query_tcp("zz-junk.cyberspace", 1, "[::1]",
                                        port, timeout=2.0)
        check("bracketed [::1] TCP wire answers NXDOMAIN",
              rcode == 3 and an == 0, f"rcode={rcode} an={an}")
    except Exception as exc:
        check("bracketed [::1] TCP wire answers NXDOMAIN", False, repr(exc))


# 5d. AAAA fallback: a v6-only name answers A with NODATA (NOERROR, 0)
#     and AAAA with answers — smoke must pass it, not fail a healthy
#     name; a name NODATA on BOTH families still fails
def _test_aaaa_fallback():
    def _v6_only(name, qtype, server, port, timeout=3.0):
        if name.startswith("zz-"):
            return (3, 0, 0)
        return (0, 0, 0) if qtype == 1 else (0, 1, 0)

    rc, out = _run_main_with_fake(_v6_only)
    check("v6-only name (A NODATA, AAAA answers) -> exit 0", rc == 0,
          f"got {rc}")
    check("AAAA leg printed", "AAAA:" in out, repr(out[:160]))

    def _nodata(name, qtype, server, port, timeout=3.0):
        return (3, 0, 0) if name.startswith("zz-") else (0, 0, 0)

    rc, out = _run_main_with_fake(_nodata)
    check("NODATA on both families -> exit 1", rc == 1, f"got {rc}")


# 5e. undialable --port is a bad argument, never "unreachable":
#     no query is attempted for 99999 / 0 / -1, and 65535 still dials
def _test_undialable_port():
    calls = {"n": 0}

    def _counting(name, qtype, server, port, timeout=3.0):
        calls["n"] += 1
        return (3, 0, 0) if name.startswith("zz-") else (0, 1, 0)

    for bad in ("99999", "0", "-1"):
        calls["n"] = 0
        real = smoke._query
        smoke._query = _counting
        old_argv = sys.argv
        sys.argv = ["smoke.py", "--server", "127.0.0.1", "--port", bad]
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf):
                rc = smoke.main()
        finally:
            smoke._query = real
            sys.argv = old_argv
        out = buf.getvalue()
        check(f"--port {bad} -> exit 1, no query, not 'unreachable'",
              rc == 1 and calls["n"] == 0 and "not a dialable port" in out
              and "unreachable" not in out, f"rc={rc} calls={calls['n']} out={out[:80]!r}")
    rc, _ = _run_main_with_fake(_counting)
    check("valid port 53599 still dials (control)", rc == 0)


# 5f. malformed --name is a bad argument, never a daemon verdict:
#     no query is attempted for a non-zone / multi-label / bad-label
#     name (each would otherwise read as NXDOMAIN "did not resolve"
#     or an ascii-encode "unreachable"); uppercase + FQDN root dot
#     still smoke (normalized before the wire)
def _test_malformed_name():
    calls = {"n": 0}

    def _counting(name, qtype, server, port, timeout=3.0):
        calls["n"] += 1
        return (3, 0, 0) if name.startswith("zz-") else (0, 1, 0)

    for bad in ("foo", "bad..cyberspace", "-bad.cyberspace",
                "bad-.cyberspace", "a_b.cyberspace", ".cyberspace",
                "é.cyberspace", "a" * 64 + ".cyberspace"):
        calls["n"] = 0
        rc, out = _run_main_with_fake(_counting, ["--name=" + bad])
        check(f"--name {bad[:20]!r} -> exit 1, no query, bad argument",
              rc == 1 and calls["n"] == 0 and "bad argument" in out
              and "unreachable" not in out
              and "did not resolve" not in out,
              f"rc={rc} calls={calls['n']} out={out[:80]!r}")
    rc, out = _run_main_with_fake(_counting, ["--name", "GENESIS.cyberspace."])
    check("uppercase + FQDN-dot name still smokes (control)", rc == 0,
          f"rc={rc} out={out[:80]!r}")


# 5g. undialable --server is a bad argument, never "unreachable":
#     no query is attempted for a bad-hostname / dotted-non-IPv4 /
#     empty server (each otherwise dies in resolution and reads as a
#     verdict on the daemon); hostname + bracketed v6 still smoke
def _test_undialable_server():
    calls = {"n": 0}

    def _counting(name, qtype, server, port, timeout=3.0):
        calls["n"] += 1
        return (3, 0, 0) if name.startswith("zz-") else (0, 1, 0)

    for bad in ("bad host!", "999.999.1.1", "", "-bad-.example"):
        calls["n"] = 0
        rc, out = _run_main_with_fake(_counting, ["--server=" + bad])
        check(f"--server {bad!r} -> exit 1, no query, bad argument",
              rc == 1 and calls["n"] == 0 and "bad argument" in out
              and "unreachable" not in out,
              f"rc={rc} calls={calls['n']} out={out[:80]!r}")
    rc, out = _run_main_with_fake(_counting, ["--server", "localhost"])
    check("hostname server still smokes (control)", rc == 0,
          f"rc={rc} out={out[:80]!r}")
    rc, out = _run_main_with_fake(_counting, ["--server", "[::1]"])
    check("bracketed v6 server still smokes (control)", rc == 0,
          f"rc={rc} out={out[:80]!r}")


# 5h. no --port: the port comes from CYBERNET_RESOLVER_PORT, exactly
#     as the daemon and the resolver client derive it (agreement, not
#     a second parser): env 53599 is queried, an explicit --port still
#     wins over the env, a non-integer env falls back to 5353, and an
#     env port above 65535 hits the same bad-argument gate as --port
def _test_env_port_default():
    seen = []

    def _counting(name, qtype, server, port, timeout=3.0):
        seen.append(port)
        return (3, 0, 0) if name.startswith("zz-") else (0, 1, 0)

    def _run(argv, env):
        seen.clear()
        real = smoke._query
        smoke._query = _counting
        old_argv = sys.argv
        old_env = os.environ.get("CYBERNET_RESOLVER_PORT")
        sys.argv = ["smoke.py", "--server", "127.0.0.1"] + argv
        if env is None:
            os.environ.pop("CYBERNET_RESOLVER_PORT", None)
        else:
            os.environ["CYBERNET_RESOLVER_PORT"] = env
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf):
                rc = smoke.main()
        finally:
            smoke._query = real
            sys.argv = old_argv
            if old_env is None:
                os.environ.pop("CYBERNET_RESOLVER_PORT", None)
            else:
                os.environ["CYBERNET_RESOLVER_PORT"] = old_env
        return rc, buf.getvalue()

    rc, _ = _run([], "53599")
    check("env port 53599 queried when --port omitted",
          rc == 0 and seen and all(p == 53599 for p in seen),
          f"rc={rc} seen={seen}")
    rc, _ = _run(["--port", "53598"], "53599")
    check("explicit --port wins over env port",
          rc == 0 and seen and all(p == 53598 for p in seen),
          f"rc={rc} seen={seen}")
    rc, _ = _run([], "banana")
    check("non-integer env port falls back to 5353",
          rc == 0 and seen and all(p == 5353 for p in seen),
          f"rc={rc} seen={seen}")
    rc, out = _run([], "99999")
    check("env port 99999 -> exit 1, no query, bad argument",
          rc == 1 and not seen and "not a dialable port" in out,
          f"rc={rc} seen={seen} out={out[:80]!r}")
    rc, _ = _run([], None)
    check("no env port -> 5353 (control)",
          rc == 0 and seen and all(p == 5353 for p in seen),
          f"rc={rc} seen={seen}")


# 5i. UDP wire follows the server HOSTNAME's resolved family, not the
#     string's shape: a daemon bound to ::1 whose operator smokes it by a
#     v6-only hostname was dialed on an AF_INET socket to the unresolved
#     string — the query never reached the v6 daemon and read as
#     "unreachable". _query must create its socket from getaddrinfo's
#     answer (family + sockaddr), as _query_tcp's create_connection
#     already does. Fake socket + fake getaddrinfo: the sandbox forbids
#     real UDP sendto (EPERM), so the wire is proven at the seam the
#     codebase uses for UDP everywhere else.
def _test_udp_hostname_family():
    import socket as _socket

    canned = {}

    class _FakeUdp:
        def __init__(self, family, kind):
            canned["family"] = family
            self.family = family

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def settimeout(self, t):
            pass

        def sendto(self, packet, target):
            canned["target"] = target
            txid = struct.unpack(">H", packet[:2])[0]
            # question section verbatim, one A answer via name pointer
            canned["resp"] = (
                struct.pack(">HHHHHH", txid, 0x8500, 1, 1, 0, 0)
                + packet[12:]
                + struct.pack(">HHHIH", 0xC00C, 1, 1, 120, 4)
                + _socket.inet_aton("10.9.8.7"))
            return len(packet)

        def recvfrom(self, n):
            return canned["resp"], canned["target"]

    def _fake_gai(host, port, family=0, type=0, *a, **k):
        if host == "v6only.example":
            return [(_socket.AF_INET6, _socket.SOCK_DGRAM, 17, "",
                     ("::1", port, 0, 0))]
        return [(_socket.AF_INET, _socket.SOCK_DGRAM, 17, "",
                 ("127.0.0.1", port))]

    real_socket, real_gai = _socket.socket, _socket.getaddrinfo
    _socket.socket, _socket.getaddrinfo = _FakeUdp, _fake_gai
    try:
        rcode, an, _ = smoke._query("alice.cyberspace", 1,
                                    "v6only.example", 5399, timeout=1.0)
    finally:
        _socket.socket, _socket.getaddrinfo = real_socket, real_gai
    check("v6-only hostname -> _query answers", rcode == 0 and an == 1,
          f"rcode={rcode} an={an}")
    check("v6-only hostname -> AF_INET6 socket created",
          canned.get("family") == _socket.AF_INET6,
          f"family={canned.get('family')}")
    check("v6-only hostname -> sendto targets the resolved ::1 sockaddr",
          canned.get("target") == ("::1", 5399, 0, 0),
          f"target={canned.get('target')}")


# 5j. UDP wire reads a WHOLE datagram, not the classic 512: recvfrom
#     discards whatever it is not handed room for, so a multi-answer
#     reply past 512 was silently amputated mid-record while the
#     header counts still claimed the answers never delivered — every
#     sibling wire (daemon._serve_udp, client._query_udp,
#     answer._forward) already reads 65535. Fake socket honors the
#     requested size like a real one (truncates to n) and records it.
def _test_udp_whole_datagram():
    import socket as _socket

    canned = {}

    class _FakeUdp:
        def __init__(self, family, kind):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def settimeout(self, t):
            pass

        def sendto(self, packet, target):
            txid = struct.unpack(">H", packet[:2])[0]
            canned["resp"] = (
                struct.pack(">HHHHHH", txid, 0x8500, 1, 1, 0, 0)
                + packet[12:] + b"\x00" * 600)
            return len(packet)

        def recvfrom(self, n):
            canned["n"] = n
            return canned["resp"][:n], ("127.0.0.1", 5399)

    real_socket = _socket.socket
    _socket.socket = _FakeUdp
    try:
        rcode, an, _ = smoke._query("alice.cyberspace", 1,
                                    "127.0.0.1", 5399, timeout=1.0)
    finally:
        _socket.socket = real_socket
    check("oversize reply -> _query answers", rcode == 0 and an == 1,
          f"rcode={rcode} an={an}")
    check("oversize reply -> recvfrom asked for a whole datagram (65535)",
          canned.get("n") == 65535, f"n={canned.get('n')}")


# 5k. env-port warnings: _default_port silently hid a set-but-ineffective
#     CYBERNET_RESOLVER_PORT (non-integer -> 5353, below 1 -> clamped to
#     1) while daemon and client both warn loudly for the same value —
#     the smoke then blamed the daemon ("unreachable") for a port the
#     operator never chose. main() must print _port_warnings to stderr
#     when (and only when) the port comes from the env.
def _test_env_port_warnings():
    seen = []

    def _counting(name, qtype, server, port, timeout=3.0):
        seen.append(port)
        return (3, 0, 0) if name.startswith("zz-") else (0, 1, 0)

    def _run(argv, env):
        seen.clear()
        real = smoke._query
        smoke._query = _counting
        old_argv = sys.argv
        old_env = os.environ.get("CYBERNET_RESOLVER_PORT")
        sys.argv = ["smoke.py", "--server", "127.0.0.1"] + argv
        if env is None:
            os.environ.pop("CYBERNET_RESOLVER_PORT", None)
        else:
            os.environ["CYBERNET_RESOLVER_PORT"] = env
        out_buf, err_buf = io.StringIO(), io.StringIO()
        try:
            with contextlib.redirect_stdout(out_buf), \
                    contextlib.redirect_stderr(err_buf):
                rc = smoke.main()
        finally:
            smoke._query = real
            sys.argv = old_argv
            if old_env is None:
                os.environ.pop("CYBERNET_RESOLVER_PORT", None)
            else:
                os.environ["CYBERNET_RESOLVER_PORT"] = old_env
        return rc, out_buf.getvalue(), err_buf.getvalue()

    rc, _, err = _run([], "banana")
    check("non-integer env port -> warns not-an-integer, still smokes 5353",
          rc == 0 and seen and all(p == 5353 for p in seen)
          and "not an integer" in err,
          f"rc={rc} seen={seen} err={err[:80]!r}")
    rc, _, err = _run([], "0")
    check("env port 0 -> warns below-floor, smokes 1",
          rc == 0 and seen and all(p == 1 for p in seen)
          and "below the 1 floor" in err,
          f"rc={rc} seen={seen} err={err[:80]!r}")
    rc, _, err = _run([], "99999")
    check("env port 99999 -> warns above-65535, gate refuses, no query",
          rc == 1 and not seen and "above 65535" in err,
          f"rc={rc} seen={seen} err={err[:80]!r}")
    rc, _, err = _run(["--port", "53598"], "banana")
    check("explicit --port with bad env -> warnings stay silent",
          rc == 0 and seen and all(p == 53598 for p in seen) and not err,
          f"rc={rc} seen={seen} err={err[:80]!r}")
    rc, _, err = _run([], "53599")
    check("valid env port -> no warning (control)",
          rc == 0 and not err, f"rc={rc} err={err[:80]!r}")
    rc, _, err = _run([], None)
    check("unset env port -> no warning (control)",
          rc == 0 and not err, f"rc={rc} err={err[:80]!r}")


# 6. packet shape: _build_query header parses, qname encodes
def _test_packet_shape():
    random.seed(0)
    pkt, txid = smoke._build_query("genesis.cyberspace", 1)
    (rtxid, flags, qd, an, ns, ar) = struct.unpack(">HHHHHH", pkt[:12])
    check("header: our txid, QDCOUNT=1", rtxid == txid and qd == 1 and an == 0,
          f"txid={rtxid} qd={qd} an={an}")
    # qname section: 7 "genesis" 10 "cyberspace" 0, then qtype=1 qclass=1
    qname = b"\x07genesis\x0acyberspace\x00"
    body = pkt[12:]
    check("qname encodes genesis.cyberspace", body.startswith(qname))
    qtype, qclass = struct.unpack(">HH", body[len(qname):len(qname) + 4])
    check("qtype=A qclass=IN", qtype == 1 and qclass == 1)


if __name__ == "__main__":
    _test_transport_raises()
    _test_fail_closed_unreachable()
    _test_happy_path()
    _test_junk_not_nxdomain()
    _test_tcp_flag_routes()
    _test_ipv6_server_forms()
    _test_aaaa_fallback()
    _test_undialable_port()
    _test_malformed_name()
    _test_undialable_server()
    _test_env_port_default()
    _test_udp_hostname_family()
    _test_udp_whole_datagram()
    _test_env_port_warnings()
    _test_packet_shape()
    p, f = CASES["passed"], CASES["failed"]
    print(f"\n{CASES['passed']} passed, {CASES['failed']} failed")
    sys.exit(1 if f else 0)
