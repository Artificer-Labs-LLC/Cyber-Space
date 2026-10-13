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
    # Non-string servers/hosts raise ValueError at the source, never
    # AttributeError/TypeError and never an aliased daemon (None->::1,
    # 123->0.0.0.123, True->0.0.0.1, 4-byte bytes->its quad).
    for bad in (None, 123, True, b"::1", b"\x7f\x00\x00\x01"):
        for fn, args in ((smoke._server_host, (bad,)),
                         (smoke._server_family, (bad,)),
                         (smoke._server_target, (bad, 5353))):
            try:
                fn(*args)
                check(f"{fn.__name__}({bad!r}) raises ValueError", False)
            except ValueError:
                check(f"{fn.__name__}({bad!r}) raises ValueError", True)
            except Exception as exc:
                check(f"{fn.__name__}({bad!r}) raises ValueError", False,
                      repr(exc))

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
            # conforming daemon reply: build_response echoes the one
            # question (qd=1 + question bytes) — a bare qd=0 header is
            # error_response shape, which smoke refuses (RD/qd checks)
            resp = struct.pack(">HHHHHH", txid, 0x8503, 1, 0, 0, 0) + q[12:]
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
            # forty A answers, each owned by a pointer back to the
            # question name: a genuine >512 reply the daemon's shape
            # allows — zero padding would be trailing bytes, which
            # smoke now refuses (see 5w), and a long unrelated owner
            # would be a stranger's record, refused likewise (see 5y)
            one = (struct.pack(">HHHIH", 0xC00C, 1, 1, 120, 4)
                   + _socket.inet_aton("10.9.8.7"))
            canned["resp"] = (
                struct.pack(">HHHHHH", txid, 0x8500, 1, 40, 0, 0)
                + packet[12:]
                + one * 40)
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
    check("oversize reply -> _query answers", rcode == 0 and an == 40,
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


# 5l. UDP wire accepts a reply ONLY from the daemon it queried: the
#     source is part of the transaction (client._query_udp's rule), but
#     _query discarded recvfrom's source, so a perfectly formed packet
#     from any other (address, port) — right txid included — earned the
#     smoke a PASS the daemon never gave. Wrong IP and wrong port both
#     refuse; the exact source (control) still answers.
def _test_udp_reply_source():
    import socket as _socket

    def _run(source):
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
                    + packet[12:]
                    + struct.pack(">HHHIH", 0xC00C, 1, 1, 120, 4)
                    + _socket.inet_aton("10.9.8.7"))
                return len(packet)

            def recvfrom(self, n):
                return canned["resp"], source

        real_socket = _socket.socket
        _socket.socket = _FakeUdp
        try:
            return smoke._query("alice.cyberspace", 1,
                                "127.0.0.1", 5399, timeout=1.0), None
        except Exception as exc:  # noqa: BLE001 - the refusal is the check
            return None, exc
        finally:
            _socket.socket = real_socket

    got, err = _run(("127.0.0.1", 5399))
    check("reply from the queried source -> _query answers (control)",
          err is None and got is not None and got[0] == 0 and got[1] == 1,
          f"got={got} err={err}")
    got, err = _run(("10.0.0.99", 5399))
    check("reply from a different IP -> _query refuses",
          got is None and isinstance(err, ValueError)
          and "unexpected source" in str(err),
          f"got={got} err={err}")
    got, err = _run(("127.0.0.1", 12345))
    check("reply from a different port -> _query refuses",
          got is None and isinstance(err, ValueError)
          and "unexpected source" in str(err),
          f"got={got} err={err}")


# 5m. A reply must be a RESPONSE: a matching txid alone never sufficed
#     (client._parse_response's rule), but both smoke wires checked only
#     the txid, so a QR-clear packet — a query, flags=RD only — claiming
#     an answer earned a PASS the daemon never gave. Both wires refuse.
def _test_qr_bit():
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
                struct.pack(">HHHHHH", txid, 0x0100, 1, 1, 0, 0)
                + packet[12:]
                + struct.pack(">HHHIH", 0xC00C, 1, 1, 120, 4)
                + _socket.inet_aton("10.9.8.7"))
            return len(packet)

        def recvfrom(self, n):
            return canned["resp"], ("127.0.0.1", 5399)

    real_socket = _socket.socket
    _socket.socket = _FakeUdp
    try:
        smoke._query("alice.cyberspace", 1, "127.0.0.1", 5399, timeout=1.0)
        err = None
    except Exception as exc:  # noqa: BLE001 - the refusal is the check
        err = exc
    finally:
        _socket.socket = real_socket
    check("UDP QR-clear packet -> _query refuses",
          isinstance(err, ValueError) and "QR bit clear" in str(err),
          f"err={err}")

    import threading
    srv = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
    srv.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
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
            resp = struct.pack(">HHHHHH", txid, 0x0100, 1, 1, 0, 0) + q[12:]
            conn.sendall(struct.pack(">H", len(resp)) + resp)
        srv.close()

    threading.Thread(target=_serve_once, daemon=True).start()
    try:
        smoke._query_tcp("alice.cyberspace", 1, "127.0.0.1", port,
                         timeout=2.0)
        err = None
    except Exception as exc:  # noqa: BLE001 - the refusal is the check
        err = exc
    check("TCP QR-clear packet -> _query_tcp refuses",
          isinstance(err, ValueError) and "QR bit clear" in str(err),
          f"err={err}")


# 5n. A reply must be the AUTHORITATIVE daemon's: client._parse_response
#     refuses an AA-clear packet (every reply the daemon builds — answers,
#     NXDOMAIN, SERVFAIL — sets AA), but both smoke wires checked only QR,
#     so a QR-set, AA-clear packet (flags=QR|RD) claiming an answer earned
#     a PASS that was some other responder's word. Both wires refuse.
def _test_aa_bit():
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
                struct.pack(">HHHHHH", txid, 0x8100, 1, 1, 0, 0)
                + packet[12:]
                + struct.pack(">HHHIH", 0xC00C, 1, 1, 120, 4)
                + _socket.inet_aton("10.9.8.7"))
            return len(packet)

        def recvfrom(self, n):
            return canned["resp"], ("127.0.0.1", 5399)

    real_socket = _socket.socket
    _socket.socket = _FakeUdp
    try:
        smoke._query("alice.cyberspace", 1, "127.0.0.1", 5399, timeout=1.0)
        err = None
    except Exception as exc:  # noqa: BLE001 - the refusal is the check
        err = exc
    finally:
        _socket.socket = real_socket
    check("UDP AA-clear packet -> _query refuses",
          isinstance(err, ValueError) and "AA bit clear" in str(err),
          f"err={err}")

    import threading
    srv = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
    srv.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
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
            resp = struct.pack(">HHHHHH", txid, 0x8100, 1, 1, 0, 0) + q[12:]
            conn.sendall(struct.pack(">H", len(resp)) + resp)
        srv.close()

    threading.Thread(target=_serve_once, daemon=True).start()
    try:
        smoke._query_tcp("alice.cyberspace", 1, "127.0.0.1", port,
                         timeout=2.0)
        err = None
    except Exception as exc:  # noqa: BLE001 - the refusal is the check
        err = exc
    check("TCP AA-clear packet -> _query_tcp refuses",
          isinstance(err, ValueError) and "AA bit clear" in str(err),
          f"err={err}")


# 5o. A reply must answer a STANDARD query: client._parse_response
#     refuses a nonzero opcode (the daemon only ever answers opcode 0,
#     and both its response builders emit opcode 0), but both smoke
#     wires checked only QR+AA, so a QR|AA-set packet with opcode 1
#     (flags=QR|AA|opcode1|RD) claiming an answer earned a PASS for a
#     packet that is not a reply to a standard query at all. Both refuse.
def _test_opcode():
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
                struct.pack(">HHHHHH", txid, 0x8D00, 1, 1, 0, 0)
                + packet[12:]
                + struct.pack(">HHHIH", 0xC00C, 1, 1, 120, 4)
                + _socket.inet_aton("10.9.8.7"))
            return len(packet)

        def recvfrom(self, n):
            return canned["resp"], ("127.0.0.1", 5399)

    real_socket = _socket.socket
    _socket.socket = _FakeUdp
    try:
        smoke._query("alice.cyberspace", 1, "127.0.0.1", 5399, timeout=1.0)
        err = None
    except Exception as exc:  # noqa: BLE001 - the refusal is the check
        err = exc
    finally:
        _socket.socket = real_socket
    check("UDP opcode-set packet -> _query refuses",
          isinstance(err, ValueError) and "opcode set" in str(err),
          f"err={err}")

    import threading
    srv = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
    srv.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
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
            resp = struct.pack(">HHHHHH", txid, 0x8D00, 1, 1, 0, 0) + q[12:]
            conn.sendall(struct.pack(">H", len(resp)) + resp)
        srv.close()

    threading.Thread(target=_serve_once, daemon=True).start()
    try:
        smoke._query_tcp("alice.cyberspace", 1, "127.0.0.1", port,
                         timeout=2.0)
        err = None
    except Exception as exc:  # noqa: BLE001 - the refusal is the check
        err = exc
    check("TCP opcode-set packet -> _query_tcp refuses",
          isinstance(err, ValueError) and "opcode set" in str(err),
          f"err={err}")


# 5p. A reply must echo RD: client._parse_response refuses an RD-clear
#     packet (the smoke/client always send RD, and build_response echoes
#     RD on every zone reply it builds), but both smoke wires checked
#     only QR+AA+opcode, so a QR|AA-set RD-clear packet (flags=QR|AA)
#     claiming an answer earned a PASS for a packet that is not the
#     daemon's reply to THIS query. Both refuse.
def _test_rd_echo():
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
                struct.pack(">HHHHHH", txid, 0x8400, 1, 1, 0, 0)
                + packet[12:]
                + struct.pack(">HHHIH", 0xC00C, 1, 1, 120, 4)
                + _socket.inet_aton("10.9.8.7"))
            return len(packet)

        def recvfrom(self, n):
            return canned["resp"], ("127.0.0.1", 5399)

    real_socket = _socket.socket
    _socket.socket = _FakeUdp
    try:
        smoke._query("alice.cyberspace", 1, "127.0.0.1", 5399, timeout=1.0)
        err = None
    except Exception as exc:  # noqa: BLE001 - the refusal is the check
        err = exc
    finally:
        _socket.socket = real_socket
    check("UDP RD-clear packet -> _query refuses",
          isinstance(err, ValueError) and "does not echo RD" in str(err),
          f"err={err}")

    import threading
    srv = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
    srv.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
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
            resp = struct.pack(">HHHHHH", txid, 0x8400, 1, 1, 0, 0) + q[12:]
            conn.sendall(struct.pack(">H", len(resp)) + resp)
        srv.close()

    threading.Thread(target=_serve_once, daemon=True).start()
    try:
        smoke._query_tcp("alice.cyberspace", 1, "127.0.0.1", port,
                         timeout=2.0)
        err = None
    except Exception as exc:  # noqa: BLE001 - the refusal is the check
        err = exc
    check("TCP RD-clear packet -> _query_tcp refuses",
          isinstance(err, ValueError) and "does not echo RD" in str(err),
          f"err={err}")


# 5q. A reply must not claim truncation: client._parse_response
#     refuses a TC-set packet (neither daemon response builder ever
#     sets TC — its replies are whole on both wires), but both smoke
#     wires checked only QR+AA+opcode+RD, so a QR|AA|RD|TC-set packet
#     claiming an answer earned a PASS for a packet that is not the
#     daemon's whole reply. Both refuse.
def _test_tc_bit():
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
                struct.pack(">HHHHHH", txid, 0x8700, 1, 1, 0, 0)
                + packet[12:]
                + struct.pack(">HHHIH", 0xC00C, 1, 1, 120, 4)
                + _socket.inet_aton("10.9.8.7"))
            return len(packet)

        def recvfrom(self, n):
            return canned["resp"], ("127.0.0.1", 5399)

    real_socket = _socket.socket
    _socket.socket = _FakeUdp
    try:
        smoke._query("alice.cyberspace", 1, "127.0.0.1", 5399, timeout=1.0)
        err = None
    except Exception as exc:  # noqa: BLE001 - the refusal is the check
        err = exc
    finally:
        _socket.socket = real_socket
    check("UDP TC-set packet -> _query refuses",
          isinstance(err, ValueError) and "truncation (TC set)" in str(err),
          f"err={err}")

    import threading
    srv = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
    srv.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
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
            resp = struct.pack(">HHHHHH", txid, 0x8700, 1, 1, 0, 0) + q[12:]
            conn.sendall(struct.pack(">H", len(resp)) + resp)
        srv.close()

    threading.Thread(target=_serve_once, daemon=True).start()
    try:
        smoke._query_tcp("alice.cyberspace", 1, "127.0.0.1", port,
                         timeout=2.0)
        err = None
    except Exception as exc:  # noqa: BLE001 - the refusal is the check
        err = exc
    check("TCP TC-set packet -> _query_tcp refuses",
          isinstance(err, ValueError) and "truncation (TC set)" in str(err),
          f"err={err}")


# 5r. A reply must not claim recursion available: client._parse_response
#     refuses an RA-set packet (the daemon is authoritative-only and
#     neither response builder ever sets RA), but both smoke wires
#     checked only QR+AA+opcode+RD+TC, so a QR|AA|RD|RA-set packet
#     claiming an answer earned a PASS for a recursive resolver's word.
#     Both refuse.
def _test_ra_bit():
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
                struct.pack(">HHHHHH", txid, 0x8580, 1, 1, 0, 0)
                + packet[12:]
                + struct.pack(">HHHIH", 0xC00C, 1, 1, 120, 4)
                + _socket.inet_aton("10.9.8.7"))
            return len(packet)

        def recvfrom(self, n):
            return canned["resp"], ("127.0.0.1", 5399)

    real_socket = _socket.socket
    _socket.socket = _FakeUdp
    try:
        smoke._query("alice.cyberspace", 1, "127.0.0.1", 5399, timeout=1.0)
        err = None
    except Exception as exc:  # noqa: BLE001 - the refusal is the check
        err = exc
    finally:
        _socket.socket = real_socket
    check("UDP RA-set packet -> _query refuses",
          isinstance(err, ValueError) and "recursion available (RA set)" in str(err),
          f"err={err}")

    import threading
    srv = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
    srv.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
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
            resp = struct.pack(">HHHHHH", txid, 0x8580, 1, 1, 0, 0) + q[12:]
            conn.sendall(struct.pack(">H", len(resp)) + resp)
        srv.close()

    threading.Thread(target=_serve_once, daemon=True).start()
    try:
        smoke._query_tcp("alice.cyberspace", 1, "127.0.0.1", port,
                         timeout=2.0)
        err = None
    except Exception as exc:  # noqa: BLE001 - the refusal is the check
        err = exc
    check("TCP RA-set packet -> _query_tcp refuses",
          isinstance(err, ValueError) and "recursion available (RA set)" in str(err),
          f"err={err}")


# 5s. A reply must not set the reserved Z bit: client._parse_response
#     refuses a Z-set packet (neither daemon response builder ever
#     sets Z — its replies are QR|AA|RD echo|rcode only), but both
#     smoke wires checked only QR+AA+opcode+RD+TC+RA, so a
#     QR|AA|RD|Z-set packet claiming an answer earned a PASS for a
#     packet that is not one of the daemon's replies. Both refuse.
def _test_z_bit():
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
                struct.pack(">HHHHHH", txid, 0x8540, 1, 1, 0, 0)
                + packet[12:]
                + struct.pack(">HHHIH", 0xC00C, 1, 1, 120, 4)
                + _socket.inet_aton("10.9.8.7"))
            return len(packet)

        def recvfrom(self, n):
            return canned["resp"], ("127.0.0.1", 5399)

    real_socket = _socket.socket
    _socket.socket = _FakeUdp
    try:
        smoke._query("alice.cyberspace", 1, "127.0.0.1", 5399, timeout=1.0)
        err = None
    except Exception as exc:  # noqa: BLE001 - the refusal is the check
        err = exc
    finally:
        _socket.socket = real_socket
    check("UDP Z-set packet -> _query refuses",
          isinstance(err, ValueError) and "reserved Z bit" in str(err),
          f"err={err}")

    import threading
    srv = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
    srv.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
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
            resp = struct.pack(">HHHHHH", txid, 0x8540, 1, 1, 0, 0) + q[12:]
            conn.sendall(struct.pack(">H", len(resp)) + resp)
        srv.close()

    threading.Thread(target=_serve_once, daemon=True).start()
    try:
        smoke._query_tcp("alice.cyberspace", 1, "127.0.0.1", port,
                         timeout=2.0)
        err = None
    except Exception as exc:  # noqa: BLE001 - the refusal is the check
        err = exc
    check("TCP Z-set packet -> _query_tcp refuses",
          isinstance(err, ValueError) and "reserved Z bit" in str(err),
          f"err={err}")


# 5t. A reply must not set AD or CD: client._parse_response refuses
#     an AD/CD-set packet (its query sends RD only, no AD/CD, and
#     neither daemon response builder ever sets them — an AD/CD-set
#     packet carries a recursive checker's marks, not the daemon's),
#     but both smoke wires checked only QR+AA+opcode+RD+TC+RA+Z, so a
#     QR|AA|RD|AD- or CD-set packet claiming an answer earned a PASS.
#     Both wires refuse either bit.
def _test_ad_cd_bits():
    import socket as _socket
    import threading

    for label, flags in (("AD", 0x8520), ("CD", 0x8510)):
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
                    struct.pack(">HHHHHH", txid, flags, 1, 1, 0, 0)
                    + packet[12:]
                    + struct.pack(">HHHIH", 0xC00C, 1, 1, 120, 4)
                    + _socket.inet_aton("10.9.8.7"))
                return len(packet)

            def recvfrom(self, n):
                return canned["resp"], ("127.0.0.1", 5399)

        real_socket = _socket.socket
        _socket.socket = _FakeUdp
        try:
            smoke._query("alice.cyberspace", 1, "127.0.0.1", 5399, timeout=1.0)
            err = None
        except Exception as exc:  # noqa: BLE001 - the refusal is the check
            err = exc
        finally:
            _socket.socket = real_socket
        check(f"UDP {label}-set packet -> _query refuses",
              isinstance(err, ValueError) and "AD/CD bits" in str(err),
              f"err={err}")

        srv = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        srv.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        port = srv.getsockname()[1]
        srv.listen(1)

        def _serve_once(srv=srv, flags=flags):
            conn, _ = srv.accept()
            with conn:
                head = conn.recv(2)
                (ln,) = struct.unpack(">H", head)
                q = b""
                while len(q) < ln:
                    q += conn.recv(ln - len(q))
                (txid,) = struct.unpack(">H", q[:2])
                resp = struct.pack(">HHHHHH", txid, flags, 1, 1, 0, 0) + q[12:]
                conn.sendall(struct.pack(">H", len(resp)) + resp)
            srv.close()

        threading.Thread(target=_serve_once, daemon=True).start()
        try:
            smoke._query_tcp("alice.cyberspace", 1, "127.0.0.1", port,
                             timeout=2.0)
            err = None
        except Exception as exc:  # noqa: BLE001 - the refusal is the check
            err = exc
        check(f"TCP {label}-set packet -> _query_tcp refuses",
              isinstance(err, ValueError) and "AD/CD bits" in str(err),
              f"err={err}")


# 5u. A reply must not carry authority/additional records:
#     client._parse_response refuses nscount/arcount nonzero
#     (neither daemon response builder ever emits any —
#     build_response sends header counts 0/0 for those sections
#     and error_response sends 0/0/0/0; records the parser would
#     only skip can carry nothing the daemon meant), but both
#     smoke wires ignored ns/ar entirely, so a QR|AA|RD-set
#     packet with ns=1 or ar=1 claiming an answer earned a PASS.
#     Both wires refuse either count.
def _test_ns_ar_counts():
    import socket as _socket
    import threading

    for label, counts in (("NS", (1, 1, 1, 0)), ("AR", (1, 1, 0, 1))):
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
                    struct.pack(">HHHHHH", txid, 0x8500, *counts)
                    + packet[12:]
                    + struct.pack(">HHHIH", 0xC00C, 1, 1, 120, 4)
                    + _socket.inet_aton("10.9.8.7"))
                return len(packet)

            def recvfrom(self, n):
                return canned["resp"], ("127.0.0.1", 5399)

        real_socket = _socket.socket
        _socket.socket = _FakeUdp
        try:
            smoke._query("alice.cyberspace", 1, "127.0.0.1", 5399, timeout=1.0)
            err = None
        except Exception as exc:  # noqa: BLE001 - the refusal is the check
            err = exc
        finally:
            _socket.socket = real_socket
        check(f"UDP {label}-count packet -> _query refuses",
              isinstance(err, ValueError) and "authority/additional" in str(err),
              f"err={err}")

        srv = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        srv.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        port = srv.getsockname()[1]
        srv.listen(1)

        def _serve_once(srv=srv, counts=counts):
            conn, _ = srv.accept()
            with conn:
                head = conn.recv(2)
                (ln,) = struct.unpack(">H", head)
                q = b""
                while len(q) < ln:
                    q += conn.recv(ln - len(q))
                (txid,) = struct.unpack(">H", q[:2])
                resp = struct.pack(">HHHHHH", txid, 0x8500, *counts) + q[12:]
                conn.sendall(struct.pack(">H", len(resp)) + resp)
            srv.close()

        threading.Thread(target=_serve_once, daemon=True).start()
        try:
            smoke._query_tcp("alice.cyberspace", 1, "127.0.0.1", port,
                             timeout=2.0)
            err = None
        except Exception as exc:  # noqa: BLE001 - the refusal is the check
            err = exc
        check(f"TCP {label}-count packet -> _query_tcp refuses",
              isinstance(err, ValueError) and "authority/additional" in str(err),
              f"err={err}")


# 5v. A reply must echo exactly one question: client._parse_response
#     refuses qdcount != 1 when a qname was asked (this smoke always
#     asks one — _build_query emits QDCOUNT=1 and both daemon response
#     builders echo exactly that one question), but both smoke wires
#     unpacked qd and ignored it, so a QR|AA|RD-set packet with qd=0
#     or qd=2 claiming an answer earned a PASS for a reply to no
#     question, or to a different batch. Both wires refuse either.
def _test_qd_count():
    import socket as _socket
    import threading

    for label, counts in (("QD0", (0, 1, 0, 0)), ("QD2", (2, 1, 0, 0))):
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
                    struct.pack(">HHHHHH", txid, 0x8500, *counts)
                    + packet[12:])
                return len(packet)

            def recvfrom(self, n):
                return canned["resp"], ("127.0.0.1", 5399)

        real_socket = _socket.socket
        _socket.socket = _FakeUdp
        try:
            smoke._query("alice.cyberspace", 1, "127.0.0.1", 5399, timeout=1.0)
            err = None
        except Exception as exc:  # noqa: BLE001 - the refusal is the check
            err = exc
        finally:
            _socket.socket = real_socket
        check(f"UDP {label} packet -> _query refuses",
              isinstance(err, ValueError) and "exactly one question" in str(err),
              f"err={err}")

        srv = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        srv.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        port = srv.getsockname()[1]
        srv.listen(1)

        def _serve_once(srv=srv, counts=counts):
            conn, _ = srv.accept()
            with conn:
                head = conn.recv(2)
                (ln,) = struct.unpack(">H", head)
                q = b""
                while len(q) < ln:
                    q += conn.recv(ln - len(q))
                (txid,) = struct.unpack(">H", q[:2])
                resp = struct.pack(">HHHHHH", txid, 0x8500, *counts) + q[12:]
                conn.sendall(struct.pack(">H", len(resp)) + resp)
            srv.close()

        threading.Thread(target=_serve_once, daemon=True).start()
        try:
            smoke._query_tcp("alice.cyberspace", 1, "127.0.0.1", port,
                             timeout=2.0)
            err = None
        except Exception as exc:  # noqa: BLE001 - the refusal is the check
            err = exc
        check(f"TCP {label} packet -> _query_tcp refuses",
              isinstance(err, ValueError) and "exactly one question" in str(err),
              f"err={err}")


# 5w. A reply must end exactly at its counted sections:
#     client._parse_response refuses bytes left over after the
#     counted sections are consumed (neither daemon response
#     builder ever emits any — build_response ends exactly at its
#     last answer's rdata and error_response is a bare header plus
#     the echoed question), but both smoke wires never read the
#     body at all, so a QR|AA|RD-set packet with junk appended
#     after its question/answers earned a PASS for bytes the
#     daemon never sent. Both wires refuse trailing bytes, after
#     an answer and after an empty (NXDOMAIN-shaped) reply alike.
def _test_trailing_bytes():
    import socket as _socket
    import threading

    for label, counts, tail in (
            ("ANSWER", (1, 1, 0, 0), b"\xde\xad\xbe\xef"),
            ("EMPTY", (1, 0, 0, 0), b"\xde\xad")):
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
                body = packet[12:]
                if counts[1]:
                    body += (struct.pack(">HHHIH", 0xC00C, 1, 1, 120, 4)
                             + _socket.inet_aton("10.9.8.7"))
                canned["resp"] = (
                    struct.pack(">HHHHHH", txid, 0x8500, *counts)
                    + body + tail)
                return len(packet)

            def recvfrom(self, n):
                return canned["resp"], ("127.0.0.1", 5399)

        real_socket = _socket.socket
        _socket.socket = _FakeUdp
        try:
            smoke._query("alice.cyberspace", 1, "127.0.0.1", 5399, timeout=1.0)
            err = None
        except Exception as exc:  # noqa: BLE001 - the refusal is the check
            err = exc
        finally:
            _socket.socket = real_socket
        check(f"UDP trailing-bytes ({label}) packet -> _query refuses",
              isinstance(err, ValueError) and "trailing bytes" in str(err),
              f"err={err}")

        srv = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        srv.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        port = srv.getsockname()[1]
        srv.listen(1)

        def _serve_once(srv=srv, counts=counts, tail=tail):
            conn, _ = srv.accept()
            with conn:
                head = conn.recv(2)
                (ln,) = struct.unpack(">H", head)
                q = b""
                while len(q) < ln:
                    q += conn.recv(ln - len(q))
                (txid,) = struct.unpack(">H", q[:2])
                body = q[12:]
                if counts[1]:
                    body += (struct.pack(">HHHIH", 0xC00C, 1, 1, 120, 4)
                             + _socket.inet_aton("10.9.8.7"))
                resp = (struct.pack(">HHHHHH", txid, 0x8500, *counts)
                        + body + tail)
                conn.sendall(struct.pack(">H", len(resp)) + resp)
            srv.close()

        threading.Thread(target=_serve_once, daemon=True).start()
        try:
            smoke._query_tcp("alice.cyberspace", 1, "127.0.0.1", port,
                             timeout=2.0)
            err = None
        except Exception as exc:  # noqa: BLE001 - the refusal is the check
            err = exc
        check(f"TCP trailing-bytes ({label}) packet -> _query_tcp refuses",
              isinstance(err, ValueError) and "trailing bytes" in str(err),
              f"err={err}")


# 5x. A reply must echo THIS question: client._parse_response refuses
#     an echoed question naming a different name (or family/class)
#     than the one asked — its answers belong to another question —
#     but both smoke wires only counted qd (==1) and walked the
#     question's bytes without reading them, so a packet echoing
#     mallory.cyberspace (or alice as AAAA/CH) claiming an answer
#     earned a PASS. Both wires refuse name, qtype and qclass drift.
def _test_echoed_question():
    import socket as _socket
    import threading

    def _enc(name):
        return b"".join(bytes([len(p)]) + p.encode("ascii")
                        for p in name.split(".")) + b"\x00"

    variants = (
        ("NAME", lambda q: _enc("mallory.cyberspace") + q[-4:]),
        ("QTYPE", lambda q: q[:-4] + struct.pack(">HH", 28, 1)),
        ("QCLASS", lambda q: q[:-4] + struct.pack(">HH", 1, 3)),
    )
    for label, mutate in variants:
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
                    + mutate(packet[12:])
                    + struct.pack(">HHHIH", 0xC00C, 1, 1, 120, 4)
                    + _socket.inet_aton("10.9.8.7"))
                return len(packet)

            def recvfrom(self, n):
                return canned["resp"], ("127.0.0.1", 5399)

        real_socket = _socket.socket
        _socket.socket = _FakeUdp
        try:
            smoke._query("alice.cyberspace", 1, "127.0.0.1", 5399,
                         timeout=1.0)
            err = None
        except Exception as exc:  # noqa: BLE001 - refusal is the check
            err = exc
        finally:
            _socket.socket = real_socket
        check(f"UDP different-question ({label}) -> _query refuses",
              isinstance(err, ValueError)
              and "different question" in str(err), f"err={err}")

        srv = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        srv.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        port = srv.getsockname()[1]
        srv.listen(1)

        def _serve_once(srv=srv, mutate=mutate):
            conn, _ = srv.accept()
            with conn:
                head = conn.recv(2)
                (ln,) = struct.unpack(">H", head)
                q = b""
                while len(q) < ln:
                    q += conn.recv(ln - len(q))
                (txid,) = struct.unpack(">H", q[:2])
                resp = (struct.pack(">HHHHHH", txid, 0x8500, 1, 1, 0, 0)
                        + mutate(q[12:])
                        + struct.pack(">HHHIH", 0xC00C, 1, 1, 120, 4)
                        + _socket.inet_aton("10.9.8.7"))
                conn.sendall(struct.pack(">H", len(resp)) + resp)
            srv.close()

        threading.Thread(target=_serve_once, daemon=True).start()
        try:
            smoke._query_tcp("alice.cyberspace", 1, "127.0.0.1", port,
                             timeout=2.0)
            err = None
        except Exception as exc:  # noqa: BLE001 - refusal is the check
            err = exc
        check(f"TCP different-question ({label}) -> _query_tcp refuses",
              isinstance(err, ValueError)
              and "different question" in str(err), f"err={err}")


# 5y. An answer must be owned by the asked name: client._parse_response
#     refuses a collected record whose owner differs from the asked
#     name (the daemon builds every answer with a pointer back to the
#     question name), but both smoke wires only counted answers and
#     walked them for the trailing check without reading the owner,
#     so a packet answering alice's question with a record owned by
#     mallory.cyberspace earned a PASS for a stranger's address.
#     Both wires refuse an answer owned by a different name.
def _test_answer_owner():
    import socket as _socket
    import threading

    def _enc(name):
        return b"".join(bytes([len(p)]) + p.encode("ascii")
                        for p in name.split(".")) + b"\x00"

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
                + packet[12:]
                + _enc("mallory.cyberspace")
                + struct.pack(">HHIH", 1, 1, 120, 4)
                + _socket.inet_aton("10.9.8.7"))
            return len(packet)

        def recvfrom(self, n):
            return canned["resp"], ("127.0.0.1", 5399)

    real_socket = _socket.socket
    _socket.socket = _FakeUdp
    try:
        smoke._query("alice.cyberspace", 1, "127.0.0.1", 5399,
                     timeout=1.0)
        err = None
    except Exception as exc:  # noqa: BLE001 - refusal is the check
        err = exc
    finally:
        _socket.socket = real_socket
    check("UDP stranger-owner answer -> _query refuses",
          isinstance(err, ValueError)
          and "owned by a different name" in str(err), f"err={err}")

    srv = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
    srv.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    srv.listen(1)

    def _serve_once(srv=srv):
        conn, _ = srv.accept()
        with conn:
            head = conn.recv(2)
            (ln,) = struct.unpack(">H", head)
            q = b""
            while len(q) < ln:
                q += conn.recv(ln - len(q))
            (txid,) = struct.unpack(">H", q[:2])
            resp = (struct.pack(">HHHHHH", txid, 0x8500, 1, 1, 0, 0)
                    + q[12:]
                    + _enc("mallory.cyberspace")
                    + struct.pack(">HHIH", 1, 1, 120, 4)
                    + _socket.inet_aton("10.9.8.7"))
            conn.sendall(struct.pack(">H", len(resp)) + resp)
        srv.close()

    threading.Thread(target=_serve_once, daemon=True).start()
    try:
        smoke._query_tcp("alice.cyberspace", 1, "127.0.0.1", port,
                         timeout=2.0)
        err = None
    except Exception as exc:  # noqa: BLE001 - refusal is the check
        err = exc
    check("TCP stranger-owner answer -> _query_tcp refuses",
          isinstance(err, ValueError)
          and "owned by a different name" in str(err), f"err={err}")


# 5z. An answer must be a record the daemon ever sends:
#     client._parse_response refuses any answer whose type is not
#     A/AAAA, whose class is not IN, or whose rdata length does not
#     match its type (A is exactly 4, AAAA exactly 16 — the daemon's
#     handler answers only the asked family, build_response hard-
#     codes class IN), but both smoke wires walked the answer section
#     for owner/trailing only and never read type/class/rdlen, so a
#     QR|AA|RD-set packet answering alice.cyberspace with a TXT record
#     (or an A record under class CH, or a short rdata) earned a PASS
#     for a record the daemon never sends. Both wires refuse all.
def _test_answer_type_class():
    import socket as _socket
    import threading

    variants = (
        ("TXT", 16, 1, b"\x03foo", "type or class"),
        ("non-IN", 1, 3, _socket.inet_aton("10.9.8.7"), "type or class"),
        ("A-rdlen5", 1, 1, b"\x0a\x09\x08\x07\x06", "rdata length"),
        ("AAAA-rdlen4", 28, 1, _socket.inet_aton("10.9.8.7"),
         "rdata length"),
    )
    for label, rtype, rclass, rdata, frag in variants:
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
                    + packet[12:]
                    + struct.pack(">HHHIH", 0xC00C, rtype, rclass, 120,
                                  len(rdata))
                    + rdata)
                return len(packet)

            def recvfrom(self, n):
                return canned["resp"], ("127.0.0.1", 5399)

        real_socket = _socket.socket
        _socket.socket = _FakeUdp
        try:
            smoke._query("alice.cyberspace", 1, "127.0.0.1", 5399,
                         timeout=1.0)
            err = None
        except Exception as exc:  # noqa: BLE001 - refusal is the check
            err = exc
        finally:
            _socket.socket = real_socket
        check(f"UDP {label} answer -> _query refuses",
              isinstance(err, ValueError) and frag in str(err),
              f"err={err}")

        srv = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        srv.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        port = srv.getsockname()[1]
        srv.listen(1)

        def _serve_once(srv=srv, rtype=rtype, rclass=rclass, rdata=rdata):
            conn, _ = srv.accept()
            with conn:
                head = conn.recv(2)
                (ln,) = struct.unpack(">H", head)
                q = b""
                while len(q) < ln:
                    q += conn.recv(ln - len(q))
                (txid,) = struct.unpack(">H", q[:2])
                resp = (struct.pack(">HHHHHH", txid, 0x8500, 1, 1, 0, 0)
                        + q[12:]
                        + struct.pack(">HHHIH", 0xC00C, rtype, rclass,
                                      120, len(rdata))
                        + rdata)
                conn.sendall(struct.pack(">H", len(resp)) + resp)
            srv.close()

        threading.Thread(target=_serve_once, daemon=True).start()
        try:
            smoke._query_tcp("alice.cyberspace", 1, "127.0.0.1", port,
                             timeout=2.0)
            err = None
        except Exception as exc:  # noqa: BLE001 - refusal is the check
            err = exc
        check(f"TCP {label} answer -> _query_tcp refuses",
              isinstance(err, ValueError) and frag in str(err),
              f"err={err}")


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


# 7. _build_query refuses a malformed name/qtype instead of raising
#    AttributeError/TypeError/struct.error or aliasing it (twin of
#    client._build_query): True built qtype A, an empty label built a
#    different name than the caller wrote, a 64-byte label wrote a
#    corrupt length byte.
def _test_build_query_malformed():
    bad = [
        (None, 1), (123, 1), (b"alice.cyberspace", 1),
        ("alice.cyberspace", True), ("alice.cyberspace", 65536),
        ("alice.cyberspace", -1), ("alice.cyberspace", "1"),
        ("alice.cyberspace", None), ("alice.cyberspace", 1.0),
        ("", 1), ("alice..cyberspace", 1), (".cyberspace", 1),
        ("alice.cyberspace.", 1), ("éalice.cyberspace", 1),
        ("a" * 64 + ".cyberspace", 1),
        (".".join(["a" * 63] * 5), 1),
    ]
    for name, qtype in bad:
        try:
            smoke._build_query(name, qtype)
            err = None
        except Exception as exc:  # noqa: BLE001 - refusal is the check
            err = exc
        check(f"_build_query({name!r}, {qtype!r}) -> ValueError",
              isinstance(err, ValueError), f"err={err}")
    pkt, _txid = smoke._build_query("genesis.cyberspace", 28)
    qtype, _qclass = struct.unpack(">HH", pkt[-4:])
    check("_build_query valid AAAA still builds", qtype == 28)


# 8. _query/_query_tcp refuse a malformed timeout instead of handing
#    it raw to the socket (twin of client._check_timeout): None blocked
#    forever on a silent daemon, True aliased to 1 second, a string
#    escaped as TypeError, inf as OverflowError. The gate fires before
#    any socket is created, so a dead port still yields ValueError.
def _test_query_timeout_malformed():
    bad = [None, True, False, "3", 0, -1, 0.0,
           float("inf"), float("nan")]
    for fn in (smoke._query, smoke._query_tcp):
        for timeout in bad:
            try:
                fn("genesis.cyberspace", 1, "127.0.0.1", 53599,
                   timeout=timeout)
                err = None
            except Exception as exc:  # noqa: BLE001 - refusal is the check
                err = exc
            check(f"{fn.__name__}(timeout={timeout!r}) -> ValueError",
                  isinstance(err, ValueError), f"err={err}")
    check("_check_timeout valid values pass through",
          smoke._check_timeout(3.0) == 3.0 and smoke._check_timeout(1) == 1)


# 9. _read_exact refuses a malformed length instead of raising or
#    aliasing it (twin of client._read_exact / daemon._read_exact):
#    a str/None/float escaped as raw TypeError, True aliased to a
#    1-byte read, and a negative length silently returned b"" as if
#    a frame had been read. The gate fires before the socket is
#    touched, so a fake socket records no recv at all.
class _FakeSock:
    def __init__(self, data=b"abcd"):
        self.data = data
        self.recvd = False

    def recv(self, n):
        self.recvd = True
        chunk, self.data = self.data[:n], self.data[n:]
        return chunk


def _test_read_exact_malformed():
    for bad in ("2", None, 2.0, True, False, -1):
        sock = _FakeSock()
        try:
            smoke._read_exact(sock, bad, 3.0)
            err = None
        except Exception as exc:  # noqa: BLE001 - refusal is the check
            err = exc
        check(f"_read_exact(n={bad!r}) -> ValueError, socket untouched",
              isinstance(err, ValueError) and not sock.recvd,
              f"err={err} recvd={sock.recvd}")
    check("_read_exact valid lengths read exact",
          smoke._read_exact(_FakeSock(), 2, 3.0) == b"ab"
          and smoke._read_exact(_FakeSock(), 0, 3.0) == b"")


# 10. _query/_query_tcp/_server_target refuse a malformed port
#     instead of aliasing or leaking it (twin of client.resolve's
#     port gate): True aliased to port 1, a string reached the
#     transport as a service name, and out-of-range ports escaped
#     as OverflowError/OSError or were dialed as a different port.
#     main() gates --port, but a direct caller bypassed it.
def _test_query_port_malformed():
    bad = [True, False, 0, -1, 65536, "5353", 53.5, None]
    for port in bad:
        for fn in (smoke._query, smoke._query_tcp):
            try:
                fn("genesis.cyberspace", 1, "127.0.0.1", port)
                err = None
            except Exception as exc:  # noqa: BLE001 - refusal is the check
                err = exc
            check(f"{fn.__name__}(port={port!r}) -> ValueError",
                  isinstance(err, ValueError), f"err={err}")
        try:
            smoke._server_target("127.0.0.1", port)
            err = None
        except Exception as exc:  # noqa: BLE001 - refusal is the check
            err = exc
        check(f"_server_target(port={port!r}) -> ValueError",
              isinstance(err, ValueError), f"err={err}")
    check("_check_port valid ports pass through",
          smoke._check_port(1) == 1 and smoke._check_port(5353) == 5353
          and smoke._check_port(65535) == 65535)


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
    _test_udp_reply_source()
    _test_qr_bit()
    _test_aa_bit()
    _test_opcode()
    _test_rd_echo()
    _test_tc_bit()
    _test_ra_bit()
    _test_z_bit()
    _test_ad_cd_bits()
    _test_ns_ar_counts()
    _test_qd_count()
    _test_trailing_bytes()
    _test_echoed_question()
    _test_answer_owner()
    _test_answer_type_class()
    _test_packet_shape()
    _test_build_query_malformed()
    _test_query_timeout_malformed()
    _test_read_exact_malformed()
    _test_query_port_malformed()
    p, f = CASES["passed"], CASES["failed"]
    print(f"\n{CASES['passed']} passed, {CASES['failed']} failed")
    sys.exit(1 if f else 0)
