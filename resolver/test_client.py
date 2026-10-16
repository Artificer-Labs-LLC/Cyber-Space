"""Tests for the client-side resolver (resolver/client.py).

Drives the REAL TCP framing path over a real socketpair() with a real
server thread (parses with dns.parse_query, answers with
dns.build_response) — actual length-prefixed frames on a real transport.
The UDP path is driven through a scripted fake socket because the sandbox
blocks UDP sendto at the syscall layer (EPERM, verified in
hidden_files/resolver-wire-loopback-test.py); the fallback contract
(UDP failure -> TCP retry) is what these tests freeze.

Run: cd ~/workspace/cybernet && ./venv/bin/python -m unittest resolver.test_client
"""

import contextlib
import io
import os
import random
import socket
import struct
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from resolver import client, dns  # noqa: E402


def _read_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("eof")
        buf += chunk
    return buf


class _ServerThread(threading.Thread):
    """Real server side: reads framed queries, answers via dns codec."""

    def __init__(self, sock, handler):
        super().__init__(daemon=True)
        self.sock = sock
        self.handler = handler

    def run(self):
        try:
            while True:
                (n,) = struct.unpack(">H", _read_exact(self.sock, 2))
                query_raw = _read_exact(self.sock, n)
                try:
                    q = dns.parse_query(query_raw)
                except Exception:
                    continue
                resp = self.handler(q)
                self.sock.sendall(struct.pack(">H", len(resp)) + resp)
        except (ConnectionError, OSError):
            pass
        finally:
            self.sock.close()


def _a_response(q, addr="10.9.8.7"):
    return dns.build_response(q, [(1, 120, socket.inet_aton(addr))], rcode=0)


def _tcp_server(handler):
    a, b = socket.socketpair()
    _ServerThread(b, handler).start()
    return a


class _FakeUdpSock:
    """Scripted UDP socket: canned datagram or a scripted OSError."""

    def __init__(self, canned=None, exc=None):
        self.canned = canned
        self.exc = exc
        self.sent = []

    def settimeout(self, t):
        pass

    def sendto(self, data, addr):
        self.sent.append((data, addr))
        if self.exc is not None:
            raise self.exc
        return len(data)

    def recvfrom(self, n):
        if self.exc is not None:
            raise self.exc
        return self.canned, ("127.0.0.1", 5353)

    def close(self):
        pass


class ClientTests(unittest.TestCase):
    def test_tcp_round_trip_real_framing(self):
        """Real socketpair, real frames: A record parsed to text."""
        server = _tcp_server(_a_response)
        addrs = client.resolve("node.cyberspace", _tcp_sock=server, tcp_only=True)
        self.assertEqual(addrs, ["10.9.8.7"])

    def test_nxdomain_raises_name_not_found(self):
        server = _tcp_server(
            lambda q: dns.build_response(q, [], rcode=3)
        )
        with self.assertRaises(client.NameNotFound):
            client.resolve("junk.cyberspace", _tcp_sock=server, tcp_only=True)

    def test_noerror_no_answers_raises_resolve_error(self):
        """NODATA (NOERROR, empty answer) is not a success: returning []
        would make the CLI print nothing and exit 0 — a false success."""
        server = _tcp_server(lambda q: dns.build_response(q, [], rcode=0))
        with self.assertRaises(client.ResolveError):
            client.resolve("node.cyberspace", _tcp_sock=server, tcp_only=True)

    def test_wrong_family_only_raises_resolve_error(self):
        """An answer holding only the other family gives no usable address."""
        server = _tcp_server(
            lambda q: dns.build_response(
                q,
                [(28, 120, socket.inet_pton(socket.AF_INET6, "2001:db8::1"))],
                rcode=0,
            )
        )
        with self.assertRaises(client.ResolveError):
            client.resolve("node.cyberspace", _tcp_sock=server, tcp_only=True)

    def test_servfail_raises_resolve_error(self):
        server = _tcp_server(
            lambda q: dns.build_response(q, [], rcode=2)
        )
        with self.assertRaises(client.ResolveError):
            client.resolve("node.cyberspace", _tcp_sock=server, tcp_only=True)

    def test_txid_mismatch_raises(self):
        def tamper(q):
            resp = _a_response(q)
            return struct.pack(">H", q["id"] ^ 0xFFFF) + resp[2:]

        server = _tcp_server(tamper)
        with self.assertRaises(client.ResolveError):
            client.resolve("node.cyberspace", _tcp_sock=server, tcp_only=True)

    def test_garbage_response_raises(self):
        server = _tcp_server(lambda q: b"\xff\xff")
        with self.assertRaises(client.ResolveError):
            client.resolve("node.cyberspace", _tcp_sock=server, tcp_only=True)

    def test_udp_path_canned_datagram(self):
        class _Echo(_FakeUdpSock):
            def sendto(self, data, addr):
                parsed = dns.parse_query(data)
                self.canned = dns.build_response(
                    parsed, [(1, 120, socket.inet_aton("10.9.8.7"))], rcode=0
                )
                return len(data)

        addrs = client.resolve("node.cyberspace", _udp_sock=_Echo())
        self.assertEqual(addrs, ["10.9.8.7"])

    def test_server_host_bracketed_v6_stripped(self):
        """Daemon-parity: _bind_family strips "[::1]" to "::1"; the
        client must dial that same bare form, not the bracketed one."""
        self.assertEqual(client._server_host("[::1]"), "::1")
        self.assertEqual(client._server_host("::1"), "::1")
        self.assertEqual(client._server_host("127.0.0.1"), "127.0.0.1")
        self.assertEqual(client._server_host("[127.0.0.1]"), "127.0.0.1")
        self.assertEqual(client._server_host("localhost"), "localhost")

    def test_server_host_nonstring_raises_value_error(self):
        """resolve() gates its server, but a direct _server_host caller
        passing a non-string escaped as AttributeError from .strip()
        (None, an int, True) or TypeError from .startswith() (bytes)
        — neither the ValueError resolve() raises for a bad server
        nor the ResolveError the wires promise. All must raise
        ValueError at the source; valid strings untouched (above)."""
        for bad in (None, 123, 1.5, True, b"[::1]", ["::1"]):
            with self.assertRaises(ValueError, msg=repr(bad)):
                client._server_host(bad)

    def test_server_target_nonstring_host_raises_value_error_not_aliased(self):
        """ip_address() aliased a non-string host (123 -> 0.0.0.123,
        True -> 0.0.0.1, a 4-byte bytes host -> its dotted quad) and
        getaddrinfo aliased None to localhost — a daemon nobody named
        was dialed and source-checked as expected. Every non-string
        host must raise ValueError at the source; literals and
        hostnames untouched (below)."""
        for bad in (None, 123, True, b"\x7f\x00\x00\x01", 1.5):
            with self.assertRaises(ValueError, msg=repr(bad)):
                client._server_target(bad, 5353)

    def test_server_target_bad_port_raises_value_error_not_aliased(self):
        """_server_target returned a malformed port verbatim in the
        sockaddr: True aliased to port 1, a string reached the
        transport as a service name, 0/-1/65536/float/None were
        dialed or escaped later. Only a real int in 1..65535 is a
        port (bool excluded, twin of smoke._check_port); boundary
        ports keep their exact target."""
        for bad in (True, False, 0, -1, 65536, "5353", 5353.0, None):
            with self.assertRaises(ValueError, msg=repr(bad)):
                client._server_target("127.0.0.1", bad)
        for good in (1, 65535):
            _fam, target, _exp = client._server_target("127.0.0.1", good)
            self.assertEqual(target, ("127.0.0.1", good))

    def test_query_wires_bad_port_raises_resolve_error(self):
        """Through the wires a bad port is a transport failure:
        _query_udp (via _server_target) and _query_tcp promise
        ResolveError, never a verbatim dial of the malformed port."""
        packet = client._build_query(0x1234, "node.cyberspace",
                                     client.QTYPE_A)
        for bad in (True, 0, 65536, "5353", None):
            with self.assertRaises(client.ResolveError, msg=repr(bad)):
                client._query_udp(0x1234, packet, "127.0.0.1", bad, 1.0,
                                  sock=_FakeUdpSock())
            with self.assertRaises(client.ResolveError, msg=repr(bad)):
                client._query_tcp(0x1234, packet, "127.0.0.1", bad, 1.0)

    def test_query_wires_nonstring_server_raises_resolve_error(self):
        """Through the wires a bad server is a transport failure:
        _query_udp/_query_tcp promise ResolveError, never a raw
        AttributeError/TypeError/ValueError escape."""
        packet = client._build_query(0x1234, "node.cyberspace",
                                     client.QTYPE_A)
        for bad in (None, 123, True, b"127.0.0.1"):
            with self.assertRaises(client.ResolveError, msg=repr(bad)):
                client._query_udp(0x1234, packet, bad, 5353, 1.0,
                                  sock=_FakeUdpSock())
            with self.assertRaises(client.ResolveError, msg=repr(bad)):
                client._query_tcp(0x1234, packet, bad, 5353, 1.0)

    def test_query_wires_bad_packet_raises_resolve_error(self):
        """Through the wires a bad packet is a transport failure:
        a str/int/None packet escaped _query_tcp as a raw TypeError
        from len()/the frame concat and _query_udp as a raw TypeError
        from a real socket's sendto — neither the ResolveError both
        wires promise — and a stub socket could carry a non-bytes
        object onto the wire verbatim. Both wires refuse it before
        the socket is touched."""
        class _FakeTcpSock:
            def __init__(self):
                self.sent = []

            def settimeout(self, t):
                pass

            def sendall(self, data):
                self.sent.append(data)

            def recv(self, n):
                return b""

            def close(self):
                pass

        for bad in ("packet", 123, None, 1.5, True, [b"x"]):
            udp_sock = _FakeUdpSock()
            with self.assertRaises(client.ResolveError, msg=repr(bad)):
                client._query_udp(0x1234, bad, "127.0.0.1", 5353, 1.0,
                                  sock=udp_sock)
            self.assertEqual(udp_sock.sent, [])
            tcp_sock = _FakeTcpSock()
            with self.assertRaises(client.ResolveError, msg=repr(bad)):
                client._query_tcp(0x1234, bad, "127.0.0.1", 5353, 1.0,
                                  sock=tcp_sock)
            self.assertEqual(tcp_sock.sent, [])

    def test_query_udp_bytearray_packet_still_round_trips(self):
        """A bytearray packet is a real packet (twin of
        _parse_response's bytes/bytearray gate): it goes on the wire
        and its canned reply parses exactly as the bytes form's."""
        packet = client._build_query(0x1234, "node.cyberspace",
                                     client.QTYPE_A)
        parsed = dns.parse_query(packet)
        canned = dns.build_response(
            parsed, [(1, 120, socket.inet_aton("10.9.8.7"))], rcode=0)
        sock = _FakeUdpSock(canned=canned)
        _flags, answers = client._query_udp(
            0x1234, bytearray(packet), "127.0.0.1", 5353, 1.0,
            sock=sock, qname="node.cyberspace", qtype=1)
        self.assertEqual(answers, [(1, socket.inet_aton("10.9.8.7"))])

    def test_udp_bracketed_v6_server_dials_bare_literal(self):
        """server="[::1]" sends to ("::1", port) and accepts a reply
        sourced from ::1 — before, the bracketed form was compared
        and dialed verbatim and could never match or connect."""
        class _V6Echo(_FakeUdpSock):
            def sendto(self, data, addr):
                self.sent.append((data, addr))
                parsed = dns.parse_query(data)
                self.canned = dns.build_response(
                    parsed, [(1, 120, socket.inet_aton("10.9.8.7"))], rcode=0
                )
                return len(data)

            def recvfrom(self, n):
                return self.canned, ("::1", 5353)

        sock = _V6Echo()
        addrs = client.resolve("node.cyberspace", server="[::1]", _udp_sock=sock)
        self.assertEqual(addrs, ["10.9.8.7"])
        self.assertEqual(sock.sent[0][1], ("::1", 5353))

    def test_server_target_literals_keep_their_family(self):
        """Literals: _server_target keeps the exact old family/target
        and the literal itself (normalized) as expected source."""
        fam, target, expected = client._server_target("::1", 5353)
        self.assertEqual(fam, socket.AF_INET6)
        self.assertEqual(target, ("::1", 5353))
        self.assertEqual(expected, "::1")
        fam, target, expected = client._server_target("127.0.0.1", 5353)
        self.assertEqual(fam, socket.AF_INET)
        self.assertEqual(target, ("127.0.0.1", 5353))
        self.assertEqual(expected, "127.0.0.1")

    def test_udp_v6only_hostname_dials_resolved_family(self):
        """A v6-only hostname server: before, _query_udp guessed
        AF_INET from the string, sent to the unresolved hostname, and
        source-checked via v4-only gethostbyname — the UDP wire never
        reached a ::1 daemon (masked only by the TCP fallback). Now
        the socket is created from getaddrinfo's family and aimed at
        its sockaddr. Fake socket + fake getaddrinfo (sandbox forbids
        real UDP sendto, EPERM)."""
        from unittest import mock

        canned = {}

        class _FakeUdp:
            def __init__(self, family, kind, *a):
                canned["family"] = family

            def settimeout(self, t):
                pass

            def close(self):
                pass

            def sendto(self, packet, target):
                canned["target"] = target
                parsed = dns.parse_query(packet)
                canned["resp"] = dns.build_response(
                    parsed, [(1, 120, socket.inet_aton("10.9.8.7"))],
                    rcode=0)
                return len(packet)

            def recvfrom(self, n):
                return canned["resp"], ("::1", 5399)

        def _fake_gai(host, port, family=0, type=0, *a, **k):
            return [(socket.AF_INET6, socket.SOCK_DGRAM, 17, "",
                     ("::1", port, 0, 0))]

        packet = client._build_query(0x1234, "node.cyberspace",
                                     client.QTYPE_A)
        with mock.patch.object(socket, "socket", _FakeUdp), \
                mock.patch.object(socket, "getaddrinfo", _fake_gai):
            flags, answers = client._query_udp(
                0x1234, packet, "v6only.example", 5399, 1.0,
                qname="node.cyberspace", qtype=client.QTYPE_A)
        self.assertEqual(answers, [(1, socket.inet_aton("10.9.8.7"))])
        self.assertEqual(canned["family"], socket.AF_INET6)
        self.assertEqual(canned["target"], ("::1", 5399, 0, 0))

    def test_udp_hostname_injected_sock_dials_resolved_address(self):
        """Injected-sock path: a hostname server is still dialed at
        its resolved address, not the unresolved string, and a reply
        from that address passes the source check."""
        from unittest import mock

        def _fake_gai(host, port, family=0, type=0, *a, **k):
            return [(socket.AF_INET, socket.SOCK_DGRAM, 17, "",
                     ("127.0.0.1", port))]

        class _Echo(_FakeUdpSock):
            def sendto(self, data, addr):
                self.sent.append((data, addr))
                parsed = dns.parse_query(data)
                self.canned = dns.build_response(
                    parsed, [(1, 120, socket.inet_aton("10.9.8.7"))],
                    rcode=0)
                return len(data)

        sock = _Echo()
        with mock.patch.object(socket, "getaddrinfo", _fake_gai):
            addrs = client.resolve("node.cyberspace",
                                   server="daemon.example", _udp_sock=sock)
        self.assertEqual(addrs, ["10.9.8.7"])
        self.assertEqual(sock.sent[0][1], ("127.0.0.1", 5353))

    def test_udp_unresolvable_hostname_raises_resolve_error(self):
        """An unresolvable hostname is a transport failure
        (ResolveError), honestly — never a parsed verdict."""
        from unittest import mock

        def _bad_gai(host, port, family=0, type=0, *a, **k):
            raise socket.gaierror("no such host")

        packet = client._build_query(0x1234, "node.cyberspace",
                                     client.QTYPE_A)
        with mock.patch.object(socket, "getaddrinfo", _bad_gai):
            with self.assertRaises(client.ResolveError):
                client._query_udp(0x1234, packet, "nope.example", 5399,
                                  1.0, qname="node.cyberspace",
                                  qtype=client.QTYPE_A)

    def test_tcp_bracketed_v6_server_dials_bare_literal(self):
        """TCP wire: create_connection receives the bare "::1", not
        "[::1]" (which it rejects as an unknown host)."""
        from unittest import mock

        server = _tcp_server(_a_response)
        seen = []

        def _fake_create(addr, timeout=None):
            seen.append(addr)
            return server

        with mock.patch.object(socket, "create_connection", _fake_create):
            addrs = client.resolve(
                "node.cyberspace", server="[::1]", port=5399, tcp_only=True
            )
        self.assertEqual(addrs, ["10.9.8.7"])
        self.assertEqual(seen, [("::1", 5399)])

    def test_udp_response_from_stranger_address_refused(self):
        """A flawless packet from the wrong source IP is not the daemon's
        answer: UDP is connectionless, so source IS the authentication
        the wire offers. Refused -> TCP fallback answers instead."""
        class _Stranger(_FakeUdpSock):
            def sendto(self, data, addr):
                parsed = dns.parse_query(data)
                self.canned = dns.build_response(
                    parsed, [(1, 120, socket.inet_aton("10.1.1.1"))], rcode=0
                )
                return len(data)

            def recvfrom(self, n):
                return self.canned, ("192.0.2.1", 5353)

        server = _tcp_server(_a_response)
        addrs = client.resolve(
            "node.cyberspace", _udp_sock=_Stranger(), _tcp_sock=server
        )
        self.assertEqual(addrs, ["10.9.8.7"])

    def test_udp_response_from_wrong_port_refused(self):
        """Right host, wrong port: still not the daemon that was asked."""
        class _WrongPort(_FakeUdpSock):
            def sendto(self, data, addr):
                parsed = dns.parse_query(data)
                self.canned = dns.build_response(
                    parsed, [(1, 120, socket.inet_aton("10.1.1.1"))], rcode=0
                )
                return len(data)

            def recvfrom(self, n):
                return self.canned, ("127.0.0.1", 9999)

        server = _tcp_server(_a_response)
        addrs = client.resolve(
            "node.cyberspace", _udp_sock=_WrongPort(), _tcp_sock=server
        )
        self.assertEqual(addrs, ["10.9.8.7"])

    def test_udp_failure_falls_back_to_tcp(self):
        """UDP OSError -> the TCP wire answers, addrs still returned."""
        dead = _FakeUdpSock(exc=OSError("sandbox EPERM"))
        server = _tcp_server(_a_response)
        addrs = client.resolve(
            "node.cyberspace", _udp_sock=dead, _tcp_sock=server
        )
        self.assertEqual(addrs, ["10.9.8.7"])

    def test_udp_truncated_tc_falls_back_to_tcp(self):
        """UDP answer with TC flag set -> retried over TCP, not trusted."""
        class _TC(_FakeUdpSock):
            def sendto(self, data, addr):
                parsed = dns.parse_query(data)
                resp = dns.build_response(parsed, [], rcode=0)
                flags = struct.unpack(">H", resp[2:4])[0] | 0x0200
                self.canned = resp[:2] + struct.pack(">H", flags) + resp[4:]
                return len(data)

        server = _tcp_server(_a_response)
        addrs = client.resolve("node.cyberspace", _udp_sock=_TC(), _tcp_sock=server)
        self.assertEqual(addrs, ["10.9.8.7"])

    def test_both_wires_down_raises_resolve_error(self):
        dead_udp = _FakeUdpSock(exc=OSError("down"))

        class _DeadTcp:
            def settimeout(self, t):
                pass

            def sendall(self, data):
                raise OSError("down")

            def recv(self, n):
                raise OSError("down")

            def close(self):
                pass

        with self.assertRaises(client.ResolveError):
            client.resolve(
                "node.cyberspace", _udp_sock=dead_udp, _tcp_sock=_DeadTcp()
            )

    def test_bad_qtype_raises_value_error(self):
        with self.assertRaises(ValueError):
            client.resolve("node.cyberspace", qtype="MX")

    def test_nonstring_qtype_raises_value_error_not_attribute_error(self):
        """A non-string qtype escaped as a raw AttributeError from
        .upper() — not the ValueError an unsupported string raises.
        Every malformed qtype must read as ValueError."""
        for bad in (None, 1, True, 1.0, b"A"):
            with self.assertRaises(ValueError, msg=f"qtype={bad!r}"):
                client.resolve("node.cyberspace", qtype=bad)

    def test_nonstring_name_raises_value_error_not_attribute_error(self):
        """A non-string name escaped as a raw AttributeError/TypeError
        from .endswith() inside _build_query — not the ValueError a
        malformed string name raises there. Every malformed name must
        read as ValueError."""
        for bad in (None, 1, True, 1.0, b"node.cyberspace"):
            with self.assertRaises(ValueError, msg=f"name={bad!r}"):
                client.resolve(bad)

    def test_nonstring_server_raises_value_error_not_attribute_error(self):
        """A non-string server escaped as a raw AttributeError/TypeError
        from .strip() inside _server_host — not the ValueError a
        malformed name/qtype raises in resolve(). Every malformed
        server must read as ValueError."""
        for bad in (None, 1, True, 1.0, b"127.0.0.1"):
            with self.assertRaises(ValueError, msg=f"server={bad!r}"):
                client.resolve("node.cyberspace", server=bad)

    def test_nonbool_tcp_only_raises_value_error_not_aliased(self):
        """tcp_only was read by bare truthiness: "false"/1/1.0/[1]
        silently forced the TCP-only wire and ""/0/None/[] silently
        allowed UDP — a wire choice matching no flag anyone set.
        Every non-bool tcp_only must read as ValueError at the
        source, before any wire is touched; real True/False are
        covered by the round-trip and UDP tests."""
        for bad in ("false", "true", 1, 0, 1.0, None, [1], []):
            with self.assertRaises(ValueError, msg=f"tcp_only={bad!r}"):
                client.resolve("node.cyberspace", tcp_only=bad)

    def test_query_wire_encoding(self):
        pkt = client._build_query(0x1234, "Node.Cyberspace.", 1)
        parsed = dns.parse_query(pkt)
        self.assertEqual(parsed["id"], 0x1234)
        self.assertEqual(parsed["qname"], "node.cyberspace")  # normalized
        self.assertEqual(parsed["qtype"], 1)
        self.assertTrue(parsed["rd"])

    def test_query_label_over_63_bytes_raises(self):
        with self.assertRaises(ValueError):
            client._build_query(0x1, "a" * 64 + ".cyberspace", 1)

    def test_query_label_exactly_63_bytes_ok(self):
        pkt = client._build_query(0x1, "a" * 63 + ".cyberspace", 1)
        self.assertEqual(dns.parse_query(pkt)["qname"],
                         "a" * 63 + ".cyberspace")

    def test_query_non_ascii_label_raises(self):
        with self.assertRaises(ValueError):
            client._build_query(0x1, "nødé.cyberspace", 1)

    def test_query_empty_label_raises_not_canonicalized(self):
        """An empty label must never silently query a different name:
        'alice..cyberspace' is not 'alice.cyberspace'."""
        for bad in ("alice..cyberspace", ".cyberspace", "alice.cyberspace.."):
            with self.assertRaises(ValueError, msg=bad):
                client._build_query(0x1, bad, 1)

    def test_query_empty_name_raises_not_root_query(self):
        """'' / '.' built a root query the daemon forwards upstream —
        a .cyberspace client must refuse it at the source."""
        for bad in ("", "."):
            with self.assertRaises(ValueError, msg=repr(bad)):
                client._build_query(0x1, bad, 1)

    def test_query_wire_name_over_255_raises(self):
        name = ".".join(["a" * 63] * 5) + ".cyberspace"
        with self.assertRaises(ValueError):
            client._build_query(0x1, name, 1)

    def test_query_bad_txid_raises_valueerror_not_aliased(self):
        """The txid was masked & 0xFFFF: 65536 silently built txid 0
        and -1 built 65535 — a query under a different transaction id
        than the caller chose — while a float/str txid escaped as
        TypeError. All must raise ValueError at the source."""
        for bad in (65536, -1, 1.5, "1", None, True):
            with self.assertRaises(ValueError, msg=repr(bad)):
                client._build_query(bad, "node.cyberspace", 1)

    def test_query_bad_qtype_raises_valueerror_not_aliased(self):
        """A bool qtype silently built as A (bool is an int subclass)
        and an out-of-range/non-int qtype escaped as struct.error /
        TypeError. All must raise ValueError at the source."""
        for bad in (70000, -1, 1.0, "A", None, True, False):
            with self.assertRaises(ValueError, msg=repr(bad)):
                client._build_query(0x1, "node.cyberspace", bad)

    def test_query_nonstring_qname_raises_valueerror(self):
        """resolve() gates the name's type, but a direct caller passing
        a non-string escaped as AttributeError/TypeError from
        .endswith() — not the ValueError _build_query's other malformed
        inputs raise. All must raise ValueError at the source."""
        for bad in (None, 123, 1.5, b"node.cyberspace", True, ["node"]):
            with self.assertRaises(ValueError, msg=repr(bad)):
                client._build_query(0x1, bad, 1)

    def test_query_txid_and_qtype_wire_boundaries_ok(self):
        for txid in (0, 65535):
            pkt = client._build_query(txid, "node.cyberspace", 65535)
            parsed = dns.parse_query(pkt)
            self.assertEqual(parsed["id"], txid)
            self.assertEqual(parsed["qtype"], 65535)

    def test_parse_response_bad_txid_raises_resolve_error_not_aliased(self):
        """The expected txid was compared as txid & 0xFFFF: 65536 and
        -65536 silently aliased to 0, so a packet for txid 0 was trusted
        as the answer to a transaction it never belonged to, and a
        float/str/None txid escaped as a raw TypeError. All must raise
        ResolveError — this parser's malformed/mistransaction contract."""
        resp = self._valid_response(txid=0)
        for bad in (65536, -65536, 1.5, "0", None, True, False):
            with self.assertRaises(client.ResolveError, msg=repr(bad)):
                client._parse_response(resp, bad, "node.cyberspace", 1)

    def test_parse_response_txid_wire_boundaries_ok(self):
        for txid in (0, 65535):
            resp = self._valid_response(txid=txid)
            _flags, answers = client._parse_response(
                resp, txid, "node.cyberspace", 1)
            self.assertEqual(len(answers), 1)

    def test_parse_response_bad_qtype_raises_resolve_error_not_aliased(self):
        """The expected qtype was compared with plain !=: True and
        1.0 compare equal to 1, so both silently aliased to A — a
        packet was trusted as answering the asked family when no
        real family was ever named. Every malformed expected qtype
        must raise ResolveError, this parser's contract."""
        resp = self._valid_response()
        for bad in (True, False, 1.0, "1", 65536, -1):
            with self.assertRaises(client.ResolveError, msg=repr(bad)):
                client._parse_response(resp, 0x42, "node.cyberspace", bad)

    def test_parse_response_non_bytes_packet_raises_resolve_error(self):
        """A str/None/int/float/list packet escaped as a raw TypeError
        from len()/struct.unpack, past this parser's ResolveError
        contract — the twin of the dns.parse_query non-bytes gate.
        A bytearray packet stays valid, exactly as in the codec."""
        resp = self._valid_response()
        for bad in ("x" * 20, None, 123, 1.5, True, [1] * 20):
            with self.assertRaises(client.ResolveError, msg=repr(bad)):
                client._parse_response(bad, 0x42, "node.cyberspace", 1)
        _flags, answers = client._parse_response(
            bytearray(resp), 0x42, "node.cyberspace", 1)
        self.assertEqual(len(answers), 1)

    def test_parse_response_qtype_none_and_boundaries_ok(self):
        resp = self._valid_response()
        _flags, answers = client._parse_response(resp, 0x42)
        self.assertEqual(len(answers), 1)
        _flags, answers = client._parse_response(
            resp, 0x42, "node.cyberspace", 1)
        self.assertEqual(len(answers), 1)

    def _valid_response(self, txid=0x42):
        q = dns.parse_query(client._build_query(txid, "node.cyberspace", 1))
        return dns.build_response(
            q, [(1, 120, socket.inet_aton("10.9.8.7"))], rcode=0
        )

    def test_parse_response_garbled_question_name_raises_resolve_error(self):
        resp = bytearray(self._valid_response())
        resp[12] = 0xFF  # bad label-length bits in the echoed question
        with self.assertRaises(client.ResolveError):
            client._parse_response(bytes(resp), 0x42)

    def test_parse_response_truncated_answer_raises_resolve_error(self):
        resp = self._valid_response()
        with self.assertRaises(client.ResolveError):
            # 12 header + 21 question + only 5 of the 12 answer bytes
            client._parse_response(resp[:38], 0x42)

    def test_parse_response_truncated_rdata_raises_resolve_error(self):
        resp = self._valid_response()
        with self.assertRaises(client.ResolveError):
            client._parse_response(resp[:-2], 0x42)  # rdata claims 4, holds 2

    def test_parse_response_qr_clear_raises_resolve_error(self):
        """A query-shaped packet (QR clear) is not an answer, txid or not."""
        resp = bytearray(self._valid_response())
        flags = struct.unpack(">H", bytes(resp[2:4]))[0] & ~0x8000
        resp[2:4] = struct.pack(">H", flags)
        with self.assertRaises(client.ResolveError):
            client._parse_response(bytes(resp), 0x42)

    def test_parse_response_aa_clear_raises_resolve_error(self):
        """An AA-clear packet is not the daemon's authoritative answer
        for the zone — every reply the daemon builds sets AA."""
        resp = bytearray(self._valid_response())
        flags = struct.unpack(">H", bytes(resp[2:4]))[0] & ~0x0400
        resp[2:4] = struct.pack(">H", flags)
        with self.assertRaises(client.ResolveError):
            client._parse_response(bytes(resp), 0x42, "node.cyberspace", 1)

    def test_resolve_aa_clear_raises_resolve_error(self):
        def tamper(q):
            resp = _a_response(q)
            flags = struct.unpack(">H", resp[2:4])[0] & ~0x0400
            return resp[:2] + struct.pack(">H", flags) + resp[4:]

        server = _tcp_server(tamper)
        with self.assertRaises(client.ResolveError):
            client.resolve("node.cyberspace", _tcp_sock=server, tcp_only=True)

    def test_parse_response_opcode_set_raises_resolve_error(self):
        """A nonzero-opcode packet is not a reply to a standard query —
        the daemon only ever answers opcode 0."""
        resp = bytearray(self._valid_response())
        flags = struct.unpack(">H", bytes(resp[2:4]))[0] | 0x0800
        resp[2:4] = struct.pack(">H", flags)
        with self.assertRaises(client.ResolveError):
            client._parse_response(bytes(resp), 0x42, "node.cyberspace", 1)

    def test_resolve_opcode_set_raises_resolve_error(self):
        def tamper(q):
            resp = _a_response(q)
            flags = struct.unpack(">H", resp[2:4])[0] | 0x0800
            return resp[:2] + struct.pack(">H", flags) + resp[4:]

        server = _tcp_server(tamper)
        with self.assertRaises(client.ResolveError):
            client.resolve("node.cyberspace", _tcp_sock=server, tcp_only=True)

    def test_parse_response_rd_clear_raises_resolve_error(self):
        """An RD-clear packet is not the daemon's reply to this query —
        the client always sends RD and build_response echoes it."""
        resp = bytearray(self._valid_response())
        flags = struct.unpack(">H", bytes(resp[2:4]))[0] & ~0x0100
        resp[2:4] = struct.pack(">H", flags)
        with self.assertRaises(client.ResolveError):
            client._parse_response(bytes(resp), 0x42, "node.cyberspace", 1)

    def test_resolve_rd_clear_raises_resolve_error(self):
        def tamper(q):
            resp = _a_response(q)
            flags = struct.unpack(">H", resp[2:4])[0] & ~0x0100
            return resp[:2] + struct.pack(">H", flags) + resp[4:]

        server = _tcp_server(tamper)
        with self.assertRaises(client.ResolveError):
            client.resolve("node.cyberspace", _tcp_sock=server, tcp_only=True)

    def test_parse_response_tc_set_raises_resolve_error(self):
        """A TC-set packet claims its answer was truncated — neither
        daemon builder ever sets TC, so it is not trusted on any wire."""
        resp = bytearray(self._valid_response())
        flags = struct.unpack(">H", bytes(resp[2:4]))[0] | 0x0200
        resp[2:4] = struct.pack(">H", flags)
        with self.assertRaises(client.ResolveError):
            client._parse_response(bytes(resp), 0x42, "node.cyberspace", 1)

    def test_resolve_tc_set_over_tcp_raises_resolve_error(self):
        def tamper(q):
            resp = _a_response(q)
            flags = struct.unpack(">H", resp[2:4])[0] | 0x0200
            return resp[:2] + struct.pack(">H", flags) + resp[4:]

        server = _tcp_server(tamper)
        with self.assertRaises(client.ResolveError):
            client.resolve("node.cyberspace", _tcp_sock=server, tcp_only=True)

    def test_parse_response_ra_set_raises_resolve_error(self):
        """An RA-set packet claims recursion was available — the daemon
        is authoritative-only and neither builder ever sets RA."""
        resp = bytearray(self._valid_response())
        flags = struct.unpack(">H", bytes(resp[2:4]))[0] | 0x0080
        resp[2:4] = struct.pack(">H", flags)
        with self.assertRaises(client.ResolveError):
            client._parse_response(bytes(resp), 0x42, "node.cyberspace", 1)

    def test_resolve_ra_set_raises_resolve_error(self):
        def tamper(q):
            resp = _a_response(q)
            flags = struct.unpack(">H", resp[2:4])[0] | 0x0080
            return resp[:2] + struct.pack(">H", flags) + resp[4:]

        server = _tcp_server(tamper)
        with self.assertRaises(client.ResolveError):
            client.resolve("node.cyberspace", _tcp_sock=server, tcp_only=True)

    def test_parse_response_z_set_raises_resolve_error(self):
        """A Z-set packet uses the reserved header bit — neither daemon
        builder ever sets it; its replies are QR|AA|RD echo|rcode only."""
        resp = bytearray(self._valid_response())
        flags = struct.unpack(">H", bytes(resp[2:4]))[0] | 0x0040
        resp[2:4] = struct.pack(">H", flags)
        with self.assertRaises(client.ResolveError):
            client._parse_response(bytes(resp), 0x42, "node.cyberspace", 1)

    def test_resolve_z_set_raises_resolve_error(self):
        def tamper(q):
            resp = _a_response(q)
            flags = struct.unpack(">H", resp[2:4])[0] | 0x0040
            return resp[:2] + struct.pack(">H", flags) + resp[4:]

        server = _tcp_server(tamper)
        with self.assertRaises(client.ResolveError):
            client.resolve("node.cyberspace", _tcp_sock=server, tcp_only=True)

    def test_parse_response_ad_set_raises_resolve_error(self):
        """An AD-set packet reports a DNSSEC check the client never
        asked for — neither daemon builder ever sets AD."""
        resp = bytearray(self._valid_response())
        flags = struct.unpack(">H", bytes(resp[2:4]))[0] | 0x0020
        resp[2:4] = struct.pack(">H", flags)
        with self.assertRaises(client.ResolveError):
            client._parse_response(bytes(resp), 0x42, "node.cyberspace", 1)

    def test_parse_response_cd_set_raises_resolve_error(self):
        """A CD-set packet reports checking disabled — the client's
        query never sends CD and neither daemon builder echoes it."""
        resp = bytearray(self._valid_response())
        flags = struct.unpack(">H", bytes(resp[2:4]))[0] | 0x0010
        resp[2:4] = struct.pack(">H", flags)
        with self.assertRaises(client.ResolveError):
            client._parse_response(bytes(resp), 0x42, "node.cyberspace", 1)

    def test_resolve_ad_set_raises_resolve_error(self):
        def tamper(q):
            resp = _a_response(q)
            flags = struct.unpack(">H", resp[2:4])[0] | 0x0020
            return resp[:2] + struct.pack(">H", flags) + resp[4:]

        server = _tcp_server(tamper)
        with self.assertRaises(client.ResolveError):
            client.resolve("node.cyberspace", _tcp_sock=server, tcp_only=True)

    def test_resolve_cd_set_raises_resolve_error(self):
        def tamper(q):
            resp = _a_response(q)
            flags = struct.unpack(">H", resp[2:4])[0] | 0x0010
            return resp[:2] + struct.pack(">H", flags) + resp[4:]

        server = _tcp_server(tamper)
        with self.assertRaises(client.ResolveError):
            client.resolve("node.cyberspace", _tcp_sock=server, tcp_only=True)

    def test_parse_response_nscount_set_raises_resolve_error(self):
        """A packet claiming authority records is not a daemon reply —
        both daemon builders emit nscount 0; the parser never reads
        that section, so its records could only be smuggled weight."""
        resp = bytearray(self._valid_response())
        resp[8:10] = struct.pack(">H", 1)
        with self.assertRaises(client.ResolveError):
            client._parse_response(bytes(resp), 0x42, "node.cyberspace", 1)

    def test_parse_response_arcount_set_raises_resolve_error(self):
        """Same for the additional section: arcount is 0 in every
        reply the daemon builds, so a nonzero count is not its reply."""
        resp = bytearray(self._valid_response())
        resp[10:12] = struct.pack(">H", 1)
        with self.assertRaises(client.ResolveError):
            client._parse_response(bytes(resp), 0x42, "node.cyberspace", 1)

    def test_resolve_nscount_set_raises_resolve_error(self):
        def tamper(q):
            resp = _a_response(q)
            return resp[:8] + struct.pack(">H", 1) + resp[10:]

        server = _tcp_server(tamper)
        with self.assertRaises(client.ResolveError):
            client.resolve("node.cyberspace", _tcp_sock=server, tcp_only=True)

    def test_resolve_arcount_set_raises_resolve_error(self):
        def tamper(q):
            resp = _a_response(q)
            return resp[:10] + struct.pack(">H", 1) + resp[12:]

        server = _tcp_server(tamper)
        with self.assertRaises(client.ResolveError):
            client.resolve("node.cyberspace", _tcp_sock=server, tcp_only=True)

    def test_parse_response_trailing_bytes_raises_resolve_error(self):
        """Bytes past the counted sections are not a daemon reply —
        build_response ends at its last answer's rdata and
        error_response is a bare header; the parser would only ignore
        trailing bytes, so they can carry nothing the daemon meant."""
        resp = self._valid_response() + b"\x00"
        with self.assertRaises(client.ResolveError):
            client._parse_response(resp, 0x42, "node.cyberspace", 1)

    def test_parse_response_trailing_bytes_after_header_only_raises(self):
        """Same for a header-only reply: error_response is exactly
        12 bytes, so a 13th byte is not its reply."""
        resp = dns.error_response(client._build_query(0x42, "node.cyberspace", 1), 2)
        self.assertEqual(len(resp), 12)
        with self.assertRaises(client.ResolveError):
            client._parse_response(resp + b"\xff", 0x42, "node.cyberspace", 1)

    def test_resolve_trailing_bytes_raises_resolve_error(self):
        def tamper(q):
            return _a_response(q) + b"\xde\xad"

        server = _tcp_server(tamper)
        with self.assertRaises(client.ResolveError):
            client.resolve("node.cyberspace", _tcp_sock=server, tcp_only=True)

    def _rdlen_offset(self, resp):
        q_end = 12 + len(b"\x04node\x0acyberspace\x00") + 4
        off = q_end + 2 + 8  # owner pointer + type/class/ttl
        self.assertEqual(resp[off : off + 2], struct.pack(">H", 4))
        return off

    def test_parse_response_a_rdlen_too_long_raises_resolve_error(self):
        """An A record carrying 5 rdata bytes is not a daemon reply —
        build_response always emits exactly 4; until now this was
        caught only downstream in _textify, and only for the asked
        family."""
        resp = bytearray(self._valid_response() + b"\x00")
        resp[self._rdlen_offset(resp) : self._rdlen_offset(resp) + 2] = (
            struct.pack(">H", 5)
        )
        with self.assertRaises(client.ResolveError):
            client._parse_response(bytes(resp), 0x42, "node.cyberspace", 1)

    def test_parse_response_a_rdlen_too_short_raises_resolve_error(self):
        """Same for 3 bytes, with the packet ending exactly at the
        short rdata so only the length check can catch it."""
        resp = bytearray(self._valid_response()[:-1])
        off = self._rdlen_offset(resp)
        resp[off : off + 2] = struct.pack(">H", 3)
        with self.assertRaises(client.ResolveError):
            client._parse_response(bytes(resp), 0x42, "node.cyberspace", 1)

    def test_parse_response_aaaa_rdlen_wrong_raises_resolve_error(self):
        """An AAAA record is exactly 16 bytes in every daemon reply;
        15 (packet ending exactly there) is refused at parse time."""
        q = dns.parse_query(client._build_query(0x42, "node.cyberspace", 28))
        resp = bytearray(
            dns.build_response(
                q,
                [(28, 120, socket.inet_pton(socket.AF_INET6, "2001:db8::7"))],
                rcode=0,
            )[:-1]
        )
        q_end = 12 + len(b"\x04node\x0acyberspace\x00") + 4
        off = q_end + 2 + 8
        self.assertEqual(resp[off : off + 2], struct.pack(">H", 16))
        resp[off : off + 2] = struct.pack(">H", 15)
        with self.assertRaises(client.ResolveError):
            client._parse_response(bytes(resp), 0x42, "node.cyberspace", 28)

    def _answer_field_offset(self, resp, field):
        q_end = 12 + len(b"\x04node\x0acyberspace\x00") + 4
        return q_end + 2 + {"type": 0, "class": 2}[field]  # after owner ptr

    def test_parse_response_non_in_class_raises_resolve_error(self):
        """A CHAOS-class answer is not a daemon reply — build_response
        hard-codes class IN on every answer; until now a non-IN record
        was skipped silently and the packet still trusted."""
        resp = bytearray(self._valid_response())
        off = self._answer_field_offset(resp, "class")
        resp[off : off + 2] = struct.pack(">H", 3)
        with self.assertRaises(client.ResolveError):
            client._parse_response(bytes(resp), 0x42, "node.cyberspace", 1)

    def test_parse_response_non_a_aaaa_type_raises_resolve_error(self):
        """A TXT answer is not a daemon reply — its handler answers
        only the asked A/AAAA family and NODATA (empty) for any
        other qtype; a foreign record was skipped, never refused."""
        resp = bytearray(self._valid_response())
        off = self._answer_field_offset(resp, "type")
        resp[off : off + 2] = struct.pack(">H", 16)  # TXT
        with self.assertRaises(client.ResolveError):
            client._parse_response(bytes(resp), 0x42, "node.cyberspace", 1)

    def test_resolve_non_in_class_raises_resolve_error(self):
        def tamper(q):
            resp = bytearray(_a_response(q))
            off = self._answer_field_offset(resp, "class")
            resp[off : off + 2] = struct.pack(">H", 3)
            return bytes(resp)

        server = _tcp_server(tamper)
        with self.assertRaises(client.ResolveError):
            client.resolve("node.cyberspace", _tcp_sock=server, tcp_only=True)

    def test_resolve_non_a_aaaa_type_raises_resolve_error(self):
        def tamper(q):
            resp = bytearray(_a_response(q))
            off = self._answer_field_offset(resp, "type")
            resp[off : off + 2] = struct.pack(">H", 5)  # CNAME
            return bytes(resp)

        server = _tcp_server(tamper)
        with self.assertRaises(client.ResolveError):
            client.resolve("node.cyberspace", _tcp_sock=server, tcp_only=True)

    def test_resolve_a_rdlen_too_long_raises_resolve_error(self):
        def tamper(q):
            resp = bytearray(_a_response(q) + b"\x00")
            q_end = 12 + len(b"\x04node\x0acyberspace\x00") + 4
            off = q_end + 2 + 8
            resp[off : off + 2] = struct.pack(">H", 5)
            return bytes(resp)

        server = _tcp_server(tamper)
        with self.assertRaises(client.ResolveError):
            client.resolve("node.cyberspace", _tcp_sock=server, tcp_only=True)

    def test_parse_response_different_question_raises_resolve_error(self):
        """Right txid, answers for ANOTHER name: a mistransaction."""
        other = dns.parse_query(
            client._build_query(0x42, "other.cyberspace", 1)
        )
        resp = dns.build_response(
            other, [(1, 120, socket.inet_aton("10.9.8.7"))], rcode=0
        )
        with self.assertRaises(client.ResolveError):
            client._parse_response(resp, 0x42, "node.cyberspace", 1)
        # and through resolve(): the server answers a different question
        server = _tcp_server(
            lambda q: dns.build_response(
                dns.parse_query(
                    client._build_query(q["id"], "other.cyberspace", 1)
                ),
                [(1, 120, socket.inet_aton("10.9.8.7"))],
                rcode=0,
            )
        )
        with self.assertRaises(client.ResolveError):
            client.resolve("node.cyberspace", _tcp_sock=server, tcp_only=True)

    def _other_owner_response(self, txid=0x42):
        """Valid question for node.cyberspace, answer owned by another name."""
        resp = self._valid_response(txid)
        q_end = 12 + len(b"\x04node\x0acyberspace\x00") + 4
        head, tail = resp[:q_end], resp[q_end:]
        self.assertEqual(tail[:2], b"\xc0\x0c")  # daemon pointer to question
        other = b"\x05other\x0acyberspace\x00"
        return head + other + tail[2:]

    def test_parse_response_answer_owned_by_other_name_raises(self):
        """Right question, but the A record belongs to another name:
        its address must not be trusted for the asked name."""
        with self.assertRaises(client.ResolveError):
            client._parse_response(
                self._other_owner_response(), 0x42, "node.cyberspace", 1
            )

    def test_resolve_answer_owned_by_other_name_raises(self):
        server = _tcp_server(
            lambda q: self._other_owner_response(q["id"])
        )
        with self.assertRaises(client.ResolveError):
            client.resolve("node.cyberspace", _tcp_sock=server, tcp_only=True)

    def test_parse_response_different_qtype_raises_resolve_error(self):
        with self.assertRaises(client.ResolveError):
            client._parse_response(
                self._valid_response(), 0x42, "node.cyberspace", 28
            )

    def test_parse_response_valid_still_parses(self):
        flags, answers = client._parse_response(self._valid_response(), 0x42)
        self.assertEqual(answers, [(1, socket.inet_aton("10.9.8.7"))])

    def _response_with_ttl(self, ttl, txid=0x42):
        q = dns.parse_query(client._build_query(txid, "node.cyberspace", 1))
        return dns.build_response(
            q, [(1, ttl, socket.inet_aton("10.9.8.7"))], rcode=0
        )

    def test_parse_response_ttl_zero_accepted(self):
        """TTL 0 is a daemon reply: a cap of 0 (CYBERNET_TTL_CAP=0) or
        a binding expiring this second both emit it (answer._ttl_for
        floors at 0). The client discards TTL, so 0 changes nothing."""
        flags, answers = client._parse_response(
            self._response_with_ttl(0), 0x42, "node.cyberspace", 1
        )
        self.assertEqual(answers, [(1, socket.inet_aton("10.9.8.7"))])

    def test_parse_response_ttl_above_default_cap_accepted(self):
        """No client-side TTL bound: the 300s cap is daemon-local
        config with no ceiling, and a verified binding can have up
        to the 365-day admission lifetime remaining — a raised-cap
        daemon legitimately emits TTLs far above 300, and the
        non-caching client gains nothing by refusing them."""
        for ttl in (301, 86400, 365 * 86400):
            flags, answers = client._parse_response(
                self._response_with_ttl(ttl), 0x42, "node.cyberspace", 1
            )
            self.assertEqual(answers, [(1, socket.inet_aton("10.9.8.7"))])

    def test_resolve_high_ttl_still_resolves(self):
        server = _tcp_server(
            lambda q: dns.build_response(
                q, [(1, 365 * 86400, socket.inet_aton("10.9.8.7"))], rcode=0
            )
        )
        self.assertEqual(
            client.resolve("node.cyberspace", _tcp_sock=server, tcp_only=True),
            ["10.9.8.7"],
        )

    def test_malformed_port_raises_value_error_not_type_error(self):
        """An explicit port is caller-supplied: a string/float/bytes
        port escaped as a raw TypeError from the transport, True
        aliased to port 1 and False to port 0, and 0 / negative /
        oversize ports passed through as misleading transport
        verdicts — not the ValueError a malformed name/qtype/server
        raises in resolve(). Every malformed explicit port must read
        as ValueError, on both wires."""
        for bad in ("5353", 5353.0, b"5353", True, False, 0,
                    -1, 65536, 70000):
            with self.assertRaises(ValueError, msg=f"port={bad!r}"):
                client.resolve("node.cyberspace", port=bad, timeout=0.2)
            with self.assertRaises(ValueError, msg=f"port={bad!r} tcp"):
                client.resolve("node.cyberspace", port=bad, timeout=0.2,
                               tcp_only=True)

    def test_env_oversize_port_still_raises_resolve_error(self):
        """port=None keeps the documented env semantics: an env port
        above 65535 is honored (see _client_port_warnings) and fails
        as a transport ResolveError — sendto raises OverflowError,
        not OSError, and it must never escape raw."""
        os.environ["CYBERNET_RESOLVER_PORT"] = "70000"
        try:
            with self.assertRaises(client.ResolveError):
                client.resolve("node.cyberspace", timeout=1.0)
        finally:
            del os.environ["CYBERNET_RESOLVER_PORT"]

    def test_malformed_timeout_udp_raises_resolve_error(self):
        """A malformed timeout reached settimeout raw: negative escaped
        as ValueError, a string as TypeError, None meant block forever,
        True aliased to 1s, inf/NaN were blocking in disguise. Every one
        must surface as ResolveError before any socket is touched."""
        packet = client._build_query(0x1234, "node.cyberspace", 1)
        for bad in (-1, 0, "2", None, True, False,
                    float("inf"), float("nan")):
            with self.assertRaises(client.ResolveError):
                client._query_udp(0x1234, packet, "127.0.0.1", 5353,
                                  bad, sock=_FakeUdpSock())

    def test_malformed_timeout_resolve_tcp_raises_resolve_error(self):
        """Same gate through resolve() on the TCP wire: the bad timeout
        is refused as ResolveError, never a raw ValueError/TypeError
        and never a silent forever-block on a dead daemon."""
        for bad in (-1, 0, "2", None, True, float("inf")):
            server = _tcp_server(_a_response)
            with self.assertRaises(client.ResolveError):
                client.resolve("node.cyberspace", timeout=bad,
                               _tcp_sock=server, tcp_only=True)

    def test_valid_timeout_still_resolves(self):
        """Boundaries untouched: int and float positive timeouts work."""
        for good in (1, 2.0, 0.5):
            server = _tcp_server(_a_response)
            self.assertEqual(
                client.resolve("node.cyberspace", timeout=good,
                               _tcp_sock=server, tcp_only=True),
                ["10.9.8.7"],
            )

    def test_read_exact_malformed_length_raises_resolve_error(self):
        """_read_exact's contract is ResolveError on a read that cannot
        happen: a str/None/float length must not escape as TypeError,
        True must not alias to a 1-byte read, and a negative length
        must not silently return b'' as if a frame had been read."""
        class _Sock:
            def __init__(self):
                self.touched = False

            def recv(self, _n):
                self.touched = True
                return b"x"

        for bad in ("2", None, 1.5, True, False, -1, [2]):
            sock = _Sock()
            with self.assertRaises(client.ResolveError):
                client._read_exact(sock, bad)
            self.assertFalse(sock.touched)

    def test_read_exact_valid_lengths_still_read(self):
        """Boundaries untouched: zero reads b'' without touching the
        socket; a real length reads exactly that many bytes."""
        class _Sock:
            def __init__(self, data):
                self.data = data

            def recv(self, n):
                chunk, self.data = self.data[:n], self.data[n:]
                return chunk

        self.assertEqual(client._read_exact(_Sock(b""), 0), b"")
        self.assertEqual(client._read_exact(_Sock(b"hello"), 5), b"hello")
        self.assertEqual(client._read_exact(_Sock(b"hello"), 3), b"hel")

    def test_textify_malformed_inputs_raise_resolve_error(self):
        """_textify's contract is ResolveError on a mismatch: a
        non-bytes rdata must not escape as TypeError from len()/
        inet_ntoa, and True must not alias to QTYPE_A."""
        for qtype, rdata in ((client.QTYPE_A, "abcd"),
                             (client.QTYPE_A, 12345),
                             (client.QTYPE_A, None),
                             (client.QTYPE_AAAA, "x" * 16),
                             (True, b"\x01\x02\x03\x04"),
                             ("1", b"\x01\x02\x03\x04")):
            with self.assertRaises(client.ResolveError):
                client._textify(qtype, rdata)

    def test_textify_valid_still_textifies(self):
        """Boundaries untouched: A/AAAA bytes and bytearray parse."""
        self.assertEqual(client._textify(client.QTYPE_A,
                                         b"\x01\x02\x03\x04"), "1.2.3.4")
        self.assertEqual(client._textify(client.QTYPE_A,
                                         bytearray(b"\x01\x02\x03\x04")),
                         "1.2.3.4")
        self.assertEqual(client._textify(client.QTYPE_AAAA, bytes(16)), "::")

    def test_main_refuses_repeated_value_flag(self):
        """CLI duplicate gate, twin of dial/resolve_chain: argparse
        silently last-won on a repeated value flag, so --port A
        --port B queried B while the operator believed the port was
        A (and --qtype/--server redirected the query the same way).
        A repeat in space, equals or mixed spelling refuses by name
        with exit 2 before any query is sent."""
        cases = (
            ("--qtype", "A", "AAAA"),
            ("--server", "127.0.0.1", "127.0.0.2"),
            ("--port", "5353", "5354"),
        )
        for flag, first, second in cases:
            for extra in ([flag, first, flag, second],
                          [f"{flag}={first}", f"{flag}={second}"],
                          [flag, first, f"{flag}={second}"],
                          [f"{flag}={first}", flag, second]):
                err = io.StringIO()
                with contextlib.redirect_stderr(err):
                    code = client.main(["alice.cyberspace"] + extra)
                self.assertEqual(code, 2, extra)
                self.assertIn(f"{flag} given more than once",
                              err.getvalue())
        # A single value flag still passes the gate: it reaches the
        # name-shape verdict (exit 2 on stdout, no duplicate refusal).
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = client.main(["not-a-name", "--port", "5353"])
        self.assertEqual(code, 2)
        self.assertNotIn("given more than once", err.getvalue())

    def test_main_refuses_repeated_tcp_only_flag(self):
        """CLI boolean duplicate gate, twin of resolve_chain's
        --with-live gate: store_true repeats silently, so
        --tcp-only --tcp-only passed to a verdict while every value
        flag refused its repeat by name. A repeat in space, equals
        or mixed spelling refuses by name with exit 2 before any
        query is sent."""
        for extra in (["--tcp-only", "--tcp-only"],
                      ["--tcp-only=x", "--tcp-only=x"],
                      ["--tcp-only", "--tcp-only=x"],
                      ["--tcp-only=x", "--tcp-only"]):
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                code = client.main(["alice.cyberspace"] + extra)
            self.assertEqual(code, 2, extra)
            self.assertIn("--tcp-only given more than once",
                          err.getvalue())
        # A single --tcp-only still passes the gate: it reaches the
        # name-shape verdict (exit 2 on stdout, no duplicate refusal).
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = client.main(["not-a-name", "--tcp-only"])
        self.assertEqual(code, 2)
        self.assertNotIn("given more than once", err.getvalue())

    def test_main_refuses_abbreviated_value_flag(self):
        """CLI abbreviation gate, twin of dial's: argparse expands any
        unambiguous prefix, so --por/--p silently became --port and
        dodged the duplicate gate above (a --por A --port B pair
        queried B). An abbreviated spelling of any long option
        refuses by name with exit 2, alone or paired, in space or
        equals spelling, before any query is sent."""
        cases = (
            ("--por", "--port"), ("--p", "--port"),
            ("--q", "--qtype"), ("--ser", "--server"),
            ("--tcp", "--tcp-only"), ("--h", "--help"),
        )
        for abbr, full in cases:
            for extra in ([abbr, "x"], [f"{abbr}=x"],
                          [abbr, "a", full, "b"],
                          [full, "a", abbr, "b"]):
                err = io.StringIO()
                with contextlib.redirect_stderr(err):
                    code = client.main(["alice.cyberspace"] + extra)
                self.assertEqual(code, 2, extra)
                self.assertIn(f"{abbr} is an abbreviation of {full}",
                              err.getvalue())

    def test_env_port_default(self):
        os.environ.pop("CYBERNET_RESOLVER_PORT", None)
        self.assertEqual(client._default_port(), 5353)
        os.environ["CYBERNET_RESOLVER_PORT"] = "5354"
        try:
            self.assertEqual(client._default_port(), 5354)
        finally:
            del os.environ["CYBERNET_RESOLVER_PORT"]


if __name__ == "__main__":
    unittest.main(verbosity=2)
