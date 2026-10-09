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

    def test_query_wire_encoding(self):
        pkt = client._build_query(0x1234, "Node.Cyberspace.", 1)
        parsed = dns.parse_query(pkt)
        self.assertEqual(parsed["id"], 0x1234)
        self.assertEqual(parsed["qname"], "node.cyberspace")  # normalized
        self.assertEqual(parsed["qtype"], 1)
        self.assertTrue(parsed["rd"])

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
