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
