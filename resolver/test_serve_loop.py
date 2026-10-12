"""Unit tests for the resolver serve loop (resolver/daemon.py run()).

run()'s contract: bind, answer until SIGINT/SIGTERM, return, never raise.
The sandbox blocks real UDP sends (PermissionError), so the socket layer is
monkeypatched exactly like the forward/TTL suite does: a scripted fake
socket feeds recvfrom packets, captures the SIGTERM/SIGINT handlers through
the real signal.signal(), and drains into the real stop handler — the loop
stops the same way a real SIGTERM would stop it, only the wire is fake.

Since the daemon binds both UDP and TCP on the same port (RFC 7766), the
fake socket stands in for both (the fake select only ever wakes the UDP
half), and daemon.select is swapped for a fake whose select() simply
returns the readable list the loop would have waited on.

Coverage:
  1. garbage packet -> SERVFAIL, QR set, query id echoed (never raised)
  2. empty datagram swallowed — the zone stays up for the next question
  3. handle_query raising -> the loop's guard answers SERVFAIL, never silence
  4. zone query with a dead mirror -> NXDOMAIN (fail-closed, never invented)
  5. the real signal handler (captured from signal.signal) ends run() cleanly
  6. both sockets bound and closed on exit (UDP + TCP faces)

Run: cd ~/workspace/cybernet && ./venv/bin/python resolver/test_serve_loop.py
"""

import os
import signal
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from resolver import answer  # noqa: E402
from resolver import daemon  # noqa: E402

CASES = {"passed": 0, "failed": 0}


def check(name, cond, extra=""):
    if cond:
        CASES["passed"] += 1
        print(f"  ok  {name}")
    else:
        CASES["failed"] += 1
        print(f"  FAIL {name} {extra}")


def _query_packet(qname, qtype=1, qid=0x5001):
    labels = b"".join(bytes([len(p)]) + p.encode() for p in qname.split("."))
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    question = labels + b"\x00" + struct.pack(">HH", qtype, 1)
    return header + question


def _rcode(reply):
    flags = struct.unpack(">H", reply[2:4])[0]
    return (flags >> 15) & 1, flags & 0xF  # QR, rcode


def _qid(reply):
    return struct.unpack(">H", reply[:2])[0]


class _FakeSocket:
    """Scripted stand-in for the daemon's UDP socket.

    recvfrom() yields the scripted packets, then invokes the REAL stop
    handler captured from signal.signal (as a real SIGTERM would) and raises
    OSError, exactly what an interrupted recvfrom looks like to the loop.
    sendto() records every reply instead of putting bytes on the wire.
    """

    def __init__(self, script, stop):
        self._script = list(script)
        self._stop = stop
        self.sent = []
        self.closed = False
        self.bound = None
        self.listened = 0

    def bind(self, addr):
        self.bound = addr

    def setsockopt(self, *a):
        pass

    def listen(self, backlog):
        self.listened = backlog

    def accept(self):
        raise OSError("fake select never wakes the TCP half")

    def recvfrom(self, n):
        if self._script:
            raw = self._script.pop(0)
            if raw is _RESTORE_MARKER:
                daemon.handle_query = answer.handle_query
                return self.recvfrom(n)
            return raw, ("127.0.0.1", 9999)
        self._stop(signal.SIGTERM, None)  # the real handler: running = False
        raise OSError("interrupted by SIGTERM")

    def sendto(self, data, addr):
        self.sent.append(data)
        return len(data)

    def close(self):
        self.closed = True


_RESTORE_MARKER = object()


def main():
    os.environ["CYBERNET_RESOLVER_BIND"] = "127.0.0.1"
    os.environ["CYBERNET_RESOLVER_PORT"] = "5353"
    os.environ["CYBERNET_MIRROR_URL"] = "http://127.0.0.1:1"  # dead: must NXDOMAIN
    os.environ["CYBERNET_UPSTREAM_DNS"] = "127.0.0.1:1"  # never queried below
    os.environ["CYBERNET_TTL_CAP"] = "300"

    # Phase A: the per-packet guard — the handler dies, the socket answers.
    real_handle = daemon.handle_query

    def _raiser(raw, **kw):
        raise RuntimeError("handler exploded")

    daemon.handle_query = _raiser

    script = [
        b"\xff\xfe\x00",                                    # 1. garbage
        b"",                                                # 2. empty: swallowed
        _query_packet("garbage.cyberspace", qid=0x5002),    # 3. handler raises
        _RESTORE_MARKER,                                     # handler restored
        _query_packet("silent.cyberspace", qid=0x5003),     # 4. dead mirror
    ]

    handlers = {}
    real_signal = signal.signal

    def _capture(signum, handler):
        handlers[signum] = handler
        return real_signal(signum, handler)

    signal.signal = _capture
    fake = _FakeSocket(script, lambda s, f: handlers[signal.SIGTERM](s, f))
    real_socket = __import__("socket").socket
    __import__("socket").socket = lambda *a, **k: fake

    class _FakeSelect:
        """select() wakes only the UDP half; the TCP face stays bound but
        idle, exactly what the scripted cases exercise."""

        @staticmethod
        def select(rlist, wlist, xlist, timeout=None):
            return ([rlist[0]], [], [])

    real_select = daemon.select
    daemon.select = _FakeSelect

    try:
        daemon.run()  # answers the script, then the stop handler ends the loop
    finally:
        __import__("socket").socket = real_socket
        signal.signal = real_signal
        daemon.select = real_select
        daemon.handle_query = real_handle

    replies = fake.sent

    check("run() returned, loop did not die on the script", True)
    check("SIGTERM handler captured and stopped the loop",
          signal.SIGTERM in handlers)
    check("socket bound from env config", fake.bound == ("127.0.0.1", 5353),
          f"bound={fake.bound}")
    check("TCP face listened on the same port", fake.listened == 16,
          f"listened={fake.listened}")
    check("socket closed on exit", fake.closed)
    check("every packet except the empty one got a reply", len(replies) == 3,
          f"got {len(replies)}")

    qr, rcode = _rcode(replies[0])
    check("garbage packet -> SERVFAIL, QR set", qr == 1 and rcode == 2,
          f"rcode={rcode}")
    check("garbage id echoed", _qid(replies[0]) == 0xFFFE,
          f"qid={_qid(replies[0]):04x}")

    qr, rcode = _rcode(replies[1])
    check("handler raising -> SERVFAIL, never silence", qr == 1 and rcode == 2,
          f"rcode={rcode}")
    check("raised-handler id echoed", _qid(replies[1]) == 0x5002,
          f"qid={_qid(replies[1]):04x}")

    qr, rcode = _rcode(replies[2])
    check("dead mirror -> NXDOMAIN (fail-closed, never invented)",
          qr == 1 and rcode == 3, f"rcode={rcode}")
    check("nxdomain id echoed", _qid(replies[2]) == 0x5003,
          f"qid={_qid(replies[2]):04x}")

    # Phase B: bind failure — run() must refuse loudly and RETURN,
    # never raise, and must not leak the half-bound UDP socket when
    # the TCP bind is the one that fails. Real sockets, ephemeral
    # port (binds only; no UDP sends, so the sandbox permits it).
    import contextlib
    import io
    import socket as _real_socket_mod

    probe = _real_socket_mod.socket(_real_socket_mod.AF_INET,
                                    _real_socket_mod.SOCK_DGRAM)
    probe.bind(("127.0.0.1", 0))
    busy_port = probe.getsockname()[1]
    probe.close()
    os.environ["CYBERNET_RESOLVER_PORT"] = str(busy_port)

    # B1: both faces occupied -> refusal, no raise.
    occ_udp = _real_socket_mod.socket(_real_socket_mod.AF_INET,
                                      _real_socket_mod.SOCK_DGRAM)
    occ_udp.bind(("127.0.0.1", busy_port))
    occ_tcp = _real_socket_mod.socket(_real_socket_mod.AF_INET,
                                      _real_socket_mod.SOCK_STREAM)
    occ_tcp.bind(("127.0.0.1", busy_port))
    occ_tcp.listen(1)
    err = io.StringIO()
    try:
        with contextlib.redirect_stderr(err):
            daemon.run()
        check("bind failure: run() returned, never raised", True)
    except Exception as exc:  # noqa: BLE001 — the contract is the test
        check("bind failure: run() returned, never raised", False, repr(exc))
    check("bind failure: refusal names the bind on stderr",
          "refusing to start" in err.getvalue()
          and "cannot bind" in err.getvalue(),
          f"stderr={err.getvalue()!r}")
    occ_udp.close()
    occ_tcp.close()

    # B2: only TCP occupied -> refusal AND the UDP socket run() had
    # already bound is closed (rebinding the port must succeed).
    occ_tcp = _real_socket_mod.socket(_real_socket_mod.AF_INET,
                                      _real_socket_mod.SOCK_STREAM)
    occ_tcp.setsockopt(_real_socket_mod.SOL_SOCKET,
                       _real_socket_mod.SO_REUSEADDR, 1)
    occ_tcp.bind(("127.0.0.1", busy_port))
    occ_tcp.listen(1)
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        daemon.run()
    check("tcp-only bind failure: refusal on stderr",
          "cannot bind" in err.getvalue(), f"stderr={err.getvalue()!r}")
    occ_tcp.close()
    rebind = _real_socket_mod.socket(_real_socket_mod.AF_INET,
                                     _real_socket_mod.SOCK_DGRAM)
    try:
        rebind.bind(("127.0.0.1", busy_port))
        check("tcp-only bind failure: half-bound UDP socket was closed",
              True)
    except OSError as exc:
        check("tcp-only bind failure: half-bound UDP socket was closed",
              False, repr(exc))
    rebind.close()

    # B3: port above 65535 — _env_int honors it (the config warning
    # predicts the bind will fail) but bind() raises OverflowError,
    # not OSError. run() must still refuse loudly and return.
    os.environ["CYBERNET_RESOLVER_PORT"] = "70000"
    err = io.StringIO()
    try:
        with contextlib.redirect_stderr(err):
            daemon.run()
        check("oversize port: run() returned, never raised", True)
    except Exception as exc:  # noqa: BLE001 — the contract is the test
        check("oversize port: run() returned, never raised", False,
              repr(exc))
    check("oversize port: refusal names the bind on stderr",
          "refusing to start" in err.getvalue()
          and "cannot bind" in err.getvalue(),
          f"stderr={err.getvalue()!r}")
    os.environ["CYBERNET_RESOLVER_PORT"] = "5353"

    # Phase C: signal registration fails (ValueError — run() called
    # from a non-main thread, the embedded-daemon case). run() must
    # warn and still serve, never raise on registration. The fake
    # select breaks the loop with a sentinel BaseException on its
    # second call, after one packet has been answered.
    class _Sentinel(BaseException):
        pass

    def _bad_signal(signum, handler):
        raise ValueError("signal only works in main thread")

    fake_c = _FakeSocket([_query_packet("silent.cyberspace", qid=0x5004)],
                         lambda s, f: None)
    calls = {"n": 0}

    class _SentinelSelect:
        @staticmethod
        def select(rlist, wlist, xlist, timeout=None):
            calls["n"] += 1
            if calls["n"] > 1:
                raise _Sentinel()
            return ([rlist[0]], [], [])

    real_socket_fn = __import__("socket").socket
    __import__("socket").socket = lambda *a, **k: fake_c
    daemon.select = _SentinelSelect
    signal.signal = _bad_signal
    err_c = io.StringIO()
    try:
        with contextlib.redirect_stderr(err_c):
            daemon.run()
        check("signal failure: run() served then exited cleanly", False,
              "sentinel never raised — loop did not run as scripted")
    except _Sentinel:
        check("signal failure: run() served then exited cleanly", True)
    except Exception as exc:  # noqa: BLE001
        check("signal failure: run() served then exited cleanly", False,
              repr(exc))
    finally:
        __import__("socket").socket = real_socket_fn
        signal.signal = real_signal
        daemon.select = real_select
    check("signal failure: warning on stderr",
          "serving without it" in err_c.getvalue(),
          f"stderr={err_c.getvalue()!r}")
    check("signal failure: packet still answered before exit",
          len(fake_c.sent) == 1, f"sent={len(fake_c.sent)}")
    check("signal failure: sockets closed on exit", fake_c.closed)

    print(f"\n{CASES['passed']} passed, {CASES['failed']} failed")
    return 1 if CASES["failed"] else 0


if __name__ == "__main__":
    sys.exit(main())
