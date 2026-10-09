"""Unit tests for the resolver serve loop (resolver/daemon.py run()).

run()'s contract: bind, answer until SIGINT/SIGTERM, return, never raise.
The sandbox blocks real UDP sends (PermissionError), so the socket layer is
monkeypatched exactly like the forward/TTL suite does: a scripted fake
socket feeds recvfrom packets, captures the SIGTERM/SIGINT handlers through
the real signal.signal(), and drains into the real stop handler — the loop
stops the same way a real SIGTERM would stop it, only the wire is fake.

Coverage:
  1. garbage packet -> SERVFAIL, QR set, query id echoed (never raised)
  2. empty datagram swallowed — the zone stays up for the next question
  3. handle_query raising -> the loop's guard answers SERVFAIL, never silence
  4. zone query with a dead mirror -> NXDOMAIN (fail-closed, never invented)
  5. the real signal handler (captured from signal.signal) ends run() cleanly

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

    def bind(self, addr):
        self.bound = addr

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

    try:
        daemon.run()  # answers the script, then the stop handler ends the loop
    finally:
        __import__("socket").socket = real_socket
        signal.signal = real_signal
        daemon.handle_query = real_handle

    replies = fake.sent

    check("run() returned, loop did not die on the script", True)
    check("SIGTERM handler captured and stopped the loop",
          signal.SIGTERM in handlers)
    check("socket bound from env config", fake.bound == ("127.0.0.1", 5353),
          f"bound={fake.bound}")
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

    print(f"\n{CASES['passed']} passed, {CASES['failed']} failed")
    return 1 if CASES["failed"] else 0


if __name__ == "__main__":
    sys.exit(main())
