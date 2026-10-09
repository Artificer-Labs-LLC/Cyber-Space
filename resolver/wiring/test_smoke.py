"""Fail-closed plumbing tests for resolver/wiring/smoke.py.

No daemon, no network: monkeypatch smoke._query to fake transport and
DNS answers in-process, and assert main()'s exit codes — the
fail-closed contract the wiring README promises ("Exit 0 only if both
pass") is real.

Four checks:
  daemon down on the wire -> _query raises (transport failure is loud)
  _query raising -> main() exits 1 ("unreachable" is said, not swallowed)
  good NOERROR+A then junk NXDOMAIN -> main() exits 0 (PASS path)
  junk not NXDOMAIN -> main() exits 1 (fail-closed answer refuses)

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
    check("PASS lines printed", "PASS: registered name resolves" in out
          and "NXDOMAIN (fail-closed)" in out, repr(out[:120]))


# 4. daemon that answers junk -> exit 1, not trusted
def _test_junk_not_nxdomain():
    def _lying(name, qtype, server, port, timeout=3.0):
        return (0, 1, 0)  # answers everything — not fail-closed

    rc, out = _run_main_with_fake(_lying)
    check("non-NXDOMAIN junk -> exit 1", rc == 1, f"got {rc}")
    check("fail-closed refusal said", "not fail-closed" in out, repr(out[:80]))


# 5. packet shape: _build_query header parses, qname encodes
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
    _test_packet_shape()
    p, f = CASES["passed"], CASES["failed"]
    print(f"\n{CASES['passed']} passed, {CASES['failed']} failed")
    sys.exit(1 if f else 0)
