"""resolver TCP wire-loopback test — the real DNS-over-TCP wire path.

The sibling UDP harness (resolver-wire-loopback-test.py) is DEFERRED in
this sandbox: UDP sendto is blocked at the syscall layer (EPERM), even on
loopback. TCP is not. So this harness drives the REAL daemon loop —
daemon.run() in the MAIN thread (it installs SIGINT/SIGTERM handlers,
which only the main thread may do) — the REAL claim endpoint + resolver
via mint_name, the REAL hostd announce (host.announce_once), and real
length-prefixed TCP DNS frames on loopback: the six-step
resolve_cyberspace() running end to end for .cyberspace queries,
fail-closed cases on the wire.

The client cases run in a worker thread; when they finish it delivers
SIGTERM to the process, and the REAL stop handler ends the daemon loop
exactly as a real SIGTERM would.

  1. wiretest.cyberspace A      -> NOERROR with >=1 A answer (real claim
                                 + real name-key announce + live verify)
  2. zz-junk.cyberspace A       -> NXDOMAIN, zero answers (fail-closed)
  3. wiretest.cyberspace AAAA   -> NODATA (v4-only node, no guess)
  4. two queries, one connection -> both answered (RFC 7766 reuse)
  5. garbage frame              -> SERVFAIL echoing the txid (never silent)
  6. example.com A (off-zone)   -> SERVFAIL echoing txid (upstream dead in
                                 sandbox; daemon fails closed, no hang)

Test-only allowances (same doctrine as the UDP harness): the 127.0.0.1
test mirror/node is allow-listed through the SSRF gate in-process
(core._reject_nonpublic_node_url patched), and CYBERNET_PUBLIC_URL points
at the test node so the announce carries honest reach. The TCP frames,
the daemon loop, the six-step, and the signal handling are all real.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/resolver-tcp-wire-loopback-test.py
"""

import os
import random
import signal
import struct
import sys
import tempfile
import threading
import time
import urllib.request

HOME = tempfile.mkdtemp(prefix="wire-home-")
os.environ["HOME"] = HOME                      # mint_name writes under ~/.cyberspace
os.environ["CYBERNET_DB_DIR"] = tempfile.mkdtemp(prefix="wire-db-")

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, REPO)

import uvicorn  # noqa: E402
from app import app  # noqa: E402
import core  # noqa: E402
import mint_name  # noqa: E402
from resolver import daemon  # noqa: E402
from resolver import host  # noqa: E402

PORT = 18380
MIRROR = f"http://127.0.0.1:{PORT}"
DNS_PORT = 53600

# the test-only SSRF allowance: the 127.0.0.1 test mirror/node only
_real_gate = core._reject_nonpublic_node_url


def _test_gate(url):
    if url.startswith(MIRROR):
        return "127.0.0.1"
    return _real_gate(url)


core._reject_nonpublic_node_url = _test_gate

server = uvicorn.Server(
    uvicorn.Config(app, host="127.0.0.1", port=PORT, log_level="error")
)
t = threading.Thread(target=server.run, daemon=True)
t.start()
for _ in range(100):
    try:
        urllib.request.urlopen(MIRROR + "/api/v1/node", timeout=1)
        break
    except Exception:
        time.sleep(0.1)
else:
    sys.exit("test node never came up")

passed = failed = 0


def check(name, cond, extra=""):
    global passed, failed
    if cond:
        passed += 1
        print(f"  ok  {name}")
    else:
        failed += 1
        print(f"  FAIL {name} {extra}")


LABEL = "wiretest"
os.environ["CYBERNET_PUBLIC_URL"] = MIRROR  # honest reach for the announce
rc = mint_name.main([LABEL, MIRROR, "--env-dir", tempfile.mkdtemp(prefix="wire-env-")])
check("mint wiretest name on the real claim endpoint", rc == 0, f"rc={rc}")
if rc != 0:
    print(f"{passed} passed, {failed} failed")
    sys.exit(1)

key_path = os.path.join(HOME, ".cyberspace", f"{LABEL}-name.key")
with open(key_path) as f:
    name_priv = f.read().strip()
announced = host.announce_once(MIRROR, LABEL, name_priv)
check("name-key reach announce accepted by the mirror", announced)

import socket  # noqa: E402


def _build_query(name, qtype):
    txid = random.getrandbits(16)
    hdr = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    qname = b"".join(
        bytes([len(p)]) + p.encode("ascii") for p in name.split(".")
    ) + b"\x00"
    pkt = hdr + qname + struct.pack(">HH", qtype, 1)
    return txid, struct.pack(">H", len(pkt)) + pkt


def _read_reply(sock):
    head = b""
    while len(head) < 2:
        chunk = sock.recv(2 - len(head))
        if not chunk:
            raise AssertionError("EOF waiting for reply length")
        head += chunk
    (n,) = struct.unpack(">H", head)
    body = b""
    while len(body) < n:
        chunk = sock.recv(n - len(body))
        if not chunk:
            raise AssertionError("EOF waiting for reply body")
        body += chunk
    return body


def _decode(resp, txid):
    rtxid, flags, _qd, an, _ns, _ar = struct.unpack(">HHHHHH", resp[:12])
    return rtxid, flags & 0x000F, an, txid, bool(flags & 0x0400)


def _aa(name, is_aa, extra=""):
    check(f"{name} — AA bit set (extension contract)", is_aa, extra)


def query(name, qtype):
    """One query, its own connection — the common client shape."""
    txid, frame = _build_query(name, qtype)
    with socket.create_connection(("127.0.0.1", DNS_PORT), timeout=4.0) as s:
        s.settimeout(4.0)
        s.sendall(frame)
        resp = _read_reply(s)
    return _decode(resp, txid)


def case_1():
    rtxid, rcode, an, txid, aa = query(f"{LABEL}.cyberspace", 1)
    check("wiretest.cyberspace A -> NOERROR + >=1 answer",
          rtxid == txid and rcode == 0 and an >= 1,
          f"rcode={rcode} an={an} txid_ok={rtxid == txid}")
    _aa("wiretest.cyberspace A", aa, f"rcode={rcode}")


def case_2():
    junk = "zz-" + "".join(random.choice("abcdefghij") for _ in range(10))
    rtxid, rcode, an, txid, aa = query(f"{junk}.cyberspace", 1)
    check("junk label -> NXDOMAIN with zero answers",
          rtxid == txid and rcode == 3 and an == 0,
          f"rcode={rcode} an={an} txid_ok={rtxid == txid}")
    _aa("junk label NXDOMAIN", aa, f"rcode={rcode}")


def case_3():
    rtxid, rcode, an, txid, aa = query(f"{LABEL}.cyberspace", 28)
    check("wiretest.cyberspace AAAA -> NODATA (rcode 0, no answers)",
          rtxid == txid and rcode == 0 and an == 0,
          f"rcode={rcode} an={an} txid_ok={rtxid == txid}")
    _aa("wiretest.cyberspace AAAA NODATA", aa, f"rcode={rcode}")


def case_4():
    txid1, frame1 = _build_query(f"{LABEL}.cyberspace", 1)
    txid2, frame2 = _build_query("zz-junk2.cyberspace", 1)
    with socket.create_connection(("127.0.0.1", DNS_PORT), timeout=4.0) as s:
        s.settimeout(4.0)
        s.sendall(frame1 + frame2)  # pipelined on one connection
        r1 = _read_reply(s)
        r2 = _read_reply(s)
    t1, rc1, an1, e1, aa1 = _decode(r1, txid1)
    t2, rc2, an2, e2, aa2 = _decode(r2, txid2)
    check("two pipelined queries on one TCP connection -> both answered",
          t1 == e1 and rc1 == 0 and an1 >= 1 and t2 == e2 and rc2 == 3,
          f"r1(rc={rc1} an={an1}) r2(rc={rc2})")
    _aa("pipelined NOERROR reply", aa1, f"rc={rc1}")
    _aa("pipelined NXDOMAIN reply", aa2, f"rc={rc2}")


def case_5():
    with socket.create_connection(("127.0.0.1", DNS_PORT), timeout=4.0) as s:
        s.settimeout(4.0)
        raw = b"\x12\x34junk-bytes-not-dns"
        s.sendall(struct.pack(">H", len(raw)) + raw)
        resp = _read_reply(s)
    rtxid, flags = struct.unpack(">HH", resp[:4])
    check("garbage frame -> SERVFAIL with txid echo",
          rtxid == 0x1234 and (flags & 0x000F) == 2, f"txid={rtxid:#x}")
    _aa("garbage-frame SERVFAIL", bool(flags & 0x0400), f"txid={rtxid:#x}")


def case_6():
    rtxid, rcode, an, txid, aa = query("example.com", 1)
    check("off-zone query -> SERVFAIL with txid echo (dead upstream)",
          rtxid == txid and rcode == 2, f"rcode={rcode} txid_ok={rtxid == txid}")
    _aa("off-zone SERVFAIL", aa, f"rcode={rcode}")


def client_main():
    # wait for the daemon's TCP face to accept, then run the wire cases
    for _ in range(100):
        try:
            s = socket.create_connection(("127.0.0.1", DNS_PORT), timeout=1)
            s.close()
            break
        except OSError:
            time.sleep(0.1)
    else:
        check("daemon TCP face came up", False)
        os.kill(os.getpid(), signal.SIGTERM)
        return
    for name, fn in [("wiretest.cyberspace A", case_1),
                     ("junk label NXDOMAIN", case_2),
                     ("wiretest.cyberspace AAAA", case_3),
                     ("pipelined reuse", case_4),
                     ("garbage frame", case_5),
                     ("off-zone query", case_6)]:
        try:
            fn()
        except Exception as exc:
            check(name, False, f"raised {exc!r}")
    os.kill(os.getpid(), signal.SIGTERM)  # the real stop path ends the loop


os.environ["CYBERNET_MIRROR_URL"] = MIRROR
os.environ["CYBERNET_RESOLVER_BIND"] = "127.0.0.1"
os.environ["CYBERNET_RESOLVER_PORT"] = str(DNS_PORT)

ct = threading.Thread(target=client_main, daemon=True)
ct.start()
daemon.run()  # main thread: real loop, real signal handlers, returns on SIGTERM
ct.join(timeout=10)

print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
