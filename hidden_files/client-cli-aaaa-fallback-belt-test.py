#!/usr/bin/env python3
"""Belt: resolver client CLI AAAA fallback on A-NODATA (default qtype only).

The daemon legitimately serves v6-only hosted names: A answers NOERROR
with no records (NODATA) and AAAA answers the address (answer.py). The
wiring smoke's registered leg learned to fall back A->AAAA on exactly
that shape, but the client CLI — the agent's own front door — defaulted
to A only, so `resolver.client v6only.cyberspace` exited 2 ("no A
record") for a live name. The fallback now lives in main(): only when
no --qtype was given, and only on the A-NODATA ResolveError. Explicit
--qtype stays strict; NXDOMAIN and SERVFAIL never trigger a second
query (the fake daemon counts queries per (name, qtype) to prove it).

Fake TCP daemon on loopback, real CLI as a subprocess — same harness
shape as resolver-client-cli-test.py.
"""

import os
import socket
import struct
import subprocess
import sys
import threading
import time

REPO = os.path.expanduser("~/workspace/cybernet")
PASS = FAIL = 0
QUERIES = []
QLOCK = threading.Lock()


def check(label, cond, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok   {label}")
    else:
        FAIL += 1
        print(f"  FAIL {label} {extra}")


def _read_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise OSError("eof")
        buf += chunk
    return buf


def _read_name(data, off):
    parts = []
    while data[off] != 0:
        n = data[off]
        parts.append(data[off + 1 : off + 1 + n].decode("ascii"))
        off += 1 + n
    return ".".join(parts), off + 1


def fake_daemon(stop, port_holder):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    srv.settimeout(0.2)
    port_holder.append(srv.getsockname()[1])

    def handle(conn):
        try:
            (n,) = struct.unpack(">H", _read_exact(conn, 2))
            q = _read_exact(conn, n)
            txid = struct.unpack(">H", q[:2])[0]
            qname, off = _read_name(q, 12)
            (qtype,) = struct.unpack(">H", q[off : off + 2])
            with QLOCK:
                QUERIES.append((qname, qtype))
            question = q[12:]
            v4 = socket.inet_aton("93.184.216.34")
            v6 = socket.inet_pton(socket.AF_INET6, "fd00::2")
            table = {
                # name lives, v6 only: A NODATA, AAAA answers
                ("v6only.cyberspace", 1): (0x8500, []),
                ("v6only.cyberspace", 28): (0x8500, [(28, v6)]),
                # dual-stack: both families answer
                ("dual.cyberspace", 1): (0x8500, [(1, v4)]),
                ("dual.cyberspace", 28): (0x8500, [(28, v6)]),
                # v4 only: A answers, AAAA NODATA
                ("v4only.cyberspace", 1): (0x8500, [(1, v4)]),
                ("v4only.cyberspace", 28): (0x8500, []),
                # name lives, no family at all: both NODATA
                ("bare.cyberspace", 1): (0x8500, []),
                ("bare.cyberspace", 28): (0x8500, []),
                # SERVFAIL on either family
                ("broken.cyberspace", 1): (0x8502, []),
                ("broken.cyberspace", 28): (0x8502, []),
            }
            flags, answers = table.get((qname, qtype), (0x8503, []))  # NXDOMAIN
            hdr = struct.pack(">HHHHHH", txid, flags, 1, len(answers), 0, 0)
            body = hdr + question
            for rtype, rdata in answers:
                body += struct.pack(">HHHIH", 0xC00C, rtype, 1, 60, len(rdata)) + rdata
            conn.sendall(struct.pack(">H", len(body)) + body)
        except OSError:
            pass
        finally:
            conn.close()

    def loop():
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            threading.Thread(target=handle, args=(conn,), daemon=True).start()
        srv.close()

    threading.Thread(target=loop, daemon=True).start()


def main():
    port_holder = []
    stop = threading.Event()
    fake_daemon(stop, port_holder)
    for _ in range(50):
        if port_holder:
            break
        time.sleep(0.05)

    def cli(*args):
        env = dict(os.environ)
        env["CYBERNET_RESOLVER_PORT"] = str(port_holder[0])
        return subprocess.run(
            [sys.executable, "-m", "resolver.client", *args],
            cwd=REPO, env=env, capture_output=True, text=True, timeout=15,
        )

    def asked(name, qtype):
        with QLOCK:
            return (name, qtype) in QUERIES

    def reset():
        with QLOCK:
            QUERIES.clear()

    r = cli("v6only.cyberspace")
    check("default on v6-only -> exit 0 + v6 address (fallback)",
          r.returncode == 0 and r.stdout.strip() == "fd00::2",
          repr((r.returncode, r.stdout, r.stderr)))
    check("fallback asked A then AAAA",
          asked("v6only.cyberspace", 1) and asked("v6only.cyberspace", 28))

    reset()
    r = cli("dual.cyberspace")
    check("default on dual-stack -> exit 0 + v4 address (A wins)",
          r.returncode == 0 and r.stdout.strip() == "93.184.216.34",
          repr((r.returncode, r.stdout, r.stderr)))
    check("dual-stack default never asked AAAA",
          not asked("dual.cyberspace", 28))

    reset()
    r = cli("v4only.cyberspace", "--qtype", "AAAA")
    check("explicit AAAA on v4-only -> exit 2 (strict, no fallback)",
          r.returncode == 2 and "no AAAA record" in r.stdout + r.stderr,
          repr((r.returncode, r.stdout, r.stderr)))
    check("explicit AAAA never asked A", not asked("v4only.cyberspace", 1))

    r = cli("v6only.cyberspace", "--qtype", "A")
    check("explicit A on v6-only -> exit 2 (strict, no fallback)",
          r.returncode == 2 and "no A record" in r.stdout + r.stderr,
          repr((r.returncode, r.stdout, r.stderr)))

    r = cli("bare.cyberspace")
    check("default on no-family name -> exit 2 naming both families",
          r.returncode == 2 and "no A or AAAA record" in r.stdout + r.stderr,
          repr((r.returncode, r.stdout, r.stderr)))

    reset()
    r = cli("nobody.cyberspace")
    check("default NXDOMAIN -> exit 1", r.returncode == 1,
          repr((r.returncode, r.stdout, r.stderr)))
    check("NXDOMAIN never fell back to AAAA",
          not asked("nobody.cyberspace", 28))

    reset()
    r = cli("broken.cyberspace")
    check("default SERVFAIL -> exit 2", r.returncode == 2,
          repr((r.returncode, r.stdout, r.stderr)))
    check("SERVFAIL never fell back to AAAA",
          not asked("broken.cyberspace", 28))

    r = cli("v6only.cyberspace", "--qtype", "aaaa")
    check("explicit lowercase aaaa on v6-only -> exit 0 + v6",
          r.returncode == 0 and r.stdout.strip() == "fd00::2",
          repr((r.returncode, r.stdout, r.stderr)))

    stop.set()
    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
