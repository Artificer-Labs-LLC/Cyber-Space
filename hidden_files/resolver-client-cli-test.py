#!/usr/bin/env python3
"""Resolver CLI e2e harness: python -m resolver.client against a fake daemon.

Spins a minimal TCP DNS face on loopback (sandbox allows TCP loopback),
then runs the REAL CLI as a subprocess with CYBERNET_RESOLVER_PORT aimed
at it. Exercises the real argument parsing, real transport fallback, and
the 0/1/2 exit-code contract. Deferred-by-design: none here — this one runs
in-sandbox because the wire path is TCP.
"""

import os
import socket
import struct
import subprocess
import sys
import threading

REPO = os.path.expanduser("~/workspace/cybernet")
PASS = FAIL = 0


def check(label, cond, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok   {label}")
    else:
        FAIL += 1
        print(f"  FAIL {label} {extra}")


def _read_name(data, off):
    parts = []
    while data[off] != 0:
        n = data[off]
        parts.append(data[off + 1 : off + 1 + n].decode("ascii"))
        off += 1 + n
    return ".".join(parts), off + 1


def fake_daemon(stop):
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
            question = q[12:]
            if qname == "alice.cyberspace" and qtype == 1:
                flags, answers = 0x8180, [(1, socket.inet_aton("93.184.216.34"))]
            elif qname == "alice.cyberspace" and qtype == 28:
                flags, answers = 0x8180, [(28, socket.inet_pton(socket.AF_INET6, "fd00::1"))]
            elif qname == "broken.cyberspace":
                flags, answers = 0x8182, []
            else:
                flags, answers = 0x8183, []
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


def _read_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise OSError("eof")
        buf += chunk
    return buf


def cli(*args, env_port=None):
    env = dict(os.environ)
    env["CYBERNET_RESOLVER_PORT"] = str(env_port if env_port is not None else port_holder[0])
    return subprocess.run(
        [sys.executable, "-m", "resolver.client", *args],
        cwd=REPO, env=env, capture_output=True, text=True, timeout=15,
    )


port_holder = []
stop = threading.Event()
fake_daemon(stop)
import time
for _ in range(50):
    if port_holder:
        break
    time.sleep(0.05)

r = cli("alice.cyberspace")
check("A query -> exit 0 + address", r.returncode == 0 and r.stdout.strip() == "93.184.216.34", repr((r.returncode, r.stdout, r.stderr)))

r = cli("alice.cyberspace", "--tcp-only")
check("--tcp-only A -> exit 0", r.returncode == 0 and r.stdout.strip() == "93.184.216.34")

r = cli("alice.cyberspace", "--qtype", "AAAA")
check("AAAA query -> exit 0 + v6", r.returncode == 0 and r.stdout.strip() == "fd00::1", repr((r.returncode, r.stdout, r.stderr)))

r = cli("nobody.cyberspace")
check("NXDOMAIN -> exit 1", r.returncode == 1 and "does not resolve" in r.stdout + r.stderr, repr((r.returncode, r.stdout, r.stderr)))

r = cli("broken.cyberspace")
check("SERVFAIL -> exit 2", r.returncode == 2, repr((r.returncode, r.stdout, r.stderr)))

r = cli("alice.cyberspace", "--qtype", "MX")
check("bad qtype -> exit 2 (argparse)", r.returncode == 2, repr((r.returncode, r.stderr)))

r = cli()
check("no name -> exit 2 (argparse)", r.returncode == 2, repr((r.returncode, r.stderr)))

r = cli("alice.cyberspace", env_port=1)  # nothing listening: UDP EPERM->TCP refused
check("dead daemon -> exit 2", r.returncode == 2, repr((r.returncode, r.stdout, r.stderr)))

stop.set()
print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
