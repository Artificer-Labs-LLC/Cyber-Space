"""Belt: the resolver daemon answers the .cyberspace zone live on the wire.

Pinned contract (primitive 2, resolution): with a dead mirror the daemon
must answer <label>.cyberspace with NXDOMAIN (rcode 3) — silence, never a
guess — stay alive through the fail-closed path, print no traceback, and
stop cleanly on SIGTERM with rc 0.

Sandbox note: this sandbox forbids UDP sendto even to loopback (EPERM), so
the UDP face cannot be exercised live here — UDP legs SKIP with a clear
note when sendto raises PermissionError. The TCP face (RFC 7766, same
fail-closed handle_query()) is the live verification; the UDP codec path
stays covered by resolver/test_serve_loop.py's fake-socket checks.

Usage: ./venv/bin/python hidden_files/daemon-live-serve-belt-test.py [--repo ROOT] [--port P]
  --repo defaults to the cybernet checkout this belt lives in; point it at
  a worktree to probe a staged line (e.g. the r3-local staging).
Loopback only: the daemon binds 127.0.0.1, the mirror and upstream point at
dead ports. Zero external network.
"""

import argparse
import errno
import os
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_REPO = os.path.dirname(HERE)

PASS = 0
FAIL = 0
SKIP = 0


def check(name, cond, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok  {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name} {extra}")


def skip(name, reason):
    global SKIP
    SKIP += 1
    print(f"  skip {name} ({reason})")


class SandboxBlocksUDP(Exception):
    pass


def query_packet(qname, qtype=1, qid=0x5001):
    labels = b"".join(bytes([len(p)]) + p.encode() for p in qname.split("."))
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    return header + labels + b"\x00" + struct.pack(">HH", qtype, 1)


def parse_reply(reply):
    if len(reply) < 12:
        return None
    qid = struct.unpack(">H", reply[:2])[0]
    flags = struct.unpack(">H", reply[2:4])[0]
    return {"qid": qid, "qr": (flags >> 15) & 1, "rcode": flags & 0xF}


def udp_query(port, qname, qtype=1, qid=0x5001, timeout=5.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        try:
            s.sendto(query_packet(qname, qtype, qid), ("127.0.0.1", port))
        except PermissionError as e:
            if e.errno == errno.EPERM:
                raise SandboxBlocksUDP("sandbox forbids UDP sendto (EPERM)")
            raise
        data, _ = s.recvfrom(4096)
        return parse_reply(data)
    finally:
        s.close()


def tcp_query(port, qname, qtype=1, qid=0x5001, timeout=5.0):
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    s.settimeout(timeout)
    try:
        pkt = query_packet(qname, qtype, qid)
        s.sendall(struct.pack(">H", len(pkt)) + pkt)
        (n,) = struct.unpack(">H", _recvall(s, 2))
        return parse_reply(_recvall(s, n))
    finally:
        s.close()


def _recvall(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("short read on TCP DNS face")
        buf += chunk
    return buf


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=DEFAULT_REPO)
    ap.add_argument("--port", type=int, default=15361)
    args = ap.parse_args()

    repo = os.path.abspath(args.repo)
    port = args.port
    venv_py = os.path.join(DEFAULT_REPO, "venv", "bin", "python")
    if not os.path.isfile(os.path.join(repo, "resolver", "daemon.py")):
        print(f"FAIL not a cybernet tree: {repo}")
        return 1
    if not os.path.isfile(venv_py):
        print(f"FAIL project venv missing: {venv_py}")
        return 1

    # The scratch port must be free, or the daemon under test is not ours.
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.bind(("127.0.0.1", port))
    except OSError as e:
        print(f"FAIL scratch port {port} busy: {e}")
        return 1
    finally:
        probe.close()

    env = dict(os.environ)
    env["CYBERNET_RESOLVER_BIND"] = "127.0.0.1"
    env["CYBERNET_RESOLVER_PORT"] = str(port)
    env["CYBERNET_MIRROR_URL"] = "http://127.0.0.1:1"   # dead: fail-closed
    env["CYBERNET_UPSTREAM_DNS"] = "127.0.0.1:9"         # dead: never forward
    env["HOME"] = tempfile.mkdtemp(prefix="daemon-belt-home-")

    out = tempfile.NamedTemporaryFile(prefix="daemon-belt-out-", delete=False)
    err = tempfile.NamedTemporaryFile(prefix="daemon-belt-err-", delete=False)
    proc = subprocess.Popen(
        [venv_py, "-m", "resolver.daemon"], cwd=repo, env=env,
        stdout=out, stderr=err,
    )
    try:
        # Readiness on the TCP face (UDP sendto is sandbox-blocked).
        ready = None
        for _ in range(100):
            try:
                ready = tcp_query(port, "ready.cyberspace", timeout=1.0)
            except OSError:
                ready = None
            if ready and ready["qr"] == 1:
                break
            time.sleep(0.1)
        check("daemon binds and answers on the wire", ready is not None and ready["qr"] == 1)
        if ready is None:
            print("  (daemon never answered; aborting legs)")
        else:
            # Leg 1: TCP face — dead mirror => NXDOMAIN, qid echoed.
            r = tcp_query(port, "probe-tcp.cyberspace", qid=0x5101)
            check("TCP A query -> NXDOMAIN rcode 3",
                  r is not None and r["rcode"] == 3 and r["qr"] == 1,
                  f"got={r}")
            check("TCP reply echoes query id",
                  r is not None and r["qid"] == 0x5101, f"got={r}")

            # Leg 2: silence regardless of qtype.
            r = tcp_query(port, "probe-aaaa.cyberspace", qtype=28, qid=0x5102)
            check("TCP AAAA query -> NXDOMAIN rcode 3",
                  r is not None and r["rcode"] == 3, f"got={r}")

            # Leg 3: UDP face — sandbox-blocked here; skip honestly.
            try:
                r = udp_query(port, "probe-udp.cyberspace", qid=0x5103)
                check("UDP A query -> NXDOMAIN rcode 3",
                      r is not None and r["rcode"] == 3 and r["qid"] == 0x5103,
                      f"got={r}")
            except SandboxBlocksUDP as e:
                skip("UDP A query -> NXDOMAIN rcode 3", str(e))

            # Leg 4: the fail-closed path never kills the zone.
            alive = proc.poll() is None
            r = tcp_query(port, "probe-after.cyberspace", qid=0x5104)
            check("daemon alive and still answering after fail-closed legs",
                  alive and r is not None and r["rcode"] == 3, f"got={r}")

        # Leg 5: clean shutdown, no traceback anywhere.
        proc.send_signal(signal.SIGTERM)
        rc = proc.wait(timeout=10)
        check("SIGTERM stops the daemon cleanly with rc 0", rc == 0, f"rc={rc}")
        out.close(); err.close()
        with open(out.name, "rb") as f:
            sout = f.read()
        with open(err.name, "rb") as f:
            serr = f.read()
        check("no traceback on daemon stdout/stderr",
              b"Traceback" not in sout and b"Traceback" not in serr,
              f"stdout_tail={sout[-200:]!r} stderr_tail={serr[-200:]!r}")
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()

    print(f"daemon-live-serve belt: {PASS} passed, {FAIL} failed, {SKIP} skipped (repo={repo})")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
