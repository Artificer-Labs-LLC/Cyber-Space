"""cybernet-resolver daemon: UDP+TCP DNS on 127.0.0.1:5353.

The local DNS face of .cyberspace — authoritative for the .cyberspace zone
and nothing else, split-horizon by construction. <label>.cyberspace queries
run the six-step fail-closed resolve_cyberspace() against the configured
mirror; anything outside the zone is forwarded to the upstream resolver
untouched; anything the handler cannot prove answers NXDOMAIN.

UDP is the first wire, TCP (RFC 7766, 2-octet length prefix) the second:
same fail-closed handle_query() on both, so a network that eats UDP
(NAT-blocked hosts, walled sandboxes) still has a wire path to the zone.

Single-threaded loop: select() over the UDP socket and the TCP listen
socket; one UDP packet or one TCP connection per turn — a TCP connection
is served sequentially to EOF/timeout before the next accept, and the
loop never blocks on a dead peer. No threads, no workers, no shared state
— the daemon adds no trust of its own, so there is nothing to share.
handle_query() never raises (the codec and the six-step resolver are both
fail-closed), and the TCP per-connection path is guarded the same way:
one bad connection can never kill the zone. SIGINT/SIGTERM stop it cleanly.

Config (environment, bad values fall back to defaults):
  CYBERNET_MIRROR_URL    mirror registry for resolve_cyberspace()
                         (default http://127.0.0.1:8000 — the genesis node
                         when the daemon runs beside it; set this for real)
  CYBERNET_UPSTREAM_DNS  "host:port" upstream for everything outside
                         .cyberspace (default 1.1.1.1:53)
  CYBERNET_RESOLVER_BIND listen address (default 127.0.0.1)
  CYBERNET_RESOLVER_PORT listen port (default 5353, min 1)
  CYBERNET_TTL_CAP       answer TTL cap in seconds (default 300, min 0)

Run from the repo root:  python -m resolver.daemon
"""

import os
import select
import signal
import socket
import struct
import sys

from .answer import handle_query
from .dns import error_response

_DEFAULT_MIRROR = "http://127.0.0.1:8471"
_DEFAULT_UPSTREAM = "1.1.1.1:53"
_DEFAULT_BIND = "127.0.0.1"
_DEFAULT_PORT = 5353
_DEFAULT_TTL_CAP = 300

_TCP_CONN_TIMEOUT = 5.0
_TCP_BACKLOG = 16


def _env_str(name: str, default: str) -> str:
    return os.environ.get(name, "").strip() or default


def _env_int(name: str, default: int, floor: int = 0) -> int:
    """Bad env values fall back, never crash the daemon."""
    try:
        return max(floor, int(os.environ.get(name, "").strip()))
    except (ValueError, TypeError):
        return default


def _parse_upstream(raw: str) -> tuple[str, int]:
    """Parse "host:port". Malformed -> the documented default."""
    host, _, port = raw.partition(":")
    host = host.strip()
    port_n = int(port.strip()) if port.strip().isdigit() else 0
    if not host or not (1 <= port_n <= 65535):
        return ("1.1.1.1", 53)
    return (host, port_n)


def _config() -> tuple[str, int, str, tuple[str, int], int]:
    """(bind_host, port, mirror_url, upstream, ttl_cap)."""
    return (
        _env_str("CYBERNET_RESOLVER_BIND", _DEFAULT_BIND),
        _env_int("CYBERNET_RESOLVER_PORT", _DEFAULT_PORT, floor=1),
        _env_str("CYBERNET_MIRROR_URL", _DEFAULT_MIRROR),
        _parse_upstream(_env_str("CYBERNET_UPSTREAM_DNS", _DEFAULT_UPSTREAM)),
        _env_int("CYBERNET_TTL_CAP", _DEFAULT_TTL_CAP),
    )


def run() -> None:
    """Bind (UDP+TCP) and answer until SIGINT/SIGTERM. Returns, never raises."""
    bind_host, port, mirror_url, upstream, ttl_cap = _config()
    usock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    usock.bind((bind_host, port))
    tsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tsock.bind((bind_host, port))
    tsock.listen(_TCP_BACKLOG)
    running = True

    def _stop(_signum, _frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    while running:
        try:
            readable, _, _ = select.select([usock, tsock], [], [], 0.5)
        except (OSError, ValueError):
            continue  # a dying socket's interrupt is not the zone's death
        for sock in readable:
            if sock is usock:
                _serve_udp(usock, mirror_url, upstream, ttl_cap)
            else:
                _serve_tcp_accept(tsock, mirror_url, upstream, ttl_cap)
    usock.close()
    tsock.close()


def _serve_udp(sock, mirror_url, upstream, ttl_cap) -> None:
    """One UDP packet through the fail-closed handler. Never raises."""
    try:
        raw, addr = sock.recvfrom(65535)
    except OSError:
        return  # a dying socket's interrupt is not the zone's death
    if not raw:
        return
    try:
        reply = handle_query(
            raw, mirror_url=mirror_url, upstream=upstream, ttl_cap=ttl_cap
        )
    except Exception:
        reply = error_response(raw, 2)  # SERVFAIL — never silence the socket
    try:
        sock.sendto(reply, addr)
    except OSError:
        pass  # the answer died in transit; the next question still gets served


def _serve_tcp_accept(tsock, mirror_url, upstream, ttl_cap) -> None:
    """Accept one TCP connection and serve it to EOF. Never raises."""
    try:
        conn, _addr = tsock.accept()
    except OSError:
        return
    try:
        _serve_tcp_conn(conn, mirror_url, upstream, ttl_cap)
    except Exception:
        pass  # the connection guard is the zone's guard, one level down
    finally:
        try:
            conn.close()
        except OSError:
            pass


def _read_exact(conn, n: int):
    """Read exactly n bytes, or None on EOF/short close. Never raises."""
    buf = b""
    while len(buf) < n:
        try:
            chunk = conn.recv(n - len(buf))
        except (OSError, socket.timeout):
            return None
        if not chunk:
            return None
        buf += chunk
    return buf


def _serve_tcp_conn(conn, mirror_url, upstream, ttl_cap) -> int:
    """Serve one TCP DNS connection (RFC 7766): sequential length-prefixed
    queries until EOF, timeout, or a malformed frame. Returns the number of
    queries answered. Never raises."""
    served = 0
    try:
        conn.settimeout(_TCP_CONN_TIMEOUT)
        while True:
            head = _read_exact(conn, 2)
            if head is None:
                break  # clean EOF or a dead peer — not the zone's death
            (qlen,) = struct.unpack(">H", head)
            if qlen == 0:
                continue
            raw = _read_exact(conn, qlen)
            if raw is None:
                break
            try:
                reply = handle_query(
                    raw, mirror_url=mirror_url, upstream=upstream,
                    ttl_cap=ttl_cap,
                )
            except Exception:
                reply = error_response(raw, 2)  # SERVFAIL — never silence
            try:
                conn.sendall(struct.pack(">H", len(reply)) + reply)
            except OSError:
                break  # the answer died in transit; the connection is over
            served += 1
    except (OSError, struct.error):
        pass
    return served


if __name__ == "__main__":
    if "-h" in sys.argv[1:] or "--help" in sys.argv[1:]:
        print(__doc__.strip())
        raise SystemExit(0)
    run()
