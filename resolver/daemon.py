"""cybernet-resolver daemon: UDP DNS on 127.0.0.1:5353.

The local DNS face of .cyberspace — authoritative for the .cyberspace zone
and nothing else, split-horizon by construction. <label>.cyberspace queries
run the six-step fail-closed resolve_cyberspace() against the configured
mirror; anything outside the zone is forwarded to the upstream resolver
untouched; anything the handler cannot prove answers NXDOMAIN.

Single-threaded loop: recv one packet, handle_query(), send the reply,
then read the next. No threads, no workers, no shared state — the daemon
adds no trust of its own, so there is nothing to share. handle_query()
never raises (the codec and the six-step resolver are both fail-closed),
but the loop still guards the per-packet path so one bad packet can never
kill the zone. SIGINT/SIGTERM stop it cleanly.

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
import signal
import socket

from .answer import handle_query
from .dns import error_response

_DEFAULT_MIRROR = "http://127.0.0.1:8471"
_DEFAULT_UPSTREAM = "1.1.1.1:53"
_DEFAULT_BIND = "127.0.0.1"
_DEFAULT_PORT = 5353
_DEFAULT_TTL_CAP = 300


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
    """Bind and answer until SIGINT/SIGTERM. Returns, never raises."""
    bind_host, port, mirror_url, upstream, ttl_cap = _config()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((bind_host, port))
    running = True

    def _stop(_signum, _frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    while running:
        try:
            raw, addr = sock.recvfrom(65535)
        except OSError:
            continue  # a dying socket's interrupt is not the zone's death
        if not raw:
            continue
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
    sock.close()


if __name__ == "__main__":
    run()
