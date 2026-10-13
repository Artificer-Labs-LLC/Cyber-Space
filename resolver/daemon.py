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
                         (default http://127.0.0.1:8471 — the genesis node
                         when the daemon runs beside it; set this for real)
                         — set but not an http(s) URL with a host ->
                         _env_str passes it through verbatim, so every
                         .cyberspace query fails at the mirror fetch and
                         answers NXDOMAIN while the daemon looks healthy;
                         run() warns loudly on stderr at startup
                         (see _daemon_config_warnings)
  CYBERNET_UPSTREAM_DNS  "host:port" (or "[ipv6]:port") upstream for
                         everything outside .cyberspace (default 1.1.1.1:53)
  CYBERNET_RESOLVER_BIND listen address (default 127.0.0.1; an IPv6
                         literal, bare or bracketed, binds an AF_INET6
                         socket, and a hostname binds the family it
                         resolves to — see _bind_target)
                         — set but not a bindable address or
                         hostname -> _env_str passes it through
                         verbatim and the bind in run()
                         raises, killing the daemon before it serves
                         anything; run() warns loudly on stderr at
                         startup (see _daemon_config_warnings)
  CYBERNET_RESOLVER_PORT listen port (default 5353, min 1)
                         — set but not an integer -> _env_int silently
                         falls back to 5353, below 1 clamps to 1, and
                         above 65535 is honored by _env_int so the bind
                         fails; run() warns loudly on stderr at startup
                         (see _daemon_config_warnings)
  CYBERNET_TTL_CAP       answer TTL cap in seconds (default 300, min 0)
                         — set but not an integer -> silently 300,
                         below 0 clamps to 0; run() warns (see
                         _daemon_config_warnings)
  CYBERNET_UPSTREAM_DNS  — set but malformed -> _parse_upstream
                         silently substitutes 1.1.1.1:53, so non-zone
                         queries go somewhere the operator never chose;
                         run() warns (see _daemon_config_warnings)

Run from the repo root:  python -m resolver.daemon
"""

import ipaddress
import os
import select
import signal
import socket
import struct
import sys
import urllib.parse

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
    """Parse "host:port" or "[ipv6]:port". Malformed -> the documented
    default. A bracketed host must be a real IPv6 literal (returned
    unbracketed, so answer._forward can pick AF_INET6); a bare IPv6
    literal has no unambiguous port split and stays malformed."""
    if not isinstance(raw, str):
        return ("1.1.1.1", 53)
    raw = raw.strip()
    if raw.startswith("["):
        host, _, rest = raw[1:].partition("]")
        host = host.strip()
        port_s = rest[1:] if rest.startswith(":") else ""
        try:
            if ipaddress.ip_address(host).version != 6:
                return ("1.1.1.1", 53)
        except ValueError:
            return ("1.1.1.1", 53)
    else:
        host, _, port_s = raw.partition(":")
        host = host.strip()
    port_n = int(port_s.strip()) if port_s.strip().isdigit() else 0
    if not host or not (1 <= port_n <= 65535):
        return ("1.1.1.1", 53)
    return (host, port_n)


def _bind_family(bind_host: str) -> tuple[int, str]:
    """(socket family, host to bind) for a CYBERNET_RESOLVER_BIND value.

    An IPv6 literal — bare ("::1") or bracketed ("[::1]", the form an
    operator copies out of a URL) — binds AF_INET6 with the brackets
    stripped; anything else (IPv4 literal, hostname) keeps AF_INET,
    exactly as before. Shape only: a malformed value still falls
    through to AF_INET and the bind raises, as it always did."""
    host = bind_host.strip()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1].strip()
    try:
        if ipaddress.ip_address(host).version == 6:
            return (socket.AF_INET6, host)
    except ValueError:
        pass
    return (socket.AF_INET, host)


def _bind_target(bind_host: str, port: int):
    """(family, sockaddr) the daemon binds for a RESOLVER_BIND value.

    A literal keeps _bind_family + the literal itself, exactly as
    before. A HOSTNAME is resolved first (getaddrinfo, AF_UNSPEC) and
    both sockets are created from the answer's family, bound to its
    sockaddr — the family can no longer be guessed from the string's
    shape. Before, every hostname kept AF_INET (via _bind_family) and
    bind() carried the unresolved string, so a v6-only hostname bind
    landed on the wrong family/address (or refused outright where no
    v4 answer exists) while the config warnings called the value
    valid — and the client/smoke wires, which resolve AF_UNSPEC,
    dialed the v6 address the daemon never bound. First getaddrinfo
    result wins, as in client._server_target. An unresolvable
    hostname raises gaierror here; run() calls this inside its bind
    try, so it reads as the existing loud refusal, never a crash."""
    family, host = _bind_family(bind_host)
    try:
        ipaddress.ip_address(host)
        return family, (host, port)
    except ValueError:
        pass
    infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC,
                               socket.SOCK_DGRAM)
    family, _kind, _proto, _canon, sockaddr = infos[0]
    return family, sockaddr


def _daemon_config_warnings() -> list[str]:
    """Loud config mistakes, or []. Unset/empty means the documented
    default (silent, a choice). Five set-but-ineffective cases the
    parsers otherwise hide: CYBERNET_RESOLVER_PORT not an integer
    (falls back to 5353, so the daemon listens somewhere the operator
    never chose), below 1 (clamped to 1), or above 65535 (honored by
    _env_int, so the bind then fails); CYBERNET_TTL_CAP not an integer
    (300) or below 0 (clamped to 0); CYBERNET_UPSTREAM_DNS set but
    malformed (_parse_upstream substitutes 1.1.1.1:53, so every
    non-.cyberspace query is forwarded somewhere unchosen); and
    CYBERNET_MIRROR_URL set but not an http(s) URL with a host and
    a dialable port (_env_str passes it through verbatim and
    _resolve_get_json can
    never fetch it, so every .cyberspace query answers NXDOMAIN
    while the daemon looks healthy — a loopback mirror is honest
    here, so unlike a node_url this gate is shape only, no
    public-address check); and CYBERNET_RESOLVER_BIND set but not a
    bindable address (_env_str passes it through verbatim and the
    bind raises, so the daemon dies before serving anything
    despite run()'s never-raises contract — shape only, offline:
    an IPv4 or IPv6 literal (bare, or bracketed for v6) or a
    syntactically valid hostname passes, a dotted all-numeric
    value that is not a valid IPv4 literal can never resolve as
    written, and a syntactically valid but unresolvable hostname is
    beyond what an offline check can prove). Mirrors
    _env_int/_parse_upstream and the fetch's scheme/host need
    exactly; never prints the values."""
    problems: list[str] = []
    raw = os.environ.get("CYBERNET_RESOLVER_PORT", "").strip()
    if raw:
        try:
            port = int(raw)
        except (ValueError, TypeError):
            problems.append(
                "CYBERNET_RESOLVER_PORT is not an integer — the 5353 "
                "default will be used instead")
        else:
            if port < 1:
                problems.append(
                    "CYBERNET_RESOLVER_PORT is below the 1 floor — 1 "
                    "will be used instead")
            elif port > 65535:
                problems.append(
                    "CYBERNET_RESOLVER_PORT is above 65535 — the bind "
                    "will fail (no valid port can be derived from it)")
    raw = os.environ.get("CYBERNET_TTL_CAP", "").strip()
    if raw:
        try:
            ttl = int(raw)
        except (ValueError, TypeError):
            problems.append(
                "CYBERNET_TTL_CAP is not an integer — the 300 default "
                "will be used instead")
        else:
            if ttl < 0:
                problems.append(
                    "CYBERNET_TTL_CAP is below the 0 floor — 0 will be "
                    "used instead")
    raw = os.environ.get("CYBERNET_UPSTREAM_DNS", "").strip()
    if raw:
        # Mirror _parse_upstream exactly (incl. the [ipv6]:port form):
        # it fell back iff the parse yields the default while the raw
        # value is not the default written out.
        if _parse_upstream(raw) == ("1.1.1.1", 53) and raw != "1.1.1.1:53":
            problems.append(
                "CYBERNET_UPSTREAM_DNS is not a valid host:port — the "
                "1.1.1.1:53 default will be used instead")
    raw = os.environ.get("CYBERNET_MIRROR_URL", "").strip()
    if raw:
        try:
            parts = urllib.parse.urlsplit(raw)
            # Port is part of the shape (dial.plan precedent): urlsplit
            # does not validate it, so parts.port must be read — it
            # raises for non-numeric/out-of-range — and 0 refused.
            port = parts.port
            mirror_ok = (
                parts.scheme in ("http", "https")
                and bool(parts.hostname)
                and (port is None or 1 <= port <= 65535)
            )
        except ValueError:
            mirror_ok = False
        if not mirror_ok:
            problems.append(
                "CYBERNET_MIRROR_URL is not a valid http(s) URL with a "
                "host — no mirror can be fetched at it, so every "
                ".cyberspace query will answer NXDOMAIN")
    raw = os.environ.get("CYBERNET_RESOLVER_BIND", "").strip()
    if raw:
        bind_ok = True
        bracketed = raw.startswith("[") and raw.endswith("]")
        inner = raw[1:-1].strip() if bracketed else raw
        try:
            ipaddress.ip_address(inner)  # v4 or v6 literal: bindable
        except ValueError:
            if bracketed:
                bind_ok = False  # brackets promise a literal; none there
            elif all(c.isdigit() or c == "." for c in raw):
                bind_ok = False  # dotted-numeric, but not a valid IPv4
            else:
                labels = raw.rstrip(".").split(".")
                bind_ok = len(raw) <= 253 and all(
                    1 <= len(label) <= 63
                    and not label.startswith("-")
                    and not label.endswith("-")
                    and all(c.isascii() and (c.isalnum() or c == "-")
                            for c in label)
                    for label in labels)
        if not bind_ok:
            problems.append(
                "CYBERNET_RESOLVER_BIND is not a bindable IPv4 or IPv6 "
                "address or hostname — the bind will fail and the "
                "daemon will not start")
    return problems


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
    """Bind (UDP+TCP) and answer until SIGINT/SIGTERM. Returns, never
    raises — a bind failure (port taken, address not local) refuses
    loudly on stderr and returns before either face is served."""
    bind_host, port, mirror_url, upstream, ttl_cap = _config()
    for warn in _daemon_config_warnings():
        print(f"resolverd: config: {warn}", file=sys.stderr)
    usock = tsock = None
    try:
        family, target = _bind_target(bind_host, port)
        usock = socket.socket(family, socket.SOCK_DGRAM)
        usock.bind(target)
        tsock = socket.socket(family, socket.SOCK_STREAM)
        tsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tsock.bind(target)
        tsock.listen(_TCP_BACKLOG)
    except (OSError, OverflowError) as exc:
        # The bind is the one step run() cannot degrade past: the port
        # is taken (a second resolverd — an install re-run beside a
        # stale daemon is the common case) or the address is not local.
        # OverflowError rides along: a port above 65535 is honored by
        # _env_int (the config warnings say the bind will fail) but
        # bind() raises OverflowError for it, NOT OSError — uncaught,
        # it broke the never-raises contract exactly where the warning
        # predicted failure. Refuse loudly and return: a raw traceback
        # under systemd reads as a crash loop, and a half-bound pair
        # (UDP bound, TCP refused) must not leak. (getattr: OverflowError
        # carries no .strerror.)
        for sock in (usock, tsock):
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        print(f"resolverd: refusing to start: cannot bind "
              f"{bind_host}:{port} ({getattr(exc, 'strerror', None) or exc})"
              f" — is another resolverd already running?",
              file=sys.stderr)
        return
    running = True

    def _stop(_signum, _frame):
        nonlocal running
        running = False

    for _sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(_sig, _stop)
        except (ValueError, OSError):
            # signal.signal only works in the main thread. An embedded
            # daemon (an agent hosting the resolver in-process, in a
            # worker thread) must still serve — the embedding process
            # owns lifetime there. Refusing to start would break the
            # never-raises contract for exactly that deployment.
            print(f"resolverd: cannot install {_sig!s} handler "
                  f"(not the main thread?) — serving without it",
                  file=sys.stderr)

    try:
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
    finally:
        for sock in (usock, tsock):
            try:
                sock.close()
            except OSError:
                pass


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
    if sys.argv[1:]:
        # The daemon takes NO arguments — it is configured by env only
        # (the systemd units pass none). Any argument is a bad argument:
        # silently ignoring one (a mistyped --port, a stray flag) started
        # the daemon on the env/default port the operator never asked
        # for, exactly the unknown-option hazard mint_name refuses.
        print(f"resolverd: refusing to start: unexpected argument(s) "
              f"{' '.join(sys.argv[1:])!r} — this daemon is configured "
              f"by environment only, no arguments are accepted",
              file=sys.stderr)
        raise SystemExit(2)
    run()
