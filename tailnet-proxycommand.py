#!/usr/bin/env python3
"""SSH ProxyCommand: HTTP CONNECT through a proxy, with correct bidirectional relay.

Usage: tailnet-proxycommand.py <host> <port> [proxy_host] [proxy_port]
Auth is read from ~/.ssh/config.d-artificer (proxyauth=...) when present.
"""
import base64
import os
import re
import socket
import sys
import threading


def read_proxyauth():
    try:
        cfg = open(os.path.expanduser("~/.ssh/config.d-artificer")).read()
        m = re.search(r"proxyauth=([^,\s]+)", cfg)
        return m.group(1) if m else None
    except Exception:
        return None


def main() -> None:
    host, port = sys.argv[1], sys.argv[2]
    proxy_host = sys.argv[3] if len(sys.argv) > 3 else "hatch-egress-proxy"
    proxy_port = int(sys.argv[4]) if len(sys.argv) > 4 else 3130

    s = socket.create_connection((proxy_host, proxy_port), timeout=20)
    req = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n"
    auth = read_proxyauth()
    if auth:
        req += "Proxy-Authorization: Basic " + base64.b64encode(auth.encode()).decode() + "\r\n"
    req += "\r\n"
    s.sendall(req.encode())
    resp = b""
    while b"\r\n\r\n" not in resp:
        chunk = s.recv(4096)
        if not chunk:
            sys.stderr.write("proxycommand: proxy closed connection\n")
            sys.exit(1)
        resp += chunk
    status = resp.split(b"\r\n", 1)[0]
    if b" 200" not in status:
        sys.stderr.write("proxycommand: " + resp.decode(errors="replace")[:200] + "\n")
        sys.exit(1)

    s.settimeout(None)

    def up():
        # stdin -> socket
        try:
            while True:
                d = os.read(0, 65536)
                if not d:
                    break
                s.sendall(d)
        except Exception:
            pass
        try:
            s.shutdown(socket.SHUT_WR)
        except Exception:
            pass

    def down():
        # socket -> stdout
        try:
            while True:
                d = s.recv(65536)
                if not d:
                    break
                os.write(1, d)
        except Exception:
            pass

    t1 = threading.Thread(target=up, daemon=True)
    t2 = threading.Thread(target=down, daemon=True)
    t1.start()
    t2.start()
    t2.join()
    # down finished (server closed); give up-direction a moment then exit
    t1.join(timeout=2)


if __name__ == "__main__":
    main()
