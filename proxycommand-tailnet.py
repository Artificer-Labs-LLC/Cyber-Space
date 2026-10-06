#!/usr/bin/env python3
"""SSH ProxyCommand: HTTP CONNECT through the egress proxy (with basic auth)."""
import base64
import os
import socket
import sys
import threading
from urllib.parse import urlparse, unquote


def main() -> None:
    host, port = sys.argv[1], sys.argv[2]
    proxy = os.environ.get("https_proxy") or os.environ.get("HTTPS_PROXY") or \
        os.environ.get("http_proxy") or os.environ.get("HTTP_PROXY")
    if not proxy:
        sys.stderr.write("proxycommand: no proxy env var set\n")
        sys.exit(1)
    p = urlparse(proxy)
    s = socket.create_connection((p.hostname, p.port or 3130), timeout=20)
    req = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n"
    if p.username:
        user = unquote(p.username)
        pw = unquote(p.password or "")
        auth = base64.b64encode(f"{user}:{pw}".encode()).decode()
        req += f"Proxy-Authorization: Basic {auth}\r\n"
    req += "Proxy-Connection: Keep-Alive\r\n\r\n"
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
        sys.stderr.write("proxycommand: " + resp.decode(errors="replace")[:300] + "\n")
        sys.exit(1)

    fin, fout = sys.stdin.buffer, sys.stdout.buffer

    def fwd(src, dst):
        try:
            while True:
                d = src.recv(65536)
                if not d:
                    break
                dst.write(d)
                dst.flush()
        except Exception:
            pass

    t1 = threading.Thread(target=fwd, args=(fin, s), daemon=True)
    t2 = threading.Thread(target=fwd, args=(s, fout), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()


if __name__ == "__main__":
    main()
