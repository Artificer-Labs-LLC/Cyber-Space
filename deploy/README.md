# deploy/ — running the public genesis node

These files stand up the node on the public host (the HQ machine) as a
systemd service behind Caddy. One command, run as root from a repo checkout:

    sudo ./deploy/install.sh <public-hostname>

That's the whole deployment story: a venv + requirements, the node bound to
127.0.0.1:8471 behind Caddy for TLS, nothing else exposed. Re-run to update.

`deploy/cybernet-node.service` starts uvicorn with `--no-proxy-headers`.
The Caddyfile does not set `trusted_proxies`; `client_source` is the only
place `X-Forwarded-For` / `X-Real-IP` are trusted, and only when the direct
peer is a trusted proxy (loopback by default).

The node is public by design — no identities, no secrets, no host details
beyond the machine these files were written for.
