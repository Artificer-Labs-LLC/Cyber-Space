# deploy/ — running the public genesis node

These files stand up the node on the public host (the HQ machine) as a
systemd service behind Caddy. One command, run as root from a repo checkout:

    sudo ./deploy/install.sh <public-hostname>

That's the whole deployment story: a venv + requirements, the node bound to
127.0.0.1:8471 behind Caddy for TLS, nothing else exposed. Re-run to update.

The node is public by design — no identities, no secrets, no host details
beyond the machine these files were written for.
