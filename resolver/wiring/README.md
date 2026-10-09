# Wiring — making the daemon real on a machine

The daemon (`resolver/daemon.py`) answers one zone and nothing else.
Wiring it in means telling the machine's own resolver to send it the
`.cyberspace` questions and nothing else. The systemd unit (section 0)
runs the daemon; the three copy-paste split-horizon configs (sections
1–3) do the telling. Pick one config.

**Status (2026-10-07):** these are written, not yet proven — they get
their first live run on the HQ node (genesis resolving its own name is
a fine smoke test), then on her machine. The port-suffix question in the
systemd-resolved unit is settled from the docs (resolved.conf(5): each
DNS= address can take an optional ":port" — `DNS=127.0.0.1:5353` is
valid; `resolvectl status` confirms it at wiring time). The remaining
untested corner is the live run itself.

## 0. The daemon as a service (new — untested on a live host)

File: `cybernet-resolver.service` in this directory. Written against the
genesis node's own host layout (`User=villhaze`,
`WorkingDirectory=/home/villhaze/cybernet/node`,
`CYBERNET_MIRROR_URL=http://127.0.0.1:8471` — the node uvicorn serves on
8471 beside Caddy).

```
sudo cp cybernet-resolver.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now cybernet-resolver.service
```

This runs only the daemon on 127.0.0.1:5353 (unprivileged port, no
capabilities needed). The split-horizon half — teaching the machine's own
resolver to send `.cyberspace` there — is still one of the three
copy-paste units below. Her machine's path will differ; edit the unit's
paths before installing there.

## 1. systemd-resolved (her machine, HQ node)

File: `cyberspace-resolved.conf` in this directory.

```
sudo cp cyberspace-resolved.conf /etc/systemd/resolved.conf.d/
sudo systemctl restart systemd-resolved
```

`Domains=~cyberspace` is a routing-only domain — only `.cyberspace`
routes to 127.0.0.1:5353; everything else keeps the system resolvers.

## 2. dnsmasq

File: `cyberspace-dnsmasq.conf` in this directory.

```
sudo cp cyberspace-dnsmasq.conf /etc/dnsmasq.d/cyberspace.conf
sudo systemctl restart dnsmasq
```

`server=/.cyberspace/127.0.0.1#5353` — only the zone goes to the
daemon. (dnsmasq's `#port` syntax is long-established.)

## 3. /etc/hosts fallback

File: `hosts-snippet.txt` in this directory. No daemon, no wiring —
pin one verified name to its address by hand. You are the trust root
here, so pin only names you've already verified through the daemon or
the registry, and re-pin on the binding's TTL.

## The daemon itself

From the repo root, with the project venv:

```
python -m resolver.daemon          # 127.0.0.1:5353 by default
```

Env: `CYBERNET_MIRROR_URL` (default `http://127.0.0.1:8000` — the
genesis node), `CYBERNET_UPSTREAM_DNS` (default `1.1.1.1:53`),
`CYBERNET_RESOLVER_BIND` / `CYBERNET_RESOLVER_PORT`,
`CYBERNET_TTL_CAP`. All env is bad-value-tolerant (falls back, never
crashes).

On the HQ node, point `CYBERNET_MIRROR_URL` at the local node so the
genesis name resolves its own address.

## Smoke test

```
python resolver/wiring/smoke.py [--name genesis.cyberspace]        # UDP path
python resolver/wiring/smoke.py --tcp [--name genesis.cyberspace]  # DNS-over-TCP path (RFC 7766)
```

1. registered name → NOERROR with at least one A record
2. random never-registered `.cyberspace` label → NXDOMAIN (fail-closed)
3. run both: the daemon serves UDP and TCP on the same port; check each wire

Exit 0 only if all run checks pass. Run it after wiring, before trusting anything.
