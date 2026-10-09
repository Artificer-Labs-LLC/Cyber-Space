# RESOLVER_RUNBOOK.md — the live end-to-end (resolver build item 3)

Status: written-not-run. The gates: (1) an approved code deploy of the
current tree to HQ (`/home/villhaze/cybernet/node`, genesis is still 0.1.0 —
`/api/v1/names/genesis` 404s at the router, so the daemon's only source of
truth isn't deployed yet), (2) a client machine for the split-horizon wiring
(the tunnel to her machine has been down since 2026-10-07 12:00 EDT).

When both gates open, run these steps in order. Every step fails closed —
stop at the first red line and fix it before moving on.

## Step 0 — preconditions on HQ

- `pushes are batched and approval-gated`: the current tree (333 commits
  locally, ~141 unpushed since the approved 07:45 batch push) must reach
  `~/cybernet/node` with her manual approval. No other way.

## Step 1 — deploy runs the script

On HQ: `cd ~/cybernet/node && git pull && sudo ./deploy/install.sh`

- install.sh now includes step **[4/4]**: installs
  `resolver/wiring/cybernet-resolver.service`, daemon-reload, enable,
  restart, `is-active` check. It exits 1 if the unit fails to start —
  treat that as the red line, not as a warning.
- Confirm: `systemctl status cybernet-resolver.service --no-pager` active.
- Confirm the mirror URL matches the node's port: the unit sets
  `CYBERNET_MIRROR_URL=http://127.0.0.1:8471` (the node's uvicorn port
  per `deploy/cybernet-node.service`). If the node moves ports, these two
  must move together.

## Step 2 — the daemon answers its own zone (on HQ)

- The genesis name must exist in the registry FIRST: POST the signed
  binding to `POST /api/v1/names/claim` (form fields: name, node_pubkey,
  issued_at, expires_at, signature — signature is the auth, fail-closed,
  see routes_social.py). Until the claim lands, `genesis.cyberspace`
  NXDOMAINs by design.
- On HQ: `python3 resolver/wiring/smoke.py` — expects the registered name
  -> NOERROR + A, junk label -> NXDOMAIN, exit 0. Both lines must say PASS.
- If smoke fails: daemon not answering -> `systemctl status
  cybernet-resolver.service`; answering but NXDOMAIN on the real name ->
  the claim isn't in `name_bindings` (check `GET /api/v1/names/genesis`,
  404 "No such name." means the registry, not the daemon, is empty).

## Step 3 — client-side split-horizon wiring (her machine)

Pick ONE of the three units in `resolver/wiring/` — systemd-resolved
(`cyberspace-resolved.conf`: `DNS=127.0.0.1:5353`, `Domains=~cyberspace`;
the `:port` suffix is valid syntax, verified against resolved.conf(5)),
dnsmasq (`cyberspace-dnsmasq.conf`), or the `/etc/hosts` pin
(`hosts-snippet.txt`, one verified name only). The wired daemon is the
HQ one — the client asks HQ's 127.0.0.1:5353, not a local copy.

## Step 4 — the smoke from the client

- `dig genesis.cyberspace` (or `getent hosts`) must answer the genesis
  node's A record. Anything else -> NXDOMAIN is the daemon's honest
  answer; a timeout is the wiring's lie — fix the wiring.
- `curl genesis.cyberspace` must reach the genesis node through the name.

## Step 5 — flip item 3

RESOLVER.md item 3 gets flipped ✅ with the run date; items 2-3 stop
reading "written-but-unproven". The devlog notes the first real `.cyberspace`
resolution.

## Recovery notes (do not skip)

- The daemon never invents: NXDOMAIN on anything the mirror never taught
  it, SERVFAIL on dead upstreams, never a guessed record. If a query
  should answer and doesn't, the gap is upstream of the daemon (registry,
  wiring), never in it.
- UDP binds are unprivileged (5353, no capabilities); ProtectSystem=strict
  — the daemon holds no writable state, so permission errors point at the
  unit file, not the code.
