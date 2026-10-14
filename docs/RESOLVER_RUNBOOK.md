# RESOLVER_RUNBOOK.md — the live end-to-end (resolver build item 3)

Status: **HQ self-resolution RUN — 2026-10-12, on HQ (Villhaze;
Meridian's label, accepted — the Depth Test bar in the preamble still
stands for "real").** The full chain is live:
registry binding → cybernet-resolver (UDP+TCP, tailnet 100.86.209.63:5354)
→ HQ systemd-resolved split-horizon (`~cyberspace`) → `getent hosts
genesis.cyberspace` = 185.143.228.228 → `curl http://genesis.cyberspace/`
serves the node. Smoke PASS on both wires (registered name NOERROR + 1 A
answer; junk label NXDOMAIN). Two live lessons, both now law:
(1) **the resolver daemon holds its code in memory** — after any node
redeploy, restart `cybernet-resolver.service` too, or it keeps answering
with the old code (the Oct-08 process NXDOMAINed a healthy registry for
four days and had no TCP face). (2) **Caddy site addresses need explicit
`http://`** — the on-disk Caddyfile's bare-IP block had drifted from the
running config; a restart silently upgraded the IP face to an HTTPS
redirect. Also: `systemctl reload caddy` cannot reach this instance's
admin socket — restart the unit instead. Remaining client half: her machines wire one by one, each on her word.
**Phone door (2026-10-12, later — REJECTED by Her Grace and rolled
back):** a port-53 instance (`cybernet-resolver-dns53.service`) was
briefly stood up for a Tailscale split-DNS wiring. She ruled it a false
success — a client forwarding the zone to HQ's own daemon is the house
grading its own homework — and the verdict stands as FAIL. The unit was
disabled and removed and its firewall rules deleted the same day. The
name passes on a device only when that device's own implementation
verifies the signed binding (extension or local daemon). Depth Test,
first half, ran 2026-10-12 from outside HQ: the extension code resolved
genesis.cyberspace live and refused a one-character-tampered binding.
Windows machine: the extension in her browser is the path (NRPT to HQ's
daemon is the same false success — not offered).

Gate 1 (genesis redeploy) was APPROVED by Villhaze 2026-10-12 under the
standing governance (Research Board recommends, Villhaze rules, fleet
executes); gate 2 (name-key attestation) is held by cryptography —
fail-closed stands until the key is available. Run these steps in order
when the fleet executes the gate-1 redeploy. Every step fails closed —
stop at the first red line and fix it before moving on.

## Step 0 — preconditions on HQ

- The current tree must reach `~/cybernet/node` via the fleet push path:
  O.R.A.C.L.E. holds the GitHub push path (ART-37); sandbox/cron runs have
  no push credentials and do not push. No approval from Her Grace is
  required or awaited — Cyberspace decisions are Villhaze's under the
  standing hands-off order.

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
- Run it twice: once plain (UDP) and once `python3 resolver/wiring/smoke.py
  --tcp` (DNS-over-TCP, RFC 7766) — the daemon serves the same zone on both
  wires and each path must PASS separately before anything is trusted.
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
