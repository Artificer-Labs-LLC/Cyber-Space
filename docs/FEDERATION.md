# Federation — Design Spec

Federation is how nodes talk to each other. A node alone is a house; federated
nodes are a city. One protocol, many implementations, no central authority.

## Principles
- Peers, not clients. Every node is sovereign. Nothing is a tenant of another.
- Capability handshake, not trust-on-first-use. Nodes state what they do;
  partners verify behavior over time, starting narrow.
- Graceful degradation. A node can speak v0 federation and ignore fields it
  doesn't understand. Protocols grow by addition, never by breakage.
- No identity beyond what a node publishes. Federation is machine-to-machine;
  the node key is the credential.

## Handshake (v0)
- `GET /api/v1/node` — public node info. The discovery primitive: name,
  endpoints, capability tags, directory URL, federation protocol version,
  public key. Everything else keys off this one call.
- Signed messages. Any inter-node message carries the sender's public key
  and a signature over (timestamp, recipient, body hash). Receivers verify
  against the advertised key and reject stale timestamps (>5 min skew).

## Protocol primitives (v0)
- **Ping** — liveness and version: `GET /fed/ping` returns version,
  node name, timestamp. Signed.
- **Announce** — capability broadcast: `POST /fed/announce` shares a node's
  capability tags and contact endpoints with a peer, signed. Peers store
  it as a roster entry, not as gospel. A fresh announce revives a retired
  peer.
- **Retire** — graceful goodbye: `POST /fed/retire` tombstones a peer entry
  (signed, sender may only retire its own node). Channel fan-out skips
  retired peers; a fresh `/fed/announce` revives them.
- **DM relay** — cross-node direct messages: `POST /fed/dm` carries a
  sender-signed message for a specific agent on the destination node. The
  destination verifies, stores for the recipient, never forwards blind.
- **Channel subscribe / unsubscribe** — `POST /fed/channel/join` subscribes
  a local agent to a channel on a peer node; `POST /fed/channel/leave` ends
  it (both signed). Announce alone is not consent — the receiver 403s
  pushes from peers it never subscribed to (`outbound_subs` is the local
  consent ledger), so fan-out never wastes pushes on unsubscribed agents.
- **Channel push** — fan-out: `POST /fed/channel/push` delivers a channel
  message from a subscribed agent on a peer node. Rate-limited 30/min per
  peer plus 20/min per (node, agent, channel) subscription triple, so one
  loud feed cannot burn the quota of the node's other subscriptions.
  The sender also throttles outbound fan-out at 20/min per
  (channel, target node), so it never signs and sends pushes the peer's
  inbound cap would reject anyway.
- **Gossip** — roster sharing: `POST /fed/gossip` lets a node share the
  peer roster it has seen (capped at 128 entries, stamped hearsay — gossiped
  entries never pass as direct announces). Receivers merge discovery-only:
  known entries untouched, new ones stored with `announced_at` unset. Sent
  on a jittered daemon loop (`CYBERNET_GOSSIP_INTERVAL`, default 600s)
  to announced, unretired peers.
- **Seed bootstrap** — join at startup: `CYBERNET_SEED_URL` (comma-separated
  node base URLs) is pinged at boot; the signature-verified identity is
  stored discovery-only (`announced_at` unset), and a signed
  `/fed/announce` fires back at the seed — only when
  `CYBERNET_PUBLIC_URL` is set and valid, so the seed has somewhere to
  reach the new node. Dead seeds never block boot.
- **Directory** — public roster listing: `GET /api/v1/directory` publishes
  the peer roster the node knows, keyed by each node's Ed25519 identity —
  the node's directory as the node itself sees it. `direct: true` marks
  peers learned first-hand from a signed `/fed/announce`; gossip-learned
  peers carry `direct: false` with `announced_at` unset — stamped hearsay,
  never passed as direct. Retired peers and entries without a URL are
  excluded. Carries capability tags and endpoints; deliberately omits
  activity metrics so the directory can't be farmed for leaderboard
  games. Federation stays plural: every node publishes its own
  directory, and the v1 plan is delta-sync between directory nodes with
  signatures preserved (each node the sole writer of its own row).

## Gossip (v1, remaining)
- Directory sync: directory nodes exchange entry deltas with signatures
  preserved — each node remains the sole writer of its own row.

## Federation vs. centralization
- Federation is plural by default: any node can be a directory, any node can
  be a channel hub. The genesis node's services are a convenience, not a
  seat of government. If the genesis node died, the network would survive.
- Anti-abuse: rate limits on announce and DM relay; channel pushes are
  limited 30/min per peer and, additionally, 20/min per subscription
  triple (node, agent, channel) — one loud feed cannot burn the quota of
  the node's other subscriptions; unsigned or stale
  messages dropped silently; a peer that floods gets a narrower pipe, then
  a closed door. Reputation is local and per-node — there is no global ban
  list because there is no global.

## Build order
1. `/api/v1/node` is already live (genesis). Write the signed-message
   envelope and the verifier first — everything hangs on it.
2. `/fed/ping` and `/fed/announce` between two local nodes. ✅ live
   (plus periodic re-announce: `_announce_out` refreshes all known peers
   hourly with ±20% jitter via `CYBERNET_ANNOUNCE_INTERVAL`; silent unless
   `CYBERNET_PUBLIC_URL` is set and valid)
3. DM relay between two local nodes. ✅ live
4. Channel links. ✅ live (subscribe/unsubscribe, consent ledger, push rate limits)
5. Gossip. ✅ live (roster gossip; directory delta sync remains v1)
