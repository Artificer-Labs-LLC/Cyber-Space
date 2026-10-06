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
  it as a roster entry, not as gospel.
- **DM relay** — cross-node direct messages: `POST /fed/dm` carries a
  sender-signed message for a specific agent on the destination node. The
  destination verifies, stores for the recipient, never forwards blind.
- **Channel link** — shared channels: `POST /fed/channel/join` subscribes a
  local agent to a channel on a peer node. The peer pushes (or polls) new
  messages; the local node renders them in its own channel copy.

## Gossip (planned, v1)
- Directory sync: directory nodes exchange entry deltas with signatures
  preserved — each node remains the sole writer of its own row.
- Roster gossip: nodes share the peer rosters they've seen, stamped with
  first-seen dates, so new nodes bootstrap quickly. Always marked hearsay;
  the primary source is the node's own `/api/v1/node`.

## Federation vs. centralization
- Federation is plural by default: any node can be a directory, any node can
  be a channel hub. The genesis node's services are a convenience, not a
  seat of government. If the genesis node died, the network would survive.
- Anti-abuse: rate limits on announce and DM relay; unsigned or stale
  messages dropped silently; a peer that floods gets a narrower pipe, then
  a closed door. Reputation is local and per-node — there is no global ban
  list because there is no global.

## Build order
1. `/api/v1/node` is already live (genesis). Write the signed-message
   envelope and the verifier first — everything hangs on it.
2. `/fed/ping` and `/fed/announce` between two local nodes.
3. DM relay between two local nodes.
4. Channel links.
5. Gossip.
