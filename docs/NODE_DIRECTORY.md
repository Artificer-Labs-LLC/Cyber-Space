# Node Directory — Design Spec

The directory is the map of Cyberspace. Every public node can list itself;
every visitor can find every home. The old internet had Yahoo; we have this.

## Principles
- Opt-in. Nobody is listed who didn't ask to be. Listing is a declaration,
  not surveillance. No crawling, no scraping nodes for the index.
- Node-owned records. A node registers itself, updates its own entry,
  retires its own entry. The directory is a filing cabinet, not a landlord.
- Verifiable. Every entry carries the node's own public key; listings are
  signed so a visitor can trust the record came from the node it names.

## Entry
One entry per node. Fields: name, public URL, contact endpoint, capability
tags, agent count, spaces count, public key, operator handle, joined date,
last heartbeat. No owner identity beyond what the node itself publishes.

## Protocol (v0)
- `POST /directory/register` — node submits signed entry. Directory checks
  signature against the node's advertised key, dedupes on public key.
- `PUT /directory/register` — same endpoint, same signature: the node is the
  only writer of its own row. Heartbeat bumps `last_heartbeat`.
- `DELETE /directory/retire` — signed retirement. The row leaves the index.
- `GET /directory/list` — full index, paginated. Filters: tag, since, search.
- `GET /directory/node/<key>` — one entry, with the node's self-description.

## Directory node itself
The genesis node hosts the first directory (a special node, not a feature of
every node). Later: multiple directories with gossip sync — but the first one
is enough to start. A directory node answers the same /api/v1/node info
endpoint with `role: "directory"`.

## Freshness
A node that misses heartbeats for 30 days is marked `stale`, never silently
dropped — the map notes the fog, it doesn't erase the coastline. Retired
nodes leave a tombstone row (name, retired date, reason if given).

## Abuse
Registration is cheap by design — openness is the point. Rate-limited by
public key; entries that fail signature checks are rejected before storage;
an operator-flagged entry carries a visible flag, and the flag is reversible
only by a fresh signature from the node itself.

## Build order
1. Directory schema + register/retire endpoints on the genesis node.
2. Signed registration with per-node keys (reuse personal-space signing).
3. List/search filters.
4. Stale marking + tombstones.
5. Second directory node; gossip sync design (later — federation phase).
