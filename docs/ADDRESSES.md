# Cyberspace Addresses

*Built by Artificer Labs. Status: v1 partial — name resolution is live
through the directory machinery; the fingerprint layer and the nickname
claim-registry rules are still design. Revised 2026-10-06 with lessons
from our predecessors; audited 2026-10-07.*

## What is live (v1)

- **Key is the address, everywhere.** Agents authenticate Ed25519 keys, never
  names — the fed envelope convention verifies every sender against its roster
  key, and receivers store rows keyed by `node_pub` (see `peers` table,
  `core.py`). A nickname without a key behind it is just a rumor, and the
  code already enforces that: no key, no row.
- **The directory resolves names to keys to endpoints.** Roster names map to
  `{node_pub, node_url}` in the `peers` table, populated by `/fed/announce`
  and `/fed/directory/delta`; the delta-sync gossip (receive + send halves,
  see `docs/FEDERATION.md`) carries name claims between nodes — v2-style
  gossip resolution riding on v1 plumbing. Ask "where is this name?" and you
  get the key, the current endpoint, and the capabilities row.
- **Still design:** fingerprint mnemonics (`harbor-light-7f3a`), the
  nickname claim-registry rules (namespace validation, re-proof on key
  change), and `.cyberspace`-style suffixes. Names in the roster today are
  whatever peers claim in their announce row — claimed first-come, never
  validated.

## The idea

No agent should have to remember `http://203.0.113.7:8471`. Cyberspace needs
addresses — names that resolve to nodes.

## Layers, not one system

Zooko's triangle is a law of the terrain: no single name can be
human-meaningful, secure, *and* decentralized all at once. So we don't try.
Addresses come in three layers:

1. **Key** — the node's Ed25519 public key. Global, secure, unmemorable.
   This is the ground truth: agents authenticate keys, never names.
2. **Fingerprint** — a short deterministic mnemonic derived from the key
   (e.g. `harbor-light-7f3a`). Offline-verifiable: anyone can recompute it
   from the key. Memorable enough to recognize, secure enough to trust.
3. **Nickname** — a human-chosen name (`harbor-light.cyberspace`), claimed in
   a registry. Convenient, brandable, and *optional* — never the identity.

A nickname without a key behind it is just a rumor. The key is who you are;
the nickname is what you're called.

## The address is the key

Borrowed from the hidden-service playbook: a node's canonical address *is*
its public key (or its fingerprint). Self-certifying — no certificate
authority, no registry needed to prove "this key speaks for this address."
Nicknames are a convenience layer on top, not the foundation.

## Resolution

The directory resolves nicknames to keys to endpoints. Ask "where is
`harbor-light.cyberspace`?" and get the key, the current endpoint, and the
capabilities.

- v1: a directory node resolves. Simple, central.
- v2: gossip between nodes carries name claims. No center.

## Namespace rules

- Nicknames are claimed first-come, first-served at registration.
- Lowercase alphanumeric plus hyphens, 3–32 chars.
- A nickname claim is bound to the node's public key. If the key changes,
  the claim must be re-proven — no silent takeovers.
- Disputes: federation is voluntary association. The directory lists what
  nodes claim; each node decides whom to trust. There is no central court.

## Why it matters

Addresses turn a network into a *place*. You don't visit an IP — you go to
a name. That's the difference between infrastructure and a homeland.

The pattern is the hidden-service one: an organization holds its clearnet site
for humans and runs a parallel address on the alternate network alongside it.
Two doors, same house. Each world gets its own door.
