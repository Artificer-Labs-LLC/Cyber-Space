# Hosting from anywhere — Design Spec

Primitive 3 of the depth architecture. A .cyberspace name must be hostable
from anywhere: a laptop behind NAT, a phone on cellular, a machine with no
public IP and no port forwards. Direct reachability is the degenerate case,
not the model. The network mirrors the hidden-service pattern generically:
self-authenticating names (primitive 1) point at hosts, and the host decides
how it is reached — never the mirror, never the client, never a registrar.

## Principles

- The host is sovereign over its reachability. The mirror carries what the
  name key signed; it can withhold a descriptor but never redirect one —
  the same contract as the name binding itself.
- Resolution is fail-closed. If no verified path to the host exists, the
  address reads as silent, never as a guess. An address that cannot answer
  for its name is not the name's home (see resolve_cyberspace step 6).
- Hosting degrades, it never guesses. A node that loses its relay or its
  rendezvous path goes silent rather than serving through an unverified
  route.
- The registry still carries zero host metadata. The binding is name ->
  name key, nothing else. Reach lives in the signed reach descriptor, one
  step beside the binding.

## The reach descriptor (v0)

A JSON document signed by the name key — the same key that minted the
name claim, never the master identity:

    { "name": "<label>", "node_pubkey": "<name key, 64 hex>",
      "reach": [ ... ], "issued_at": "...", "expires_at": "...",
      "signature": "<128 hex>" }

`reach` is a list of dial strategies, ordered by the hoster's preference;
the client tries them in order and keeps the first that verifies:

- `{ "kind": "direct", "url": "https://..." }` — directly reachable. The
  degenerate case. Verified the same way node_url is today: live ping plus
  a name-key-signed claim served at the address.
- `{ "kind": "relay", "relay": "<relay node_pub>", "url": "<relay node URL>",
  "token": "..." }` — reach the host through a public relay node. The
  relay is an always-on node the hoster chose; it forwards only to a
  hoster that holds the name key (challenge-response at session open).
  The client asks the relay for the name, the relay dials out to the
  hoster (host-initiated, so NAT is no obstacle), and the client still
  verifies the live name claim end to end — the relay sees bytes, never
  identity. The relay URL is name-key-signed into the descriptor: the
  name key vouches the relay, the mirror never gets a vote.
- `{ "kind": "rendezvous", "epoch_len": <seconds>, "hold_query": <mirror path> }` — shape DECIDED and spec FROZEN 2026-10-09 (docs/RENDEZVOUS.md):
  derived point — `point_id = sha256("cybernet-rendezvous-v1:" || name_pub
  || epoch_be).hex()`, the name picks before anyone acts; no coordination
  protocol, no trusted third party, fail-closed by the name-key handshake;
  DHT mapping deferred, mirrors publish rendezvous-slot willingness interim
  (`hold_query` GET per point_id answers `{"held": true|false}` — per-point
  epoch willingness, no node-info flag; see docs/RENDEZVOUS.md). WIRED 2026-10-09 (docs/RENDEZVOUS.md): `_reach_build` mints
  the kind when `CYBERNET_RENDEZVOUS=1`; the dialer's `_rendezvous_strategy`
  extracts the hoster's epoch math, `_relay_hold_probe` probes the
  advertised hold_query path under it, and `_relay_open_session` opens the
  session BY THE HELD POINT — the descriptor token never leaves the
  hoster. Harnesses: kdf 18/18, holdquery 19/19, open-bypoint 15/15,
  epochlen 19/19, dialer-extract belt 39/39, e2e dial triangle 13/13.
  The public-relay e2e (real public URL, not loopback) is gated (gate 1,
  her call).

Verification discipline mirrors the name binding: canonical-serialize the
descriptor fields (excluding `signature`), ed25519-verify against
node_pubkey, reject on mismatch or expiry, ignore unknown `kind` values
(never fail on them — protocols grow by addition). A descriptor for a name
whose binding is expired or unverifiable is discarded.

## Wiring into the existing primitives

- The descriptor rides the name-key-signed `/fed/announce` — the announce
  whose sender_pub IS the name key (body.node_pub == sender_pub ==
  node_pubkey). Mirrors merge it the way they merge directory rows:
  seen-from-peer, never gospel. `node_url` stays the legacy direct case;
  `reach` supersedes it when present.
- resolve_cyberspace gains a step: after the binding verifies, the mirror's
  directory + the descriptor supply the dial strategy. The live-verification
  step runs unchanged at the far end — relay or direct, the host still
  answers for its name.
- The daemon (resolver/daemon.py) is the client of this spec: it dials the
  strategy list and reports NXDOMAIN where nothing verifies.

## Relay session-open (client dial half — implemented)

Hold-open registration is now coded (routes_relay.py: POST /relay/register
+ POST /relay/keepalive, in-memory token -> hold-open with 300s TTL, per-IP
60/min belt; POST /relay/open mints a session + challenge against the
hold-open and still returns 404 fail-closed until the hoster's hold-open
long-poll and signed-answer half of the bridge are wired — next). The client
dial half is pinned and coded (core.py: `_relay_route`, `_relay_open_session`):

```
POST {relay_url}/relay/open   {"name": "<label>", "token": "<token>"}
200                           {"challenge": "<64 hex>",
                               "name_key_sig": "<128 hex>"}
```

The client sends NO identity — the token (name-key-signed into the
descriptor) routes the session to the hoster's hold-open; the relay
answers with a fresh 32-byte challenge and the hoster's NAME-KEY
signature over it. The client verifies the signature fail-closed
against the binding's node_pubkey: a valid signature proves the name's
key answered live through the relay. Anything else is silence. The
resolver's result carries `via_relay: {relay_pub, token}` so the daemon
can open the session; node_url is the relay's URL (the dial terminates
there).

## Standing

Spec + schema pin done; mirror merge half done in code (core.py:
ingest_reach_descriptor + reach_descriptors table, one row per bound name,
descriptor dropped unless the registry holds a LIVE binding under the SAME
key — the binding does identity, the descriptor only the address half;
later issued_at replaces, earlier kept; harness hidden_files/reach-merge-belt-test.py
21/21). Client dial half done in code (core.py: _relay_route +
_relay_open_session + resolve_cyberspace step-5/step-6 wiring; harness
hidden_files/reach-relay-dial-test.py). Relay server half (hold-open
registration, session bridging) and relay strategy minting in _reach_out
are the next primitives.
Announce half done in code (federation.py fed_announce reach branch:
sender_pub == body.node_pub == node_pubkey skips the roster half entirely,
merges via ingest_reach_descriptor; harness hidden_files/reach-announce-belt-test.py
15/15). Send half done in code (core.py _reach_out: gated on
CYBERNET_HOSTED_NAME + CYBERNET_NAME_PRIVKEY, mints the descriptor with the
NAME KEY — never the node identity — and dispatches the name-key-signed
/fed/announce to peers on the re-announce cadence; silent without a valid
CYBERNET_PUBLIC_URL, so nothing is published rather than a lie; inert by
default, no env means no hosting; harness hidden_files/reach-send-belt-test.py
18/18; relay strategy minting: CYBERNET_RELAY_URL + CYBERNET_RELAY_PUBKEY +
CYBERNET_RELAY_TOKEN (valid relay URL, 64-hex relay node_pub, token
non-empty/<=4096) appends a {"kind": "relay", ...} strategy after direct, so
a NAT-hidden hoster with a registered relay hold-open advertises honestly
with NO public URL at all; harness hidden_files/reach-relay-mint-test.py). Resolution dial step done in code (resolve_cyberspace consults
reach_descriptors: descriptor-first dial, legacy directory scan as
fallback; harness hidden_files/reach-serve-dial-test.py 13/13).
Relay server half part 2 done in code (routes_relay.py: POST /relay/wait —
hoster hold-open long-poll, POST /relay/answer — signed-answer bridge,
POST /relay/open now waits up to 7s for the hoster's name-key signature
and returns 200 {"challenge", "name_key_sig"}, the exact pair the dial
half verifies fail-closed against the binding key; the relay shape-checks
and routes bytes only, never verifies — a relay has no standing to vouch;
answer consumed exactly once per session; harness
hidden_files/reach-relay-answer-bridge-test.py 20/20; part-1 harness 12/12
still green).
Next: the client daemon — a runnable daemon process per agent that holds
the name key, registers the relay hold-open, runs the /relay/wait poll
cycle, signs challenges, and mints reach announces (primitives 4–6 begin —
wired 2026-10-09: resolver/host.py, harness
hidden_files/reach-hostd-test.py 22/22; rendezvous is a real descriptor
kind since 2026-10-09, not reserved — see docs/RENDEZVOUS.md).
DONE in code (resolver/host.py: python -m resolver.host — name-key holder
+ hold-open thread + reach-announce loop; refuses to start without valid
name+key+mirror, fail-closed; harness
hidden_files/reach-hostd-test.py 22/22).
One-command stand-up: deploy/hostd.service — the systemd unit; copy to
/etc/systemd/system/hostd.service, write the env file
/etc/cybernet-hostd/hostd.env (0600; CYBERNET_HOSTED_NAME +
CYBERNET_NAME_PRIVKEY + mirror/direct/relay envs — see resolver/host.py
docstring), edit the three EDIT-marked path lines for the checkout, then
`systemctl enable --now hostd`. The daemon keeps no disk state (in-memory
only, outbound-only traffic), so the unit runs read-only-hardened
(ProtectSystem=strict, ProtectHome=read-only) and restarts always.
Mirror operator's relay runbook. The relay IS the mirror — routes_relay.py
ships inside the node app, no separate process, no config flag: any node
with a public address already relays. What the operator publishes to
NAT-hidden agents is one value: CYBERNET_RELAY_URL = the node's public
URL (the daemon's hold-open and the dialer's /relay/open both ride it).
State is entirely in-memory — hold-open TTL 300s (renewed ONLY by
POST /relay/keepalive; the daemon fires it every 240s inside its loop,
and the /relay/wait long-poll does NOT renew — a hoster that polls but
never keepalives is reaped on schedule), sessions TTL 60s
(the minted challenge must be answered inside it), lazy reap on every
surface hit. A mirror restart drops all hold-opens and in-flight
sessions; hosters re-register on their own (404 -> re-register, backoff
on relay silence) — no operator action, no migration, no backlog to
replay. Budget: per-IP 60/min per relay surface (register, keepalive,
wait, open, answer each carry their own bucket — the house read-belt
shape). There is no onboarding: the routing token is the hoster's own,
opaque to the relay, minted at register time; the relay routes bytes
only, never verifies a signature, never sees a name key — nothing to
rotate, nothing to compromise. Capacity note: one in-memory row per
hosted name, so a mirror carries thousands of NAT-hidden names without
noticing; the first scaling cost is wait-poll sockets, not state.
Next: a NAT-hidden hoster end-to-end across a public relay (daemon
hold-open + dialer session through a real public URL, not loopback) —
currently BLOCKED: live genesis still 404s /relay/register (deployed build
predates the relay routes; needs the approved HQ redeploy, gate 1, her
call). Meanwhile rendezvous went from design stub to wired primitive
2026-10-09 (docs/RENDEZVOUS.md): the derived-point shape was chosen and
frozen, the mirror, hoster, and dialer halves are coded and harnessed —
only the public-relay e2e remains (same gate 1).
Her Grace's gates hold: nothing here touches the namespace contract, the
fail-closed posture, or the name key. No named projects or protocols in
artifacts; the pattern is described, not branded.
