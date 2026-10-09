# Rendezvous — wired primitive (2026-10-09)

The third dial strategy in the reach descriptor — WIRED 2026-10-09
(mirror, hoster, and dialer halves coded and harnessed; status at the
end of this note). The design space below is frozen history: the
problem it had to solve and the shape candidates.

## The problem the relay leaves open

The `relay` kind (HOSTING.md) works: the hoster picks an always-on public
relay, holds it open, and the relay bridges sessions. But the hoster chose
the point — a single always-on node the hoster (or whoever runs it) controls.
That is fine for the shipped path, and it is also the one structural trust
the relay design concentrates: whoever runs the chosen relay observes the
full metadata of who is talking to the hoster (timing, volume, the fact of
contact — never identity, the relay sees bytes, but metadata is real).

Rendezvous is the answer to: client and hoster meet at a point **neither
chose alone**.

## Non-negotiable properties

- **No unilateral steering.** Neither client nor hoster can force the meeting
  point onto a node either controls. Unilateral choice is the thing being
  removed.
- **The point sees opaque session material, never identity.** Same contract
  as the relay: name-key-signed end-to-end verification still happens at
  the far end; the point never learns whose name is being reached.
- **Fail-closed.** If no rendezvous point is found for the epoch, the name
  reads silent — never a fallback to an unverified point.
- **Descriptor-driven.** Whatever the point is, it must be expressible as a
  `reach` entry the name key signed: `{ "kind": "rendezvous", ... }` with
  everything the daemon needs to compute the meeting. Unknown fields ignored
  by older daemons, per the addition-only growth rule.

## Candidate shapes

1. **Derived point.** Point identity = KDF(name key pub, epoch). Both client
   and hoster compute the same point from the name itself; both register a
   hold-open with it, and it pairs them. Nobody chose it — the name did.
   Hard part: a point only works if a node that matches the derived identity
   exists and is reachable. Needs a mapping from derived identity to live
   node, which is either a directory lookup (mirrors, again) or a DHT —
   and a DHT is a whole second project.
2. **Introducer slot.** Mirrors carry a rendezvous-request slot: hoster posts
   a blinded request (epoch + token, no name), client posts a matching one;
   the mirror pairs them onto a node neither named. The mirror becomes the
   steering party by default, which violates "neither chose alone" unless
   the pairing rule is deterministic and auditable.

Neither is specified yet. Both need the e2e relay path proven first — the
session protocol (hold-open, challenge, bridge) is the same protocol a
rendezvous point would run; only point selection changes.

## Decision (2026-10-09 — rendezvous shape decided)

**Derived point wins.** The introducer slot loses on its own grounds.

The introducer slot's steering problem is structural, not fixable with
auditing: the mirror remains the sole executor of the pairing. A
deterministic pairing rule lets the parties recompute where they *should*
have landed, but only after revealing their blinded requests to each
other — which defeats the blindness the slot was built on. Auditable after
the fact is not non-steerable in the moment; the mirror still picks the
node, and its transcript is the only witness. Determinism without an
independent executor is a receipt, not a constraint.

The derived point puts the choice in a function nobody controls:
`point = KDF(name_pub, epoch)`. No party — hoster, client, mirror, or
operator — can steer it onto a node they run, because the name picks before
anyone acts. Both sides compute it independently; no coordination protocol,
no new machinery, no trusted third party. The shipped session protocol
(hold-open, name-key challenge, bridge) runs unmodified at the point.

Fail-closed is structural, not bolted on: a squatter can claim to hold the
derived point, but session material is name-key-signed end-to-end and the
point never sees identity. A fake point fails the name handshake and the
name reads silent — the same guarantee the relay already ships.

The known hard part is acknowledged, not solved: the mapping from derived
identity to a live willing node. A DHT is still a second project and is
still deferred. The interim is addition-only on HOSTING.md: mirrors
publish rendezvous-slot willingness (which derived points they will hold
for the epoch); clients resolve willingness from the mirrors they already
know. Directory-first, DHT later, and the descriptor field grows without
breaking older daemons.

Honest limit, kept visible: the derived point is publicly computable —
anyone who knows the name can predict where its traffic concentrates next
epoch. This shape removes *steering*, not *observation*. Metadata
concentration (the "relay sees the fact of contact" problem) is reduced —
the point moves every epoch and nobody chose it — but not eliminated.
Rotating slots and multi-point fan-out stay reserved as the follow-on.

## Frozen descriptor spec (2026-10-09 — fields frozen, code still gated)

The derived-point dial strategy, fully specified so code time is pure
implementation. Rendezvous code still starts only after the relay e2e is
proven (gate 1); this spec changes no daemon behavior today.

Reach entry, name-key-signed in the descriptor:

    { "kind": "rendezvous",
      "epoch_len": 3600,
      "hold_query": "/rendezvous/slots" }

- `epoch_len`: seconds per epoch, integer, 60–86400. Default 3600.
  Shorter epochs rotate the point faster (less metadata concentration,
  more hold-open churn); the hoster picks the trade, the client follows.
- `hold_query`: relative mirror path where a daemon asks a known mirror
  which derived points it will hold this epoch. GET, query `point`
  (64 hex point_id); 200 with `{"willing": true, "until": <epoch end>}`
  or `{"willing": false}`.

Point identity, computed identically by hoster and client, no exchange:

    epoch    = floor(now / epoch_len)
    point_id = sha256("cybernet-rendezvous-v1:" || name_pub_32bytes
                      || epoch_8bytes_big_endian).hex()

`name_pub` is the name key (64 hex in descriptors, 32 bytes on the wire) —
the same name the reach descriptor is signed under. `point_id` is an opaque
64-hex meeting token, never an identity: the point still never learns whose
name it is pairing, and session material is name-key-signed end-to-end.
A point_id whose epoch has passed is dead — fail-closed reads silent.

Epoch-boundary tolerance (no clock is perfect):

- `now` is unix time (UTC seconds). `epoch = floor(now / epoch_len)` counts
  whole epochs since the unix epoch — epoch 0 is 1970-01-01T00:00:00Z, so
  hoster and client always agree on what "epoch E" means.
- Hoster and client each derive TWO point_ids: current E and previous
  E−1. The dialer tries E first, then E−1. The hoster holds both points at
  the same mirror (still paired from the name, not steered).
- Mirror `hold_query` answers `willing` for points in the current or the
  immediately previous epoch; anything older is silent (fail-closed).
- Rationale: at an epoch boundary (or under normal clock skew) the two
  sides can disagree on which epoch is "now". Without the E−1 grace the
  pair never meets and neither side learns why — a silent break in the
  very primitive that's supposed to need no coordination. Trying both
  costs one extra hold-open and one extra query; no clocks are assumed
  to agree beyond that. Skew worse than one full epoch_len is a broken
  clock (NTP it), not a pairing problem — the pair stays silent.

Mirror willingness, interim directory (DHT deferred):

- Mirrors post their willingness as node-info on the node they run:
  `"rendezvous_willing": true` plus a per-epoch slot cap
  (`"rendezvous_slots_per_epoch"`, default 256, integer, advertised).
- A daemon wanting to hold the derived point GETs `hold_query` on the
  mirrors it already knows; the first willing mirror is the meeting
  surface. Both sides hold-open to the same point_id at the same mirror —
  the mirror pairs the two hold-opens, which is pairing, not steering:
  the point was derived from the name before either side acted.
- Willingness is directory-only: mirrors learn the point_id (a bare token)
  and the fact of contact, never the name. Directory-first, DHT later.

Addition-only growth rule honored: `rendezvous` is a new `kind` value —
older daemons ignore unknown kinds (HOSTING.md) and keep dialing `relay`.

## Status

**Shape decided and spec frozen: derived point.** HOSTING.md's
`{ "kind": "rendezvous", ... }` is
`{ "kind": "rendezvous", "epoch_len": <seconds>, "hold_query": <mirror path> }`
with the point_id derivation and mirror willingness contract above. Mirror
side of the contract is WIRED (2026-10-09): `POST /relay/register` accepts
an optional `rendezvous_point` + `name_pub` pair (refused 400 when the point
is not in a willing epoch, so a miscomputed point is a loud client error,
never a silent mispairing), indexes point_id -> hold-open (addition-only;
the hold-open protocol itself is unmodified), `keepalive` refreshes the
point entry, and `GET /relay/hold_query?point_id=` answers
`{"held": true|false}` — true only for fresh, registered, still-willing
points; everything else silent `false`, never a 4xx. Loopback-tested
(hidden_files/rendezvous-holdquery-test.py, 19/19 on the real app).
`POST /relay/open` also accepts the derived `rendezvous_point` in place
of the routing token (2026-10-09) — the dialer opens a session without
ever learning the token; the mirror resolves point -> held token only
for fresh, registered, still-willing points (malformed, unregistered,
stale, old-epoch = 404 silence, exactly like an unknown token), and the
name-key signature stays the dialer-verified auth. Explicit token wins
when both are given. Loopback-tested
(hidden_files/rendezvous-open-bypoint-test.py, 15/15 on the real route
functions, incl. full hoster-answer round trips and token-wins-when-both).
Daemons still ignore the `rendezvous` kind; the shipped NAT-hidden path is
`relay`. Hoster-side (dual-point hold in hostd) is wired; dialer-side is now
WIRED (2026-10-09): core._relay_hold_probe derives the (E, E-1) pair from
the binding's name key and GETs /relay/hold_query before /relay/open — a
positively-answered nobody-holds reads as silence (no session minted);
held -> open as before; query-unknown (relay predates hold_query,
transport failure, un-derivable point) -> legacy open, so a new dialer
never goes silent under an old relay. SSRF gate note: query strings are
host-level (stripped before the shape match in _reject_nonpublic_node_url
and _node_url_host; stored node addresses stay query-free). Harness
hidden_files/dialer-hold-probe-test.py 9/9. Dialer-side open-by-point
WIRED (2026-10-09): `_relay_hold_probe` now returns the held point_id
(not a bare True), and `_relay_open_session` opens the session BY THAT
POINT — `{"name", "rendezvous_point"}`, the descriptor token never sent
— when the probe said held; held:false -> silence; probe-unknown ->
legacy `{"name", "token"}`. End-to-end proven: the real dial half
bridged a live daemon through the real relay app with the point doing
the routing (reach-relay-dial-e2e-test.py 13/13, reach-hostd-test.py
22/22). A bogus descriptor token no longer fail-closes on the
rendezvous path — the held point routes and the name-key challenge
signature is the auth; token silence stays the legacy-relay behavior.
The public-relay e2e and the
deployed genesis build remain gated (gate 1, her call).

**Rendezvous is a REAL descriptor kind (2026-10-09).** The reservation
is lifted: `_reach_build` mints `{ "kind": "rendezvous",
"epoch_len": <60..86400>, "hold_query": "/relay/hold_query" }` when
`CYBERNET_RENDEZVOUS=1` (epoch_len from `CYBERNET_RENDEZVOUS_EPOCH_LEN`,
fail-closed to the frozen default 3600; only rides with a relay
strategy — the derived points are held at that relay). The advertised
epoch_len now drives the meeting math on all four sides: the dialer's
`_rendezvous_strategy` extraction feeds `_relay_hold_probe` /
`_relay_open_session` (core.py), the hostd daemon holds under the same
env value (hold_open.py `_rendezvous_epoch_len`), and the relay
validates willingness under the epoch_len carried in the register
body (routes_relay.py — stored per point record, old records read as
3600). A miscomputed point is still a loud 400 at register; a relay
too old to know epoch_len keeps working (record defaults to 3600).
Harness hidden_files/rendezvous-epochlen-test.py 19/19 on the real
relay app: 600-math registers and answers willing, the same name's
3600-math point reads held:false, dialer probe finds the held point
under the advertised math. Note: the frozen spec's `hold_query:
"/rendezvous/slots"` was written before the relay became the meeting
surface — the wired path is the relay's `/relay/hold_query`, and the
descriptor advertises the wired path.
