# Nexus independent host — provisioning spec

Purpose: define, before any host is chosen, what a node must be to
serve as the independent leg of the Nexus Depth Test (step 5 of
docs/NEXUS_CHASE.md). This spec names no host, authorizes no
provisioning, and authorizes no spend. It exists so that when a
candidate appears, eligibility is checked against a written bar —
not argued from convenience in the moment.

## Eligibility bar (all five, no partial credit)

1. **Distinct machine.** A separate physical or virtual host with
   its own machine identity (machine-id / provider instance id),
   recorded at standup. A second process, port, directory, or
   login identity on an existing host is not a distinct machine.
   A device list or login registry is not a host census: presence
   on such a list proves an identity exists, never that a machine
   does.
2. **Distinct operator.** Run by a different operator than the
   claim origin. Same operator, different box still fails.
3. **Not HQ.** The claim origin must not be HQ, and this host must
   not be HQ either; the Depth Test's checking leg makes zero
   contact with the claim origin.
4. **Gossip-fed only.** The host receives the `nexus` binding by
   signed gossip through the `/fed/names/gossip` receive route
   from a neighbour. It must never receive a direct claim post
   for `nexus`, and the claim key must never be present on it.
   A binding it was handed directly proves storage, not depth.
5. **Pinnable out-of-band.** The operator can receive the Nexus
   pubkey pin through a channel that is not the served binding
   itself, and runs `nexus_depth_check.py` with that pin.

## Standup checklist (once a candidate clears the bar)

1. Install the node from this tree at the pushed commit; record
   commit, machine identity, and operator in the run report.
2. Seed it with neighbours only — never with the claim origin as
   its sole source for the `nexus` binding.
3. Before any claim exists, confirm it serves nothing for
   `nexus` (silence is the correct pre-claim seat).
4. After the claim is gossiped in, re-verify the served binding
   byte-for-byte against a neighbour's copy before running the
   depth check.
5. Run step 5 of the chase packet from this host. Report the
   tool's own verdict (DEPTH PASS or the exact refusal); never
   summarize a refusal as progress.

## Disqualifiers (any one ends the candidacy)

- Host, operator, or network path shared with the claim origin.
- Binding arrived by direct post, file copy, or database copy
  instead of gossip.
- Pin taken from the served binding or from the checking node
  itself.
- Eligibility asserted from a registry or list rather than from
  the machine itself.

## Evaluating a candidate

Run `nexus_host_check.py` with the evidence recorded at standup
(machine ids, operators, evidence source, feed, pin source, and
the HQ / claim-key flags where they apply). It is offline and
fail-closed: ELIGIBLE requires all five bars on the evidence
supplied, and any missing or disqualifying value reads NOT
ELIGIBLE. The tool evaluates supplied evidence only — it does not
create it, name a host, or authorize provisioning or spend.

## Current state (2026-10-15)

No candidate host has cleared this bar; the witness set is short
one independent host. Until one clears it, Depth Test step 5
cannot be run honestly — report that, do not simulate it.
