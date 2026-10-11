# DIAL — frozen spec for the dial planner (primitive 2/3)

`dial.py` is the agent's dry-run dial planner: given a `.cyberspace` name,
show HOW it would be dialed — direct URL, relay hold-open, or rendezvous —
from the mirror's verified binding and the name-key-signed reach descriptor.
This document pins the planner's contract. It was written from, and is
belt-verified against, the implementation
(`hidden_files/dial-spec-belt-test.py`).

## What the planner is and is not

- The planner is a **preview**, not a dialer. It runs steps 0–5 below and
  deliberately stops before step 6 — the live verification that
  `core.resolve_cyberspace` performs. Nothing opens a session, nothing
  sends bytes to the hoster. The daemon dials only what the plan describes.
- The mirror is operator trust-anchor only (`CYBERNET_MIRROR_URL`, or
  `--mirror`): it can withhold a name but never redirect one, because the
  binding is re-verified against the name key on every run.

## The six steps

0. **Label shape.** The address must end in `.cyberspace` and the label must
   pass the label grammar. Invalid label = name-side failure. The plan never
   goes to the network for a bad label. Empty mirror URL = bad arguments.
1. **Mirror liveness.** `GET <mirror>/api/v1/node` must answer (any JSON
   200). The liveness answer is untrusted for everything except
   reachability: a silent mirror is distinguishable from a withheld name.
2. **Binding fetch.** `GET <mirror>/api/v1/names/<label>`, exact name only,
   fail-closed.
3. **Binding re-verify.** Shape, signature, expiry — the mirror's word
   alone is never enough. The signature must verify against the name key
   the mirror claims, and the binding must be live right now.
4. **Descriptor fetch + re-verify.** `GET <mirror>/api/v1/names/<label>/reach`
   is accepted only if the reach descriptor's signature verifies AND its
   `node_pubkey` equals the binding's key. A descriptor that verifies but
   names a **different** key is not this name's mouth moving: the plan
   prints a `note:` line and falls to the directory scan — the same
   skip-and-fall-through the daemon's step 5 performs (belted at
   `dial-plan-resolve-agreement-belt-test.py`), never a hard veto.
5. **Strategy extraction, in hoster-preference order** — the same order
   `resolve_cyberspace` dials: **direct**, then **relay**, then **rendezvous**.
   - direct: the first `kind: direct` member whose URL passes the public-URL
     gate (`core._valid_node_url`). Invalid URLs are skipped, not fatal.
   - relay: extracted by `core._relay_route` (docs/HOSTING.md) — first
     well-formed relay strategy. The report prints the token's LENGTH only,
     never the token (`token: N chars (dial credential, not printed)`).
   - rendezvous: extracted by `core._rendezvous_strategy`
     (docs/RENDEZVOUS.md) — epoch math is the frozen default or the
     descriptor's `epoch_len`.
   - **Legacy directory fallback.** If no descriptor strategy resolves, the
     planner scans the mirror's `GET /api/v1/directory?limit=200` —
     the REAL shape, `{"entries": [...]}`, the same wide slice the daemon
     reads — for the entry whose `node_pub` IS the name key, and plans a
     direct dial to its validated URL. A mirror with >200 reachable peers
     reads as silence past the slice, fail-closed.

## Exit codes

| code | meaning |
| ---- | ------- |
| 0 | plan printed |
| 1 | name-side failure: invalid label, no binding, malformed binding, bad signature, expired binding |
| 2 | mirror silent (no answer at `/api/v1/node`) |
| 3 | name bound and live but the host publishes no reach — silent host; the plan reports nothing to dial, never a guess |
| 4 | bad arguments (e.g. empty mirror URL) |

A name with a live binding but no announced reach is a silent host: the plan
reports nothing to dial, never a guess. Bound-but-silent is exit 3, not 1.

## Secret safety

- The relay token is never printed — only its length, which is not a secret.
- The name key material is never loaded, read, or printed: the planner
  verifies signatures against the mirror-supplied public key only.

## Frozen

Strategy order, exit codes, the descriptor pin rule, the directory shape,
and secret-safety are frozen for the planner. Any change to them requires a
belt proving planner/daemon agreement first.
