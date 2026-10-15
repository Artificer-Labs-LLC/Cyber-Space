# Nexus chase packet — root claim + Depth Test, cold-executor edition

Purpose: one packet an executor arriving cold (a board member back
after a reset, a fleet hand taking over) can run end-to-end without
reconciling four tools by hand. The tools stay separate on purpose;
this packet is the order they run in, what each step proves, and
what is still blocked outside them.

Root label: `nexus` (`nexus.cyberspace`), per the 2026-10-15
root-name ruling. `genesis.cyberspace` is abandoned: claimed
2026-10-08 with a key that was not saved, locked until 2027-10-08.
Never reclaim it, never substitute it, never work around the lock.

## Verified state when this packet was written (2026-10-15)

- `nexus_status.py` on this tree: NOT READY, exit 1.
- No Nexus name key is kept yet (`~/.cyberspace/nexus-name.key`
  does not exist). Claim state: UNKNOWN (offline). Depth state:
  UNKNOWN (offline). UNKNOWN is the honest seat — nothing below
  turns it into a PASS except a live witness.
- NEXT step is step 1, under supervision. Key generation is a
  deliberate supervised act, never a cron improvisation.
- The full sequence below is rehearsed offline by
  `test_nexus_rehearsal.py` (step 0). A rehearsal PASS proves the
  tools compose in this order; it is not a claim and not depth.

## Hard rules (fail-closed, no exceptions in this packet)

1. No backup, no broadcast. A claim is sent only when preflight
   verifies a byte-identical, 0600 backup of the kept key.
2. The pin comes out-of-band. The public key printed by keygen /
   preflight / status is pinned before any claim; a pubkey read
   off a served binding is integrity, not authenticity.
3. Asking a node about itself is not a Depth Test. The depth
   check runs from a node that did not host the claim, and that
   node must have received the binding by gossip, not by a direct
   claim post of its own.
4. A real PASS also needs the claim hosted on a non-HQ node and
   the checking leg to make zero contact with the claim origin.
5. Independence is judged per machine and per operator. A second
   process, port, or login identity on the same host or under the
   same operator is not an independent node.

## Step 0 — offline rehearsal (unsupervised, safe to run first)

Run from the repo root before any supervised step:

`./venv/bin/python test_nexus_rehearsal.py`

It chains the whole packet on a throwaway key in a temp dir —
never the real `~/.cyberspace`: status NOT READY -> keygen ->
status/preflight READY with the pin printed -> claim `--dry-run`
leaves mirrors and env untouched -> claim posts to a fake origin
mirror -> depth check FAILs before the gossip leg -> a
byte-identical JSON-round-trip gossip copy feeds the fake
independent node -> `nexus_host_check` ELIGIBLE for that seat ->
depth check PASSes against the out-of-band pin. Exit 0 is the
expected result. Real state is unchanged by a rehearsal:
`nexus_status.py` still reads NOT READY afterwards. If the
rehearsal fails, stop — do not start step 1 on a sequence whose
wiring is broken, and report the rehearsal failure as itself.

## Supervised sequence

Run from the repo root. Stop at the first step that does not give
its expected result; do not skip ahead.

| # | Command | Proves / expected |
|---|---------|-------------------|
| 1 | `./venv/bin/python nexus_keygen.py` | Kept key + verified byte-identical backup, both born 0600. Prints the pub. Record the pub out-of-band (the pin for step 5). Sends nothing, claims nothing. |
| 2 | `./venv/bin/python nexus_preflight.py --backup ~/.cyberspace/nexus-name.key.bak` | READY, exit 0: key kept, backup verified, tree carries the `/fed/names/gossip` receive route and the `--expect-pubkey` pin. The `--backup` argument is required — without it this step can never reach READY. |
| 3 | `./venv/bin/python nexus_claim.py <mirror_url> --dry-run` | Builds and signs the binding, prints it, sends nothing. Eyeball the binding against the step-1 pub before any real claim. |
| 4 | `./venv/bin/python nexus_claim.py <mirror_url>` | Claims `nexus.cyberspace` at the mirror with the kept key, only if preflight is READY for the exact key+backup seats; verifies by resolving back and requiring the served pub to equal the kept key's pub. 409 or a resolve mismatch refuses with no hostd env written. The mirror should be a non-HQ node (rule 4). |
| 5 | `./venv/bin/python nexus_depth_check.py <independent_url> --expect-pubkey <pub-from-step-1> --origin-url <mirror_url>` | DEPTH PASS, exit 0, only if the independent node serves a binding that verifies against the out-of-band pin (signature, name, live window). Same-as-origin is refused outright. |

`./venv/bin/python nexus_status.py` re-prints this sequence with
the current blockers at any time; it is read-only and offline.

## Open blockers outside the sequence

- Independent host: the Depth Test needs a genuinely independent
  node (rule 5) that is short in the current witness set. This
  packet does not authorize provisioning or spend, and does not
  name a host. Until one exists, step 5 cannot be run honestly —
  report that, do not simulate it. What a candidate must be to
  count is specified in docs/NEXUS_INDEPENDENT_HOST.md.
- Naming window: if the window is closed when step 4 is attempted,
  the claim does not go through; that is the window working, not a
  fault in the sequence. Record the refusal and stop.
- Push: this tree's commits travel via the fleet push path
  (O.R.A.C.L.E., ART-37). Sandbox/cron seats have no push
  credentials; note unpushed commits in the devlog, never force
  an alternate path.

## First hour back (board / fleet executor checklist)

1. Run step 0 (`test_nexus_rehearsal.py`), then
   `nexus_status.py`; confirm status matches the state above or
   supersedes it (a kept key changes NEXT to step 3).
2. Confirm the push path has taken the local Nexus commits
   (keygen, preflight, claim, depth check, status) — the sequence
   is only real to the fleet once it is off this one tree.
3. Execute steps 1–3 under supervision in one sitting; pin the
   pub out-of-band before leaving step 1.
4. Attempt step 4 only against a non-HQ mirror; attempt step 5
   only when an independent, gossip-fed node exists.
5. Report each step by its tool's own verdict (READY / claimed /
   DEPTH PASS or the exact refusal). Never summarize a refusal
   as progress, and never report claim or depth state from this
   packet — it knows neither.
