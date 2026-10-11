# Rotation — primitive 4 (identity: key continuity)

Frozen spec 2026-10-10. Describes what is wired, not what might be.

## The problem

A .cyberspace name binding is self-authenticating: the name key signs its own
claim (`name-claim|<label>|<pub>|<issued>|<expires>`), and anyone holding the
binding can verify it without trusting the mirror. But a name outlives its
key. Keys are lost, rotated, upgraded. When the key changes, how does a
verifier who trusted the OLD binding know the NEW binding names the same
lineage — without a registry to ask?

The answer is a rotation record: the OLD key vouches for the NEW key. One
signature is the whole continuity.

## The record

A rotation record is:

```
name-rotate|<label>|<old_pub>|<new_pub>|<issued_at>
```

signed by the OLD key. Every field is canonicalized before signing and before
verifying, twin-of-mirror: label stripped + lowercased, hex keys stripped +
lowercased, naive timestamps read as UTC. The payload prefix is disjoint from
`name-claim`, so a claim payload can never verify as a rotation and vice
versa.

Properties, all enforced fail-closed at mint, verify, and accept:

- **Point event, not a binding.** A rotation carries no expiry. "At time T, the
  holder of the old key designated this new key." Liveness belongs to the new
  claim, which carries its own issued/expires window.
- **Not yet in force.** A rotation dated in the future is signed and valid but
  inert until its timestamp passes. Future rotations can be published early
  and take effect on their own clock.
- **No self-rotation.** old == new is refused at mint and at verify.
- **Not a binding.** A rotation record fed to `verify_name.py` fails closed —
  it is not a name binding and can never be confused with one.

## The loop: MINT -> SUBMIT -> PROMOTE

`rotate_name.py` (primitive-4 client tool) runs one loop, in order, deliberate
at every step:

1. **MINT** — loads `~/.cyberspace/<label>-name.key` (the OLD key), mints and
   self-verifies the rotation record, writes:
   - `~/.cyberspace/<label>-rotate.json` — the record (publish this)
   - `~/.cyberspace/<label>-name.key.next` — the NEW key seed (0600)
   
   The old key file is NEVER overwritten by minting. Promotion stays a
   deliberate operator step.

2. **SUBMIT** (`--submit [MIRROR_URL]`) — posts the record AND a fresh binding
   to the mirror's `POST /api/v1/names/rotate`. The new binding is a new
   `name-claim` signed by the NEW key, issued at submit time (so it cannot
   predate the rotation), with `--expiry-days` (default 730) like `mint_name`.
   Submit verifies the mirror actually moved the name before reporting
   success: the live binding must resolve to the new key AND the new hop must
   appear in `GET /names/{name}/rotations`. Refuses before sending (record
   must verify and be in force; `.next` must derive the new key; current key
   must still derive the old key — submit-before-promote is enforced
   client-side) and after (non-200, unparseable reply, or resolve-back mismatch
   refuses; key files are only ever read, never written).
   
   `--submit` and `--promote` together exits 2: the order is load-bearing.

3. **PROMOTE** (`--promote`) — closes the loop AFTER the mirror accepted.
   Re-verifies the rotation record (signature, in force, `.next` derives the
   new key, current key still derives the old key), then atomically swaps
   `.next` into the name key (`os.replace`, never half-written, 0600), keeping
   the old seed at `.prev` for chain-walking history. Deliberate CLI flag
   only; never automatic.

Exit codes: 0 = done; 1 = refused (reason on stderr); 2 = usage / unreadable.

## The mirror side

- `POST /api/v1/names/rotate` — accepts a rotation record + new binding. The
  record must verify under the CURRENTLY BOUND key (the old key's authority
  moves the binding), and the new binding must verify under the new key with
  fresh timestamps. The hop is stored in `name_rotations` and the live
  binding updated — atomically.
- `GET /api/v1/names/{name}/rotations` — the immutable point-event history
  from `name_rotations`, oldest designation first. Survives binding expiry:
  dead names keep their chains. 404 on no rows (absence, not emptiness), 400
  on a bad label. Ordering is `accepted_at, rowid` — rowid is the mirror's
  true insertion order; second-granularity ties once made same-second
  rotations order unstable, fixed 2026-10-10.

## The client side: following a chain

`resolve_chain.py` walks a name's rotation history fail-closed, from a mirror
or fully offline (rotations JSON on stdin):

- name-consistency FIRST (naming-the-sides reasons — a cross-label replay
  names the problem instead of misfiring as a signature failure),
- then each hop's signature under its OLD key (the old key vouches for the
  new),
- then linkage: hop N's old == hop N-1's new; a gap is a broken lineage.

`--expect-original-key` pins the caller's trusted head; `--with-live` fetches
the live binding, verifies it offline, and demands it name the chain's
terminal key. A dead name (binding expired/absent) reads DEAD — chain intact,
label available — never broken.

## Why genesis can never rotate

`genesis` was claimed 2026-10-08 and its private key was never saved. No one
holds the old key, so no one can mint a rotation record for it. The record
format makes this structural, not a policy: without the old key's signature,
there is no rotation. "genesis" is locked to its claimed binding until its
expiry, 2027-10-08.

## Belt coverage (primitive 4)

- `hidden_files/rotate-name-belt-test.py` 15/15 — mint/verify (incl. 9 refusals)
- `hidden_files/rotate-promote-belt-test.py` 15/15 — promote loop
- `hidden_files/rotate-submit-belt-test.py` 14/14 — submit against the real app
- `hidden_files/rotate-history-belt-test.py` 14/14 — read-side incl. offline walk
- `hidden_files/resolve-chain-belt-test.py` 22/22 — chain walking end-to-end
- `hidden_files/claim-verify-agreement-belt-test.py` 29/29 — mirror/verifier parity

Primitive 4 (identity) is complete end-to-end: mint, submit, promote, read,
walk. The next primitive-4 work is split-horizon resolver wiring (gated:
name-key attestation for the genesis mirror is Her Grace's call).
