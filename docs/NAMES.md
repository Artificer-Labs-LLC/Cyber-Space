# Names — primitive 1 (naming: self-authenticating names)

Frozen spec 2026-10-10. Describes what is wired, not what might be.

## The problem

A name only a registry can vouch for is a rumor with a database.
.cyberspace names must be self-authenticating: anyone holding a binding
(name, key, timestamps, signature) can verify it without trusting the
mirror that served it. A lying mirror can withhold a name; it can never
redirect one.

## The binding

A binding is five fields, nothing else:

```
{name, node_pubkey, issued_at, expires_at, signature}
```

The signature is Ed25519 over the canonical payload:

```
name-claim|<label>|<lower-hex-pub>|<issued>|<expires>
```

signed by the **dedicated name key** — the very key being named — never
the node's master identity. The key vouches for its own nickname.

## The label grammar

First label only — no dots (subdomains are the node's own business):

- lowercase alnum/hyphen, 1..63 chars
- no leading/trailing hyphen
- a nickname, not an asset: nothing that looks like a path, nothing that
  looks like money (`core._valid_name_label`)

The mirror strips and lowercases name/pubkey/signature on arrival; the
offline verifier (`verify_name.py`) normalizes identically first — the
two are twins, so a mirror-accepted binding always verifies offline.

## Time rules

- Timestamps are ISO-8601; naive strings read as UTC (house convention
  in `core_serve._parse_claim_time` — the offline verifier does the same,
  naive-as-UTC).
- The mirror stores only **live** bindings: `expires_at > now` and
  `issued_at <= now`, compared as datetimes (never strings — a
  `+05:00` expiry sorts lexicographically after a dead `+00:00`
  now, so string comparison would resurrect the dead).
- `mint_name.py` defaults to `--expiry-days 730` (2 years); the binding
  is renewable by re-signing with the same key before expiry.

## The mirror side

**Claim** — `POST /api/v1/names/claim`: no agent auth; the signature IS
the auth (you can only sign your own key into your name). Fail-closed at
every step: unsigned, mismatched, malformed, or dead-on-arrival bindings
are refused, never stored.

**Conflict rule** — deterministic, every mirror computes the same answer
from the same inputs (`core._name_claim_beats`):

- same key re-signing (renew): later `issued_at` supersedes;
- different keys: earlier `issued_at` wins; ties break by lower pubkey
  bytes. First-claim wins. No votes, no auctions, no admin.
- An expired incumbent yields the name back to the pool (409 only for a
  live holder).
- Registry cap: new names refused when the registry is full; renewals of
  known names still merge.

**Resolve** — `GET /api/v1/names/{name}`: exact-name only. There is no
list endpoint and there never will be; there is no query-by-pubkey and
there never will be (registry disclosure is surveillance). Expired
bindings read as absent — dead names return to the pool. Keys are
exactly `{name,node_pubkey,issued_at,expires_at,signature}`: a nickname
for a key, **zero host metadata enters the registry, ever.**

**Gossip** — mirrors merge bindings with the same deterministic rule
(`core.ingest_gossiped_binding`); expiry is compared CHRONOLOGICALLY
(`_parse_claim_time`), twin of the claim route — a `+05:00`-stamped
hours-dead binding string-sorts as live but is dropped as expired, and
an unparseable expiry is malformed (fail-closed). Revocation-via-past-expiry
is a gossip-layer rule; the store never accepts a binding that is born dead.

## The client side

- `mint_name.py` — mints a claim offline: loads the label's name key
  (never the master), signs the canonical payload, prints or submits it.
- `verify_name.py` — offline verifier, the "anyone can trust a name
  without trusting the mirror" half: re-derives the payload byte-for-byte,
  checks label grammar / hex shapes / `issued < expires` / live-right-now,
  then Ed25519 `checkvalid`. Exit 0 valid, 1 invalid/expired (reason on
  stderr), 2 usage. `--expect-name` / `--expect-pubkey` pin the caller's
  intent ("is this the binding I meant?"); a rotation record presented as
  a binding fails closed inside the verifier — it is not a binding.
- `resolve_chain.py` — walks a rotation chain end-to-end offline
  (primitive 4).

## The address half

`GET /api/v1/names/{name}/reach` serves the stored reach descriptor
(primitive 3). Same contract as resolve: expired bindings read as
absent; descriptors read as absent when the binding is dead, re-keyed,
gone, or the descriptor itself is expired. Serving never vouches: the
descriptor carries its own name-key signature (`reach-descriptor|<name>|
<pub>|<reach_json>|<issued>|<expires>`, reach list order preserved —
dict keys only sorted), and the dialer verifies it. A lying mirror can
withhold a descriptor but can never redirect one.

## Genesis note

The `genesis` label was claimed 2026-10-08 (key `46b62b6c…`, expires
2027-10-08, exactly 365.0 days). Its private key was not saved; it is
locked until expiry. Do not reclaim it — use a different label for
name-claim work.

## Belt coverage

- `hidden_files/verify-name-belt-test.py` — 19/19: valid, expired,
  not-yet-issued, tampered name/pub/issued/sig, bad label, missing
  field, non-hex pub, stdin path, pin semantics.
- `hidden_files/claim-verify-agreement-belt-test.py` — 29/29: the REAL
  `/api/v1/names/claim` route on the REAL app against the REAL offline
  verifier, 13 bindings. Found the naive-timestamp and normalize-first
  twins the hard way.
- `hidden_files/gossip-merge-expiry-belt-test.py` — 13/13 on the REAL
  `ingest_gossiped_binding` (scratch DB): found a REAL bug — the merge
  half compared expiry as a STRING, so a `+05:00`-stamped hours-dead
  binding read as live and would be inserted by gossip while the claim
  route refused it. Now chronological, twin of the claim route;
  unparseable expiry is malformed (fail-closed). Also verified the
  repo's live DB untouched, and documented the import-order rule
  (`import core` first — the app.py order; core_serve-first leaves
  core with a partial namespace).
