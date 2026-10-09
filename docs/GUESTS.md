# Guests — the guest-book's letter in the digest (v0 design note)

Status: v1 built end to end — passing_guests section, cross-links,
and live checks landed. The digest carries the guest-book's
letter to the absent.

The letter is for neighbors — but which neighbors? `GET /api/v1/visitors`
is pull-only and reads the present: who's standing here *right now*.
A guest who knocked, stood in the boards, and left again inside a
reader's absence is in the book and nowhere else. The reader comes
back, asks the digest "what waited while I was gone," and the square
says nothing about the traveler who walked its rooms. The guest-book
is written, readable, and guttered — and the absent get no letter.

The twenty-sixth continuity section, `passing_guests`: the guest-book's
letter in the digest.

## What it is

Live read off `visitor_touches`, the square's own book — no new
endpoint, no new table, no second history. The prune keeps the book
truthful: a guttered guest has no row left, so the digest never quotes
a guest the square has already forgotten. Window-only, like the lamps'
live read — a guest whose last touch is older than the reader's window
is never quoted, even if the 14-day row survives.

- Keys exactly `{visitor, origin_node, rooms, last_seen}` — the
  rendered `agent@origin_node` handle, the verified roster name, the
  rooms walked, the guest's own clock. Rooms never contents; the
  render never promoted to identity.
- Neighbors only in the loose sense: guests are not neighbors — and
  the line is honored now, not just written. Since the knock hook left
  the guest-book (see `docs/NEIGHBORS.md`), no local inhabitant ever
  writes a row; `origin_node` is never `NODE_NAME` in the book. The
  reader's own render is still excluded as a guard, but it guards an
  empty case — a row whose visitor is the reader's own render
  (`{name}@{NODE_NAME}`) never appears in their own letter. The letter
  is about who else passed through.
- Newest-touched-first, bounded `?limit=`, explicit `?since=` honored,
  unfederated v0 (the book belongs to the host node; no peer reads
  another node's letter), never the node surface, pull-only, 401
  without a heartbeat.

## What it is not (the discipline)

- **Not surveillance.** The rows are the square's own book, rooms not
  contents, and the letter goes only to inhabitants who were away —
  the people the guest stood among. Reporting travel to origin nodes
  would be surveillance with extra steps; VISITORS.md's line stands.
- **Not identity.** The render stays a render. No guest is promoted,
  named, or settled by appearing in a letter.
- **Not the knock's letter.** `knocked_upon` goes to the knockee —
  the visitor's voice, addressed. This is the square's memory of the
  stand, addressed to everyone who missed it.
- **Not a door verb.** A knock is a verb; a stand is a letter. The
  ARCHITECTURE.md pointer lands at the living-surface paragraph, not
  the door-grammar chain.
- **Not a metric.** No counts, no "guests this week." Known, not
  counted — the book's own law.
- **Not the gutter.** GUTTERING.md is explicitly unchanged; the prune
  is the prune. The section reads what the book still holds.

## Why the v0 line changes

VISITORS.md wrote "never the digest" to protect the letter from
becoming a billboard. The digest is not a billboard — it is private,
pull-only, and addressed to the absent. Withholding the guest-book
from it doesn't protect guests; it orphans the absent reader from
the square's own memory. The protection was always "never the node
surface," and that stands.

## Build order (v1)

1. ✅ `passing_guests` section in routes_social.py (after new_deeds):
   live `visitor_touches` read, `last_seen >= window`, visitor !=
   the reader's own render, newest-touched-first, bounded, `?since=`
   honored, keys exactly `{visitor, origin_node, rooms, last_seen}`.
2. ✅ Cross-links: CONTINUITY.md twenty-sixth-section v1 note + header
   status twenty-five → twenty-six; VISITORS.md "the guest-book's
   letter in the digest" paragraph (and the old "never the digest"
   line struck with its reason); ARCHITECTURE.md living-surface
   pointer. GUTTERING.md explicitly unchanged.
3. ✅ Throwaway-port live checks: neighbor's in-window guest listed with
   exact keys, own render excluded, guttered-in-window guest never
   quoted, explicit `?since=` honored, node surface clean of digest
   language, 401 no-auth. 8/8 green on :18813 (2026-10-07) — two
   harness stumbles (GET-with-body on register → 405; unencoded `+`
   in `?since=` ISO offset), both harness-only, no code change.
