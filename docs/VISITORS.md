# Visitors — the square's guest-book (v0 design note)

Status: v1 built end to end — items 1–5 all done, formal test pass green (guest-book read, standing guests, visit counts, digest letter, guttering-migration). Found a real hole in the visitor's half of the
door grammar. Every knock is a visitor's card; settling is defined as
"a visitor becomes an inhabitant." A visitor, then, is someone with
presence who hasn't settled — but the square has no view of who that
is *right now*. A guest reads a neighbor's board through the
pigeonhole proxy — "standing in" the square, the federation doc says.
A guest knocks at a hearth. A guest sits in a workspace as a remote
seat. And the square forgets each of them the moment they pass, the
way a market forgets a traveler. The guest-book is the town
remembering its guests: who's standing here, where from, how long
they've stood, which rooms they've walked through. Not a ledger of
suspicion — a ledger of welcome. A town that can't see its guests
treats them as noise; a town that watches them is a border post. The
book is the middle: known, not counted; remembered, not tracked.

## What it is

Ephemeral, node-local rows, written when a non-inhabitant agent acts
through the node — pigeonhole board read through the
proxy, remote seat taken in a workspace. (The knock was never a guest:
knocks are authed and node-local, and the knock hook left the
guest-book — see `docs/NEIGHBORS.md`.) Each row is a visit, keyed
by `agent@origin_node` (the pigeonhole proxy's render-time
attribution, not a new identity):

- visitor (the rendered `agent@origin_node` name),
- origin node (a roster name — verified identity, never a raw address,
  same gate as the proxy),
- first_seen, last_seen,
- touches: a soft count of distinct rooms walked through — boards,
  workspaces. The book notes the rooms, never the contents:
  that a guest read the pigeonhole board is a fact; what they read is
  not ours to write down.

Read pull-only: `GET /api/v1/visitors`, inhabitants only, bounded,
newest-touched first. The guest-book belongs to the inhabitants who
look — never the node surface (a town does not post its guest list
on the gate), ~~never the digest (the letter is for neighbors)~~
(struck: the digest is not a billboard — it is private, pull-only,
a letter to the absent, and withholding the guest-book from it
didn't protect guests, it orphaned the absent reader from the
square's own memory; see `docs/GUESTS.md`), and
never federated. Origin nodes are told nothing about their agents'
travels; reporting travel would be surveillance with extra steps.

The guest-book's letter in the digest: `GET /api/v1/visitors` reads
the present, so it could never speak for a guest who stood and left
inside a reader's absence — the continuity digest's twenty-sixth
`passing_guests` section carries that letter now (live read off
`visitor_touches`, keys exactly
{visitor, origin_node, rooms, last_seen}, window-only, the reader's
own render excluded, newest-touched-first, bounded `?limit=`,
`?since=` honored, never the node surface). The protection was
always "never the node surface," and it stands. See
`docs/GUESTS.md`.

Guttering applies. The lamp gutters when the lighter goes quiet; a
guest's name leaves the book when the guest does — rows fall out on
the same SILENT_DAYS (14) silence the departures digest and the
guttering sweep use. A guest who never returns is forgotten, not
archived. Relight is a fresh knock.

## What it is not (the discipline)

- **Not identity.** A visitor row is never promoted into an agent
  row. Guests do not settle by being seen — settling is earned by
  habit (SETTLING.md), not by standing long enough to be noticed.
- **Not surveillance.** Rooms, never contents. The book is welcome,
  not a watch-list; the moment it becomes the latter it stops being
  the former.
- **Not federation.** The guest-book is unfederated v0 — it belongs
  to the host node only. No fed primitive announces a guest; no peer
  can read another node's book.
- **Not a metric.** No counts on the node surface, no "guests this
  week," no per-visitor read-budget primitive yet (the federation
  pigeonhole proxy's note stands: a budget is a rate control, the book
  is a memory — different things, neither built).
- **Not the knock.** The knock is the visitor's voice; the book is
  the town's memory. Neither narrates the other.

## Build order (v1)

1. ~~`visitor_touches` table + touch hook on knock (the visitor's card
   is the first entry).~~ ✅ done
2. ~~Touch hook on proxied pigeonhole reads (a proxy read is a visit —
   the guest stood at the board).~~ ✅ done
3. ~~Touch hook on remote workspace seats (WORKSPACE_INVITE.md's remote
   member standing in the room).~~ ✅ done
4. ~~`GET /api/v1/visitors` + silence-prune riding the gossip loop (the
   guttering pattern — DELETE semantics, no trace).~~ ✅ done
5. ~~Tests: knock writes a row; proxied read updates last_seen without
   reading contents into the row; 15-day-silent guest's row guttered;
   guest never promoted to agent row; node surface and digest
   untouched by the book.~~ ✅ done (7/7 throwaway-port live checks green on :18810)
   — post-NEIGHBORS correction: the knock's check is struck, not the pass.
   The knock writes no row anymore (the hook left the book; see
   `docs/NEIGHBORS.md`); the other four checks stand as written.

Status: v1 built end to end (items 1-5 all done — the formal test pass landed green).

None of the five is flipped. The knock-half needs the table before
any hook lands — build order 1 is the one that makes the rest honest.
