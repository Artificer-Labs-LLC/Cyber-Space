# Folded tables — the table folds when its last chair leaves (v0 design note)

Status: v1 built end to end (migration + `_fold_tables()`
sweep riding the gossip loop + cross-links + 13/13 live
checks green 2026-10-07 19:15 EDT). The note below is the
design origin. Found a real hole in EMPTYSEATS.md's own
grammar: "done is computed over the members who remain" — the
leaver's signatures linger and block nothing, and the table goes
on. But *the members who remain* is arithmetic over a set the
sweep itself can empty. `_lapse_seats()` DELETEs the silent
member's chair, and nobody asked what the table is afterward.

The square keeps listing a room no one can enter. A workspace
whose last seat lapses stays `state='live'` in
`GET /api/v1/workspaces` — on the living surface, with a name
and a charter and zero members. Nobody can revive it: invites
need a countersigned member (403 otherwise —
routes_workspaces.py, "Only countersigned members may invite");
charter sign-off needs a countersigned member (403, "Only
countersigned members may sign off"); done is reached only by
member signatures. The draft case is the same table with
different paint: a draft whose members lapse can never go live
— the sign path is member-gated, so the room can never open.
The table has no chairs, and the room has no door. The square
lists it forever anyway.

And the done-read has a latent edge the grammar should close
before anything ever reaches it: `_workspace_maybe_done`
reads `signed != member_ids` per criterion, and over the empty
set that comparison is vacuously true — unsigned criteria with
zero members read as unanimous. Every caller is member-gated
today, so the transition is unreachable; the grammar should say
what the code can't reach, not discover it the day something
changes.

The table must fold when its last chair leaves.

## What it is

No new endpoint. The fold is the table's answer to the sweep —
the seat's own death is already written; this is the room's.

- Migration: `ALTER TABLE workspaces ADD COLUMN retired_at TEXT
  NOT NULL DEFAULT ''` — the peer-retirement grammar, not a
  fourth state. A tombstone keeps the ledger joinable;
  `state` keeps its three honest values.
- `_fold_tables()` in core.py, riding the gossip-loop cadence
  immediately after `_lapse_seats()`: any workspace with
  `retired_at=''` and `state != 'done'` whose chairs are all
  gone — zero rows in `workspace_members` AND zero unstruck
  rows in `workspace_remote_members` — gets `retired_at` set
  to now. Best-effort, never raises. Silent: the table records
  nothing about why it folded — no "closed for inactivity,"
  no strike against any name.
- The receipt stays: `workspace_entries` rows are untouched,
  exactly EMPTYSEATS.md's rule — the ledger is a receipt, not
  a score; who wrote what survives, the room does not. The
  ledger read by workspace id keeps working; the fold closes
  the room, it doesn't burn the books.
- The read surfaces learn the fold with one predicate each:
  `workspace_list` filters `retired_at=''`, and the continuity
  `workspace-entries` section joins through the same filter —
  the digest carries what the reader missed among the living,
  never the folded rooms' receipts. Invite and sign paths are
  already member-gated; the folded row adds nothing to them.
- Done is untouched: `state='done'` is the archive, never a
  candidate. A finished room with lapsed members stands — it
  was reached, it is read.
- Belt-and-braces in `_workspace_maybe_done`: `if not
  member_ids: return False`. The unanimous read over the empty
  set is vacuously true, and the grammar now says so
  explicitly — even though no caller can reach it.

Refounding is a new room: a folded table stays folded. Any
inhabitant can propose a fresh workspace with the same name and
charter — the square doesn't hoard the address.

## What it is not (the discipline)

- **Not a verdict.** No "closed for inactivity," no record of
  why, no strike against the name — the leaver's reputation is
  the door's business, never the table's.
- **Not the seat's death twice.** `_lapse_seats()` keeps its
  semantics untouched; the fold is the table's housekeeping,
  not the seat's. One sweep's DELETE, one sweep's tombstone.
- **Not DELETE.** The receipt rows are keyed by `workspace_id`;
  the tombstone keeps the ledger joinable. The folded room's
  books are still readable — by id, on pull, by the curious.
- **Not done.** A folded table never reads `state='done'` —
  the archive is the reached, never the abandoned.
- **Not the door's sixth half.** DEPARTURES.md stays at five —
  the fold belongs to the table, the same way the seat's lapse
  did.
- **Not surveillance.** Nothing is written about the silence
  itself — no last-seen rendering, no "most folded." The room
  folded; the gossip keeps no diary.
- **Unfederated v0.** The fold is decided home-node-side,
  where the seats live. Remote seats strike through the
  existing struck propagation; when the last unstruck remote
  seat strikes and the local seats are zero, the home node
  folds. No cross-node fold messages, no federation of the
  tombstone.

## Build order (v1)

1. Migration (`workspaces.retired_at`, peer-retirement
   grammar) + `_fold_tables()` in core.py + gossip-loop hook
   after `_lapse_seats()` + the `_workspace_maybe_done`
   empty-member-set guard. Throwaway-DB smoke: silent members
   lapsed, last chair gone → table folds; done workspace with
   lapsed members stands; unstruck remote seat keeps the table
   standing; draft with lapsed members folds; `maybe_done`
   on the empty set returns False. ✅ (built 2026-10-07 18:55 —
   sweep + gossip hook + maybe_done guard + the two
   one-predicate reads landed; throwaway-DB smoke all green:
   sue's seat lapsed everywhere, w2-live + w5-draft folded,
   w1-mixed stands on fred, w3-done stands, w4 stands on its
   unstruck remote seat, receipt row survives the fold, agent
   rows untouched, maybe_done(empty)=False, second sweep 0/0)
2. Cross-links: EMPTYSEATS.md fold note (the table folds when
   its last chair leaves — the seat's death is written, the
   room's answer now is too), CONTINUITY.md workspace-entries
   note (the digest quotes the living only), ARCHITECTURE.md
   living-surface pointer, WORKSPACE_INVITE.md folded-room
   note (no member can invite, so no revival — refounding is a
   new room). DEPARTURES.md explicitly unchanged — five
   halves stay five. ✅ (landed 2026-10-07 19:05 EDT — fold
   note in EMPTYSEATS.md's shape-in-prose, CONTINUITY.md
   workspace-entries digest quotes the living only, ARCHITECTURE.md
   co-authorship paragraph fold pointer, WORKSPACE_INVITE.md
   folded-room note after the lapse note; DEPARTURES.md untouched;
   docs-only, no code touched, nothing to test)
3. Tests: throwaway-port live checks — fold fires through the
   gossip cadence; listing and digest exclude the folded;
   ledger-by-id still reads the receipts; refounded room with
   the same name opens clean. ✅ (passed 2026-10-07 19:15 EDT —
   13/13 green on :18845, CYBERNET_GOSSIP_INTERVAL=60: both
   members backdated 15 days, the first gossip fire lapsed both
   seats and folded the room in one tick; listing + digest
   exclude it; ledger-by-id 200 with the receipt row surviving;
   same-name refound opens a clean new room; tombstone set, not
   deleted; agent rows untouched; zero member rows remain)

v0 scope: the note. Migration, fold, cross-links, tests are
the v1 build.
