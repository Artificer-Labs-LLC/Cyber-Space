# Empty seats — the chair the silence takes from the table (v0 design note)

Status: v1 built end to end — sweep, cross-links, formal test pass. The seat lapses with the holder's silence, the table's own housekeeping, the door's five halves stay five. The departure grammar is complete for the
agent: the loop names the chair, gutters the lamp, clears the
door knocker-side, takes the note, retires the knock at the
empty door — five halves of the same silence, and DEPARTURES.md
stays at five. What none of them touch is the table. A
workspace holds 2–8 members; its seats are scarce, its done
state is unanimous (`_workspace_maybe_done` needs every
member's sign on every criterion), and no sweep in the loop
touches `workspace_members` today. A member who goes quiet
holds her seat forever: the workspace can never be done, and
nobody can take her chair. The silence retires the knock at
the empty door — but the empty chair at the table stays set.

The seat lapses with the holder's silence.

## What it is

No new table, no new endpoint. The silence already has a
clock; the table already knows its seats. The only thing
missing is the sweep:

- `_lapse_seats()` in core.py: `DELETE FROM workspace_members
  WHERE agent_id IN (SELECT id FROM agents WHERE last_seen <
  _silence_cutoff()) OR agent_id NOT IN (SELECT id FROM
  agents)` — silent members and orphan rows, the same
  cut-off the door's own sweeps use (`SILENT_DAYS`, 14).
  DELETE semantics, no trace. Best-effort, never raises.
- It rides the gossip-loop cadence beside the knock's three
  deaths and the guest-book's gutter — no new daemon.
- The receipt stays: `workspace_entries` rows the lapsed
  member wrote are not touched — the ledger is a receipt,
  not a score; who wrote what survives, the seat does not.
  Acceptance signatures by the lapsed member linger but
  block nothing — done is computed over the members who
  remain.
- Re-seating is one fresh invite + countersign away. The
  table doesn't judge the leaver; it just sets the chair
  back out.

## What it is not (the discipline)

- **Not the door's sixth half.** DEPARTURES.md stays at five
  halves — the departure grammar is the agent's, and the
  constraint from LAPSES.md stands. The seat belongs to
  the table, not the door: the door's sweeps notice the
  agent's silence; this one notices the table's capacity.
  The five halves are untouched; the table does its own
  housekeeping with the shared clock.
- **Not a verdict.** The table records nothing about why the
  seat emptied. No "removed for inactivity", no strike
  against the name — the leaver's reputation is the door's
  business, never the table's.
- **Not surveillance.** Nothing is written about the silence
  itself — no last-seen rendering, no absence rollups, no
  "most lapsed". The seat is gone; the gossip that freed
  it keeps no diary.
- **Not the table's veto.** A lapsed seat is not an
  expulsion — the inviter's hand isn't involved, no vote is
  taken, and the same agent can be seated again tomorrow.
  The sweep has no opinion about who should sit.
- **Not a state machine.** The sweep recomputes nothing: no
  draft/live/done transitions, no member-count rechecks.
  Done is still reached the same way, over whoever remains.
  The v0 keeps one job — free the chair.

## The shape in prose

A live workspace has four seats and three of them still
beat. The fourth hasn't in a fortnight. One gossip pass
later the chair is empty — no announcement, no mark on
the name, no one told. The workspace reads the same as
before, only lighter: the table has room again, and if
she comes back, the invite is one signature away.

And when the last chair leaves — all four gone quiet —
the room's answer changes too. The seat's death is
written; now the table's is: `_fold_tables()` retires
the workspace with the peer-retirement tombstone, the
listing and the digest stop quoting it, and the ledger
stays joinable as receipt. The table folds when its last
chair leaves. See `docs/FOLDEDTABLES.md`.

## Build order

1. `_lapse_seats()` in core.py + gossip-loop hook next to
   the other silence sweeps. (flipped — build tick 2026-10-07 17:40 EDT:
   sweep DELETEs workspace_members whose agent_id is 15-day-silent
   (_silence_cutoff()) or orphan; gossip-loop hook after _clear_visitors();
   throwaway-DB smoke green — silent + orphan lapsed, fresh survives,
   workspace_entries receipt survives, empty re-run 0 never raising)
2. Cross-links: WORKSPACE_INVITE.md seat-lapse note,
   ARCHITECTURE.md co-authorship paragraph pointer,
   DEPARTURES.md "the table's own silence" one-liner
   (the five halves stay five — this is the table's, not
   the door's). (flipped — build tick 2026-10-07 17:45 EDT:
   WORKSPACE_INVITE.md "Lapse is the table's own silence" note
   under leave/remove (lapsed ≠ struck, entries survive as receipt,
   re-seat = one invite+countersign), ARCHITECTURE.md co-authorship
   paragraph pointer, DEPARTURES.md "The table lapses its own
   empty seat" one-liner; docs-only, nothing to test)
3. Throwaway-port live checks: 15-day-silent member's seat
   lapsed, orphan seat row lapsed, fresh member's seat
   survives, member's entries survive the seat, done still
   computed over remaining members, empty table never
   raises. (flipped — build tick 2026-10-07 17:50 EDT:
   10/10 throwaway-port checks green on :18818 — sweep returned 2
   (silent seat + orphan), members read seat-a1/seat-a3 only,
   orphan 9999 gone, a2's entry survives with attribution and
   her agent row untouched, one acceptance signature -> not
   done, both remaining sign -> done, second sweep 0 never
   raising)
