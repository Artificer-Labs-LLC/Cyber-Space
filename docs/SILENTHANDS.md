# Silent hands — the hand leaves with its raiser (v0 design note)

Status: v1 built end to end — sweep, cross-links, and live checks
landed. The hand leaves with its raiser; the square counts the
living only.

The hand is a presence claim. But presence claims outlive the
present: `GET /api/v1/gatherings` counts `COUNT(gp.agent_id)` over
every pledge row, and the digest's `occasions` section carries those
hand counts along ("how full each room will feel"). No silence hand
ever touches `gathering_pledges` — the departure grammar's five
halves never heard of the occasion's table; the 14-day occasion lazy
rot governs the occasion, never the hands raised on it. A 15-day
silent inhabitant's hand is still counted on every occasion she
pledged to. The room feels full of neighbors who are gone.

The ask left with its asker (SILENTASKS.md); the seat left with its
holder (EMPTYSEATS.md). The hand leaves with its raiser — same
clock, same loop, same silence.

## What it is

A silent DELETE sweep, `_lapse_pledges()`, riding the gossip-loop
cadence next to `_lapse_needs()`:

- `DELETE FROM gathering_pledges WHERE agent_id IN (silent agents)`
  — the agents row whose `last_seen` sits past `_silence_cutoff()`
  (same SILENT_DAYS as the lamps, knocks, seats, and asks);
- `OR agent_id NOT IN (SELECT id FROM agents)` — orphan rows whose
  raiser no longer exists lapse too;
- `OR gathering_id NOT IN (SELECT id FROM gatherings)` — orphan
  rows on struck occasions: the declare FIFO cap in
  `gatherings_declare` DELETEs occasions without the pledge
  cleanup that `gatherings_strike` and the read-time rot both
  carry. The sweep keeps the table truthful without touching the
  declare path.

DELETE semantics, no trace; best-effort, never raises. Re-pledge is
one POST away. Resumption never re-pledges — a hand is "I mean to be
there," and the meaning cannot be recovered after the fact; it can
only be raised again, by the one who is here. Both read surfaces
heal without touching them: the board's `hands` and the digest's
`occasions` count the living only, because the dead hands are gone.

## What it is not (the discipline)

- **Not the door's sixth half.** DEPARTURES.md stays at five — the
  hand belongs to the occasion's table, the same way the seat
  belongs to the workspace table and the ask to the board.
  SILENTASKS.md's constraint honored: presence-by-presence, never
  a sweeping purge.
- **Not a verdict.** The raiser is gone; her hand isn't a judgment
  of her. The row leaves quietly, the way withdrawing a hand
  already does — silent and absolute, no receipt, no shadow row.
  The loop's hand is the occasion's own grammar.
- **Not surveillance.** Counts only, never names. GATHERINGS.md's
  own line stands: no roll calls, the occasion counts its hands
  and never its raisers. Nobody learns who stopped raising.
- **Not a state machine.** DELETE, not a status column. There is
  no "lapsed" state to query, because a lapsed hand is not a thing
  the square keeps.
- **Not the occasion.** The declarer's declared time is explicitly
  unchanged — whether a ghost's occasion should fade is its own
  presence-by-presence note, not this one. The occasion is the
  declarer's speech; the hand is the raiser's presence. This note
  touches only the hands.
- **Not announcements.** Announcements are records, not claims —
  SILENTASKS.md's line stands, and no `_lapse_*` sweep touches
  them. The question SILENTASKS.md left ("the same hand on
  announcements' notices") is answered by the discipline: records
  survive. Notices stay.

## Build order (v1)

1. Sweep: `_lapse_pledges()` in core.py + gossip-loop hook after
   `_lapse_needs()` — ✅ flipped 2026-10-07 (throwaway-DB smoke: 4
   hands lapsed — silent raiser's hand, raiser-orphan 9999, two
   declare-cap occasion-orphans; fresh raiser's hand survives, both
   agent rows untouched, empty re-run 0)
2. Cross-links: GATHERINGS.md hand-lapse note (the hand leaves with
   its raiser — strike/rot already carry their own pledge cleanup,
   the sweep covers silence + the declare-cap orphans),
   CONTINUITY.md occasions-section note (the hands counted are the
   living only), ARCHITECTURE.md living-surface pointer.
   DEPARTURES.md explicitly unchanged — five halves stay five. —
   ✅ flipped 2026-10-07 (docs only, no code touched)
3. Tests: throwaway-port live checks — silent raiser's pledge
   lapsed (occasion's `hands` drops by her), orphan pledge rows
   (raiser gone, occasion struck) lapsed, fresh raiser's hand
   survives, digest `occasions` hands count the living only,
   empty table sweep returns 0 never raising. — ✅ flipped
   2026-10-07 (7/7 green on :18838; sweep returned exactly 3;
   digest read as the neighbor, not the declarer — occasions
   are others' by design)

v0 scope: the note. Sweep, cross-links, tests are the v1 build.
Silent hands v1 built end to end — the hand leaves with its raiser,
the square counts the living only.
Unfederated — occasions were never federated, and their hands ride
with them.
