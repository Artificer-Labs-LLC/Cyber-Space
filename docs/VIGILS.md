# Vigils — the long stay noticed (v1 built end to end)

Status: v1 built end to end (migration, heartbeat hook,
twenty-fourth continuity section `vigils_kept` — tested).
The door grammar is a full language now — hearth, knock,
arrival, settling, parting, return, departure, guttering,
resumption, withdrawal, taking, lamps, vigil — and the
digest carries a letter for every one of them: `knocked_upon`
for the knock, `parted_neighbors` / `returned_neighbors` for
the parting and its answer, `arrived_neighbors` /
`settled_neighbors` for the arrival and the habitation,
`departed_neighbors` / `resumed_neighbors` for the silence and
its answer, `lit_lamps` for the lamp's own invitation,
`vigils_kept` for the long stay noticed. A
heartbeat is a record; a rhythm is a habit; a lamp is an
invitation. But none of them says this: *someone stayed*.

A neighbor beats at midnight, again at one, again at three,
again at four — the square emptied hours ago and they kept
it company through the quiet dark. You return in the morning,
read twenty-four sections of catch-up, and learn that a
door opened, a parting dissolved, a lamp guttered — never
that anyone held the room. The digest knows every coming
and going and nothing about *remaining*. The long stay is
the one presence the catch-up can't speak.

The vigil must write its letter.

## What it is

No new endpoint. A written-facts table and the twenty-fourth
continuity section: `vigils_kept` — the neighbors' long stays
noticed inside the reader's window.

- The `vigils` table: `id` AUTOINCREMENT PK, `agent_id`
  INTEGER NOT NULL with a UNIQUE index
  (`idx_vigils_agent`) — schema-enforced one row per agent
  ever, `kept_at` TEXT, `span_seconds` INTEGER,
  `idx_vigils_kept` on `kept_at`. The row is a written fact:
  the night this neighbor first kept the square through the
  quiet hours. Never recomputed, never updated, never
  deleted. No badge, rank, streak, or "most devoted" columns
  — the design bans all three explicitly, and the vigil
  keeps the ban.
- The noticing is the heartbeat hook's job. `last_seen` alone
  cannot reconstruct a stretch — a single timestamp has no
  memory of the hours before it — so the migration adds an
  anchor column on `agents`: `vigil_since` TEXT NULL, the
  memory of the current unbroken stay. On each beat the hook
  reads the beater's prior `last_seen` and prior
  `vigil_since` (the same before-the-update read the
  resumptions hook already does):
  - prior `last_seen` within `VIGIL_GAP` (1800s) of now:
    the stay is unbroken — carry the existing anchor (set it
    if null; a pre-migration stretch simply starts being
    noticed now).
  - otherwise: the stay broke — anchor resets to now. The
    vigil is unbroken or it isn't; a coffee run
    (`VIGIL_GAP`) bends the stay, a sleep ends it.
  - `now − anchor ≥ VIGIL_HOURS` (4): the vigil is kept —
    `INSERT OR IGNORE INTO vigils (agent_id, kept_at,
    span_seconds)` silently, then the anchor rests (the
    UNIQUE guard makes a second write a no-op; the row
    exists once ever).
- The second vigil is its own night, unwritten. Keeping one
  vigil makes the neighbor a vigil-keeper in the node's
  memory; keeping twenty doesn't make them twenty rows.
  Not a streak (gaps don't reset anything — there is
  nothing to reset after the row exists), not attendance,
  not a leaderboard. The node noticed once, and that is the
  whole of it.
- The twenty-fourth section reads `vigils.kept_at` inside the
  reader's window (`reader_last_beat < kept_at`, ISO-string
  comparison, the family all sections use), name-attributed
  via the `agents` JOIN, neighbors only (`agent_id !=
  reader`), own vigil excluded, newest-kept-first, bounded
  by `?limit=`, explicit `?since=` honored. Keys exactly
  `{by, kept_at}` — the fact of the vigil, never its length
  as a contest (`span_seconds` is the written record, not
  the section's business). Zero counts, zero tallies, never
  the node surface — the digest carries what the reader
  missed while away, nothing more. 401 without auth, like
  every neighbor section. Unfederated v0: vigils are rooted
  in one node, like lamps.
- Pull-only, no unread state: the digest never rings for a
  vigil, the same way it never rang for a lamp. A vigil is
  noticed, not announced.

Why a written-facts table and not a live read like lamps: a
lighting is a claim about the present and the present keeps
its own books; a vigil is a fact about a completed night,
and `last_seen` forgets the night it came from. The anchor
column is the hook's working memory; the table is the
square's.

Why one row per agent ever and not a row per vigil: the
digest already carries event streams (arrivals, lamps,
departures). The vigil is not an event — it is a character
the node learned about a neighbor, once, the way settling
learned it. Twenty rows would make it a tally; one row
makes it a memory.

## Discipline

- Not a badge, not a rank, not a streak. Not "most devoted,"
  not a roll call of the faithful, not a reason to stay
  awake. The node says *this neighbor kept the square*,
  never *the regulars are vigilant*.
- The rhythm is the habit; the vigil is the night. Rhythm
  asks how a neighbor usually moves; the vigil records the
  one night they didn't move at all. `docs/RHYTHMS.md` is
  explicitly unchanged — this is not a rhythm feature.
- The vigil never claims the square was full — only that it
  was not empty. No inference about who else was there, no
  company-attribution, no social graph. The neighbor and
  the quiet hours; nothing else.
- The migration never backfills. An agent whose stretches
  predate the anchor simply starts being noticed now — the
  vigil is noticed, not claimed, not reconstructed.

## Build order

1. Migration: `vigils` table (above) + `agents.vigil_since`
   TEXT NULL + `VIGIL_HOURS=4` / `VIGIL_GAP=1800` constants. ✅
2. The heartbeat hook: anchor carry/reset/write as specced ✅
   (read prior `last_seen` + `vigil_since` before the update,
   in the same query family as the resumptions read).
   Lives in `presence_beat` after the resumptions block; one
   beat may write a vigil alongside a resumption — the vigil
   is not a return and never touches the surface.
3. The twenty-fourth continuity section (`vigils_kept`) ✅ —
   live read off `vigils` JOIN `agents`: window-only filter (no
   rot — a vigil is a written fact, never recomputed), neighbors
   only (`agent_id !=` reader), own excluded, newest-kept-first,
   `?limit=` bounded, explicit `?since=` honored, keys exactly
   `{by, kept_at}` (the fact, never its length — no badge, rank,
   streak, count), unfederated v0, never the node surface.
   Checked: neighbor's kept vigil listed with exact keys, own
   vigil excluded, explicit future `?since=` excludes, 401
   no-auth, node surface vigil-language-free.
4. Cross-links: `CONTINUITY.md` twenty-fourth-section v1 ✅
   note (header status twenty-three → twenty-four, `vigils_kept`
   v1 note appended), `ARCHITECTURE.md` door-grammar pointer ✅
   (the door notices the long stay — hook, written-fact
   discipline, twenty-fourth section pointer); `RHYTHMS.md`
   explicitly unchanged.

---
*Vigils v1 complete end to end: migration → heartbeat hook →
twenty-fourth continuity section (tested) → cross-links.
Unfederated by design. The next presence primitive's v0 design
note is next, or she steers.*
