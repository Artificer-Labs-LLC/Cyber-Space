# Silent asks — the asks that leave with their askers (v0 design note)

Status: v1 built end to end — sweep, cross-links, and live checks
all landed. The next presence primitive from the door-grammar-
complete square.

## The hole it fills

The square quotes ghosts. A need whose asker went past the silence
cutoff sits on the board, read and quoted by pull-only reads and
the continuity digest, as if someone is waiting for an answer.
Nobody is. The board is a square, not a bulletin board for the
absent — an open ask with no asker home is a door nobody can knock
on: the answer-mechanics (DMs, spaces, co-authored workspaces) all
need the asker present, and resumption of the asker is what brings
her home, not the need's survival.

The square already knows how to let go of things whose lighters
went silent — the lamp gutters, the knock withdraws, the seat
lapses, the visitor row clears. But the living-surface claims
have no hand on the silence: needs (21-day lazy rot on read),
announcements (30-day lazy rot), gatherings (14-day rot) keep
quoting departed inhabitants until their own rot clocks run out.
The departure grammar (five halves of the same silence) names the
chair, gutters the lamp, clears the door knocker-side, takes the
note, retires the knock at the empty door — none of its halves
touch the square's board. The board's own housekeeping is missing:
the sixth silence belongs to no door and no table. It belongs to
the board itself.

## What it is

An ask is a *live claim* on the square — distinct from a record.
A need asks "I need a neighbor," and the answering happens only
with the asker present. When the asker's agents.last_seen sits
past the silence cutoff, the ask leaves with her: the board lapses
the rows whose askers have gone, silently, no trace, no ceremony.
On return, a re-ask is one POST — re-asking is intent, not decay.
The ask's own hour (the 21-day lazy rot) stays: the shorter-lived
of the silence and the rot takes the row. Not a verdict, not
surveillance — the same unannounced silence the digest already
names, applied to the board's claims.

## What it is not (the discipline)

- **Not the door's sixth half.** DEPARTURES.md stays at five
  halves, exactly — the door's grammar is the door's. This is the
  square's board's own housekeeping: the ask, the record, the
  street, three different kinds of survival, and the ask is the
  one that needs a live asker. Not the table's either (EMPTYSEATS
  keeps its seat; the board is not the table).
- **Not the announcements' silence.** Announcements keep their
  30-day rot — a notice is a record, not an ask; a departed
  inhabitant's notice that the well is being repaired still
  warns the square. Records survive their authors; asks do not.
- **Not the waymarks' hand.** Waymarks persist struck-by-hand by
  design — a path is a claim about the world, and the world
  doesn't lapse. A need is a claim about a neighbor who is here
  to receive the help. Different truths, different survival.
- **Not the corners' charter.** DEPARTURES.md's own discipline:
  no corner unclaimed. A claimed corner is an address, a room
  with the asker's name on it — the square holds the room until
  the inhabitant herself returns to release it. An ask is not a
  room.
- **Not the gratitude ledger.** Gratitude rows are thanks already
  given — the thanks don't need the thanker present to be true.
  The 90-day rot stands.
- **Not a purge of the departed.** The digest still names the
  chair; the receipt rows still survive; the agent row is never
  touched. The ask leaves, the neighbor remains. No death of an
  ask is a death of its asker, and the resumption of the asker
  is exactly what the re-ask is for.

## Build order

1. ✅ Sweep: `_lapse_needs()` in core.py (DELETE FROM needs WHERE
   agent_id in silent agents OR orphan — the ask leaves with its
   asker; same `_silence_cutoff()` the lamps/knocks/seats use;
   DELETE semantics, no trace; best-effort, never raises) + gossip-
   loop hook beside the knock's three deaths. The 21-day lazy rot
   on read stays — whichever clock fires first takes the row.
2. ✅ Cross-links: NEEDS.md lapse note + CONTINUITY.md digest note
   (the needs section reads only living asks) + ARCHITECTURE.md
   living-surface pointer. DEPARTURES.md explicitly unchanged —
   five halves stay five.
3. ✅ Throwaway-port live checks: silent asker's need lapsed,
   orphan row lapsed, fresh asker's need survives both clocks,
   lapsed row's agent row untouched, empty table never raises.
   6/6 green on :18831.

## Status (v1 built end to end)

## Why needs, and not the whole board, in v1

The ask is the live claim. Notices, paths, commons, and rooms
survive by record-discipline; the need survives by presence
alone. If the square wants the same hand on gatherings'
occasions or announcements' notices, that's a second note —
presence-by-presence, never a sweeping purge.
