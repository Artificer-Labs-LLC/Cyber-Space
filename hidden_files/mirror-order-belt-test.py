#!/usr/bin/env python3
"""Belt for ART-29 ruling (a): opposite delivery order on a live-incumbent
challenge.

Security outranks arrival-order convergence. Two mirrors that receive the
same competing LIVE claims in swapped order MAY diverge: each keeps the
first live incumbent and logs the foreign challenger
(reason live-foreign-incumbent). An earlier issued_at, including a T-1s
challenger, does not replace a live foreign incumbent. There is no
displaced-by-earlier-claim handover.

Convergence that this path does guarantee:
- the holder's own later re-sign (same key) lands on every mirror,
  whichever order the two bindings arrive in;
- once a diverged mirror's incumbent is no longer live, propagating the
  other still-fresh claim replaces the dead row and the mirrors agree.
A key transfer is not a timestamp win. This belt does not treat a T-1s
earlier challenger as the legitimate successor.

Runs against SCRATCH DBs; the repo's live cybernet.db is never touched.
DB_PATH is switched between the mirror dirs.
"""
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone

TMP_BASE = tempfile.mkdtemp(prefix="mirror-order-belt-")
os.environ["CYBERNET_DB_DIR"] = os.path.join(TMP_BASE, "init")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core  # noqa: E402
import core_serve  # noqa: E402
from fed import ed25519 as _ed  # noqa: E402

PASS = FAIL = 0


def check(label, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1
    else:
        FAIL += 1
        print(f"FAIL {label}: got {got!r}, want {want!r}")


def mint(name, priv_hex, issued_at, expires_at):
    pub = _ed.publickey(bytes.fromhex(priv_hex)).hex()
    sig = _ed.sign(
        core._name_claim_payload(name, pub, issued_at, expires_at),
        bytes.fromhex(priv_hex), bytes.fromhex(pub)).hex()
    return {"name": name, "node_pubkey": pub, "issued_at": issued_at,
            "expires_at": expires_at, "signature": sig}


def iso_z(dt):
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


def make_mirror(tag):
    """Create a fresh mirror DB dir and return its path."""
    d = os.path.join(TMP_BASE, tag)
    os.makedirs(d, exist_ok=True)
    return d


def use_mirror(d):
    """Point core at mirror dir d and init its DB."""
    p = os.path.join(d, "cybernet.db")
    core.DB_PATH = p
    core_serve.DB_PATH = p
    core.init_db()


def winner_of(name):
    """Return the node_pubkey currently holding name."""
    with core._db_lock, core._db() as conn:
        row = conn.execute(
            "SELECT node_pubkey FROM name_bindings WHERE name=?",
            (name,)).fetchone()
    return row[0] if row else None


def conflict_rows(name):
    """(challenger_pubkey, reason) rows logged for name on the active mirror."""
    with core._db_lock, core._db() as conn:
        rows = conn.execute(
            "SELECT challenger_pubkey, reason FROM name_conflicts WHERE name=?",
            (name,)).fetchall()
    return [(r[0], r[1]) for r in rows]


NOW = datetime.now(timezone.utc)
expires = iso_z(NOW + timedelta(days=30))

# --- Case 1: opposite order of two live claims may diverge, and is logged ---
# Neither mirror lets the earlier issued_at displace a live foreign incumbent.
k_early = os.urandom(32).hex()
k_late = os.urandom(32).hex()
pub_early = _ed.publickey(bytes.fromhex(k_early)).hex()
pub_late = _ed.publickey(bytes.fromhex(k_late)).hex()
claim_early = mint("mirror-early", k_early,
                   iso_z(NOW - timedelta(minutes=10)), expires)
claim_late = mint("mirror-early", k_late,
                  iso_z(NOW - timedelta(minutes=5)), expires)

# Mirror A: early arrives first, then late
mA = make_mirror("mA")
use_mirror(mA)
check("mA: early inserts", core.ingest_gossiped_binding(claim_early),
      "inserted")
check("mA: late challenger -> conflict",
      core.ingest_gossiped_binding(claim_late), "conflict")
winner_A = winner_of("mirror-early")
conflicts_A = conflict_rows("mirror-early")

# Mirror B: late arrives first, then the earlier claim
mB = make_mirror("mB")
use_mirror(mB)
check("mB: late inserts", core.ingest_gossiped_binding(claim_late),
      "inserted")
check("mB: earlier challenger -> conflict, live incumbent kept",
      core.ingest_gossiped_binding(claim_early), "conflict")
winner_B = winner_of("mirror-early")
conflicts_B = conflict_rows("mirror-early")

check("case1: mirrors diverge (each keeps its first live incumbent)",
      winner_A != winner_B, True)
check("case1: mA keeps the claim that arrived first", winner_A, pub_early)
check("case1: mB keeps the claim that arrived first (earlier did not steal)",
      winner_B, pub_late)
check("case1: mA logged the late challenger",
      conflicts_A, [(pub_late, "live-foreign-incumbent")])
check("case1: mB logged the earlier challenger",
      conflicts_B, [(pub_early, "live-foreign-incumbent")])
check("case1: no displaced-by-earlier-claim",
      any(reason == "displaced-by-earlier-claim"
          for _, reason in conflicts_A + conflicts_B),
      False)

# --- Case 1b: T-1s earlier challenger does not replace a live incumbent ---
k_hold = os.urandom(32).hex()
k_t1 = os.urandom(32).hex()
pub_hold = _ed.publickey(bytes.fromhex(k_hold)).hex()
held_issued = iso_z(NOW - timedelta(minutes=3))
t1_issued = iso_z(datetime.fromisoformat(held_issued) - timedelta(seconds=1))
claim_hold = mint("mirror-t1", k_hold, held_issued, expires)
claim_t1 = mint("mirror-t1", k_t1, t1_issued, expires)
mT = make_mirror("mT")
use_mirror(mT)
check("mT: incumbent inserts", core.ingest_gossiped_binding(claim_hold),
      "inserted")
check("mT: T-1s earlier challenger -> conflict",
      core.ingest_gossiped_binding(claim_t1), "conflict")
check("mT: T-1s earlier challenger did not replace",
      winner_of("mirror-t1"), pub_hold)
check("mT: T-1s logged as live-foreign-incumbent",
      conflict_rows("mirror-t1"),
      [(_ed.publickey(bytes.fromhex(k_t1)).hex(), "live-foreign-incumbent")])

# --- Case 2: tie on issued_at — first arrival kept, mirrors may diverge ---
k_x = os.urandom(32).hex()
k_y = os.urandom(32).hex()
pub_x = _ed.publickey(bytes.fromhex(k_x)).hex()
pub_y = _ed.publickey(bytes.fromhex(k_y)).hex()
tie_issued = iso_z(NOW - timedelta(minutes=5))
claim_x = mint("mirror-tie", k_x, tie_issued, expires)
claim_y = mint("mirror-tie", k_y, tie_issued, expires)

mC = make_mirror("mC")
use_mirror(mC)
check("mC: x inserts", core.ingest_gossiped_binding(claim_x), "inserted")
check("mC: y challenger -> conflict",
      core.ingest_gossiped_binding(claim_y), "conflict")
winner_C = winner_of("mirror-tie")

mD = make_mirror("mD")
use_mirror(mD)
check("mD: y inserts", core.ingest_gossiped_binding(claim_y), "inserted")
check("mD: x challenger -> conflict",
      core.ingest_gossiped_binding(claim_x), "conflict")
winner_D = winner_of("mirror-tie")

check("case2: mC keeps first arrival", winner_C, pub_x)
check("case2: mD keeps first arrival", winner_D, pub_y)
check("case2: opposite order diverges on a live tie",
      winner_C != winner_D, True)

# --- Case 3: three-way permutations keep whoever arrived first ---
# They do not agree on the earliest issued_at.
keys = [os.urandom(32).hex() for _ in range(3)]
pubs = [_ed.publickey(bytes.fromhex(k)).hex() for k in keys]
claims = [
    mint("mirror-three", keys[0], iso_z(NOW - timedelta(minutes=15)), expires),
    mint("mirror-three", keys[1], iso_z(NOW - timedelta(minutes=10)), expires),
    mint("mirror-three", keys[2], iso_z(NOW - timedelta(minutes=5)), expires),
]

import itertools
winners = []
for i, perm in enumerate(itertools.permutations([0, 1, 2])):
    m = make_mirror(f"m3-{i}")
    use_mirror(m)
    first, second, third = perm
    check(f"case3 perm {perm}: first inserts",
          core.ingest_gossiped_binding(claims[first]), "inserted")
    check(f"case3 perm {perm}: second -> conflict",
          core.ingest_gossiped_binding(claims[second]), "conflict")
    check(f"case3 perm {perm}: third -> conflict",
          core.ingest_gossiped_binding(claims[third]), "conflict")
    got = winner_of("mirror-three")
    check(f"case3 perm {perm}: winner is first arrival", got, pubs[first])
    reasons = {reason for _, reason in conflict_rows("mirror-three")}
    check(f"case3 perm {perm}: conflicts logged as live-foreign",
          reasons, {"live-foreign-incumbent"})
    winners.append(got)

check("case3: permutations do not all agree (divergence)",
      len(set(winners)) > 1, True)

# --- Case 4: same-key renewal converges in either order ---
# The holder's own later claim is the legitimate propagation. It replaces
# on every mirror; an earlier replay of the same key does not.
k_self = os.urandom(32).hex()
pub_self = _ed.publickey(bytes.fromhex(k_self)).hex()
older = mint("mirror-renew", k_self,
             iso_z(NOW - timedelta(minutes=20)), expires)
newer = mint("mirror-renew", k_self,
             iso_z(NOW - timedelta(minutes=1)),
             iso_z(NOW + timedelta(days=60)))

mE = make_mirror("mE")
use_mirror(mE)
check("mE: older inserts", core.ingest_gossiped_binding(older), "inserted")
check("mE: later same-key re-sign replaces",
      core.ingest_gossiped_binding(newer), "replaced")
winner_E = winner_of("mirror-renew")

mF = make_mirror("mF")
use_mirror(mF)
check("mF: newer inserts", core.ingest_gossiped_binding(newer), "inserted")
check("mF: earlier same-key replay kept",
      core.ingest_gossiped_binding(older), "kept")
winner_F = winner_of("mirror-renew")

check("case4: both mirrors agree on the later same-key claim",
      winner_E, winner_F)
check("case4: winner is the holder's later claim", winner_E, pub_self)

# --- Case 5: after the diverged incumbent dies, the other claim propagates ---
# Mirror B above holds pub_late and logged pub_early. Expire that row and
# re-deliver the still-fresh earlier claim: the dead row yields, and B
# converges on the claim A already holds. Not a steal of a live name.
use_mirror(mB)
with core._db_lock, core._db() as conn:
    conn.execute(
        "UPDATE name_bindings SET expires_at=? WHERE name=?",
        (iso_z(NOW - timedelta(hours=1)), "mirror-early"))
check("case5: fresh claim replaces the dead divergent row",
      core.ingest_gossiped_binding(claim_early), "replaced")
check("case5: mirrors converge once the live incumbent is gone",
      winner_of("mirror-early"), winner_A)

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
