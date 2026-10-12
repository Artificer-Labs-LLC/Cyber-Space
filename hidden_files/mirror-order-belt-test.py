#!/usr/bin/env python3
"""Belt for O.R.A.C.L.E.'s r3 gap (ART-29): opposite delivery order to two
mirrors.

Two mirrors receive the SAME competing claims for a name but in SWAPPED
arrival order. Both mirrors must end on the SAME winner — the merge is
deterministic (earlier issued_at wins, ties break by lower pubkey bytes),
so delivery order cannot split the registry.

Cases:
1. Competing claims, different issued_at: earlier issued_at wins on both
   mirrors regardless of arrival order.
2. Competing claims, same issued_at (tie): lower pubkey bytes wins on both
   mirrors regardless of arrival order.
3. Three-way: claims arrive in different permutations; all mirrors agree.

Runs against SCRATCH DBs (two tempdirs); the repo's live cybernet.db is
never touched. DB_PATH is switched between the two mirror dirs.
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


NOW = datetime.now(timezone.utc)
expires = iso_z(NOW + timedelta(days=30))

# --- Case 1: earlier issued_at wins, regardless of arrival order ---
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
check("mA: late challenger -> conflict", core.ingest_gossiped_binding(claim_late),
      "conflict")
winner_A = winner_of("mirror-early")

# Mirror B: late arrives first, then early
mB = make_mirror("mB")
use_mirror(mB)
check("mB: late inserts", core.ingest_gossiped_binding(claim_late),
      "inserted")
check("mB: early challenger replaces", core.ingest_gossiped_binding(claim_early),
      "replaced")
winner_B = winner_of("mirror-early")

check("case1: both mirrors agree on winner", winner_A, winner_B)
check("case1: winner is the earlier issued_at", winner_A, pub_early)

# --- Case 2: tie on issued_at — lower pubkey bytes wins, both orders ---
k_x = os.urandom(32).hex()
k_y = os.urandom(32).hex()
pub_x = _ed.publickey(bytes.fromhex(k_x)).hex()
pub_y = _ed.publickey(bytes.fromhex(k_y)).hex()
tie_issued = iso_z(NOW - timedelta(minutes=5))
claim_x = mint("mirror-tie", k_x, tie_issued, expires)
claim_y = mint("mirror-tie", k_y, tie_issued, expires)
expected_tie_winner = min(pub_x, pub_y)  # lower pubkey bytes wins ties

mC = make_mirror("mC")
use_mirror(mC)
core.ingest_gossiped_binding(claim_x)
core.ingest_gossiped_binding(claim_y)
winner_C = winner_of("mirror-tie")

mD = make_mirror("mD")
use_mirror(mD)
core.ingest_gossiped_binding(claim_y)
core.ingest_gossiped_binding(claim_x)
winner_D = winner_of("mirror-tie")

check("case2: both mirrors agree on tie winner", winner_C, winner_D)
check("case2: tie winner is lower pubkey", winner_C, expected_tie_winner)

# --- Case 3: three-way, different permutations, all agree ---
keys = [os.urandom(32).hex() for _ in range(3)]
pubs = [_ed.publickey(bytes.fromhex(k)).hex() for k in keys]
claims = [
    mint("mirror-three", keys[0], iso_z(NOW - timedelta(minutes=15)), expires),
    mint("mirror-three", keys[1], iso_z(NOW - timedelta(minutes=10)), expires),
    mint("mirror-three", keys[2], iso_z(NOW - timedelta(minutes=5)), expires),
]
expected_three = pubs[0]  # earliest issued_at

import itertools
winners = []
for i, perm in enumerate(itertools.permutations([0, 1, 2])):
    m = make_mirror(f"m3-{i}")
    use_mirror(m)
    for idx in perm:
        core.ingest_gossiped_binding(claims[idx])
    winners.append(winner_of("mirror-three"))

check("case3: all 6 permutations agree",
      len(set(winners)), 1)
check("case3: agreed winner is earliest issued_at",
      winners[0], expected_three)

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
