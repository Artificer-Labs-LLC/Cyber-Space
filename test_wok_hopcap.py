#!/usr/bin/env python3
"""Window-open witness kinds, split 2/4: ART-42 per-name hop cap on the
writer. (d) clean flood, (i) isolation, (j) per-name, and Villhaze's
8488e86f option A / 4d23ee5c option (i) rows V1-V3. Every mutant here is
killed by a row in this file."""
import time

from wok_common import (FUT, K, PAST, POOL, ZERO, bind, check, clean_chain, core, counts,
                        finish, for_name, open_or, rebuilt, record_mutant, rot, wipe, wo)

KINDS_IN = ("reserve-hold", "name-refused", "origin-pin", "origin-handoff")
real_counted = wo.counted_hops

# ---------------------------------------------------------------- (d) ART-42 392140b7: clean rotations are not admissions
def plant_flood(names=20, hops=70):
    with core._db_lock, core._db() as conn:
        wo.init_schema(conn)
        bind(conn, "honest", ZERO, FUT)
        rot(conn, "honest", K, ZERO, PAST)
        for i in range(names):
            last = clean_chain(conn, f"c{i:04d}", hops)
            bind(conn, f"c{i:04d}", last, FUT)
        last = clean_chain(conn, "flood", 80)
        bind(conn, "flood", last, FUT)


def flood_row():
    """Row: 20 names x 70 clean hops plus one name with 80 clean hops.
    The window opens, the honest hold rebuilds at node B, and no clean name
    gets any kind row (no refusal, no hold)."""
    wipe()
    plant_flood()
    t0 = time.monotonic()
    opened, err = open_or("d")
    el = time.monotonic() - t0
    lid, ent, ok, why, view = rebuilt()
    hold = for_name(view, "reserve-hold", "honest")
    clean_rows = [r for k in KINDS_IN for r in view[k]
                  if r.get("name") and (r["name"].startswith("c") or r["name"] == "flood")]
    good = (err is None and ok and len(hold) == 1 and hold[0]["reserved_for"] == K
            and not clean_rows and el < 30)
    return good, (err, ok, why, len(hold), len(clean_rows), round(el, 2)), lid, ent


real_d, info_d, saved_log, saved_entries = flood_row()
check("(d) 65+ clean rotations on one name (and 20x70 elsewhere): window opens for other names",
      real_d, info_d)

wo.counted_hops = lambda hops: len(hops)
try:
    mut_d1, _i, _l, _e = flood_row()
finally:
    wo.counted_hops = real_counted
record_mutant("clean rotations counted toward the per-name cap",
              "65+ clean rotations: window opens, no clean-name kind row",
              real_d, not mut_d1)

real_snapshot = wo.snapshot_bindings
real_bounds = wo.bounds_problem


def charging_snapshot(conn):
    snap = real_snapshot(conn)
    snap["charged"] = conn.execute("SELECT COUNT(*) FROM name_rotations").fetchone()[0]
    return snap


def charging_bounds(snap):
    used = len(snap.get("kind_source", ())) + snap.get("charged", 0)
    if used > wo.SNAPSHOT_GLOBAL_CAP:
        return f"window budget exceeded ({used}/{wo.SNAPSHOT_GLOBAL_CAP})"
    return real_bounds(snap)


wo.snapshot_bindings, wo.bounds_problem = charging_snapshot, charging_bounds
try:
    mut_d2, _i, _l, _e = flood_row()
finally:
    wo.snapshot_bindings, wo.bounds_problem = real_snapshot, real_bounds
record_mutant("clean rotations draw on the shared window budget",
              "65+ clean rotations: window opens, no clean-name kind row",
              real_d, not mut_d2)

# ---------------------------------------------------------------- (i) per-name isolation, witnessed in rows_root
def plant_isolation():
    """'over': 70 clean hops, then a weak hop (to ZERO), then 5 more hops.
    Counted hops = 71 (up to and including the earliest weak hop), not 76.
    Clean names: c-held0, c-held2 (held), c-res1 (K->ZERO reserve-hold)."""
    with core._db_lock, core._db() as conn:
        wo.init_schema(conn)
        last = clean_chain(conn, "over", 70)
        rot(conn, "over", last, ZERO, "2002-01-01T00:00:00+00:00")
        prev = ZERO
        for h in range(5):
            rot(conn, "over", prev, POOL[80 + h], f"2002-01-01T00:{h + 1:02d}:00+00:00")
            prev = POOL[80 + h]
        bind(conn, "over", prev, FUT)
        bind(conn, "c-held0", POOL[0], FUT)
        bind(conn, "c-held2", POOL[1], FUT)
        bind(conn, "c-res1", ZERO, FUT)
        rot(conn, "c-res1", K, ZERO, PAST)


def isolation_row():
    wipe()
    plant_isolation()
    with core._db_lock, core._db() as conn:
        held = {r[0] for r in wo.snapshot_bindings(conn)["held"]}
    opened, err = open_or("iso")
    lid, ent, ok, why, view = rebuilt()
    ref = for_name(view, "name-refused", "over")
    res = for_name(view, "reserve-hold", "c-res1")
    clean_refused = [r for r in view["name-refused"] if r["name"] != "over"]
    good = (err is None and counts()["window"] == 1 and ok
            and len(ref) == 1 and ref[0]["reason"] == "hop-cap"
            and ref[0]["detail"].get("hops") == 71 and ref[0]["detail"].get("cap") == 64
            and len(res) == 1 and res[0]["reserved_for"] == K
            and {"c-held0", "c-held2"} <= held and not clean_refused)
    return good, (err, ok, why, ref, len(res), sorted(held)), lid, ent, view


real_i, info_i, iso_log, iso_entries, iso_view = isolation_row()
check("(i) one name over the cap: window opens, clean names bind, over-cap name refused "
      "with hops=71 (up to the earliest weak hop)", real_i, info_i)

real_isolate = wo.isolate_over_cap


def refuse_whole(snap):
    over = wo.over_cap_names(snap)
    if over:
        raise wo.WindowRefused(f"per-name cap exceeded {over}")
    return over


wo.isolate_over_cap = refuse_whole
try:
    mut_i1 = isolation_row()[0]
finally:
    wo.isolate_over_cap = real_isolate
record_mutant("per-name overflow refuses the whole window",
              "isolation: window opens, only the over-cap name refused",
              real_i, not mut_i1)

wo.counted_hops = lambda hops: len(hops)
try:
    mut_i2 = isolation_row()[0]
finally:
    wo.counted_hops = real_counted
record_mutant("refusal counts every hop, not only up to the earliest weak hop",
              "isolation: refusal row records hops=71",
              real_i, not mut_i2)

# ---------------------------------------------------------------- (j) the window cap is per name
def plant_two_at_cap_minus_one():
    """Two names, each with 63 clean hops then one weak hop: 64 counted each."""
    with core._db_lock, core._db() as conn:
        wo.init_schema(conn)
        for name in ("pa", "pb"):
            last = clean_chain(conn, name, 63)
            rot(conn, name, last, ZERO, "2003-01-01T00:00:00+00:00")
            bind(conn, name, ZERO, FUT)


def per_name_row():
    wipe()
    plant_two_at_cap_minus_one()
    opened, err = open_or("pn")
    lid, ent, ok, why, view = rebuilt()
    holds = {r["name"] for r in view["reserve-hold"]}
    good = (err is None and ok and holds == {"pa", "pb"} and not view["name-refused"])
    return good, (err, ok, holds, view["name-refused"])


real_j, info_j = per_name_row()
check("(j) two names each at the cap both admit (reserve-hold), neither refused", real_j, info_j)
real_over = wo.over_cap_names


def global_total(snap):
    tot = sum(snap.get("hops_per_name", {}).values())
    if tot > wo.SNAPSHOT_PER_NAME:
        return {n: tot for n, c in snap["hops_per_name"].items() if c}
    return {}


wo.over_cap_names = global_total
try:
    mut_j = per_name_row()[0]
finally:
    wo.over_cap_names = real_over
record_mutant("one global hop total across all names",
              "two names at the cap both admit",
              real_j, not mut_j)

# ---------------------------------------------------------------- Villhaze ART-42 8488e86f (A) / 4d23ee5c (i)
# V1: exactly 65 clean hops on one name.
def v1_row():
    wipe()
    with core._db_lock, core._db() as conn:
        wo.init_schema(conn)
        last = clean_chain(conn, "v65", 65)
        bind(conn, "v65", last, FUT)
    opened, err = open_or("v1")
    lid, ent, ok, why, view = rebuilt()
    rows = [r for k in KINDS_IN for r in view[k] if r.get("name") == "v65"]
    return (err is None and ok and counts()["window"] == 1 and not rows), (err, ok, rows)


real_v1, info_v1 = v1_row()
check("(V1) 65 clean hops: the window opens and the name gets no kind row", real_v1, info_v1)
wo.counted_hops = lambda hops: len(hops)
try:
    mut_v1 = v1_row()[0]
finally:
    wo.counted_hops = real_counted
record_mutant("V1: every hop counted (len(hops))",
              "65 clean hops: window opens, no kind row",
              real_v1, not mut_v1)


# V2: 1 weak hop then 64 clean hops (65 hops, 1 anchor-read).
def plant_v2(conn, name="v2"):
    rot(conn, name, K, ZERO, "2001-01-01T00:00:00+00:00")
    rot(conn, name, ZERO, POOL[0], "2001-01-01T00:01:00+00:00")
    last = clean_chain(conn, name, 63, minute0=2)
    bind(conn, name, last, FUT)


def v2_row():
    wipe()
    with core._db_lock, core._db() as conn:
        wo.init_schema(conn)
        plant_v2(conn)
    opened, err = open_or("v2")
    lid, ent, ok, why, view = rebuilt()
    hold = for_name(view, "reserve-hold", "v2")
    refused = for_name(view, "name-refused", "v2")
    good = (err is None and ok and counts()["window"] == 1 and len(hold) == 1
            and hold[0]["reserved_for"] == K and not refused)
    return good, (err, ok, hold, refused)


real_v2, info_v2 = v2_row()
check("(V2) 1 weak hop then 64 clean: window opens, name reserve-holds for K (1 counted hop)",
      real_v2, info_v2)


def exempt_clean_only(hops):
    """Mutant: clean histories are exempt; any weak history counts every hop."""
    return 0 if wo.earliest_weak_index(hops) is None else len(hops)


wo.counted_hops = exempt_clean_only
try:
    mut_v2 = v2_row()[0]
finally:
    wo.counted_hops = real_counted
record_mutant("V2: exempt only clean names, count every hop otherwise",
              "1 weak + 64 clean: window opens, reserve-hold",
              real_v2, not mut_v2)


# V3: 65 anchor-read hops on name 1 (64 clean, then the weak hop); clean name 2.
def v3_row():
    wipe()
    with core._db_lock, core._db() as conn:
        wo.init_schema(conn)
        last = clean_chain(conn, "n1", 64)
        rot(conn, "n1", last, ZERO, "2002-01-01T00:00:00+00:00")
        bind(conn, "n1", ZERO, FUT)
        bind(conn, "n2", POOL[89], FUT)
    with core._db_lock, core._db() as conn:
        held = {r[0] for r in wo.snapshot_bindings(conn)["held"]}
    opened, err = open_or("v3")
    lid, ent, ok, why, view = rebuilt()
    ref = for_name(view, "name-refused", "n1")
    closure = view.get("hold-closure", [])
    good = (err is None and ok and counts()["window"] == 1 and len(ref) == 1
            and ref[0]["reason"] == "hop-cap" and ref[0]["detail"].get("hops") == 65
            and "n2" in held and not for_name(view, "name-refused", "n2")
            and len(closure) == 1
            and max(e["seq"] for e in ent if e["kind"] == "name-refused")
            < next(e["seq"] for e in ent if e["kind"] == "hold-closure"))
    return good, (err, ok, ref, sorted(held))


real_v3, info_v3 = v3_row()
check("(V3) 65 anchor-read hops on name 1: name 1 FLAGged (hops=65) in the open's "
      "transaction, clean name 2 opens", real_v3, info_v3)
wo.isolate_over_cap = refuse_whole
try:
    mut_v3 = v3_row()[0]
finally:
    wo.isolate_over_cap = real_isolate
record_mutant("V3: per-name overflow refuses the whole window",
              "65 anchor-read hops on n1: n1 FLAG, n2 opens",
              real_v3, not mut_v3)

finish("test_wok_hopcap.py")
