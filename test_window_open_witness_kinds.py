#!/usr/bin/env python3
"""Belts for the four witness kinds ruled in with the open_window writer.

Own scratch DB. The preconditions suite stays on its own file and its own
count. Each row has a mutant that must fail that row.
"""
import json
import os
import sys
import tempfile
import time

os.environ["CYBERNET_DB_DIR"] = tempfile.mkdtemp(prefix="wok-")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import core  # noqa: E402
core.init_db()
import legacy_witness as lw  # noqa: E402
import window_open as wo  # noqa: E402
from fed import ed25519 as _ed  # noqa: E402

PASS = FAIL = 0
MUTANTS = []

PAST = "2000-01-01T00:00:00+00:00"
FUT = "2099-01-01T00:00:00+00:00"
ZERO = "00" * 32
SIG = "00" * 64
KINDS_IN = ("reserve-hold", "name-refused", "origin-pin", "origin-handoff")


def check(label, cond, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok  {label}")
    else:
        FAIL += 1
        print(f"  FAIL {label} {extra}")


def record_mutant(name, row, real_ok, mutant_fails):
    MUTANTS.append((name, row, real_ok, mutant_fails))
    check(f"MUTANT {name}: real passes and mutant fails the row",
          real_ok and mutant_fails, (real_ok, mutant_fails))


def wipe():
    with core._db_lock, core._db() as conn:
        wo.init_schema(conn)
        for table in ("window_open_log", "window_refused_bindings", "window_kind_source",
                      "legacy_migration_log", "legacy_log_meta", "name_bindings",
                      "name_rotations", "window_close_log", "legacy_migrations"):
            conn.execute(f"DELETE FROM {table}")


def bind(conn, name, pub, exp=PAST):
    conn.execute(
        "INSERT INTO name_bindings (name,node_pubkey,issued_at,expires_at,signature) "
        "VALUES (?,?,?,?,?)",
        (name, pub, PAST, exp, SIG))


def rot(conn, name, old, new, at=PAST):
    conn.execute(
        "INSERT INTO name_rotations "
        "(name,old_pubkey,new_pubkey,issued_at,signature,accepted_at) VALUES (?,?,?,?,?,?)",
        (name, old, new, PAST, SIG, at))


def reap():
    with core._db_lock, core._db() as conn:
        core._name_registry_has_room(conn)


def counts():
    with core._db_lock, core._db() as conn:
        wo.init_schema(conn)
        return {
            "window": conn.execute("SELECT COUNT(*) FROM window_open_log").fetchone()[0],
            "log": conn.execute("SELECT COUNT(*) FROM legacy_migration_log").fetchone()[0],
            "kinds": conn.execute("SELECT COUNT(*) FROM window_kind_source").fetchone()[0],
        }


def exported():
    """Node B's input: the log bytes, round-tripped, with no database."""
    with core._db_lock, core._db() as conn:
        log_id, entries = wo.export_log(conn)
    return log_id, json.loads(json.dumps(entries))


def rebuilt():
    log_id, entries = exported()
    ok, why = lw.verify_chain(entries, log_id)
    return log_id, entries, ok, why, lw.rebuild_window_kinds(entries)


def open_or(by="kinds"):
    try:
        return wo.open_window(by), None
    except wo.WindowRefused as e:
        return None, str(e)


def for_name(view, kind, name):
    return [r for r in view[kind] if r.get("name") == name]


def bad_kind_skips_checkvalid():
    called = {"n": 0}
    real = lw._ed.checkvalid

    def spy(*args, **kwargs):
        called["n"] += 1
        return real(*args, **kwargs)

    lw._ed.checkvalid = spy
    try:
        bad = lw.verify_witness_signature("not-a-kind", b"nope", K, "00" * 64)
        piped = lw.verify_witness_signature(
            "reserve-hold|x", b"cyberspace-witness/v0|reserve-hold|x", K, "00" * 64)
    finally:
        lw._ed.checkvalid = real
    return bad is False and piped is False and called["n"] == 0


def demote_to_refused(snap, why):
    """Mutant: do not raise. Relabel every reserve-hold as name-refused.
    There is still no per-source overflow column."""
    del why
    for row in snap.get("kind_source") or ():
        if row.get("disposition") == "reserve-hold":
            row["disposition"] = "name-refused"
            row["reason"] = "demoted"
            row["reserved_for"] = None
            row["reserved_for_raw"] = None


def backward_anchor(hops):
    """Mutant of _anchor_from_hops: walk back to the last non-weak key."""
    anchor = None
    for old, new in hops:
        if not wo.is_weak_pubkey(old):
            anchor = old
        if not wo.is_weak_pubkey(new):
            anchor = new
    if anchor:
        return anchor, None
    return None, "FLAG-VILLHAZE: chain starts on weak key"


def plant_kz1(name, pub_text):
    with core._db_lock, core._db() as conn:
        wo.init_schema(conn)
        bind(conn, name, ZERO, PAST)
        rot(conn, name, pub_text, ZERO, PAST)


def plant_z1x(name):
    with core._db_lock, core._db() as conn:
        wo.init_schema(conn)
        bind(conn, name, X, PAST)
        rot(conn, name, ZERO, X, PAST)


K = _ed.publickey(bytes.fromhex("71" * 32)).hex()
X = _ed.publickey(bytes.fromhex("72" * 32)).hex()
PLAIN = _ed.publickey(bytes.fromhex("73" * 32)).hex()
K_UP = K.upper()

# ---------------------------------------------------------------- sizing / kinds
check("four ruled-in kinds are exact KINDS members",
      all(k in lw.KINDS for k in KINDS_IN)
      and lw.WITNESS_KINDS == KINDS_IN + ("hold-closure",))
check("hold-closure is one ceiling slot and a resolution record stays out",
      lw.HOLD_CLOSURE_ENTRIES == 1 and "hold-closure" in lw.KINDS
      and "resolution" not in lw.KINDS
      and lw.max_log_entries(0, 0, 0) == lw.WINDOW_EDGES + lw.HOLD_CLOSURE_ENTRIES)
check("kinds are ASCII and contain no '|'",
      all(isinstance(k, str) and "|" not in k and k.encode("ascii") == k.encode()
          for k in lw.KINDS))
check("orphan pin adds ENTRIES_PER_NAME to the log ceiling",
      lw.ENTRIES_PER_NAME == 4
      and lw.max_log_entries(0, 1, 1) == lw.max_log_entries(0, 1, 0) + lw.ENTRIES_PER_NAME)
check("proof byte budget grows when the orphan pin grows",
      lw.proof_max_bytes(0, 1, 1) > lw.proof_max_bytes(0, 1, 0))
check("64 counted hops is inside the per-name cap",
      wo.over_cap_names({"hops_per_name": {"n": 64}, "kind_source": []}) == {})
check("65 counted hops is over the per-name cap, and is not a window problem",
      wo.over_cap_names({"hops_per_name": {"n": 65}, "kind_source": []}) == {"n": 65}
      and wo.bounds_problem({"hops_per_name": {"n": 65}, "kind_source": []}) is None)
check("unknown kind never reaches checkvalid", bad_kind_skips_checkvalid())
domain = lw.witness_message("reserve-hold", {"orphan": 1, "reserved_for": K})
check("domain tag is cyberspace-witness/v0|<kind>",
      domain.startswith(b"cyberspace-witness/v0|reserve-hold\n") and b"reserved_for=" in domain)

# ---------------------------------------------------------------- (a) K->Z1, reap, open
wipe()
with core._db_lock, core._db() as conn:
    bind(conn, "plain", PLAIN, FUT)
plant_kz1("heldk", K_UP)
reap()
with core._db_lock, core._db() as conn:
    left = conn.execute("SELECT COUNT(*) FROM name_bindings WHERE name='heldk'").fetchone()[0]
    plain = conn.execute("SELECT COUNT(*) FROM name_bindings WHERE name='plain'").fetchone()[0]
check("(a) reap dropped the expired K->Z1 binding and kept the honest one",
      left == 0 and plain == 1, (left, plain))
opened, err = open_or("a")
check("(a) open records the orphan reserve", err is None and opened["orphan_count"] >= 1, (opened, err))
log_id, entries, ok, why, view = rebuilt()
hold = for_name(view, "reserve-hold", "heldk")
pin = for_name(view, "origin-pin", "heldk")
hand = for_name(view, "origin-handoff", "heldk")
check("(a) node B rebuilds reserve-hold for K with orphan=1 from the log only",
      ok and len(hold) == 1 and hold[0]["reserved_for"] == K and hold[0]["k0_pub"] == K
      and hold[0]["orphan"] == 1 and hold[0]["reserved_for"] == K_UP.lower(),
      (ok, why, hold))
check("(a) same snapshot wrote origin-pin and origin-handoff",
      pin and pin[0]["origin"] == K and hand and hand[0]["origin"] == K
      and hand[0]["successor"] == ZERO, (pin, hand))
check("(a) an honest name with no weak hop is not a witness kind",
      not any(e.get("name") == "plain" for e in entries))
with core._db_lock, core._db() as conn:
    blob = conn.execute(
        "SELECT reserved_for, source, orphan FROM window_kind_source WHERE name='heldk'"
    ).fetchone()
check("(a) frozen reserved_for is the exact 32 key bytes, keyed by name_rotations",
      blob is not None and bytes(blob[0]) == bytes.fromhex(K) and blob[1] == "name_rotations"
      and blob[2] == 1, blob)
reserve_entry = next(e for e in entries if e["kind"] == "reserve-hold" and e["name"] == "heldk")
detail = json.loads(reserve_entry["detail"])
sig = detail.pop("witness_sig")
check("(a) witness signature verifies over the kind domain",
      lw.verify_witness_signature("reserve-hold", lw.witness_message("reserve-hold", detail),
                                  core._NODE_PUB, sig))
real_a = (ok and len(hold) == 1 and hold[0]["orphan"] == 1 and hold[0]["reserved_for"] == K)

real_plan = wo._plan_entries


def lie_orphan(row):
    lied = dict(row)
    lied["orphan"] = False
    return real_plan(lied)


wo._plan_entries = lie_orphan
try:
    wipe()
    plant_kz1("heldk", K_UP)
    reap()
    open_or("a-mut")
    _lid, _ent, _ok, _why, mview = rebuilt()
    mhold = for_name(mview, "reserve-hold", "heldk")
    mutant_a = not (mhold and mhold[0]["orphan"] == 1 and mhold[0]["reserved_for"] == K)
finally:
    wo._plan_entries = real_plan
record_mutant("orphan flag dropped from reserve-hold",
              "K->Z1 reap rebuilds reserve-hold orphan=1",
              real_a, mutant_a)

# ---------------------------------------------------------------- (b) Z1->X orphan => name-refused
wipe()
plant_z1x("flagged")
reap()
opened, err = open_or("b")
log_id, entries, ok, why, view = rebuilt()
refused = for_name(view, "name-refused", "flagged")
reserved = for_name(view, "reserve-hold", "flagged")
check("(b) Z1->X orphan is name-refused at node B, not reserve-hold",
      err is None and ok and len(refused) == 1 and refused[0]["orphan"] == 1
      and not reserved and "weak key" in (refused[0]["reason"] or ""),
      (err, ok, why, refused, reserved))
seen = {e["kind"] for e in entries}
check("(b) name-refused carries origin-pin and origin-handoff",
      "name-refused" in seen and "origin-pin" in seen and "origin-handoff" in seen, seen)
real_b = err is None and ok and len(refused) == 1 and not reserved

real_anchor = wo._anchor_from_hops
wo._anchor_from_hops = backward_anchor
try:
    wipe()
    plant_z1x("flagged")
    reap()
    open_or("b-mut")
    _lid, _ent, _ok, _why, mview = rebuilt()
    mutant_b = bool(for_name(mview, "reserve-hold", "flagged")) and not for_name(
        mview, "name-refused", "flagged")
finally:
    wo._anchor_from_hops = real_anchor
record_mutant("backward walk anchors the last honest key",
              "Z1->X orphan is name-refused at node B",
              real_b, mutant_b)

# ---------------------------------------------------------------- (c) global overflow, no source column
wipe()
with core._db_lock, core._db() as conn:
    wo.init_schema(conn)
    bind(conn, "honest", ZERO, FUT)
    rot(conn, "honest", K, ZERO, PAST)
    conn.executemany(
        "INSERT INTO name_bindings (name,node_pubkey,issued_at,expires_at,signature) "
        "VALUES (?,?,?,?,?)",
        [(f"w{i:04d}", ZERO, PAST, FUT, SIG) for i in range(wo.SNAPSHOT_GLOBAL_CAP)])
opened, err = open_or("c")
empty = counts()
check("(c) global overflow refuses the whole open",
      opened is None and err and empty == {"window": 0, "log": 0, "kinds": 0},
      (opened, err, empty))
check("(c) the honest chain is not written as name-refused",
      empty["kinds"] == 0 and empty["log"] == 0)
real_c = opened is None and empty == {"window": 0, "log": 0, "kinds": 0}

real_overflow = wo._overflow
wo._overflow = demote_to_refused
try:
    wipe()
    with core._db_lock, core._db() as conn:
        bind(conn, "honest", ZERO, FUT)
        rot(conn, "honest", K, ZERO, PAST)
        conn.executemany(
            "INSERT INTO name_bindings (name,node_pubkey,issued_at,expires_at,signature) "
            "VALUES (?,?,?,?,?)",
            [(f"w{i:04d}", ZERO, PAST, FUT, SIG) for i in range(wo.SNAPSHOT_GLOBAL_CAP)])
    open_or("c-mut")
    _lid, _ent, _ok, _why, mview = rebuilt()
    mutant_c = bool(for_name(mview, "name-refused", "honest")) and counts()["window"] == 1
finally:
    wo._overflow = real_overflow
record_mutant("overflow demotes reserve-hold to name-refused",
              "global overflow refuses whole; honest chain is not name-refused",
              real_c, mutant_c)

# ---------------------------------------------------------------- (d) ART-42 392140b7: clean rotations are not admissions
# A pool of real prime-order keys, so every clean hop is genuinely clean.
POOL = [_ed.publickey(bytes([0x10 + (i % 200)]) * 31 + bytes([i])).hex() for i in range(90)]
assert all(not wo.is_weak_pubkey(k) for k in POOL)


def clean_chain(conn, name, n, base=0, minute0=0):
    """n clean hops POOL[base] -> POOL[base+1] -> ... ; returns the last key."""
    for h in range(n):
        rot(conn, name, POOL[base + h], POOL[base + h + 1],
            f"2001-01-01T{(minute0 + h) // 60:02d}:{(minute0 + h) % 60:02d}:00+00:00")
    return POOL[base + n]


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

real_counted = wo.counted_hops
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

# ---------------------------------------------------------------- (e) KINDS missing a new kind => node B rejects
ok_saved, why_saved = lw.verify_chain(saved_entries, saved_log)
check("(e) the honest log verifies while reserve-hold is a kind", ok_saved, why_saved)
saved_kinds = lw.KINDS
lw.KINDS = tuple(k for k in saved_kinds if k != "reserve-hold")
try:
    rejected, why_rej = lw.verify_chain(saved_entries, saved_log)
finally:
    lw.KINDS = saved_kinds
check("(e) a KINDS tuple missing reserve-hold: node B rejects the log",
      rejected is False and why_rej and "unknown kind" in why_rej, why_rej)
real_e = ok_saved and rejected is False and "unknown kind" in (why_rej or "")

real_shape = lw.entry_shape_problem


def pretend_hold(entry):
    if isinstance(entry, dict) and entry.get("kind") not in lw.KINDS:
        fake = dict(entry)
        fake["kind"] = "hold"
        return real_shape(fake)
    return real_shape(entry)


lw.KINDS = tuple(k for k in saved_kinds if k != "reserve-hold")
lw.entry_shape_problem = pretend_hold
try:
    mutant_ok, mutant_why = lw.verify_chain(saved_entries, saved_log)
finally:
    lw.entry_shape_problem = real_shape
    lw.KINDS = saved_kinds
record_mutant("unknown kind skipped in the shape check",
              "KINDS missing reserve-hold: node B rejects the log",
              real_e, mutant_ok is True)

# ---------------------------------------------------------------- hold-closure (Villhaze 49a4fdca)
def closure_view():
    _lid, entries, ok, why, view = rebuilt()
    return entries, ok, why, view.get("hold-closure", [])


def plant_two():
    with core._db_lock, core._db() as conn:
        wo.init_schema(conn)
        bind(conn, "one", ZERO, PAST)
        bind(conn, "two", ZERO, PAST)
        rot(conn, "one", K, ZERO, PAST)
        rot(conn, "two", X, ZERO, PAST)


wipe()
plant_two()
reap()
opened, err = open_or("hold")
entries, ok, why, closures = closure_view()
one = closures[0] if len(closures) == 1 else {}
detail = dict(one.get("detail") or {})
sig = detail.pop("witness_sig", None)
signed_detail = dict(detail)
closure_root = detail.pop("rows_root", None)
closure_n = detail.pop("rows_n", None)
signed_ok = bool(sig) and lw.verify_witness_signature(
    "hold-closure", lw.witness_message("hold-closure", signed_detail), core._NODE_PUB, sig)
check("(h) one hold-closure, state closed, on the accepted port",
      err is None and ok and len(closures) == 1 and one.get("name") is None
      and detail == {
          "precondition": "witness+weak_reason",
          "state": "closed",
          "port": "c259535",
          "ruling": "49a4fdca",
      }
      and one.get("state") == "closed" and one.get("port") == "c259535"
      and one.get("ruling") == "49a4fdca"
      and one.get("precondition") == "witness+weak_reason"
      and signed_ok and isinstance(closure_root, str) and isinstance(closure_n, int)
      and not any(e.get("kind") == "resolution" for e in entries),
      (err, ok, why, closures, signed_ok))
real_h = (err is None and ok and len(closures) == 1 and detail.get("state") == "closed"
          and detail.get("port") == "c259535" and signed_ok)

real_close = wo._append_hold_closure


def skip_closure(conn, rows, *_a):
    del conn, rows


wo._append_hold_closure = skip_closure
try:
    wipe()
    plant_two()
    reap()
    open_or("hold-mut")
    _ent, _ok, _why, missed = closure_view()
    mutant_h = len(missed) == 0
finally:
    wo._append_hold_closure = real_close
record_mutant("hold-closure writer is a no-op",
              "node B rebuilds one closed hold-closure from the accepted port",
              real_h, mutant_h)


def per_row(conn, rows, *_a):
    for row in rows:
        real_close(conn, [row])


wo._append_hold_closure = per_row
try:
    wipe()
    plant_two()
    reap()
    open_or("hold-rows")
    _ent, _ok, _why, many = closure_view()
    mutant_rows = len(many) != 1
finally:
    wo._append_hold_closure = real_close
record_mutant("hold-closure written once per frozen row",
              "two reserved names still produce one hold-closure",
              real_h, mutant_rows)

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

# ---------------------------------------------------------------- (k) node B re-derives the refusal
def b_rederive(entries, log_id):
    ok, why = lw.verify_chain(entries, log_id)
    rok, rwhy = lw.verify_rows_root(entries)
    dok, refused = lw.rederive_refusals(entries)
    return (ok and rok and dok and refused == {"over": 71}), (ok, why, rok, rwhy, dok, refused)


real_k, info_k = b_rederive(iso_entries, iso_log)
check("(k) node B: chain verifies, rows_root covers every row, refusal re-derived (over: 71 > 64)",
      real_k, info_k)

real_append = wo._append_kind_entries
real_close = wo._append_hold_closure
_late = []


def append_skip_refusal(conn, rows):
    keep = [r for r in rows if r.get("reason") != "hop-cap"]
    _late[:] = [r for r in rows if r.get("reason") == "hop-cap"]
    return real_append(conn, keep)


def close_then_refusal(conn, rows, rows_root=None, rows_n=None):
    real_close(conn, rows, rows_root, rows_n)
    real_append(conn, _late)


wo._append_kind_entries, wo._append_hold_closure = append_skip_refusal, close_then_refusal
try:
    wipe()
    plant_isolation()
    open_or("k-mut")
    _l, _e = exported()
    mut_k = b_rederive(_e, _l)[0]
finally:
    wo._append_kind_entries, wo._append_hold_closure = real_append, real_close
record_mutant("refusal row written outside rows_root",
              "node B re-derives the refusal inside rows_root",
              real_k, not mut_k)

# ---------------------------------------------------------------- (l) advisory: reserve-hold carries weak-hop evidence
res = for_name(iso_view, "reserve-hold", "c-res1")
d = res[0]["detail"] if res else {}
dok, _r = lw.rederive_refusals(iso_entries)
real_l = (d.get("weak_index") == 0 and d.get("weak_old") == K and d.get("weak_new") == ZERO
          and wo.weak_reason(d.get("weak_new")) is not None and dok)
check("(l) reserve-hold carries weak_index/weak_old/weak_new and node B re-derives it", real_l, d)
real_plan = wo._plan_entries


def plan_no_evidence(row):
    out = real_plan(row)
    for _k, _k0, det in out:
        for f in ("weak_index", "weak_old", "weak_new"):
            det.pop(f, None)
    return out


wo._plan_entries = plan_no_evidence
try:
    wipe()
    plant_isolation()
    open_or("l-mut")
    _lid, _ent, _ok, _why, mv = rebuilt()
    r2 = for_name(mv, "reserve-hold", "c-res1")
    d2 = r2[0]["detail"] if r2 else {}
    mut_l = d2.get("weak_old") == K and d2.get("weak_new") == ZERO
finally:
    wo._plan_entries = real_plan
record_mutant("reserve-hold written without weak-hop evidence",
              "reserve-hold carries evidence node B re-derives",
              real_l, not mut_l)

print("mutant table:")
print(f"  {'mutant':<52} {'row':<62} real mutant-fails")
for name, row, real_ok, mutant_fails in MUTANTS:
    print(f"  {name:<52} {row:<62} {str(real_ok):<5} {mutant_fails}")

print(f"{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
