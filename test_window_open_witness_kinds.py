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
      all(k in lw.KINDS for k in KINDS_IN) and lw.WITNESS_KINDS == KINDS_IN)
check("kinds are ASCII and contain no '|'",
      all(isinstance(k, str) and "|" not in k and k.encode("ascii") == k.encode()
          for k in lw.KINDS))
check("orphan pin adds ENTRIES_PER_NAME to the log ceiling",
      lw.ENTRIES_PER_NAME == 4
      and lw.max_log_entries(0, 1, 1) == lw.max_log_entries(0, 1, 0) + lw.ENTRIES_PER_NAME)
check("proof byte budget grows when the orphan pin grows",
      lw.proof_max_bytes(0, 1, 1) > lw.proof_max_bytes(0, 1, 0))
check("64 hops is inside the per-name cap",
      wo.bounds_problem({"hops_per_name": {"n": 64}, "kind_source": []}) is None)
check("65 hops is over the per-name cap",
      wo.bounds_problem({"hops_per_name": {"n": 65}, "kind_source": []}) is not None)
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

# ---------------------------------------------------------------- (d) 10^5 junk hops across 1,000 names
wipe()
junk = []
for i in range(1000):
    name = f"j{i:04d}"
    for h in range(100):
        n = 1 + i * 100 + h
        if h == 0:
            old, new = ZERO, f"{n:064x}"
        else:
            old, new = f"{n:064x}", f"{n + 1000000:064x}"
        junk.append((name, old, new, PAST, SIG, PAST))
with core._db_lock, core._db() as conn:
    wo.init_schema(conn)
    conn.executemany(
        "INSERT INTO name_rotations "
        "(name,old_pubkey,new_pubkey,issued_at,signature,accepted_at) VALUES (?,?,?,?,?,?)",
        junk)
    bind(conn, "honest", ZERO, PAST)
    rot(conn, "honest", K, ZERO, PAST)
del junk
t0 = time.monotonic()
opened, err = open_or("d")
elapsed = time.monotonic() - t0
empty = counts()
check("(d) 10^5 junk hops: open refuses cleanly within 30s",
      opened is None and err and elapsed < 30 and empty == {"window": 0, "log": 0, "kinds": 0},
      (elapsed, opened, err, empty))
check("(d) junk refuse did not record the honest name", empty["log"] == 0 and empty["kinds"] == 0)
with core._db_lock, core._db() as conn:
    conn.execute("DELETE FROM name_rotations WHERE name != 'honest'")
    conn.execute("DELETE FROM name_bindings WHERE name != 'honest'")
reap()
opened, err = open_or("d-clean")
log_id, entries, ok, why, view = rebuilt()
hold = for_name(view, "reserve-hold", "honest")
saved_entries = entries
saved_log = log_id
check("(d) after the junk is gone, the honest reserve-hold rebuilds at node B",
      err is None and ok and len(hold) == 1 and hold[0]["reserved_for"] == K and hold[0]["orphan"] == 1,
      (err, ok, why, hold))
real_d = (opened is not None and ok and len(hold) == 1 and hold[0]["orphan"] == 1
          and empty == {"window": 0, "log": 0, "kinds": 0} and elapsed < 30)

wo._overflow = demote_to_refused
try:
    wipe()
    with core._db_lock, core._db() as conn:
        bind(conn, "honest", ZERO, FUT)
        rot(conn, "honest", K, ZERO, PAST)
        prev = ZERO
        for h in range(65):
            nxt = f"{h + 1:064x}"
            rot(conn, "flood", prev, nxt, f"2001-01-01T00:{h:02d}:00+00:00")
            prev = nxt
    open_or("d-mut")
    _lid, _ent, _ok, _why, mview = rebuilt()
    mutant_d = bool(for_name(mview, "name-refused", "honest"))
finally:
    wo._overflow = real_overflow
record_mutant("per-name overflow demotes the honest hold",
              "10^5 junk refuses cleanly; honest hold still rebuilds",
              real_d, mutant_d)

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

print("mutant table:")
print(f"  {'mutant':<52} {'row':<62} real mutant-fails")
for name, row, real_ok, mutant_fails in MUTANTS:
    print(f"  {name:<52} {row:<62} {str(real_ok):<5} {mutant_fails}")

print(f"{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
