#!/usr/bin/env python3
"""Window-open witness kinds, split 4/4: node B wiring (ART-42).

legacy_witness._rules runs, in order: the size limits (max_log_entries /
proof_max_bytes), verify_rows_root, rederive_refusals. window_open and
rederive_refusals share ONE counted_hops. Every proof here goes through the
real _rules with a real signed head, full span and committed hop rows.
Rows: Examiner (forged / dropped FLAG), Lodestar (clean 65 / 1 weak + 64
clean accepted), Cipher (tampered hop row refused before re-derivation),
Bulwark (over-limit refused with nothing hashed or counted). Every mutant
here is killed by a row in this file."""
import inspect
import json

from wok_common import (FUT, K, POOL, Probe, ZERO, b_accepts, b_proof, bind, check,
                        clean_chain, core, finish, finish_window, lw, open_or, record_mutant,
                        rot, wipe, wo)

real_counted = wo.counted_hops
real_vrr = lw.verify_rows_root
real_rr = lw.rederive_refusals
real_size = lw.check_size_limits

# ---------------------------------------------------------------- one shared counted_hops
src_lw = inspect.getsource(lw)
check("one counted_hops: defined only in window_open; rederive_refusals and the snapshot "
      "both call window_open.counted_hops",
      "def counted_hops" not in src_lw
      and "wo.counted_hops(" in inspect.getsource(lw.rederive_refusals)
      and "counted_hops(hops)" in inspect.getsource(wo.snapshot_bindings)
      and "rederive_refusals(entries, hop_rows)" in inspect.getsource(lw._rules))


def both_true():
    lw.verify_rows_root = lambda *a, **k: (True, None)
    lw.rederive_refusals = lambda *a, **k: (True, {})


def restore():
    lw.verify_rows_root, lw.rederive_refusals = real_vrr, real_rr
    lw.check_size_limits = real_size
    wo.counted_hops = real_counted


# ---------------------------------------------------------------- Examiner: forged and dropped FLAG
def forged_flag_proof():
    """Writer lies: FLAGs 'p64' (63 clean + 1 weak = 64 counted) as hop-cap."""
    wipe()
    with core._db_lock, core._db() as conn:
        wo.init_schema(conn)
        last = clean_chain(conn, "p64", 63)
        rot(conn, "p64", last, ZERO, "2003-01-01T00:00:00+00:00")
        bind(conn, "p64", ZERO, FUT)
    real_over = wo.over_cap_names
    wo.over_cap_names = lambda snap: {n: c for n, c in snap.get("hops_per_name", {}).items()
                                      if c >= wo.SNAPSHOT_PER_NAME}
    try:
        open_or("ex-forge")
    finally:
        wo.over_cap_names = real_over
    finish_window()
    return b_proof()


def dropped_flag_proof():
    """Writer lies: 'p65' (64 clean + 1 weak = 65 counted) is not FLAGged."""
    wipe()
    with core._db_lock, core._db() as conn:
        wo.init_schema(conn)
        last = clean_chain(conn, "p65", 64)
        rot(conn, "p65", last, ZERO, "2003-01-01T00:00:00+00:00")
        bind(conn, "p65", ZERO, FUT)
    real_iso = wo.isolate_over_cap
    wo.isolate_over_cap = lambda snap: {}
    try:
        open_or("ex-drop")
    finally:
        wo.isolate_over_cap = real_iso
    finish_window()
    return b_proof()


forged = forged_flag_proof()
dropped = dropped_flag_proof()
f_ok, f_why = b_accepts(*forged)
d_ok, d_why = b_accepts(*dropped)
real_ex1 = (not f_ok) and "forged" in f_why and "'p64'" in f_why
real_ex2 = (not d_ok) and "dropped" in d_why and "p65" in d_why
check("(Examiner) a forged FLAG on a name with 64 anchor-read hops is refused", real_ex1, f_why)
check("(Examiner) a dropped FLAG on a name with 65 anchor-read hops is refused", real_ex2, d_why)
both_true()
try:
    mf_ok, _ = b_accepts(*forged)
    md_ok, _ = b_accepts(*dropped)
finally:
    restore()
record_mutant("Examiner: verify_rows_root and rederive_refusals return True",
              "forged FLAG (64 anchor-read hops) refused", real_ex1, mf_ok)
record_mutant("Examiner: verify_rows_root and rederive_refusals return True",
              "dropped FLAG (65 anchor-read hops) refused", real_ex2, md_ok)


# ---------------------------------------------------------------- Lodestar: honest windows accepted
def clean65_proof():
    wipe()
    with core._db_lock, core._db() as conn:
        wo.init_schema(conn)
        last = clean_chain(conn, "l65", 65)
        bind(conn, "l65", last, FUT)
    open_or("lo-65")
    finish_window()
    return b_proof()


def weak1_proof():
    wipe()
    with core._db_lock, core._db() as conn:
        wo.init_schema(conn)
        rot(conn, "l1w", K, ZERO, "2001-01-01T00:00:00+00:00")
        rot(conn, "l1w", ZERO, POOL[0], "2001-01-01T00:01:00+00:00")
        last = clean_chain(conn, "l1w", 63, minute0=2)
        bind(conn, "l1w", last, FUT)
    open_or("lo-1w")
    finish_window()
    return b_proof()


c65 = clean65_proof()
w1 = weak1_proof()
c_ok, c_why = b_accepts(*c65)
w_ok, w_why = b_accepts(*w1)
real_lo1 = c_ok and c_why["name"] == "imp"
real_lo2 = w_ok and w_why["name"] == "imp"
check("(Lodestar) a witnessed window that opens 65 clean hops is accepted at node B",
      real_lo1, c_why)
check("(Lodestar) a witnessed window that opens 1 weak + 64 clean hops is accepted at node B",
      real_lo2, w_why)


def rederive_len(entries, hops=None):
    """Mutant: rederive_refusals counts len(hops)."""
    wo.counted_hops = lambda h: len(h)
    try:
        return real_rr(entries, hops)
    finally:
        wo.counted_hops = real_counted


lw.rederive_refusals = rederive_len
try:
    mc_ok, _ = b_accepts(*c65)
    mw_ok, _ = b_accepts(*w1)
finally:
    restore()
record_mutant("Lodestar: rederive_refusals uses len(hops)",
              "65 clean hops accepted at node B", real_lo1, not mc_ok)
record_mutant("Lodestar: rederive_refusals uses len(hops)",
              "1 weak + 64 clean accepted at node B", real_lo2, not mw_ok)

# ---------------------------------------------------------------- Cipher: tampered hop row
proof, wset, log_id = w1
tampered = json.loads(json.dumps(proof))
row = next(r for r in tampered["hops"] if r["name"] == "l1w" and r["i"] == 0)
row["new"] = POOL[5]          # the weak hop now looks clean
with Probe() as pr:
    t_ok, t_why = b_accepts(tampered, wset, log_id)
real_ci = (not t_ok) and t_why.startswith("rows_root") and pr.n["counted"] == 0
check("(Cipher) a hop row tampered after signing is refused at verify_rows_root, before "
      "any hop is re-derived", real_ci, (t_why, pr.n))
lw.verify_rows_root = lambda *a, **k: (True, None)
try:
    with Probe() as mpr:
        mt_ok, mt_why = b_accepts(tampered, wset, log_id)
finally:
    restore()
record_mutant("Cipher: verify_rows_root returns True",
              "tampered hop row refused before re-derivation", real_ci,
              mt_ok or mpr.n["counted"] > 0)

# ---------------------------------------------------------------- Bulwark: limits first
# No rotations: the open writes only the hold-closure, then the import path.
PINS = (1, 0, 0)
M = lw.max_log_entries(*PINS)
wipe()
open_or("bw")
with core._db_lock, core._db() as conn:
    n_now = conn.execute("SELECT COUNT(*) FROM legacy_migration_log").fetchone()[0]
finish_window(fillers=M + 1 - (n_now + 5))
over_n = b_proof()
real_len = len(over_n[0]["span"])
with Probe() as p1:
    o1_ok, o1_why = b_accepts(*over_n, pins=PINS)
real_bw1 = (real_len == M + 1 and not o1_ok and "max_log_entries" in o1_why
            and p1.n == {"hashed": 0, "counted": 0})
check(f"(Bulwark) a window one over max_log_entries ({M + 1} > {M}) is refused with 0 rows "
      "hashed and 0 hop counts", real_bw1, (real_len, o1_why, p1.n))

wipe()
open_or("bw2")
finish_window()
fit = b_proof()
BIG = (1, 0, 0)
cap = lw.proof_max_bytes(*BIG)
base = len(json.dumps(fit[0]).encode())
padded = dict(fit[0])
padded["pad"] = ""
padded["pad"] = "x" * (cap + 1 - len(json.dumps(padded).encode()))
with Probe() as p2:
    o2_ok, o2_why = b_accepts(padded, fit[1], fit[2], pins=BIG)
real_bw2 = (len(json.dumps(padded).encode()) == cap + 1 and not o2_ok
            and "proof_max_bytes" in o2_why and p2.n == {"hashed": 0, "counted": 0})
check(f"(Bulwark) a proof one over proof_max_bytes ({cap + 1} > {cap}) is refused with 0 rows "
      "hashed and 0 hop counts", real_bw2, (o2_why, p2.n))
fit_ok, fit_why = b_accepts(*fit, pins=BIG)
check("(Bulwark) the same proof without the pad is accepted under the same pins", fit_ok, fit_why)

_cur = {}


def late_limits():
    """Mutant: the limits check runs after verify_rows_root."""
    lw.check_size_limits = lambda proof, pins: _cur.update(proof=proof, pins=pins)

    def vrr_then_size(entries, hops=None, log_id=None):
        out = real_vrr(entries, hops, log_id)
        real_size(_cur["proof"], _cur["pins"])
        return out
    lw.verify_rows_root = vrr_then_size


late_limits()
try:
    with Probe() as m1:
        b_accepts(*over_n, pins=PINS)
    with Probe() as m2:
        b_accepts(padded, fit[1], fit[2], pins=BIG)
finally:
    restore()
record_mutant("Bulwark: limits checked after verify_rows_root",
              "one over max_log_entries: 0 hashed, 0 counted", real_bw1, m1.n["hashed"] > 0)
record_mutant("Bulwark: limits checked after verify_rows_root",
              "one over proof_max_bytes: 0 hashed, 0 counted", real_bw2, m2.n["hashed"] > 0)

finish("test_wok_nodeb.py")
