#!/usr/bin/env python3
"""Window-open witness kinds, split 3/4: (h) the single hold-closure,
(k) node B re-derives the hop-cap refusal inside rows_root, (l) reserve-hold
weak-hop evidence. Every mutant here is killed by a row in this file."""
from wok_common import (FUT, K, PAST, POOL, X, ZERO, bind, check, clean_chain, core, exported,
                        exported_hops, finish, for_name, lw, open_or, reap, rebuilt,
                        record_mutant, rot, wipe, wo)


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
hops_root = detail.pop("hops_root", None)
hops_n = detail.pop("hops_n", None)
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
      and isinstance(hops_root, str) and isinstance(hops_n, int)
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


# ---------------------------------------------------------------- (k) node B re-derives the refusal
def plant_isolation():
    """'over': 70 clean hops, then a weak hop (to ZERO), then 5 more hops.
    Counted hops = 71. Clean names: c-held0, c-held2, c-res1 (K->ZERO)."""
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


def b_rederive(entries, log_id, hops):
    ok, why = lw.verify_chain(entries, log_id)
    rok, rwhy = lw.verify_rows_root(entries, hops)
    dok, refused = lw.rederive_refusals(entries, hops)
    return (ok and rok and dok and refused == {"over": 71}), (ok, why, rok, rwhy, dok, refused)


wipe()
plant_isolation()
open_or("iso")
iso_log, iso_entries, _ok, _why, iso_view = rebuilt()
iso_hops = exported_hops()
real_k, info_k = b_rederive(iso_entries, iso_log, iso_hops)
check("(k) node B: chain verifies, rows_root covers every row, refusal re-derived (over: 71 > 64)",
      real_k, info_k)

real_append = wo._append_kind_entries
_late = []


def append_skip_refusal(conn, rows):
    keep = [r for r in rows if r.get("reason") != "hop-cap"]
    _late[:] = [r for r in rows if r.get("reason") == "hop-cap"]
    return real_append(conn, keep)


def close_then_refusal(conn, rows, *a):
    real_close(conn, rows, *a)
    real_append(conn, _late)


wo._append_kind_entries, wo._append_hold_closure = append_skip_refusal, close_then_refusal
try:
    wipe()
    plant_isolation()
    open_or("k-mut")
    _l, _e = exported()
    mut_k = b_rederive(_e, _l, exported_hops())[0]
finally:
    wo._append_kind_entries, wo._append_hold_closure = real_append, real_close
record_mutant("refusal row written outside rows_root",
              "node B re-derives the refusal inside rows_root",
              real_k, not mut_k)

# ---------------------------------------------------------------- (l) advisory: reserve-hold carries weak-hop evidence
res = for_name(iso_view, "reserve-hold", "c-res1")
d = res[0]["detail"] if res else {}
dok, _r = lw.rederive_refusals(iso_entries, iso_hops)
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

finish("test_wok_closure.py")
