#!/usr/bin/env python3
"""ART-42 Bulwark pre-verify brake (on v2 Part 2): row BW-PV1 and its named
mutants M-PVAFTER, M-PVNONE. A kill is BW-PV1 failing its own assertion;
exceptions are ERROR, not kills.

Fixtures, the throwaway DB dir, the checkvalid memo and the route helpers
are test_wok_wiring.py's own (everything before its runner), loaded into a
namespace so this file adds no second copy of them. The memo sits BELOW the
counters, so every counted verify is a real call into fed.ed25519.checkvalid."""
import collections, os, sys, threading, time
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
_src = open(os.path.join(HERE, "test_wok_wiring.py")).read()
g = {"__name__": "wokw", "__file__": os.path.join(HERE, "test_wok_wiring.py")}
exec(compile(_src[:_src.index("\nR_ = []\n")], "test_wok_wiring.py", "exec"), g)

core, wiring, rlw, _ed = g["core"], g["wiring"], g["rlw"], g["_ed"]
A, WP, TestClient, appmod = g["A"], g["WP"], g["TestClient"], g["appmod"]
URL = "/api/v1/legacy-log/observe"
BUDGET = rlw.OBSERVE_VERIFY_SIGS_PER_IP
FLOOD = rlw.OBSERVE_PER_IP                 # the whole route-entry allowance of one IP
SIGS = 2                                   # junk carries 2 well-formed sigs (2-of-3 pin)
assert FLOOD * SIGS > BUDGET, "flood must exceed the brake or the row cannot discriminate"

VL, CV = [0], [0]
_vl, _cv = wiring.verify_legacy, _ed.checkvalid
def cl(ip): return TestClient(appmod.app, client=(ip, 40000))


def row_pv1():
    # BW-PV1: IP X sends its whole per-IP route allowance (120) of heads whose
    # two witness signatures are well-formed but wrong (they pass every
    # 0-verify pre-check). The brake must stop X at BUDGET checkvalid calls
    # (BUDGET/2 verify_legacy calls), answer 429 after that, and leave an
    # honest valid head from IP Y untouched (200 observed).
    g["reset_route_db"](); rlw._PIN_CACHE.clear(); wiring._MARK_CACHE.clear(); g["CACHE"].clear()
    sa, la = g["root_head"](A, 4)
    r0 = cl("192.0.2.1").post(URL, json={"head": sa, "level": la})
    assert r0.status_code == 200, r0.text
    core._hits.clear()
    junk = dict(sa, signatures=[{"witness": WP[0], "sig": "11" * 64}, {"witness": WP[1], "sig": "22" * 64}])
    vl_cur = wiring.verify_legacy            # the mutant's wrapper, if one is installed
    def vl_count(*a, **k): VL[0] += 1; return vl_cur(*a, **k)
    def cv_count(*a, **k): CV[0] += 1; return _cv(*a, **k)
    VL[0] = CV[0] = 0
    with mock.patch.object(wiring, "verify_legacy", vl_count), mock.patch.object(_ed, "checkvalid", cv_count):
        x = cl("203.0.113.10")
        codes = [x.post(URL, json={"head": junk, "level": la}).status_code for _ in range(FLOOD)]
        vl_x, cv_x = VL[0], CV[0]
        s6, l6 = g["next_head"](A, 4, 6)
        ry = cl("198.18.0.99").post(URL, json={"head": s6, "level": l6})
    hist = dict(collections.Counter(codes))
    want = {400: BUDGET // SIGS, 429: FLOOD - BUDGET // SIGS}
    ok = (vl_x == BUDGET // SIGS and cv_x <= BUDGET and hist == want
          and ry.status_code == 200 and ry.json().get("status") == "observed")
    row_pv1.last = dict(budget_sigs=BUDGET, flood=FLOOD, x_codes=hist, x_verify_legacy=vl_x,
                        x_checkvalid=cv_x, y=(ry.status_code, ry.json().get("status") or ry.json().get("detail")))
    return ok


# M-PVAFTER: the per-IP verify charge runs AFTER verify_legacy returns. The
# route's own call becomes a recorder; the real charge is applied by a
# wrapper around verify_legacy only once it has returned (a verified head).
_pending = threading.local()
_real_charge = rlw.charge_observe_verify
def _record(src, n): _pending.v = (src, n)
def _vl_then_charge(*a, **k):
    v = _vl(*a, **k)
    src, n = getattr(_pending, "v", (None, 0))
    if src is not None: _real_charge(src, n)
    return v
MUT = [
    ("M-PVAFTER per-IP verify charge moved after verify_legacy", row_pv1,
     [mock.patch.object(rlw, "charge_observe_verify", _record),
      mock.patch.object(wiring, "verify_legacy", _vl_then_charge)]),
    ("M-PVNONE pre-verify brake removed", row_pv1,
     [mock.patch.object(rlw, "charge_observe_verify", lambda src, n: None)]),
]

T0 = time.time(); R_ = []
bounded, RowTimeout = g["bounded"], g["RowTimeout"]
def run(fn):
    try:
        with bounded(): return bool(fn()), ""
    except (Exception, RowTimeout) as e: return False, f" [ERROR {type(e).__name__}: {e}]"

ok, err = run(row_pv1)
R_.append(("BW-PV1", ok)); print(f"  {'ok  ' if ok else 'FAIL'} BW-PV1{err} {getattr(row_pv1, 'last', {})}")
for name, row, patches in MUT:
    real, err = run(row)
    for p in patches: p.start()
    try:
        mut, merr = run(row); d = getattr(row, "last", {})
    finally:
        for p in reversed(patches): p.stop()
    res = f"ERROR{merr}" if merr else ("SURVIVED" if mut else "KILLED")
    good = real and res == "KILLED"; R_.append((name, good))
    print(f"  {'ok  ' if good else 'FAIL'} MUTANT {name}: real={real}{err} -> {res} {d}")
fails = sum(1 for _, o in R_ if not o)
print(f"wok_preverify: {len(R_) - fails} passed, {fails} failed ({time.time() - T0:.1f}s)")
raise SystemExit(1 if fails else 0)
