#!/usr/bin/env python3
"""ART-42 Bulwark pre-verify brake (on v2 Part 2): row BW-PV1 and its named
mutants M-PVAFTER, M-PVNONE; BW-PV2 rows (strict encoding, key-only
dedupe, set membership) and M-NOSTRICT, M-PAIRKEY, M-NOSETCHECK(2). A kill is BW-PV1 failing its own assertion;
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
WK, lw, WitnessSet = g["WK"], g["lw"], g["lw"].WitnessSet
def wrong_sigs(idx):
    """Well-formed, strict-valid (R canonical, prime order, S < L) signatures
    over OTHER bytes: they pass every 0-verify pre-check and fail checkvalid."""
    return [{"witness": WP[i], "sig": WK[i].sign(b"bulwark-not-this-head").signature.hex()} for i in idx]


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
    junk = dict(sa, signatures=wrong_sigs((0, 1)))
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

# ======================= BW-PV2 (on the brake) =======================
import hashlib
K = lambda ip: f"legacy-log:observe:verify:{ip}"
def charged(ip): return len(core._hits.get(K(ip), ()))
def stored(): return g["route_rows"]()
_SEEDS = [hashlib.sha256(b"wiring-witness-%d" % i).digest() for i in range(3)]
def _scalar(i):
    hh = hashlib.sha512(_SEEDS[i]).digest(); a = int.from_bytes(hh[:32], "little")
    return (a & ((1 << 254) - 8)) | (1 << 254)
def sig_nonce(i, msg, r):
    """A valid signature by witness i with a chosen nonce r (distinct bytes
    from the RFC 8032 deterministic one, accepted by checkvalid and libsodium)."""
    A_ = bytes.fromhex(WP[i]); R = _ed._encodepoint(_ed._scalarmult(_ed._BPOINT, r))
    h = int.from_bytes(_ed._H(R + A_ + msg), "little")
    return (R + ((r + h * _scalar(i)) % _ed._L).to_bytes(32, "little")).hex()
def good_sig(i, h): return WK[i].sign(lw.head_bytes(h)).signature.hex()
T8 = bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05")  # order-8 (Cipher vectors)
NONCANON = bytes.fromhex("ed" + "ff" * 30 + "7f")                                       # y = p (>= p)
assert _ed._is_small_order(_ed._decodepoint_strict(T8))
def fresh():
    g["reset_route_db"](); rlw._PIN_CACHE.clear(); wiring._MARK_CACHE.clear(); g["CACHE"].clear()
    CV[0] = 0
def cv_count(*a, **k): CV[0] += 1; return _cv(*a, **k)
def route(ip, signed, level):
    with mock.patch.object(_ed, "checkvalid", cv_count):
        r = cl(ip).post(URL, json={"head": signed, "level": level})
    try: d = r.json().get("detail") or r.json().get("status")
    except Exception: d = r.text[:80]
    return r.status_code, str(d)[:60]

def row_pv2_enc():
    # Bad encodings cost 0 verifies and 0 budget. S/R sub-cases go through the
    # route (a real pin). A sub-cases cannot pass _load_pin (weak_reason), so
    # they run at verify_legacy against a directly built set (belt).
    fresh(); sa, la = g["root_head"](A, 4); h = sa["head"]; out = {}; ok = True
    g0 = good_sig(0, h); raw = bytes.fromhex(g0)
    S_L = raw[:32] + (int.from_bytes(raw[32:], "little") + _ed._L).to_bytes(32, "little")
    rs = {"S>=L": S_L.hex(), "R non-canonical": (NONCANON + raw[32:]).hex(), "R small-order": (T8 + raw[32:]).hex()}
    for n, (case, sg) in enumerate(rs.items()):
        ip = f"203.0.113.{40 + n}"; CV[0] = 0
        code, d = route(ip, dict(sa, signatures=[{"witness": WP[0], "sig": sg}, {"witness": WP[1], "sig": good_sig(1, h)}]), la)
        out[case] = dict(code=code, verifies=CV[0], charged=charged(ip), stored=stored())
        ok = ok and code == 400 and "WeakWitnessSig" in d and CV[0] == 0 and charged(ip) == 0 and stored() == 0
    for case, apub in (("A non-canonical", NONCANON.hex()), ("A small-order", T8.hex())):
        W = WitnessSet(2, [apub, WP[0], WP[1]]); hw = dict(h, witness_set=W.id)
        signed = {"head": hw, "signatures": [{"witness": apub, "sig": good_sig(0, hw)},
                                             {"witness": WP[0], "sig": good_sig(0, hw)}]}
        CV[0] = 0; err = None
        with mock.patch.object(_ed, "checkvalid", cv_count):
            try: wiring.verify_legacy(signed, W, g["LOG"], sig_ok=lw.checkvalid_ok)
            except lw.WitnessRefused as e: err = type(e).__name__
        out[case] = dict(refused=err, verifies=CV[0])
        ok = ok and err == "WeakWitnessSig" and CV[0] == 0
    row_pv2_enc.last = out
    return ok

def row_pv2_dup():
    # A second DISTINCT valid sig from an in-set witness already in the head:
    # refused by the key-only dedupe, 0 verifies, 0 budget, nothing stored.
    fresh(); sa, la = g["root_head"](A, 4); h = sa["head"]; m = lw.head_bytes(h)
    s1, s2 = good_sig(0, h), sig_nonce(0, m, 12345)
    assert s1 != s2 and _cv(bytes.fromhex(s2), m, bytes.fromhex(WP[0]))
    ip = "203.0.113.50"
    code, d = route(ip, dict(sa, signatures=[{"witness": WP[0], "sig": s1}, {"witness": WP[0], "sig": s2},
                                             {"witness": WP[1], "sig": good_sig(1, h)}]), la)
    row_pv2_dup.last = dict(code=code, detail=d, verifies=CV[0], charged=charged(ip), stored=stored())
    return code == 400 and "DuplicateWitness" in d and CV[0] == 0 and charged(ip) == 0 and stored() == 0

OUTK = g["SigningKey"](hashlib.sha256(b"bulwark-out-of-set").digest())
def row_pv2_out():
    # Out-of-set key with its own valid sig: 0 verifies, 0 charged, nothing stored.
    fresh(); sa, la = g["root_head"](A, 4); h = sa["head"]; ip = "203.0.113.51"
    opub = OUTK.verify_key.encode().hex()
    code, d = route(ip, dict(sa, signatures=[{"witness": opub, "sig": OUTK.sign(lw.head_bytes(h)).signature.hex()}]), la)
    row_pv2_out.last = dict(code=code, detail=d, verifies=CV[0], charged=charged(ip), stored=stored())
    return code == 400 and "UnpinnedWitness" in d and CV[0] == 0 and charged(ip) == 0 and stored() == 0

def row_pv2_injunk():
    # In-set key, nothing stored, strict-valid junk sig: exactly 1 verify, 1 charged, nothing stored.
    fresh(); sa, la = g["root_head"](A, 4); ip = "203.0.113.52"
    code, d = route(ip, dict(sa, signatures=wrong_sigs((0,))), la)
    row_pv2_injunk.last = dict(code=code, verifies=CV[0], charged=charged(ip), stored=stored())
    return code == 400 and CV[0] == 1 and charged(ip) == 1 and stored() == 0

ROWS = [("BW-PV1", row_pv1), ("BW-PV2-ENC bad encodings (S>=L, R/A non-canonical, R/A small-order)", row_pv2_enc),
        ("BW-PV2-DUP second distinct valid sig, same in-set witness", row_pv2_dup),
        ("BW-PV2-OUT out-of-set key", row_pv2_out), ("BW-PV2-INJUNK in-set key, junk sig", row_pv2_injunk)]
class _Any(set):
    def __contains__(self, x): return True
    def __len__(self): return 3
_ANY = _Any()
_SETCHK = '''        if w not in pubs:
            raise UnpinnedWitness("signature from a witness this node does not pin")
'''
MUT += [
    ("M-NOSTRICT strict_encoding_reason -> None", row_pv2_enc,
     [mock.patch.object(wiring, "strict_encoding_reason", lambda w, s: None)]),
    ("M-PAIRKEY witness_dedupe_key -> (pubkey, sig)", row_pv2_dup,
     [mock.patch.object(wiring, "witness_dedupe_key", lambda w, s: (w, s))]),
    ("M-NOSETCHECK precheck_signatures set check removed", row_pv2_out,
     [mock.patch.object(wiring, "precheck_signatures", g["src_fn"](wiring, _SETCHK, "", "precheck_signatures"))]),
    ("M-NOSETCHECK2 precheck set check AND verify_head eligible check removed", row_pv2_out,
     [mock.patch.object(wiring, "precheck_signatures", g["src_fn"](wiring, _SETCHK, "", "precheck_signatures")),
      mock.patch.object(lw, "eligible_witnesses", lambda pubs: _ANY)]),
]

T0 = time.time(); R_ = []
bounded, RowTimeout = g["bounded"], g["RowTimeout"]
def run(fn):
    try:
        with bounded(): return bool(fn()), ""
    except (Exception, RowTimeout) as e: return False, f" [ERROR {type(e).__name__}: {e}]"

for rname, rfn in ROWS:
    ok, err = run(rfn)
    R_.append((rname, ok)); print(f"  {'ok  ' if ok else 'FAIL'} {rname}{err} {getattr(rfn, 'last', {})}")
for name, row, patches in MUT:
    real, err = run(row)
    for p in patches: p.start()
    try:
        mut, merr = run(row); d = getattr(row, "last", {})
    finally:
        for p in reversed(patches): p.stop()
    res = f"ERROR{merr}" if merr else ("SURVIVED" if mut else "KILLED")
    good = real and res == "KILLED"; R_.append((name, good))
    print(f"  {'ok  ' if good else 'FAIL'} MUTANT {name} (row {row.__name__}): real={real}{err} -> {res} {d}")
fails = sum(1 for _, o in R_ if not o)
print(f"wok_preverify: {len(R_) - fails} passed, {fails} failed ({time.time() - T0:.1f}s)")
raise SystemExit(1 if fails else 0)
