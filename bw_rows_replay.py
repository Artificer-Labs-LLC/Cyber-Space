#!/usr/bin/env python3
"""Bulwark replay rows for r5/r6 (ART-37). Rotation-record replay after recovery.

Run from a tree root:  ./venv/bin/python bw_rows_replay.py   (or TREE=/path)
Throwaway DB (CYBERNET_DB_DIR = fresh mkdtemp). Ephemeral keys only; reads no *.key.

R-A  A->B, recovery B->A, then the holder of retired key B replays the OLD
     A->B record with a FRESH B binding.  Expect: refused, A stays.  Per seat:
     R-A1 /names/rotate, R-A2 gossip single `rotation`, R-A3 gossip `rotation_chain`.
R-B  Record issued_at == stored binding issued_at (equality) must be refused
     (strict >).  Per seat R-B1/2/3.  Kills a `>=` mutant.
R-C  Examiner's two rows (replace the old R-C1).
     R-C1a stored A@T2; gossip delivers A's own older binding A@T0 (T0<T2).
           ASSERT not stored (result != replaced) and stored issued_at stays T2.
           Mutant M-C1a: flip same-key later-wins in _name_claim_beats (`>` -> `<`).
     R-C1b stored A row with UNPARSEABLE issued_at (expires_at fine). Gossip A@T0, then
           replay old A->B@T1. Option 1 (cd7c35b9 = r5 same-key fallback): EXPECTED-OPEN.
     R-C1bR  chair's R-C1b-route: replayed A@T0 POSTed to /names/claim. EXPECTED-OPEN (opt1).
     R-C1bRR same POST then A->B@T1 replay. EXPECTED-OPEN (opt1).
     R-C1bHG/HR owner's fresh A heals via gossip / route; replay still refused.
     R-C1bFR foreign claim on the route over a fully unparseable row is refused.
     R-C1c1/2/3 ruling (c): a fresh rotation over an unparseable row is refused per seat.
     R-C1b25 a 25h-old A@T0 is dropped-stale at intake; row stays held.
     Default (BW-RC1B fail-closed in core.py): the three rows are ASSERTED and the heal rows
     expect the owner's fresh A refused. BW_FAILCLOSED=0 = option-1 expectations (8f39154).
     R-C2  DB restore of an old row: OUT OF SCOPE for code rows. Runbook text:
           "re-sign, don't restore" (after a restore the owner re-signs a fresh
           binding before re-federating). Not executed.
     R-C3  lagging mirror that only ever saw A@T0 receives B + A->B@T1.
           EXPECTED-OPEN evidence row (REPORTED, not asserted).
R-C1bGC  lazy GC (_name_registry_has_room) never deletes a frozen row: unrelated new
     claim (gossip / route) leaves it byte-identical; foreign claim refused. R-C1bGCP: parseable
     expired rows ARE pruned (positive control).
R-D  One sender, N stale (replayed) rotation records per seat: count rotation-
     record Ed25519 verifies, binding verifies, max _db_lock hold, and rows written
     to name_bindings / name_rotations / name_conflicts.  ASSERT 0 rotation
     verifies and 0 name_bindings/name_rotations writes.
     R-D3 unanchored 8-hop self-signed chain (attacker's own keys): ASSERT 0
     rotation verifies (anchor/postdate check runs before any verify).
"""
import os, sys, tempfile, time, threading
from datetime import datetime, timedelta, timezone

TREE = os.environ.get("TREE") or os.path.dirname(os.path.abspath(__file__))
os.environ["CYBERNET_DB_DIR"] = tempfile.mkdtemp(prefix="bw-replay-rows-")
sys.path.insert(0, TREE)
import core  # noqa: E402  (core first — app.py order)
core.init_db()
import rotate_name  # noqa: E402
import fed.ed25519 as _fe  # noqa: E402
import nacl.signing  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from app import app  # noqa: E402
import routes_social_serve as _rss  # noqa: E402

C = TestClient(app)
NOW = datetime.now(timezone.utc)
iso = lambda d: d.strftime("%Y-%m-%dT%H:%M:%SZ")
T = lambda **kw: iso(NOW - timedelta(**kw))
EXP = iso(NOW + timedelta(days=30))
pub = lambda k: k.verify_key.encode().hex()
key = nacl.signing.SigningKey.generate
RESULTS = []

# ---------- instrumentation: verify counters, lock-hold timer
CNT = {"rot": 0, "bind": 0}
_rot_cv, _bind_cv = rotate_name.checkvalid, _fe.checkvalid
def _rot(*a): CNT["rot"] += 1; return _rot_cv(*a)
def _bind(*a): CNT["bind"] += 1; return _bind_cv(*a)
rotate_name.checkvalid = _rot
_fe.checkvalid = _bind
HOLD = []
class _TimedLock:
    def __init__(s, l): s.l = l
    def __enter__(s): s.l.acquire(); s.t = time.perf_counter(); return s
    def __exit__(s, *a): HOLD.append(time.perf_counter() - s.t); s.l.release()
_tl = _TimedLock(core._db_lock)
core._db_lock = _tl
_rss._db_lock = _tl

def bind(k, name, iss, exp=EXP):
    return dict(name=name, node_pubkey=pub(k), issued_at=iss, expires_at=exp,
                signature=k.sign(core._name_claim_payload(name, pub(k), iss, exp)).signature.hex())
def rec(name, old, new, iss):
    return rotate_name.mint_rotation(name, bytes(old), pub(new), iss)
def route_rotate(r, b):
    return C.post("/api/v1/names/rotate", data=dict(
        name=r["name"], old_pubkey=r["old_pubkey"], new_pubkey=r["new_pubkey"],
        rotation_issued_at=r["issued_at"], rotation_signature=r["signature"],
        binding_issued_at=b["issued_at"], binding_expires_at=b["expires_at"],
        binding_signature=b["signature"]))
def gossip(b, r=None, chain=None):
    b = dict(b)
    if r is not None: b["rotation"] = r
    if chain is not None: b["rotation_chain"] = chain
    return core.ingest_gossiped_binding(b)
def holder(name):
    with core._db_lock, core._db() as conn:
        x = conn.execute("SELECT node_pubkey, issued_at FROM name_bindings WHERE name=?", (name,)).fetchone()
    return tuple(x) if x else None
def counts(name):
    with core._db_lock, core._db() as conn:
        return tuple(conn.execute(f"SELECT COUNT(*) FROM {t} WHERE name=?", (name,)).fetchone()[0]
                     for t in ("name_rotations", "name_conflicts"))
def row(rid, asserted, ok, detail):
    RESULTS.append((rid, asserted, ok))
    tag = ("PASS" if ok else "FAIL") if asserted else ("HELD" if ok else "BYPASSED")
    print(f"{rid:6s} {tag:8s} {detail}")

# seat drivers: claim A, rotate A->B, recover B->A (each via the seat under test)
def setup(seat, name, t_a=20, t_r1=10, t_b=9, t_r2=5, t_a2=4):
    A, B = key(), key()
    if seat == "route":
        assert C.post("/api/v1/names/claim", data=bind(A, name, T(minutes=t_a))).status_code == 200
    else:
        assert gossip(bind(A, name, T(minutes=t_a))) == "inserted"
    R1 = rec(name, A, B, T(minutes=t_r1))
    R2 = rec(name, B, A, T(minutes=t_r2))
    if seat == "route":
        assert route_rotate(R1, bind(B, name, T(minutes=t_b))).status_code == 200
        assert route_rotate(R2, bind(A, name, T(minutes=t_a2))).status_code == 200
    elif seat == "single":
        assert gossip(bind(B, name, T(minutes=t_b)), r=R1) == "replaced"
        assert gossip(bind(A, name, T(minutes=t_a2)), r=R2) == "replaced"
    else:
        assert gossip(bind(B, name, T(minutes=t_b)), chain=[R1]) == "replaced"
        assert gossip(bind(A, name, T(minutes=t_a2)), chain=[R2]) == "replaced"
    assert holder(name)[0] == pub(A)
    return A, B, R1

def replay(seat, R1, B, name):
    fresh = bind(B, name, T(seconds=1))
    if seat == "route":
        r = route_rotate(R1, fresh); return f"HTTP {r.status_code}"
    if seat == "single":
        return gossip(fresh, r=R1)
    return gossip(fresh, chain=[R1])

SEATS = (("1", "route"), ("2", "single"), ("3", "chain"))

# ---------------- R-A
for n, seat in SEATS:
    name = f"ra-{seat}"
    A, B, R1 = setup(seat, name)
    out = replay(seat, R1, B, name)
    h = holder(name)[0]
    row(f"R-A{n}", True, h == pub(A), f"{seat}: replay old A->B -> {out}; holder={'A' if h == pub(A) else 'B'}")

# ---------------- R-B  (record issued_at == stored binding issued_at)
for n, seat in SEATS:
    name = f"rb-{seat}"
    A, B = key(), key()
    t0 = T(minutes=3)
    if seat == "route":
        assert C.post("/api/v1/names/claim", data=bind(A, name, t0)).status_code == 200
    else:
        assert gossip(bind(A, name, t0)) == "inserted"
    R = rec(name, A, B, t0)  # equal instant
    fresh = bind(B, name, T(seconds=1))
    if seat == "route": out = f"HTTP {route_rotate(R, fresh).status_code}"
    elif seat == "single": out = gossip(fresh, r=R)
    else: out = gossip(fresh, chain=[R])
    h = holder(name)[0]
    row(f"R-B{n}", True, h == pub(A), f"{seat}: record.issued_at == stored.issued_at -> {out}; holder={'A' if h == pub(A) else 'B'}")

# control: a legitimate rotation (record strictly after stored binding) still works on every seat
for n, seat in SEATS:
    name = f"ok-{seat}"
    A, B = key(), key()
    if seat == "route":
        assert C.post("/api/v1/names/claim", data=bind(A, name, T(minutes=3))).status_code == 200
    else:
        gossip(bind(A, name, T(minutes=3)))
    R = rec(name, A, B, T(minutes=2))
    fresh = bind(B, name, T(seconds=1))
    if seat == "route": out = f"HTTP {route_rotate(R, fresh).status_code}"
    elif seat == "single": out = gossip(fresh, r=R)
    else: out = gossip(fresh, chain=[R])
    h = holder(name)[0]
    row(f"CTRL{n}", True, h == pub(B), f"{seat}: legit rotation record > stored -> {out}; holder={'B' if h == pub(B) else 'A'}")

# ---------------- R-C  Examiner's rows
def raw_issued(name, iss):  # throwaway DB only: force the stored issued_at text
    with core._db_lock, core._db() as conn:
        conn.execute("UPDATE name_bindings SET issued_at=? WHERE name=?", (iss, name))

# R-C1a: stored A@T2 (setup's recovery binding, t_a2=4m ago); gossip A@T0 (20m ago)
name = "rc1a"
A, B, R1 = setup("single", name, t_a=20)
t2 = holder(name)[1]
out_imp = gossip(bind(A, name, T(minutes=20)))
h = holder(name)
row("R-C1a", True, out_imp != "replaced" and h == (pub(A), t2),
    f"stored A@T2={t2}; gossip A@T0 -> {out_imp}; stored issued_at now {h[1]} (kept T2={h[1] == t2})")

# Option 1 (ART-37 cd7c35b9): an unparseable stored row may be replaced only by a binding
# signed by that row's own node_pubkey (= the r5 fallback, core.py:1299-1302), on both paths.
# A replayed A@T0 IS signed by the row's own key, so option 1 cannot tell it from a re-sign.
# R-C1b / R-C1bR / R-C1bRR are therefore EXPECTED-OPEN under option 1 (reported, not asserted);
# This commit carries BW-RC1B (fail-closed both paths), so they are ASSERTED by default;
# BW_FAILCLOSED=0 reproduces the option-1 run (only meaningful against 8f39154's core.py).
BAD = "not-a-timestamp"
FC = os.environ.get("BW_FAILCLOSED", "1") != "0"  # fail-closed (BW-RC1B) is in core.py on this commit

# R-C1b (gossip): gossip A@T0 (<24h, A-signed) over the unparseable row; then A->B@T1 replay.
name = "rc1b"
A, B, R1 = setup("single", name, t_a=20)
raw_issued(name, BAD)
out_imp = gossip(bind(A, name, T(minutes=20)))
mid = holder(name)
out = replay("single", R1, B, name)
h = holder(name)
row("R-C1b", FC, out_imp != "replaced" and mid == (pub(A), BAD) and out != "replaced" and h == (pub(A), BAD),
    (f"" if FC else "EXPECTED-OPEN(opt1) ") + f"gossip A@T0 -> {out_imp} (stored {mid[1]}); replay A->B@T1 -> {out}; "
    f"holder={'A' if h[0] == pub(A) else 'B'} stored={h[1]}")

# R-C1b-route (chair): A's replayed A@T0 POSTed to /names/claim over the unparseable row is refused.
name = "rc1b-r"
A, B, R1 = setup("single", name, t_a=20)
raw_issued(name, BAD)
r1 = C.post("/api/v1/names/claim", data=bind(A, name, T(minutes=20)))
mid = holder(name)
row("R-C1bR", FC, r1.status_code != 200 and mid == (pub(A), BAD),
    (f"" if FC else "EXPECTED-OPEN(opt1) ") + f"route POST replayed A@T0 -> HTTP {r1.status_code}; stored {mid[1]}")

# R-C1b-route-replay: same POST, then A->B@T1 replayed over gossip.
name = "rc1b-rr"
A, B, R1 = setup("single", name, t_a=20)
raw_issued(name, BAD)
r1 = C.post("/api/v1/names/claim", data=bind(A, name, T(minutes=20)))
mid = holder(name)
out = replay("single", R1, B, name)
h = holder(name)
row("R-C1bRR", FC, r1.status_code != 200 and out != "replaced" and h == (pub(A), BAD),
    (f"" if FC else "EXPECTED-OPEN(opt1) ") + f"route POST A@T0 -> HTTP {r1.status_code} (stored {mid[1]}); replay A->B@T1 -> {out}; "
    f"holder={'A' if h[0] == pub(A) else 'B'}")

# R-C1b-heal (gossip / route): owner's fresh A (now) over the unparseable row. Fail-closed
# (default here): REFUSED, row stays bad (runbook clears). Option 1: accepted and healed.
# Either way the A->B@T1 replay afterwards is still refused.
for tag, via in (("G", "gossip"), ("R", "route")):
    name = f"rc1b-heal-{via}"
    A, B, R1 = setup("single", name, t_a=20)
    raw_issued(name, BAD)
    fb = bind(A, name, T(seconds=0))
    o1 = gossip(fb) if via == "gossip" else f"HTTP {C.post('/api/v1/names/claim', data=fb).status_code}"
    s1 = holder(name)
    o2 = replay("single", R1, B, name)
    s2 = holder(name)
    want = (not FC)  # fail-closed build refuses the heal by design
    healed = s1 == (pub(A), fb["issued_at"])
    ok = (healed == want) and o2 != "replaced" and s2[0] == pub(A)
    row(f"R-C1bH{tag}", True, ok,
        f"{via}: fresh A(now) -> {o1} (stored {s1[1]}); replay A->B@T1 -> {o2}; holder={'A' if s2[0] == pub(A) else 'B'}")

# R-C1b-foreign-route: foreign fresh claim on /names/claim over a row whose issued_at AND
# expires_at won't parse (so the :1182 live-foreign guard is skipped and the fallback decides).
name = "rc1b-foreign"
A, X = key(), key()
assert C.post("/api/v1/names/claim", data=bind(A, name, T(minutes=3))).status_code == 200
with core._db_lock, core._db() as conn:
    conn.execute("UPDATE name_bindings SET issued_at=?, expires_at=? WHERE name=?", (BAD, BAD, name))
rX = C.post("/api/v1/names/claim", data=bind(X, name, T(seconds=0)))
h = holder(name)
row("R-C1bFR", True, rX.status_code != 200 and h == (pub(A), BAD),
    f"route: foreign fresh claim over unparseable row -> HTTP {rX.status_code}; holder={'A' if h[0] == pub(A) else 'X'}")

# R-C1c (ruling c): a rotation over an unparseable stored row is refused on every seat,
# even a FRESH A->B record (issued 2s ago) with a fresh B binding (1s ago).
for n, seat in SEATS:
    name = f"rc1c-{seat}"
    A, B = key(), key()
    if seat == "route":
        assert C.post("/api/v1/names/claim", data=bind(A, name, T(minutes=3))).status_code == 200
    else:
        assert gossip(bind(A, name, T(minutes=3))) == "inserted"
    raw_issued(name, BAD)
    R = rec(name, A, B, T(seconds=2))
    fresh = bind(B, name, T(seconds=1))
    if seat == "route": out = f"HTTP {route_rotate(R, fresh).status_code}"
    elif seat == "single": out = gossip(fresh, r=R)
    else: out = gossip(fresh, chain=[R])
    h = holder(name)
    row(f"R-C1c{n}", True, h == (pub(A), BAD),
        f"{seat}: fresh A->B over unparseable row -> {out}; holder={'A' if h[0] == pub(A) else 'B'} stored={h[1]}")

# R-C1b-25h (evidence, not asserted): same as R-C1b but A@T0 is 25h old.
name = "rc1b-25h"
A, B = key(), key()
assert gossip(bind(A, name, T(minutes=5))) == "inserted"
raw_issued(name, "not-a-timestamp")
o1 = gossip(bind(A, name, T(hours=25)))
R1 = rec(name, A, B, T(minutes=3))
o2 = gossip(bind(B, name, T(seconds=1)), r=R1)
row("R-C1b25", True, o1 != "replaced" and holder(name)[1] == "not-a-timestamp",
    f"A@T0(25h) -> {o1}; stored {holder(name)[1]}; A->B -> {o2}")

# R-C2: out of scope (runbook: "re-sign, don't restore"); not executed.
print(f"{'R-C2':6s} {'SCOPE':8s} DB restore -> runbook text \"re-sign, don't restore\"; no code row")

# R-C3: expected-open evidence
name = "rc-lagging"
A, B = key(), key()
gossip(bind(A, name, T(minutes=20)))  # this mirror never saw A->B nor B->A
R1 = rec(name, A, B, T(minutes=10))
out = gossip(bind(B, name, T(seconds=1)), r=R1)
row("R-C3", False, holder(name)[0] == pub(A), f"EXPECTED-OPEN lagging mirror (only A@T0) gets B + A->B@T1 -> {out}")

# ---------------- R-D  cost of N stale records from one sender
N = int(os.environ.get("BW_N", "5"))
for n, seat in SEATS:
    name = f"rd-{seat}"
    A, B, R1 = setup(seat, name)
    before_h, before_c = holder(name), counts(name)
    CNT["rot"] = CNT["bind"] = 0; HOLD.clear()
    t = time.perf_counter()
    for _ in range(N):
        replay(seat, R1, B, name)
    dt = time.perf_counter() - t
    after_h, after_c = holder(name), counts(name)
    bind_w = int(after_h != before_h); rot_w = after_c[0] - before_c[0]; conf_w = after_c[1] - before_c[1]
    ok = CNT["rot"] == 0 and bind_w == 0 and rot_w == 0
    row(f"R-D{n}", True, ok, f"{seat}: N={N} stale replays -> rotation verifies={CNT['rot']} binding verifies={CNT['bind']} "
        f"max lock hold={max(HOLD)*1000:.0f}ms wall={dt:.1f}s writes: bindings={bind_w} rotations={rot_w} conflicts(+audit)={conf_w}")

# R-D4: unanchored 8-hop chain of the attacker's own valid hops against a live foreign incumbent
name = "rd-chain8"
V = key(); gossip(bind(V, name, T(minutes=30)))
ks = [key() for _ in range(9)]
chain = [rec(name, ks[i], ks[i + 1], T(minutes=20 - i)) for i in range(8)]
CNT["rot"] = 0; HOLD.clear()
out = gossip(bind(ks[8], name, T(seconds=1)), chain=chain)
row("R-D4", True, CNT["rot"] == 0 and holder(name)[0] == pub(V),
    f"unanchored 8-hop self chain -> {out}; rotation verifies={CNT['rot']} max lock hold={max(HOLD)*1000:.0f}ms")

# ---------------- R-C1bGC (Examiner 96dbe6a4, ART-37): lazy GC in _name_registry_has_room
# must never delete a frozen (unparseable) row. Seed name N held by A with an unparseable
# stamp, trigger an UNRELATED genuinely-new-name claim (which runs the GC), assert N's row
# is byte-identical, then a foreign key X claims N on the same path: refused, holder A.
# Variants: e = expires_at '2026-02-30T00:00:00Z' only (sorts below now, the live hole);
#           b = issued_at AND expires_at unparseable; i = issued_at unparseable, expires_at
#           parseable and PAST (frozen by _old_binding_beaten's definition, so GC keeps it).
# Positive control R-C1bGCP: parseable expired rows (Z and +00:00 spellings) ARE pruned.
GC_BAD_EXP = "2026-02-30T00:00:00Z"
def fullrow(name):
    with core._db_lock, core._db() as conn:
        x = conn.execute("SELECT name, node_pubkey, issued_at, expires_at, signature "
                         "FROM name_bindings WHERE name=?", (name,)).fetchone()
    return tuple(x) if x else None
def gc_seed(name, A, iss, exp):  # throwaway DB only: claim, then force the stored stamps
    assert C.post("/api/v1/names/claim", data=bind(A, name, T(minutes=3))).status_code == 200
    with core._db_lock, core._db() as conn:
        conn.execute("UPDATE name_bindings SET issued_at=?, expires_at=? WHERE name=?", (iss, exp, name))
    return fullrow(name)
def via_path(via, b):
    if via == "gossip":
        return gossip(b)
    return f"HTTP {C.post('/api/v1/names/claim', data=b).status_code}"
GC_LANDED = ("inserted", "replaced", "HTTP 200")
for tag, via in (("G", "gossip"), ("R", "route")):
    for var, iss_fn, exp in (("e", lambda: T(minutes=3), GC_BAD_EXP),
                             ("b", lambda: BAD, GC_BAD_EXP),
                             ("i", lambda: BAD, T(days=1))):
        name = f"rc1bgc-{var}-{via}"
        A, X, K = key(), key(), key()
        before = gc_seed(name, A, iss_fn(), exp)
        o_new = via_path(via, bind(K, f"gc-unrel-{var}-{via}", T(seconds=0)))
        mid = fullrow(name)
        o_x = via_path(via, bind(X, name, T(seconds=0)))
        after = fullrow(name)
        ok = (o_new in GC_LANDED and mid == before and o_x not in GC_LANDED
              and after == before)
        row(f"R-C1bGC{tag}{var}", True, ok,
            f"{via}: seed A iss={before[2]!r} exp={before[3]!r}; unrelated new claim -> {o_new}; "
            f"row {'byte-identical' if mid == before else 'CHANGED/GONE: ' + repr(mid and mid[1:4])}; "
            f"foreign X claim -> {o_x}; holder="
            f"{'A' if after and after[1] == pub(A) else ('X' if after and after[1] == pub(X) else repr(after))}")
for tag, via in (("G", "gossip"), ("R", "route")):
    names = []
    for sfx in ("Z", "+00:00"):
        name = f"rc1bgcp-{via}-{'z' if sfx == 'Z' else 'p'}"
        exp = (NOW - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S") + sfx
        gc_seed(name, key(), T(days=2), exp)
        names.append(name)
    o_new = via_path(via, bind(key(), f"gcp-unrel-{via}", T(seconds=0)))
    left = [n for n in names if fullrow(n) is not None]
    row(f"R-C1bGCP{tag}", True, o_new in GC_LANDED and not left,
        f"{via}: 2 parseable expired rows (Z, +00:00); unrelated new claim -> {o_new}; survivors={left}")

# ---------------- BW-RP1 (ART-37, Villhaze c707d344; Examiner/chair spec): every node-side seat
# that decides a STORED binding is live uses resolve_cyberspace's predicate (core.py step 4,
# now _binding_stamps_live): both stamps parse, expires_at > now, issued_at <= now, and
# expires - issued <= NAME_EXPIRY_DAYS.  Seed: A claims N, a valid A-signed reach descriptor is
# ingested, then the stored binding's stamps are forced (throwaway DB) to the variant.  Seats:
#   S  serve   GET /names/N/reach              frozen -> 404          live -> 200
#   P  reaper  _reap_expired_reach_descriptors frozen -> row deleted  live -> kept
#   I  ingest  fresh A descriptor              frozen -> not stored   live -> replaced
#   N  names_resolve GET /names/N              frozen -> 404          live -> 200
# Variants: u issued_at unparseable; f issued_at 1h in the future; c lifetime 366d (over cap);
# controls CZ / CP parseable live stamps in 'Z' and '+00:00' spellings.
REACH = [{"kind": "https", "url": "https://bw-rp1.example"}]
_iso_p = lambda d: d.strftime("%Y-%m-%dT%H:%M:%S") + "+00:00"
_cap = core.NAME_EXPIRY_DAYS
RP1_VARIANTS = (
    ("u", True, BAD, EXP),
    ("f", True, iso(NOW + timedelta(hours=1)), EXP),
    ("c", True, T(days=1), iso(NOW - timedelta(days=1) + timedelta(days=_cap + 1))),
    ("CZ", False, T(minutes=3), EXP),
    ("CP", False, _iso_p(NOW - timedelta(minutes=3)), _iso_p(NOW + timedelta(days=30))),
)
def reach_desc(k, name, iss):
    return core._reach_mint(bytes(k).hex(), pub(k), name, REACH, iss, EXP)
def reach_row(name):
    with core._db_lock, core._db() as conn:
        x = conn.execute("SELECT node_pubkey, issued_at FROM reach_descriptors WHERE name=?",
                         (name,)).fetchone()
    return tuple(x) if x else None
def rp1_seed(name, A, iss, exp):
    assert C.post("/api/v1/names/claim", data=bind(A, name, T(minutes=3))).status_code == 200
    o = core.ingest_reach_descriptor(reach_desc(A, name, T(minutes=2)))
    assert o == "inserted", o
    with core._db_lock, core._db() as conn:
        conn.execute("UPDATE name_bindings SET issued_at=?, expires_at=? WHERE name=?", (iss, exp, name))
for var, frozen, iss, exp in RP1_VARIANTS:
    d = f"binding iss={iss!r} exp={exp!r}"
    n = f"rp1-s-{var.lower()}"; A = key(); rp1_seed(n, A, iss, exp)
    st = C.get(f"/api/v1/names/{n}/reach").status_code
    row(f"RP1-S{var}", True, st == (404 if frozen else 200), f"reach serve: {d}; GET reach -> HTTP {st}")
    n = f"rp1-p-{var.lower()}"; A = key(); rp1_seed(n, A, iss, exp)
    with core._db_lock, core._db() as conn:
        reaped = core._reap_expired_reach_descriptors(conn)
    left = reach_row(n)
    row(f"RP1-P{var}", True, (left is None) == frozen,
        f"reaper: {d}; reaped={reaped}; descriptor {'gone' if left is None else 'kept'}")
    n = f"rp1-i-{var.lower()}"; A = key(); rp1_seed(n, A, iss, exp)
    o = core.ingest_reach_descriptor(reach_desc(A, n, T(seconds=0)))
    left = reach_row(n)
    row(f"RP1-I{var}", True,
        (o not in ("inserted", "replaced") and left is None) if frozen else (o == "replaced"),
        f"reach ingest: {d}; fresh A descriptor -> {o}; stored={'none' if left is None else 'yes'}")
    n = f"rp1-n-{var.lower()}"; A = key(); rp1_seed(n, A, iss, exp)
    st = C.get(f"/api/v1/names/{n}").status_code
    row(f"RP1-N{var}", True, st == (404 if frozen else 200), f"names_resolve: {d}; GET name -> HTTP {st}")

fails = [r for r, a, ok in RESULTS if a and not ok]
print("---\nSUMMARY: %d asserted rows, %d failed%s" % (sum(1 for _, a, _ in RESULTS if a), len(fails),
      (": " + " ".join(fails)) if fails else ""))
sys.exit(1 if fails else 0)
