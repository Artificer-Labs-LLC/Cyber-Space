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
     R-C1b stored A row with UNPARSEABLE issued_at (expires_at fine) -> reaches the
           fix-1/4 fallback in _old_binding_beaten (3df1395): same key always beats.
           Gossip A@T0, then replay old A->B@T1 with a fresh B binding.
           ASSERT replay refused and A keeps the name.
     R-C2  DB restore of an old row: OUT OF SCOPE for code rows. Runbook text:
           "re-sign, don't restore" (after a restore the owner re-signs a fresh
           binding before re-federating). Not executed.
     R-C3  lagging mirror that only ever saw A@T0 receives B + A->B@T1.
           EXPECTED-OPEN evidence row (REPORTED, not asserted).
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

# R-C1b: stored A row with unparseable issued_at; gossip A@T0; replay A->B@T1 + fresh B
name = "rc1b"
A, B, R1 = setup("single", name, t_a=20)
raw_issued(name, "not-a-timestamp")
out_imp = gossip(bind(A, name, T(minutes=20)))
mid = holder(name)
out = replay("single", R1, B, name)
h = holder(name)[0]
row("R-C1b", True, h == pub(A) and out != "replaced",
    f"stored A issued_at unparseable; gossip A@T0 -> {out_imp} (stored now {mid[1]}); "
    f"replay A->B@T1 -> {out}; holder={'A' if h == pub(A) else 'B'}")

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

fails = [r for r, a, ok in RESULTS if a and not ok]
print("---\nSUMMARY: %d asserted rows, %d failed%s" % (sum(1 for _, a, _ in RESULTS if a), len(fails),
      (": " + " ".join(fails)) if fails else ""))
sys.exit(1 if fails else 0)
