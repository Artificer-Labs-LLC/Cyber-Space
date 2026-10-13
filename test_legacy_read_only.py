#!/usr/bin/env python3
"""READ deploy (oracle/legacy-log-read-only, off 7b15ca9).

(1) app mounts exactly GET /api/v1/legacy-log/head and /proof of the legacy
routes; (2) neither GET calls weak_reason / is_weak or verifies a signature;
(3) a burst of /proof on a large log finishes within a stated limit and
neither blocks the event loop nor holds the DB; (4) /head is a Genesis-only
signed head marked unwitnessed, with no cosign/threshold fields, and node
B refuses it. Each mutant is killed by a row here."""
import os
import tempfile
import threading
import time

os.environ["CYBERNET_DB_DIR"] = tempfile.mkdtemp(prefix="legacy-read-")
os.environ.pop("CYBERNET_GENESIS_WITNESSES", None)

import core  # noqa: E402
core.init_db()
import app as appmod  # noqa: E402
import legacy_witness as lw  # noqa: E402
import routes_legacy_witness as rlw  # noqa: E402
import window_open as wo  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

PASS = FAIL = 0
MUT = []


def check(label, cond, extra=""):
    global PASS, FAIL
    PASS += bool(cond)
    FAIL += not cond
    print(f"  {'ok ' if cond else 'FAIL'} {label}" + ("" if cond else f" {extra}"))


def mutant(name, row, real_ok, mf):
    MUT.append((name, row, real_ok, mf))
    check(f"MUTANT {name}: real passes and mutant fails the row", real_ok and mf, (real_ok, mf))


def flat(routes):
    for r in routes:
        sub = getattr(r, "original_router", None)
        if sub is not None:
            yield from flat(sub.routes)
        else:
            yield r


def legacy_paths(app):
    return sorted((m, r.path) for r in flat(app.routes) if getattr(r, "path", "").startswith(
        ("/api/v1/legacy-log", "/api/v1/agents/import-legacy")) for m in getattr(r, "methods", []))


WANT = [("GET", "/api/v1/legacy-log/head"), ("GET", "/api/v1/legacy-log/proof")]
real_rt = legacy_paths(appmod.app) == WANT
check("(routes) app mounts exactly GET /legacy-log/head and GET /legacy-log/proof", real_rt,
      legacy_paths(appmod.app))
m_app = FastAPI()
m_app.include_router(rlw.router)
m_app.add_api_route("/api/v1/agents/import-legacy", rlw.import_legacy, methods=["POST"])
mutant("re-add /agents/import-legacy", "(routes) exactly the two GETs", real_rt,
       legacy_paths(m_app) != WANT)

# ---------------------------------------------------------------- a large log
N = 3000
with core._db_lock, core._db() as conn:
    wo.init_schema(conn)
    for i in range(N):
        wo.append_log_entry(conn, kind="hold", account=f"acct-{i}", name=f"n{i}",
                            detail={"name": f"n{i}"})
client = TestClient(appmod.app, client=("198.51.100.7", 40000))


@appmod.app.get("/__loop_probe")
async def _loop_probe():
    return {"ok": True}

# ---------------------------------------------------------------- (2) no weak_reason / verify on GET
import hop_certs  # noqa: E402
from fed import ed25519 as _ed  # noqa: E402

SPIES = [(wo, "weak_reason"), (wo, "is_weak_pubkey"), (lw, "_sig_ok"), (lw, "verify_head"),
         (_ed, "checkvalid"), (hop_certs, "verify_sig")]
calls = {"n": 0}


def with_spies(fn):
    saved = []
    for mod, attr in SPIES:
        if not hasattr(mod, attr):
            continue
        real = getattr(mod, attr)

        def spy(*a, _r=real, **k):
            calls["n"] += 1
            return _r(*a, **k)
        saved.append((mod, attr, real))
        setattr(mod, attr, spy)
    calls["n"] = 0
    try:
        fn()
    finally:
        for mod, attr, real in saved:
            setattr(mod, attr, real)
    return calls["n"]


def get_both():
    rlw._view_cache.clear()
    assert client.get("/api/v1/legacy-log/head").status_code == 200
    assert client.get("/api/v1/legacy-log/proof", params={"name": "n7"}).status_code == 200


n_real = with_spies(get_both)
check("(no-verify) GET /head and /proof: weak_reason/is_weak/signature-verify calls == 0", n_real == 0, n_real)
real_view = rlw._signed_view


def verifying_view(name):
    body = real_view(name)
    if body:
        lw.verify_head(body["head"], lw.WitnessSet(1, [core._NODE_PUB.lower()]), body["head"]["head"]["log_id"])
        wo.weak_reason(core._NODE_PUB.lower())
    return body


rlw._signed_view = verifying_view
try:
    n_mut = with_spies(get_both)
finally:
    rlw._signed_view = real_view
mutant("verify the head / weak_reason on the GET path", "(no-verify) call counter == 0", n_real == 0, n_mut > 0)

# ---------------------------------------------------------------- (3) burst: lock hold
class TimedLock:
    def __init__(self, real):
        self.real, self.held, self.t = real, 0.0, None

    def acquire(self, *a, **k):
        ok = self.real.acquire(*a, **k)
        if ok:
            self.t = time.perf_counter()
        return ok

    def release(self):
        self.held += time.perf_counter() - self.t
        self.real.release()

    def locked(self):
        return self.real.locked()

    __enter__ = acquire

    def __exit__(self, *exc):
        self.release()


LIMIT_S = 30.0
import httpx  # noqa: E402
import socket  # noqa: E402
import uvicorn  # noqa: E402

os.environ.setdefault("CYBERNET_RATE_LIMIT", "100000")
rlw.PROOF_PER_IP, rlw.PROOF_GLOBAL = 10 ** 6, 10 ** 7
_s = socket.socket()
_s.bind(("127.0.0.1", 0))
PORT = _s.getsockname()[1]
_s.close()
BASE = f"http://127.0.0.1:{PORT}"
_server = uvicorn.Server(uvicorn.Config(appmod.app, host="127.0.0.1", port=PORT, log_level="error"))
threading.Thread(target=_server.run, daemon=True).start()
for _ in range(400):
    if _server.started:
        break
    time.sleep(0.05)


def burst(n=64):
    rlw._view_cache.clear()
    real_lock = core._db_lock
    tl = TimedLock(real_lock)
    core._db_lock = tl
    waits, stop, codes = [], threading.Event(), []

    def writer():
        while not stop.is_set():
            t = time.perf_counter()
            with core._db_lock:
                pass
            waits.append(time.perf_counter() - t)
            time.sleep(0.01)

    def one(i):
        r = httpx.get(f"{BASE}/api/v1/legacy-log/proof", params={"name": f"n{i % 4}"},
                      headers={"X-Probe": str(i)}, timeout=120)
        codes.append(r.status_code)
    w = threading.Thread(target=writer)
    w.start()
    ts = [threading.Thread(target=one, args=(i,)) for i in range(n)]
    t0 = time.perf_counter()
    for t in ts:
        t.start()
    time.sleep(0.2)
    h0 = time.perf_counter()
    hr = httpx.get(f"{BASE}/__loop_probe", timeout=30)
    head_s = time.perf_counter() - h0
    for t in ts:
        t.join()
    total = time.perf_counter() - t0
    stop.set()
    w.join()
    core._db_lock = real_lock
    held = tl.held                          # includes the writer's own (empty) holds
    return {"total": total, "head_s": head_s, "codes": set(codes), "hcode": hr.status_code,
            "held": held, "max_wait": max(waits) if waits else 0.0}


B = burst()
real_lk = B["held"] < 1.0 and B["max_wait"] <= 0.25 and B["total"] <= 60.0
check(f"(burst) 64 concurrent /proof on the {N}-entry fixture finish within {LIMIT_S:.0f} s, all 200",
      B["total"] <= LIMIT_S and B["codes"] == {200}, B)
check("(burst) a concurrent GET on another route answers in < 1 s (event loop not blocked)",
      B["head_s"] < 1.0 and B["hcode"] == 200, B["head_s"])
check("(burst) total core._db_lock hold < 1 s in the (sub-60 s) window; a concurrent write waits <= 250 ms",
      real_lk, (B["held"], B["max_wait"]))


def walk_inside_lock(name):
    with core._db_lock, core._db() as conn:
        log_id, entries = wo.export_log(conn)
        if not entries:
            return None
        if name is not None and not any(e["kind"] == "hold" and e.get("name") == name for e in entries):
            return None
        pub = core._NODE_PUB.lower()
        o, c, state = rlw._window_fields(entries)
        head = {"log_id": log_id, "witness_set": lw.WitnessSet(1, [pub]).id, "seq": len(entries),
                "head_hash": entries[-1]["entry_hash"], "window_open_seq": o,
                "window_close_seq": c, "window_state": state, **wo.head_roots(conn)}
        signed = lw.sign_head(head, [lambda m: (pub, _ed.sign(m, bytes.fromhex(core._NODE_PRIV),
                                                               bytes.fromhex(pub)).hex())])
        return {"head": signed, "span": [lw.full(e) for e in entries],
                "hops": wo.export_hop_rows(conn), "bound": wo.export_bound_leaves(conn)}


rlw._signed_view = walk_inside_lock
try:
    MB = burst()
finally:
    rlw._signed_view = real_view
mutant("move the proof walk inside the DB lock", "(burst) lock hold < 1 s / write wait <= 250 ms",
       real_lk, not (MB["held"] < 1.0 and MB["max_wait"] <= 0.25))

# ---------------------------------------------------------------- (3b) Bulwark single-flight row
# Cold cache, 64 concurrent GETs split across /head and /proof: exactly 1
# build and 1 sign call, readers hold core._db_lock ~0 s, a concurrent
# write waits <= 250 ms. /__loop_probe above stays as an extra check.
class ReaderTimedLock(TimedLock):
    """Times holds by every thread except the writer thread."""
    def __init__(self, real, writer_ident):
        super().__init__(real)
        self.writer, self.reader_held, self.reader_acq, self._mine = writer_ident, 0.0, 0, False

    def acquire(self, *a, **k):
        ok = self.real.acquire(*a, **k)
        if ok:
            self.t = time.perf_counter()
            self._mine = threading.get_ident() != self.writer[0]
            if self._mine:
                self.reader_acq += 1
        return ok

    def release(self):
        if self._mine:
            self.reader_held += time.perf_counter() - self.t
        self.real.release()

    __enter__ = acquire

    def __exit__(self, *exc):
        self.release()


def sf_burst(n=64):
    rlw._view_cache.clear()
    cnt = {"build": 0, "sign": 0}
    real_build, real_sign = rlw._build, rlw._ed.sign

    def counting_build(top):
        cnt["build"] += 1
        return real_build(top)

    def counting_sign(*a, **k):
        cnt["sign"] += 1
        return real_sign(*a, **k)
    rlw._build, rlw._ed.sign = counting_build, counting_sign
    real_lock = core._db_lock
    wid = [None]
    tl = ReaderTimedLock(real_lock, wid)
    core._db_lock = tl
    waits, stop, codes, started = [], threading.Event(), [], threading.Event()

    def writer():
        wid[0] = threading.get_ident()
        started.set()
        while not stop.is_set():
            t = time.perf_counter()
            with core._db_lock:
                pass
            waits.append(time.perf_counter() - t)
            time.sleep(0.01)

    def one(i):
        if i % 2:
            r = httpx.get(f"{BASE}/api/v1/legacy-log/proof", params={"name": f"n{i % 4}"}, timeout=120)
        else:
            r = httpx.get(f"{BASE}/api/v1/legacy-log/head", timeout=120)
        codes.append(r.status_code)
    try:
        w = threading.Thread(target=writer)
        w.start()
        started.wait(5)
        go = threading.Barrier(n)
        ts = [threading.Thread(target=lambda i=i: (go.wait(), one(i))) for i in range(n)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        stop.set()
        w.join()
    finally:
        core._db_lock = real_lock
        rlw._build, rlw._ed.sign = real_build, real_sign
    return {"build": cnt["build"], "sign": cnt["sign"], "codes": sorted(set(codes)), "n": len(codes),
            "reader_held": tl.reader_held, "reader_acq": tl.reader_acq,
            "max_wait": max(waits) if waits else 0.0}


def sf_ok(r):
    return (r["build"] == 1 and r["sign"] == 1 and r["codes"] == [200] and r["n"] == 64
            and r["reader_held"] < 0.01 and r["max_wait"] <= 0.25)


SF = sf_burst()
real_sf = sf_ok(SF)
check("(burst-sf) cold cache, 64 concurrent GET /head + /proof: exactly 1 build, 1 sign, "
      "readers hold core._db_lock ~0 s (<10 ms), a write waits <= 250 ms", real_sf, SF)


async def _view_no_single_flight(name):
    """MUTANT: every cache miss starts its own build (no asyncio lock, no _view_lock)."""
    from starlette.concurrency import run_in_threadpool
    top = await run_in_threadpool(rlw._top_seq)
    built = rlw._view_cache.get(top)
    if built is None:
        built = await run_in_threadpool(rlw._build, top)
        if built is None:
            return None
        rlw._view_cache[top] = built
    holds, body = built
    return None if (name is not None and name not in holds) else body


real_v = rlw._view
rlw._view = _view_no_single_flight
try:
    SFM1 = sf_burst()
finally:
    rlw._view = real_v
mutant("drop single-flight (build count > 1)", "(burst-sf) 1 build / 1 sign",
       real_sf, SFM1["build"] > 1 and not sf_ok(SFM1))

real_b = rlw._build


def build_inside_lock(top):
    with core._db_lock:
        return real_b(top)


rlw._build = build_inside_lock
try:
    SFM2 = sf_burst()
finally:
    rlw._build = real_b
mutant("build inside core._db_lock", "(burst-sf) readers hold lock ~0 s / write waits <= 250 ms",
       real_sf, not sf_ok(SFM2))
print("  burst-sf real:", SF)
print("  burst-sf mutant no-single-flight:", SFM1)
print("  burst-sf mutant build-in-lock:", SFM2)

# ---------------------------------------------------------------- (4) unwitnessed head
r = client.get("/api/v1/legacy-log/head").json()
real_uw = (set(r) == {"head", "signatures", "witnessed", "status"} and r["witnessed"] is False
           and r["status"] == "unwitnessed" and len(r["signatures"]) == 1
           and r["signatures"][0]["witness"] == core._NODE_PUB.lower()
           and not any(k in r for k in ("cosign", "cosigns", "threshold", "fragments")))
check("(head) /head is Genesis-only signed, marked unwitnessed, no cosign/threshold fields", real_uw, r)


def with_fragment(signed):
    out = rlw.__dict__["_real_unwitnessed"](signed)
    out["cosign"] = {"witness": "aa" * 32, "sig": "bb" * 64}
    return out


rlw._real_unwitnessed = rlw.unwitnessed_head
rlw.unwitnessed_head = with_fragment
try:
    rm = client.get("/api/v1/legacy-log/head").json()
finally:
    rlw.unwitnessed_head = rlw._real_unwitnessed
mutant("include a single-witness fragment in /head", "(head) no cosign/threshold fields", real_uw,
       "cosign" in rm)
W3 = [_ed.publickey(bytes([0x40 + i]) * 32).hex() for i in range(3)]
try:
    lw.verify_head({"head": r["head"], "signatures": r["signatures"]}, lw.WitnessSet(2, W3),
                   r["head"]["log_id"])
    b_ok = True
except lw.WitnessRefused:
    b_ok = False
check("(head) node B (pinned 2-of-3) refuses the head: no threshold cosign", not b_ok)

pr = client.get("/api/v1/legacy-log/proof", params={"name": "n3"}).json()
real_pf = (set(pr) == {"head", "span", "hops", "bound", "witnessed", "status"}
           and pr["witnessed"] is False and pr["head"]["witnessed"] is False
           and not any(k in pr["head"] for k in ("cosign", "cosigns", "threshold", "fragments")))
check("(proof) /proof is marked unwitnessed, head included, no cosign/threshold fields", real_pf, list(pr))
nf = client.get("/api/v1/legacy-log/proof", params={"name": "nosuch"})
check("(proof) 404 detail does not say 'witnessed'",
      nf.status_code == 404 and "witnessed" not in nf.json()["detail"].lower(), nf.text)
real_up = rlw.unwitnessed_proof
rlw.unwitnessed_proof = lambda body: body
try:
    mp = client.get("/api/v1/legacy-log/proof", params={"name": "n3"}).json()
finally:
    rlw.unwitnessed_proof = real_up
mutant("/proof returns the unfiltered _signed_view body", "(proof) marked unwitnessed", real_pf,
       mp.get("witnessed") is not False)

print("mutant table:")
print("  mutant | row | real passes | mutant fails | killed")
for n, rr, ok, mf in MUT:
    print(f"  {n} | {rr} | {ok} | {mf} | {'KILLED' if ok and mf else 'NOT KILLED'}")
print(f"legacy_read_only: {PASS} passed, {FAIL} failed")
raise SystemExit(1 if FAIL else 0)
