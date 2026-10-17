#!/usr/bin/env python3
"""ART-42 wiring cut: legacy_log_observe through head_level (locked in the
Research Board room; Bulwark 8360b0c8 items 1-4 folded in per Villhaze
ART-42 4fb5eb94). Every row has at least one named mutant it kills; a kill
is the named row failing its own assertion (exceptions are ERROR)."""
import hashlib, os, sqlite3, sys, tempfile, time
from unittest import mock

os.environ["CYBERNET_DB_DIR"] = tempfile.mkdtemp(prefix="wok-wiring-")
os.environ["CYBERNET_NAME_CLAIM_RATE_LIMIT"] = "10000"
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from nacl.signing import SigningKey  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import core  # noqa: E402
core.init_db()
import app as appmod  # noqa: E402
import head_level as hl  # noqa: E402
import legacy_level_wiring as wiring  # noqa: E402
import legacy_witness as lw  # noqa: E402
import routes_legacy_witness as rlw  # noqa: E402
import window_open  # noqa: E402
import wok_merkle as wm  # noqa: E402
from fed import ed25519 as _ed  # noqa: E402

T0 = time.time()
G = SigningKey(hashlib.sha256(b"wiring-genesis").digest())
GPUB = G.verify_key.encode().hex()
LIDB = hl.log_id_of(GPUB); LOG = LIDB.hex()
WK = [SigningKey(hashlib.sha256(b"wiring-witness-%d" % i).digest()) for i in range(3)]
WP = [k.verify_key.encode().hex() for k in WK]
WSET = lw.WitnessSet(2, WP)
ZR = "00" * 32
sig_ok = lw.checkvalid_ok


def legacy(seq, root, signers=(0, 1)):
    h = {"log_id": LOG, "witness_set": WSET.id, "seq": seq, "head_hash": root.hex(),
         "window_open_seq": None, "window_close_seq": None, "window_state": "unopened",
         **{k: ZR for k in lw.HEAD_ROOT_FIELDS}}
    return lw.sign_head(h, [lambda m, k=WK[i]: (k.verify_key.encode().hex(), k.sign(m).signature.hex())
                            for i in signers])


def level(size, root, prev=(0, hl.ZERO32), proof=(), cosigns=None, issued=1_700_000_000):
    b = hl.pack_head(0, LIDB, size, root, prev[0], prev[1], hl.ZERO32, issued)
    return {"blob": b.hex(), "genesis_sig": G.sign(b).signature.hex(),
            "cosigns": [] if cosigns is None else cosigns, "consistency": [p.hex() for p in proof]}


def db():
    c = sqlite3.connect(":memory:", isolation_level=None)   # autocommit: no rollback hides a write
    wiring.init_schema(c)
    return c


def obs(conn, signed, lv):
    return wiring.observe(conn, wiring.verify_legacy(signed, WSET, LOG, sig_ok), lv, GPUB, None, sig_ok)


def snap(conn):
    t = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
    return tuple((n, tuple(sorted(map(tuple, conn.execute(f"SELECT * FROM {n}").fetchall())))) for n in t)


def typed(cls, fn):
    try: fn(); return False
    except Exception as e: return isinstance(e, cls)


def count(conn, table, where="1=1", args=()):
    return conn.execute(f"SELECT COUNT(*) FROM {table} WHERE {where}", args).fetchone()[0]


A = wm.leaves("a", 16)
B = wm.leaves("b", 16, share=2)          # forks after the first 2 leaves
C = wm.leaves("c", 16, share=2)
R = lambda L, n: wm.mth(L[:n])           # noqa: E731


def root_head(L, n, **kw):
    return legacy(n, R(L, n)), level(n, R(L, n), **kw)


def next_head(L, m, n, proof=None):
    return legacy(n, R(L, n)), level(n, R(L, n), prev=(m, R(L, m)),
                                      proof=wm.proof(m, L[:n]) if proof is None else proof)


# ------------------------------------------------------------------ rows

def row_gate():
    # Bulwark gate row: a DuplicateCosign / MalformedCosign encoding of a head,
    # then the clean encoding of the same head (another source). The clean
    # one is stored; refused bytes leave no observed row, no contested row,
    # no write of any kind. Then the same for a second head at the same seq.
    c = db(); s0 = snap(c)
    sa, la = root_head(A, 4)
    dup = dict(la, cosigns=[{"pub": WP[0], "sig": "00" * 64}, {"pub": WP[0], "sig": "11" * 64}])
    mal = dict(la, cosigns=["x"])
    if not (typed(hl.DuplicateCosign, lambda: obs(c, sa, dup)) and typed(hl.MalformedCosign, lambda: obs(c, sa, mal))
            and snap(c) == s0):
        return False
    try: ok = obs(c, sa, la)["status"] == "observed"
    except Exception: return False
    ok = ok and count(c, "legacy_observed_heads") == 1 and count(c, "legacy_level_marks") == 1
    s1 = snap(c)
    sb, lb = root_head(B, 4)
    ok = ok and typed(hl.DuplicateCosign, lambda: obs(c, sb, dict(lb, cosigns=[{"pub": WP[1], "sig": "00" * 64}] * 2)))
    ok = ok and typed(hl.MalformedCosign, lambda: obs(c, sb, dict(lb, cosigns=[{"pub": 1, "sig": "00"}])))
    return ok and snap(c) == s1 and count(c, "legacy_contested_heads") == 0


def row_mapping():
    # Lodestar mapping row: stored seq == head_level tree_size; the observed
    # (seq, head_hash) is the (tree_size, root) mark. Mismatch either way is
    # MappingMismatch with nothing written.
    c = db(); s0 = snap(c)
    sa = legacy(4, R(A, 4))
    if not (typed(wiring.MappingMismatch, lambda: obs(c, sa, level(5, R(A, 4))))
            and typed(wiring.MappingMismatch, lambda: obs(c, sa, level(4, R(B, 4))))
            and snap(c) == s0):
        return False
    try: obs(c, sa, level(4, R(A, 4)))
    except Exception: return False
    o = c.execute("SELECT seq, head_hash FROM legacy_observed_heads").fetchall()
    m = [(x.size, x.root.hex()) for x in wiring.proven_marks(c, LOG, GPUB, None, sig_ok)]
    return o == [(4, R(A, 4).hex())] and m == [(4, R(A, 4).hex())] and o == m


def row_seeding():
    # Lodestar seeding rows: no mark, an observed row at seq N (a pre-cut
    # hint); a head at N+1 claiming prev (N, head_hash) with a valid proof
    # raises FirstContactRefused and writes nothing. Marks stay [].
    c = db()
    c.execute("INSERT INTO legacy_observed_heads VALUES (?,?,?,?)", (LOG, 4, R(A, 4).hex(), 1))
    s0 = snap(c)
    s5, l5 = next_head(A, 4, 5)
    return (typed(hl.FirstContactRefused, lambda: obs(c, s5, l5)) and snap(c) == s0
            and wiring.proven_marks(c, LOG, GPUB, None, sig_ok) == [])


def row_rule3():
    # Bulwark rule 3: a mark comes only from a root-verified head or a
    # consistency proof from a proven mark. Bad/empty/foreign proofs, a root
    # head with a proof, a root restart over an existing mark, and a chain
    # from a non-latest mark are all refused with nothing written.
    c = db()
    try:
        obs(c, *root_head(A, 4))
        obs(c, *next_head(A, 4, 7))
    except Exception: return False
    kinds = [r[0] for r in c.execute("SELECT proof_kind FROM legacy_level_marks ORDER BY tree_size")]
    marks = [(m.size, m.root) for m in wiring.proven_marks(c, LOG, GPUB, None, sig_ok)]
    if kinds != ["root", "consistency"] or marks != [(4, R(A, 4)), (7, R(A, 7))]:
        return False
    s0 = snap(c)
    p = wm.proof(7, A[:9]); tam = [bytes([p[0][0] ^ 1]) + p[0][1:]] + p[1:]
    bad = [tam, [], wm.proof(7, B[:9])]
    ok = all(typed(hl.ConsistencyRefused, lambda q=q: obs(c, *next_head(A, 7, 9, proof=q))) for q in bad)
    ok = ok and typed(hl.ConsistencyRefused, lambda: obs(c, legacy(9, R(A, 9)), level(9, R(A, 9), proof=[R(A, 1)])))
    ok = ok and typed(wiring.NotFromLatestMark, lambda: obs(c, *root_head(A, 9)))
    ok = ok and typed(wiring.NotFromLatestMark, lambda: obs(c, *next_head(A, 4, 9)))
    return ok and snap(c) == s0


def row_fork():
    # Fork row (Loom/Bulwark; Bulwark 8360b0c8 item 2): two threshold heads
    # at one (log_id, seq) with different head_hash -> exactly one contested
    # record, an empty mark, no second observed row; the log stays contested
    # (replays and third heads refused, still one record). Root-head fork and
    # a fork that chains from a shared proven mark.
    for pre in (False, True):
        c = db()
        try:
            if pre:
                obs(c, *root_head(A, 2))
                obs(c, *next_head(A, 2, 4))
                r = obs(c, *next_head(B, 2, 4))
            else:
                obs(c, *root_head(A, 4))
                r = obs(c, *root_head(B, 4))
        except Exception: return False
        if r["status"] != "contested": return False
        s1 = snap(c)
        again = (typed(wiring.LogContested, lambda: obs(c, *(next_head(B, 2, 4) if pre else root_head(B, 4))))
                 and typed(wiring.LogContested, lambda: obs(c, *(next_head(C, 2, 4) if pre else root_head(C, 4)))))
        if not (again and snap(c) == s1 and count(c, "legacy_contested_heads") == 1
                and count(c, "legacy_level_marks") == 0
                and wiring.proven_marks(c, LOG, GPUB, None, sig_ok) == []
                and [x[0] for x in c.execute("SELECT head_hash FROM legacy_observed_heads WHERE seq=4")] == [R(A, 4).hex()]):
            return False
    return True


def row_stale():
    # Bulwark 8360b0c8 item 2: a head with seq below the latest mark is
    # StaleHead (also a replay of an older head), nothing written.
    c = db()
    try:
        obs(c, *root_head(A, 4)); obs(c, *next_head(A, 4, 7))
    except Exception: return False
    s0 = snap(c)
    return (typed(wiring.StaleHead, lambda: obs(c, *next_head(A, 4, 5)))
            and typed(wiring.StaleHead, lambda: obs(c, *root_head(A, 4))) and snap(c) == s0
            and obs(c, *next_head(A, 4, 7))["status"] == "already-observed" and snap(c) == s0)


SEEN_BLOBS = []
_CH = hl.cheap_head
def _spy_cheap(blob, *a, **k):
    SEEN_BLOBS.append(blob); return _CH(blob, *a, **k)


def row_examiner():
    # Examiner row: a mark not built from a root proof is refused before
    # cheap_head runs on the new head. Forged rows go straight into the mark
    # table (a forged (999999, ...), a non-root lowest row, a consistency row
    # with a bogus proof, a stored (size, root) that differs from its head):
    # MarkNotRootProven, and the incoming head's blob never reaches cheap_head.
    def forged_db(kind):
        c = db()
        if kind == "huge":
            lv = level(999999, R(A, 4))
            c.execute("INSERT INTO legacy_level_marks VALUES (?,?,?,?,?,?,?,?,?)",
                      (LOG, 999999, R(A, 4).hex(), "root", "00", "00" * 64, "[]", "[]", 1))
            return c, (999999, R(A, 4))
        if kind == "nonroot":
            lv = level(4, R(A, 4), prev=(2, R(A, 2)), proof=wm.proof(2, A[:4]))
            c.execute("INSERT INTO legacy_level_marks VALUES (?,?,?,?,?,?,?,?,?)",
                      (LOG, 4, R(A, 4).hex(), "consistency", lv["blob"], lv["genesis_sig"], "[]",
                       '["%s"]' % lv["consistency"][0], 1))
            return c, (4, R(A, 4))
        obs(c, *root_head(A, 2))
        if kind == "badproof":
            lv = level(4, R(A, 4), prev=(2, R(A, 2)))
            c.execute("INSERT INTO legacy_level_marks VALUES (?,?,?,?,?,?,?,?,?)",
                      (LOG, 4, R(A, 4).hex(), "consistency", lv["blob"], lv["genesis_sig"], "[]",
                       '["%s"]' % ("11" * 32), 1))
            return c, (4, R(A, 4))
        lv = level(4, R(A, 4), prev=(2, R(A, 2)), proof=wm.proof(2, A[:4]))       # "differs"
        c.execute("INSERT INTO legacy_level_marks VALUES (?,?,?,?,?,?,?,?,?)",
                  (LOG, 4, R(B, 4).hex(), "consistency", lv["blob"], lv["genesis_sig"], "[]",
                   '[%s]' % ",".join('"%s"' % x for x in lv["consistency"]), 1))
        return c, (4, R(B, 4))
    ok = True
    with mock.patch.object(hl, "cheap_head", _spy_cheap):
        for kind in ("huge", "nonroot", "badproof", "differs"):
            c, (sz, rt) = forged_db(kind); s0 = snap(c)
            n = sz + 1 if sz < 999999 else 1000000
            L = A if rt == R(A, sz) or kind == "huge" else B
            lv = level(n, R(A, n) if n <= 16 else R(A, 5), prev=(sz, rt), proof=[])
            sh = legacy(n, bytes.fromhex(lv["blob"])[-153:][41:73] if False else (R(A, n) if n <= 16 else R(A, 5)))
            del SEEN_BLOBS[:]
            ok = ok and typed(wiring.MarkNotRootProven, lambda: obs(c, sh, lv)) and snap(c) == s0 \
                and bytes.fromhex(lv["blob"]) not in SEEN_BLOBS
    # control: a real chain passes and the new head does reach cheap_head
    c = db()
    try:
        with mock.patch.object(hl, "cheap_head", _spy_cheap):
            obs(c, *root_head(A, 2)); del SEEN_BLOBS[:]
            s4, l4 = next_head(A, 2, 4); obs(c, s4, l4)
    except Exception: return False
    return ok and bytes.fromhex(l4["blob"]) in SEEN_BLOBS


# ---- item 1: request-path cost (route) ----------------------------------
os.environ.update({"CYBERNET_GENESIS_WITNESSES": ",".join(WP), "CYBERNET_GENESIS_LOG_ID": LOG,
                   "CYBERNET_GENESIS_WITNESS_THRESHOLD": "2", "CYBERNET_GENESIS_NODE_PUB": GPUB})
IPN = [0]
def client():
    IPN[0] += 1
    return TestClient(appmod.app, client=("198.51.100.%d" % (IPN[0] % 250 + 1), 40000))
WEAK, VERIFIES = [0], [0]
_wr, _cv = window_open.weak_reason, _ed.checkvalid
def _count_weak(*a, **k): WEAK[0] += 1; return _wr(*a, **k)
def _count_cv(*a, **k): VERIFIES[0] += 1; return _cv(*a, **k)
def reset_route_db():
    with core._db_lock, core._db() as conn:
        wiring.init_schema(conn)
        for t in ("legacy_observed_heads", "legacy_level_marks", "legacy_contested_heads"):
            conn.execute(f"DELETE FROM {t}")
    core._hits.clear() if hasattr(core, "_hits") else None
def route_rows():
    with core._db_lock, core._db() as conn:
        return sum(conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
                   for t in ("legacy_observed_heads", "legacy_level_marks", "legacy_contested_heads"))
def post(body):
    rlw.pinned(); rlw.genesis_level_pub()         # pin loaded (and weak-checked) before counting
    WEAK[0] = VERIFIES[0] = 0
    with mock.patch.object(window_open, "weak_reason", _count_weak), mock.patch.object(_ed, "checkvalid", _count_cv):
        t = time.time(); r = client().post("/api/v1/legacy-log/observe", json=body); dt = time.time() - t
    return r, dt


def row_cost_oversize():
    # Bulwark 8360b0c8 item 1: a valid 2-of-3 plus 400 junk entries (was 25.4 s
    # and 200) is refused before any verify: 0 verifies, 0 weak_reason calls,
    # no row, well under a second.
    reset_route_db()
    sa, la = root_head(A, 4)
    junk = [{"witness": hashlib.sha256(b"j%d" % i).hexdigest(), "sig": "00" * 64} for i in range(400)]
    r, dt = post({"head": dict(sa, signatures=sa["signatures"] + junk), "level": la})
    return r.status_code == 400 and WEAK[0] == 0 and VERIFIES[0] == 0 and dt < 1.0 and route_rows() == 0


def row_cost_unpinned():
    # item 1(b): a valid 2-of-3 plus N unpinned entries (N=1, under the cap)
    # is UnpinnedWitness with 0 weak_reason calls and 0 verifies; the clean
    # head then goes through (control).
    reset_route_db()
    sa, la = root_head(A, 4)
    extra = [{"witness": hashlib.sha256(b"u").hexdigest(), "sig": "00" * 64}]
    r, _ = post({"head": dict(sa, signatures=sa["signatures"] + extra), "level": la})
    ok = r.status_code == 400 and "UnpinnedWitness" in r.text and WEAK[0] == 0 and VERIFIES[0] == 0 and route_rows() == 0
    r2, _ = post({"head": sa, "level": la})
    return ok and r2.status_code == 200 and r2.json().get("status") == "observed" and WEAK[0] == 0


def row_cost_dup_witness():
    # item 1(b): a duplicate witness is DuplicateWitness, 0 verifies, 0
    # weak_reason calls.
    reset_route_db()
    sa, la = root_head(A, 4)
    d = dict(sa["signatures"][0], sig="00" * 64)
    r, _ = post({"head": dict(sa, signatures=[sa["signatures"][0], d]), "level": la})
    return r.status_code == 400 and "DuplicateWitness" in r.text and VERIFIES[0] == 0 and WEAK[0] == 0 and route_rows() == 0


def row_witness_case():
    # Cipher (ART-42): lowercase 64-hex only on every path, no normalizing.
    # A pinned witness spelled in uppercase is refused by the filter
    # (MalformedWitnessSig, 0 verifies) and by lw.verify_head itself.
    reset_route_db()
    sa, la = root_head(A, 4)
    up = dict(sa["signatures"][1], witness=sa["signatures"][1]["witness"].upper())
    body = dict(sa, signatures=[sa["signatures"][0], up])
    r, _ = post({"head": body, "level": la})
    route = r.status_code == 400 and "MalformedWitnessSig" in r.text and VERIFIES[0] == 0 and route_rows() == 0
    direct = typed(lw.WitnessRefused, lambda: lw.verify_head(body, WSET, LOG, sig_ok=sig_ok))
    try: ctl = lw.verify_head(sa, WSET, LOG, sig_ok=sig_ok)["seq"] == 4
    except Exception: return False
    return route and direct and ctl and "lowercase" in _why(lambda: lw.verify_head(body, WSET, LOG, sig_ok=sig_ok))


def _why(fn):
    try: fn(); return ""
    except Exception as e: return str(e)


def row_tried_once():
    # item 1(c): lw.verify_head marks a witness tried before verifying it:
    # a valid 2-of-3 plus N bad-signature entries reusing one pinned key gives
    # at most 1 verify for that key (and the head still verifies).
    sa = legacy(4, R(A, 4))
    bad = [{"witness": WP[2], "sig": "00" * 64}] * 50
    per = {}
    def so(pub, msg, sig):
        per[pub] = per.get(pub, 0) + 1; return sig_ok(pub, msg, sig)
    try: lw.verify_head(dict(sa, signatures=bad + sa["signatures"]), WSET, LOG, sig_ok=so)
    except Exception: return False
    return per.get(WP[2], 0) <= 1 and max(per.values()) <= 1


def row_pin_weak():
    # item 1(a): weak_reason runs at pin load against wset.pubs; a weak pinned
    # key refuses the whole pin (503, no row), and repeated requests do not
    # rerun it.
    reset_route_db()
    ident = _ed._encodepoint(_ed._IDENT).hex()
    old = os.environ["CYBERNET_GENESIS_WITNESSES"]
    os.environ["CYBERNET_GENESIS_WITNESSES"] = ",".join(WP[:2] + [ident])
    try:
        sa, la = root_head(A, 4)
        rlw._PIN_CACHE.clear()
        WEAK[0] = 0
        with mock.patch.object(window_open, "weak_reason", _count_weak):
            codes = [client().post("/api/v1/legacy-log/observe", json={"head": sa, "level": la}).status_code
                     for _ in range(5)]
            refused = rlw.pinned() is None
        return codes == [503] * 5 and refused and 1 <= WEAK[0] <= 3 and route_rows() == 0
    finally:
        os.environ["CYBERNET_GENESIS_WITNESSES"] = old
        rlw._PIN_CACHE.clear()


def row_route_fork():
    # Bulwark 8360b0c8 item 2 through the route: the second head at seq 4 is
    # recorded as contested evidence; /witnessed shows no mark for that seq
    # and one contested entry carrying both hashes.
    reset_route_db()
    sa, la = root_head(A, 4); sb, lb = root_head(B, 4)
    r1, _ = post({"head": sa, "level": la}); r2, _ = post({"head": sb, "level": lb})
    w = client().get("/api/v1/legacy-log/witnessed").json()
    return (r1.status_code == 200 and r2.status_code == 200 and r2.json().get("status") == "contested"
            and [m for m in w["marks"] if m["log_id"] == LOG] == []
            and [sorted(x["head_hashes"]) for x in w["contested"]] == [sorted([R(A, 4).hex(), R(B, 4).hex()])])


ROWS = [
    ("(W-G) Bulwark gate: DuplicateCosign/MalformedCosign encodings leave no row of any kind; the clean encoding is stored", row_gate),
    ("(W-M) Lodestar mapping: stored seq == tree_size, observed (seq, head_hash) == mark (tree_size, root)", row_mapping),
    ("(W-S) Lodestar seeding: no mark + observed row at N; head at N+1 -> FirstContactRefused, nothing written", row_seeding),
    ("(W-R3) Bulwark rule 3: marks only from a root head or a consistency proof from the latest proven mark", row_rule3),
    ("(W-F) fork: one contested record, empty mark, no second observed row; log stays contested", row_fork),
    ("(W-ST) stale head (seq below the latest mark) refused, nothing written", row_stale),
    ("(W-E) Examiner: forged/non-root marks -> MarkNotRootProven before cheap_head sees the new head", row_examiner),
    ("(W-C1) 2-of-3 + 400 junk entries: refused, 0 verifies, 0 weak_reason, < 1 s", row_cost_oversize),
    ("(W-C2) 2-of-3 + unpinned entry: UnpinnedWitness, 0 verifies, 0 weak_reason", row_cost_unpinned),
    ("(W-C3) duplicate witness: DuplicateWitness, 0 verifies", row_cost_dup_witness),
    ("(W-LC) uppercase pinned witness refused by the filter (MalformedWitnessSig, 0 verifies) and by lw.verify_head; no normalizing", row_witness_case),
    ("(W-C4) lw.verify_head: one pinned key reused with bad sigs -> at most 1 verify for it", row_tried_once),
    ("(W-C5) weak pinned key refuses the whole pin at load (503); weak_reason not rerun per request", row_pin_weak),
    ("(W-F2) fork through the route: /witnessed shows contested evidence, no mark for that seq", row_route_fork),
]


# ------------------------------------------------------------------ mutants

def src_fn(mod, old, new, fn):
    """Exec a mutated copy of mod; classes rebound to the real ones."""
    src = open(mod.__file__).read(); assert src.count(old) == 1, (mod.__name__, old)
    ns = {"__name__": mod.__name__ + "_mut", "__file__": mod.__file__}
    exec(compile(src.replace(old, new), "mut", "exec"), ns)
    for k, v in vars(mod).items():
        if isinstance(v, type) and k in ns:
            ns[k] = v
    return ns[fn]
def wmut(old, new, fn="observe"):
    return mock.patch.object(wiring, fn, src_fn(wiring, old, new, fn))

ORIG_OBS = wiring.observe
CACHE = set()
def obs_headhash_cache(conn, vhead, level, *a, **k):
    hh = vhead.head["head_hash"]
    if hh in CACHE: raise hl.Refused("cached refusal")
    try: return ORIG_OBS(conn, vhead, level, *a, **k)
    except hl.Refused: CACHE.add(hh); raise
def obs_contested_first(conn, vhead, level, *a, **k):
    h = vhead.head; wiring.init_schema(conn)
    other = [r[0] for r in conn.execute("SELECT head_hash FROM legacy_observed_heads WHERE log_id=? AND seq=?",
                                        (h["log_id"], h["seq"]))]
    if other and h["head_hash"] not in other:
        wiring._mark_contested(conn, h["log_id"], h["seq"], other[0], h["head_hash"], 1)
    return ORIG_OBS(conn, vhead, level, *a, **k)
def obs_insert_or_ignore(conn, vhead, level, *a, **k):
    """Pre-cut route: legacy verify, then INSERT OR IGNORE."""
    h = vhead.head; wiring.init_schema(conn)
    conn.execute("INSERT OR IGNORE INTO legacy_observed_heads VALUES (?,?,?,?)", (h["log_id"], h["seq"], h["head_hash"], 1))
    return {"status": "observed"}
ORIG_PM = wiring.proven_marks
def pm_seed_observed(conn, log_id, *a, **k):
    out = ORIG_PM(conn, log_id, *a, **k)
    for seq, hh in conn.execute("SELECT seq, head_hash FROM legacy_observed_heads WHERE log_id=?", (log_id,)):
        out.append(hl.VerifiedMark(seq, bytes.fromhex(hh), hl.VerifiedMark._token))
    return sorted(set(out), key=lambda m: m.size)
def pm_trust_rows(conn, log_id, *a, **k):
    return [hl.VerifiedMark(r[0], bytes.fromhex(r[1]), hl.VerifiedMark._token) for r in wiring._mark_rows(conn, log_id)]
ORIG_VL = wiring.verify_legacy
def vl_weak_loop(signed, *a, **k):
    for s in (signed.get("signatures") or []) if isinstance(signed, dict) else []:
        w = s.get("witness") if isinstance(s, dict) else None
        if isinstance(w, str):
            why = lw.witness_key_admitted(w)
            if why: raise lw.WitnessRefused("weak key")
    return ORIG_VL(signed, *a, **k)
def vl_no_precheck(signed, wset, pinned_log, sig_ok=None):
    return wiring.VerifiedLegacyHead(lw.verify_head(signed, wset, pinned_log, sig_ok=sig_ok), wiring.VerifiedLegacyHead._token)

OBS_INSERT_FIRST = ('    blob, path = _level_shape(level)\n',
                    '    conn.execute("INSERT OR IGNORE INTO legacy_observed_heads VALUES (?,?,?,?)", (log_id, seq, head_hash, 1))\n'
                    '    blob, path = _level_shape(level)\n')
FORK_STORE_BOTH = ('''        _mark_contested(conn, log_id, seq, stored[0], head_hash, now)
        conn.execute("DELETE FROM legacy_level_marks WHERE log_id=?", (log_id,))
        return {"status": "contested", "log_id": log_id, "seq": seq}''',
                   '''        conn.execute("INSERT INTO legacy_observed_heads VALUES (?,?,?,?)", (log_id, seq, head_hash, now))
        return {"status": "observed", "log_id": log_id, "seq": seq}''')
FORK_KEEP_MARK = ('''        conn.execute("DELETE FROM legacy_level_marks WHERE log_id=?", (log_id,))
''', '')
MUT = [
    ("(W-G1) observed INSERT placed ahead of the verify", row_gate, [wmut(*OBS_INSERT_FIRST)]),
    ("(W-G2) refusal cache keyed by head_hash (not raw-encoding digest)", row_gate, [mock.patch.object(wiring, "observe", obs_headhash_cache)]),
    ("(W-G3) contested recorded before the level encoding is verified", row_gate, [mock.patch.object(wiring, "observe", obs_contested_first)]),
    ("(W-M1) tree_size == seq check dropped", row_mapping, [wmut("    if new_mark.size != seq:", "    if False:")]),
    ("(W-M2) root == head_hash check dropped", row_mapping, [wmut("    if new_mark.root.hex() != head_hash:", "    if False:")]),
    ("(W-S1) mark seeded from legacy_observed_heads", row_seeding, [mock.patch.object(wiring, "proven_marks", pm_seed_observed)]),
    ("(W-S2) observation-built raw mark handed to cheap_head", row_seeding, [wmut("        vmark = next((m for m in marks if (m.size, m.root) == claimed), None)",
                                                                                "        vmark = next((m for m in marks if (m.size, m.root) == claimed), None) or next(((r[0], bytes.fromhex(r[1])) for r in conn.execute('SELECT seq, head_hash FROM legacy_observed_heads WHERE log_id=?', (log_id,)) if (r[0], bytes.fromhex(r[1])) == claimed), None)")]),
    ("(W-R1) consistency proof not checked", row_rule3, [mock.patch.object(hl, "verify_consistency", lambda *a: True)]),
    ("(W-R2) root restart over an existing mark allowed", row_rule3, [wmut("    if vmark != latest:", "    if vmark is not None and vmark != latest:")]),
    ("(W-R3) chain from a non-latest proven mark allowed", row_rule3, [wmut("    if vmark != latest:", "    if vmark is None and latest is not None:")]),
    ("(W-F1) plain INSERT OR IGNORE (pre-cut route)", row_fork, [mock.patch.object(wiring, "observe", obs_insert_or_ignore)]),
    ("(W-F2) fork stores both heads, mark seeded from the first", row_fork, [wmut(*FORK_STORE_BOTH)]),
    ("(W-F3) contested recorded but the mark kept", row_fork, [wmut(*FORK_KEEP_MARK)]),
    ("(W-ST1) stale check dropped", row_stale, [wmut("    if latest is not None and seq < latest.size:", "    if False:")]),
    ("(W-E1) proven_marks trusts stored rows (no replay from the root)", row_examiner, [mock.patch.object(wiring, "proven_marks", pm_trust_rows)]),
    ("(W-C1a) weak_reason back in the request loop", row_cost_oversize, [mock.patch.object(wiring, "verify_legacy", vl_weak_loop)]),
    ("(W-C1b) signatures pre-check removed", row_cost_oversize, [mock.patch.object(wiring, "verify_legacy", vl_no_precheck)]),
    ("(W-C2) unpinned-witness check removed", row_cost_unpinned, [mock.patch.object(wiring, "precheck_signatures", src_fn(wiring, "        if w not in pubs:\n            raise UnpinnedWitness", "        if False:\n            raise UnpinnedWitness", "precheck_signatures"))]),
    ("(W-C2b) weak_reason back in the request loop", row_cost_unpinned, [mock.patch.object(wiring, "verify_legacy", vl_weak_loop)]),
    ("(W-C3) duplicate-witness check removed", row_cost_dup_witness, [mock.patch.object(wiring, "precheck_signatures", src_fn(wiring, "        if w in seen:\n            raise DuplicateWitness", "        if False:\n            raise DuplicateWitness", "precheck_signatures"))]),
    ("(W-LC1) filter lowercases witness pubs again (case-insensitive acceptance)", row_witness_case, [mock.patch.object(wiring, "precheck_signatures", src_fn(wiring, "        w = e[\"witness\"]\n        if lw.HEX64_RE.fullmatch(w) is None:", "        w = e[\"witness\"].lower()\n        if lw.HEX64_RE.fullmatch(w) is None:", "precheck_signatures"))]),
    ("(W-LC2) lw.verify_head skips non-lowercase witnesses silently", row_witness_case, [mock.patch.object(lw, "verify_head", src_fn(lw, "        if isinstance(w, str) and HEX64_RE.fullmatch(w) is None:\n            raise WitnessRefused", "        if False:\n            raise WitnessRefused", "verify_head"))]),
    ("(W-C4) lw.verify_head marks a witness only on success", row_tried_once, [mock.patch.object(lw, "verify_head", src_fn(lw, '''        if not (isinstance(w, str) and isinstance(sig, str) and w in eligible) or w in tried:
            continue
        tried.add(w)                        # Bulwark 8360b0c8: one verify per witness
        if (sig_ok or _sig_ok)(w, msg, sig):
            good.add(w)''', '''        if not (isinstance(w, str) and isinstance(sig, str) and w in eligible) or w in good:
            continue
        if (sig_ok or _sig_ok)(w, msg, sig):
            good.add(w)''', "verify_head"))]),
    ("(W-C5) pin-load weak_reason check removed", row_pin_weak, [mock.patch.object(rlw, "_load_pin", src_fn(rlw, "                if lw.witness_key_admitted(pub):\n                    raise WeakPinnedWitness(pub)", "                if False:\n                    raise WeakPinnedWitness(pub)", "_load_pin"))]),
    ("(W-F2r) route fork via plain INSERT OR IGNORE", row_route_fork, [mock.patch.object(wiring, "observe", obs_insert_or_ignore)]),
]

R_ = []
for label, fn in ROWS:
    try: ok = bool(fn())
    except Exception as e: ok = False; label += f" [ERROR {type(e).__name__}: {e}]"
    R_.append((label, ok)); print(f"  {'ok  ' if ok else 'FAIL'} {label}")
table = []
for name, row, patches in MUT:
    real = row()
    CACHE.clear(); rlw._PIN_CACHE.clear(); wiring._MARK_CACHE.clear()
    try:
        for p in patches: p.start()
        try: res = "SURVIVED" if row() else "KILLED"
        finally:
            for p in reversed(patches): p.stop()
    except Exception as e:
        res = f"ERROR({type(e).__name__}: {e})"
    CACHE.clear(); rlw._PIN_CACHE.clear(); wiring._MARK_CACHE.clear()
    table.append((name, row.__name__, real, res))
    ok = real and res == "KILLED"; R_.append((f"MUTANT {name}", ok))
    print(f"  {'ok  ' if ok else 'FAIL'} MUTANT {name}: real passes and named row fails")
print("mutant table (kill = named row fails its own assertion; exceptions are ERROR):\n  mutant | row | real passes | result")
for n, r, a, b in table: print(f"  {n} | {r} | {a} | {b}")
fails = sum(1 for _, ok in R_ if not ok)
print(f"wok_wiring: {len(R_) - fails} passed, {fails} failed ({time.time() - T0:.1f}s)")
raise SystemExit(1 if fails else 0)
