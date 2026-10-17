#!/usr/bin/env python3
"""ART-42 wiring cut: legacy_log_observe through head_level (locked in the
Research Board room; Bulwark 8360b0c8 items 1-4 folded in per Villhaze
ART-42 4fb5eb94). Every row has at least one named mutant it kills; a kill
is the named row failing its own assertion (exceptions are ERROR).

Villhaze ART-42 7e9eb9b5 (b) / a73a009e: every log here is a REAL
legacy_witness hash chain (entries -> entry_hash -> prev_hash links), and a
head_hash is its entry_hash tip. No wok_merkle anywhere: the rows that were
built on synthetic RFC 9162 roots are rebased onto real chains, and marks
advance by chain extension over header skeletons. Examiner's fixture LW
(23ae4b05) and rows LW-1..LW-10, Villhaze's tamper and gap rows, and
Lodestar's fork-ordering row (b5334563) are at the end."""
import json
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


def level(size, root, prev=(0, hl.ZERO32), ext=(), cosigns=None, issued=1_700_000_000):
    b = hl.pack_head(0, LIDB, size, root, prev[0], prev[1], hl.ZERO32, issued)
    return {"blob": b.hex(), "genesis_sig": G.sign(b).signature.hex(),
            "cosigns": [] if cosigns is None else cosigns, "extension": list(ext)}


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


# ---- real legacy_witness chains (no wok_merkle) ----
def ent(seq, prev, kind="hold", agent=None, aps=None, name=None, t=None):
    """One real log entry, hashed with lw's own code."""
    e = {"seq": seq, "prev_hash": prev, "kind": kind, "agent_id": agent, "agent_prev_seq": aps,
         "name": name, "migration_id": None, "k0_pub": None, "detail": "{}",
         "logged_at": 1_700_000_000 + 10 * seq + (0 if t is None else t)}
    e["name_sha256"] = lw.name_hash(name); e["body_sha256"] = lw.body_hash(e)
    return e


def build(specs, base=()):
    """base entries, then one entry per spec, each prev_hash = entry_hash of
    the one before ("none" at seq 1). A spec may pin seq / prev_hash to
    build a deliberately bad but self-consistent chain."""
    out = list(base)
    prev = lw.entry_hash(out[-1], LOG) if out else "none"
    for sp in specs:
        sp = dict(sp); seq = sp.pop("seq", len(out) + 1); pv = sp.pop("prev", prev)
        e = ent(seq, pv, **sp); out.append(e); prev = lw.entry_hash(e, LOG)
    return out


def gen_log(tag, n, base=()):
    """A real chain of holds, one fresh agent per entry (no back-links)."""
    k = len(base)
    return build([{"agent": 1000 * (ord(tag[0]) - 96) + i, "name": f"{tag}{i}"} for i in range(k + 1, n + 1)], base)


def tip(L, n):
    return bytes.fromhex(lw.entry_hash(L[n - 1], LOG))


def sk(L, a, b):
    """Header skeletons of seq a+1..b."""
    return [lw.skeleton(e) for e in L[a:b]]


A = gen_log("a", 16)
B = gen_log("b", 16, base=A[:2])          # forks after the first 2 entries
C = gen_log("c", 16, base=A[:2])
R = tip
for _L in (A, B, C):
    assert lw.verify_chain(_L, LOG) == (True, tip(_L, 16).hex())


def root_head(L, n, **kw):
    return legacy(n, R(L, n)), level(n, R(L, n), **kw)


def next_head(L, m, n, ext=None):
    return legacy(n, R(L, n)), level(n, R(L, n), prev=(m, R(L, m)),
                                      ext=sk(L, m, n) if ext is None else ext)


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
    # Bulwark rule 3 on real chains: a mark comes only from a root-verified
    # head or a chain extension from the latest proven mark. A tampered,
    # empty or foreign extension, a root head carrying an extension, a root
    # restart over an existing mark, and a chain from a non-latest mark are
    # all refused with nothing written.
    c = db()
    try:
        obs(c, *root_head(A, 4))
        obs(c, *next_head(A, 4, 7))
    except Exception: return False
    kinds = [r[0] for r in c.execute("SELECT proof_kind FROM legacy_level_marks ORDER BY tree_size")]
    marks = [(m.size, m.root) for m in wiring.proven_marks(c, LOG, GPUB, None, sig_ok)]
    if kinds != ["root", "chain"] or marks != [(4, R(A, 4)), (7, R(A, 7))]:
        return False
    s0 = snap(c)
    good = sk(A, 7, 9)
    bad = [[dict(good[0], kind="withdraw")] + good[1:], [], sk(B, 7, 9), good[:1]]
    ok = all(typed(hl.ExtensionRefused, lambda q=q: obs(c, *next_head(A, 7, 9, ext=q))) for q in bad)
    ok = ok and typed(hl.ExtensionRefused, lambda: obs(c, legacy(9, R(A, 9)), level(9, R(A, 9), ext=sk(A, 0, 1))))
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
    # Bulwark 8360b0c8 item 2 with Lodestar's ordering (b5334563, Villhaze
    # 0ff5838c): a head below the latest mark at an UNSTORED seq is
    # StaleHead (chained or root), nothing written; a replay of a STORED
    # head is already-observed, nothing written.
    c = db()
    try:
        obs(c, *root_head(A, 4)); obs(c, *next_head(A, 4, 7))
    except Exception: return False
    s0 = snap(c)
    return (typed(wiring.StaleHead, lambda: obs(c, *next_head(A, 4, 5)))
            and typed(wiring.StaleHead, lambda: obs(c, *root_head(A, 5))) and snap(c) == s0
            and obs(c, *root_head(A, 4))["status"] == "already-observed"
            and obs(c, *next_head(A, 4, 7))["status"] == "already-observed" and snap(c) == s0)


SEEN_BLOBS = []
_CH = hl.cheap_head
def _spy_cheap(blob, *a, **k):
    SEEN_BLOBS.append(blob); return _CH(blob, *a, **k)


def row_examiner():
    # Examiner row: a mark not built from a root proof is refused before
    # cheap_head runs on the new head. Forged rows go straight into the mark
    # table (a forged (999999, ...), a non-root lowest row, a chain row with
    # a foreign extension, a stored (size, root) that differs from its head,
    # an RFC 9162 "consistency" row): MarkNotRootProven, and the incoming
    # head's blob never reaches cheap_head.
    def ins(c, size, root, kind, lv, ext):
        c.execute("INSERT INTO legacy_level_marks VALUES (?,?,?,?,?,?,?,?,?)",
                  (LOG, size, root.hex(), kind, lv["blob"], lv["genesis_sig"], "[]", json.dumps(ext), 1))
    def forged_db(kind):
        c = db()
        if kind == "huge":
            c.execute("INSERT INTO legacy_level_marks VALUES (?,?,?,?,?,?,?,?,?)",
                      (LOG, 999999, R(A, 4).hex(), "root", "00", "00" * 64, "[]", "[]", 1))
            return c, (999999, R(A, 4))
        lv = level(4, R(A, 4), prev=(2, R(A, 2)), ext=sk(A, 2, 4))
        if kind == "nonroot":
            ins(c, 4, R(A, 4), "chain", lv, sk(A, 2, 4)); return c, (4, R(A, 4))
        obs(c, *root_head(A, 2))
        if kind == "badproof":
            ins(c, 4, R(A, 4), "chain", lv, sk(B, 2, 4)); return c, (4, R(A, 4))
        if kind == "rfc":
            ins(c, 4, R(A, 4), "consistency", lv, sk(A, 2, 4)); return c, (4, R(A, 4))
        ins(c, 4, R(B, 4), "chain", lv, sk(A, 2, 4))                       # "differs"
        return c, (4, R(B, 4))
    ok = True
    with mock.patch.object(hl, "cheap_head", _spy_cheap):
        for kind in ("huge", "nonroot", "badproof", "differs", "rfc"):
            c, (sz, rt) = forged_db(kind); s0 = snap(c)
            n = 5 if sz < 999999 else 1000000
            lv = level(n, R(A, 5), prev=(sz, rt), ext=[])
            del SEEN_BLOBS[:]
            ok = ok and typed(wiring.MarkNotRootProven, lambda: obs(c, legacy(n, R(A, 5)), lv)) and snap(c) == s0 \
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


def _mx(p):
    return "".join(ch.upper() if k % 2 else ch for k, ch in enumerate(p))
TABLES3 = ("legacy_observed_heads", "legacy_level_marks", "legacy_contested_heads")


def row_ndup_cosign_wired():
    # N-DUP(a) through the wiring: a case-variant cosign pair (lower/UPPER,
    # UPPER/lower, lower/mixed) is DuplicateCosign before any verify, and
    # nothing is written to any of the three tables.
    c = db()
    sa, la = root_head(A, 4)
    P, sg = WP[0], "ab" * 64
    pairs = [[{"pub": P, "sig": sg}, {"pub": P.upper(), "sig": sg}], [{"pub": P.upper(), "sig": sg}, {"pub": P, "sig": sg}],
             [{"pub": P, "sig": sg}, {"pub": _mx(P), "sig": sg}]]
    before = [count(c, t) for t in TABLES3]; s0 = snap(c)
    n = [0]
    def so(pub, msg, sig): n[0] += 1; return sig_ok(pub, msg, sig)
    vh = wiring.verify_legacy(sa, WSET, LOG, sig_ok)
    ok = True
    for pr in pairs:
        n[0] = 0
        ok = ok and typed(hl.DuplicateCosign, lambda: wiring.observe(c, vh, dict(la, cosigns=pr), GPUB, None, so)) and n[0] == 0
    return ok and [count(c, t) for t in TABLES3] == before and snap(c) == s0


def row_ndup_witness():
    # N-DUP(b): witness W spelled lower/UPPER, both orders: the filter refuses
    # DuplicateWitness with 0 verifies and no row; lw.verify_head called
    # directly makes at most 1 verify for W (tried keyed on the normalised w).
    sa, la = root_head(A, 4)
    s0, s1 = sa["signatures"]
    W = s1["witness"]
    ok = True
    for pair in ([s1, dict(s1, witness=W.upper())], [dict(s1, witness=W.upper()), s1]):
        reset_route_db()
        r, _ = post({"head": dict(sa, signatures=pair), "level": la})
        ok = ok and r.status_code == 400 and "DuplicateWitness" in r.text and VERIFIES[0] == 0 and route_rows() == 0
        per = {}
        def so(pub, msg, sig):
            per[pub] = per.get(pub, 0) + 1; return sig_ok(pub, msg, sig)
        try: lw.verify_head(dict(sa, signatures=[s0] + pair), WSET, LOG, sig_ok=so)
        except Exception: pass
        ok = ok and per.get(W, 0) == 1 and max(per.values()) <= 1
    return ok


def row_norm_accept_witness():
    # N-DUP(c) for witnesses: UPPER / mixed-case pinned witnesses are accepted
    # exactly as the lowercase baseline (status, level, verify count), by the
    # filter + route and by lw.verify_head directly.
    reset_route_db()
    sa, la = root_head(A, 4)
    s0, s1 = sa["signatures"]
    body = dict(sa, signatures=[dict(s0, witness=_mx(s0["witness"])), dict(s1, witness=s1["witness"].upper())])
    r, _ = post({"head": sa, "level": la})
    base = (r.status_code, r.json().get("status"), r.json().get("level"), VERIFIES[0])
    reset_route_db()
    r, _ = post({"head": body, "level": la})
    same = base[1] == "observed" and (r.status_code, r.json().get("status"), r.json().get("level"), VERIFIES[0]) == base
    try: direct = lw.verify_head(body, WSET, LOG, sig_ok=sig_ok)["seq"] == 4
    except Exception: return False
    return same and direct


def row_norm_strict_witness():
    # N-DUP(d) for witnesses: trailing newline (lower/upper), padding, non-hex,
    # short: the filter refuses MalformedWitnessSig with 0 verifies and no row;
    # lw.verify_head refuses them even when two valid signatures would
    # otherwise make quorum.
    sa, la = root_head(A, 4)
    s0, s1 = sa["signatures"]
    W, X = s1["witness"], WP[2]
    ok = True
    for bad in (W + "\n", W.upper() + "\n", " " + W, W + " ", W[:63], "g" + W[1:]):
        reset_route_db()
        r, _ = post({"head": dict(sa, signatures=[s0, dict(s1, witness=bad)]), "level": la})
        ok = ok and r.status_code == 400 and "MalformedWitnessSig" in r.text and VERIFIES[0] == 0 and route_rows() == 0
    for bad in (X + "\n", X.upper() + "\n", " " + X, X[:63]):
        ok = ok and typed(lw.WitnessRefused, lambda b=bad: lw.verify_head(
            dict(sa, signatures=[s0, s1, {"witness": b, "sig": "00" * 64}]), WSET, LOG, sig_ok=sig_ok))
    try: ok = ok and lw.verify_head(dict(sa, signatures=[s0, s1, {"witness": X.upper(), "sig": "00" * 64}]),
                                    WSET, LOG, sig_ok=sig_ok)["seq"] == 4
    except Exception: return False
    return ok


def row_stored_lower():
    # Every stored pub is lowercase: a head observed with upper/mixed-case
    # cosign pubs and witness pubs stores only lowercase 64-hex pubs.
    reset_route_db()
    sa, la = root_head(A, 4)
    sigs = [dict(e, witness=e["witness"].upper()) for e in sa["signatures"]]
    lv = dict(la, cosigns=[{"pub": WP[2].upper(), "sig": "00" * 64},
                           {"pub": "".join(ch.upper() if k % 2 else ch for k, ch in enumerate(WP[0])), "sig": "11" * 64}])
    r, _ = post({"head": dict(sa, signatures=sigs), "level": lv})
    if r.status_code != 200 or r.json().get("status") != "observed":
        return False
    with core._db_lock, core._db() as conn:
        rows = conn.execute("SELECT cosigns FROM legacy_level_marks").fetchall()
        cells = [str(v) for t in ("legacy_observed_heads", "legacy_level_marks", "legacy_contested_heads")
                 for row in conn.execute(f"SELECT * FROM {t}").fetchall() for v in row]
    pubs = [c["pub"] for (js,) in rows for c in json.loads(js)]
    no_upper = all(w.upper() not in cell for w in WP for cell in cells if w.upper() != w)
    return len(rows) == 1 and len(pubs) == 2 and all(hl.PUB_RE.fullmatch(p) for p in pubs) and no_upper


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


# ======================= Fixture LW (Examiner ART-42 23ae4b05) =======================
# A real legacy_witness log, built with lw code only; heads at seq 2 and 4
# signed by a pinned non-Genesis witness majority; level blobs Genesis-
# signed and cosigned under real parsed pins (single-operator). L is the
# wiring's binding, log_id_of(genesis_pub) (left exactly as the code has it).
import struct  # noqa: E402
L = hl.log_id_of(GPUB).hex()
assert L == LOG
CK = SigningKey(hashlib.sha256(b"lw-fleet-cosigner").digest()); CKP = CK.verify_key.encode().hex()
OPL = b"\x07" * 32
_PS = [SigningKey(hashlib.sha256(b"lw-pin-signer-%d" % i).digest()) for i in range(3)]
def _pinfile():
    body = hl.PIN_MAGIC + LIDB + struct.pack(">QQ", 1, 1_700_000_000) + bytes([1])
    body += OPL + bytes([hl.CLASS_FLEET, 1]) + bytes.fromhex(CKP) + struct.pack(">QQ", 0, 10 ** 9)
    return body + bytes([2]) + b"".join(bytes([i]) + _PS[i].sign(body).signature for i in (0, 1))
LWP = hl.parse_pins(_pinfile(), GPUB, sig_ok, tuple(k.verify_key.encode().hex() for k in _PS), 2)

E = build([{"kind": "window-open"},
           {"kind": "hold", "agent": 7, "name": "alice"},
           {"kind": "hold", "agent": 9, "name": "bob"},
           {"kind": "migrate-pending", "agent": 7, "aps": 2, "name": "alice"}])
E7 = build([{"kind": "hold", "agent": 11, "name": "carol"},
            {"kind": "hold", "agent": 12, "name": "dave"},
            {"kind": "withdraw", "agent": 7, "aps": 4, "name": "alice"}], base=E)
H = {n: lw.entry_hash(E7[n - 1], L) for n in range(1, 8)}
H2, H4 = H[2], H[4]
for _e in E7:
    assert lw.entry_shape_problem(_e) is None
assert lw.verify_chain(E[:2], L) == (True, H2) and lw.verify_chain(E, L) == (True, H4)
assert lw.verify_chain(E7, L) == (True, H[7])
# sibling log: shares E1-E2, different E3/E4 (Examiner LW-4 / LW-8, Lodestar)
F = build([{"kind": "hold", "agent": 21, "name": "mallory"}, {"kind": "hold", "agent": 22, "name": "trent"}], base=E[:2])
# other base: different E1-E2 (so a different tip at 2), self-consistent 3-4 (LW-3)
O = build([{"kind": "window-open", "t": 1}, {"kind": "hold", "agent": 31, "name": "oscar"},
           {"kind": "hold", "agent": 32, "name": "peggy"}, {"kind": "hold", "agent": 33, "name": "quinn"}])
assert lw.entry_hash(O[1], L) != H2 and O[2]["prev_hash"] != H2


def lw_head(seq, hh, signers=(0, 1)):
    h = {"log_id": L, "witness_set": WSET.id, "seq": seq, "head_hash": hh,
         "window_open_seq": 1, "window_close_seq": None, "window_state": "open",
         **{k: "ab" * 32 for k in lw.HEAD_ROOT_FIELDS}}
    return lw.sign_head(h, [lambda m, k=WK[i]: (k.verify_key.encode().hex(), k.sign(m).signature.hex())
                            for i in signers])


def lw_level(size, hh, prev=(0, None), ext=(), issued=1_700_000_500):
    proot = hl.ZERO32 if prev[1] is None else bytes.fromhex(prev[1])
    b = hl.pack_head(1, LIDB, size, bytes.fromhex(hh), prev[0], proot, OPL, issued)
    body = b[b.index(b"\n") + 1:]
    return {"blob": b.hex(), "genesis_sig": G.sign(b).signature.hex(),
            "cosigns": [{"pub": CKP, "sig": CK.sign(hl.COSIGN_PREFIX + body).signature.hex()}],
            "extension": list(ext)}


VCALLS, HASHES = [0], [0]
def vso(pub, msg, sig):
    VCALLS[0] += 1; return sig_ok(pub, msg, sig)
_SHA = hashlib.sha256
_LOGFMT = lw.LOG_FORMAT.encode()
def _count_sha(data=b"", *a, **k):
    """Counts entry_hash work wherever it runs (also inside a source mutant's
    own namespace): every sha256 over a legacy-log header."""
    if isinstance(data, (bytes, bytearray)) and bytes(data[:len(_LOGFMT)]) == _LOGFMT:
        HASHES[0] += 1
    return _SHA(data, *a, **k)
class _count_eh_ctx:
    def __enter__(self):
        self.p = mock.patch.object(hashlib, "sha256", _count_sha); self.p.start()
    def __exit__(self, *e):
        self.p.stop()


def lw_obs(c, signed, lv, count=False):
    """verify_legacy, then observe under LWP. With count=True, only the
    observe step's verifies and entry_hash calls are counted."""
    vh = wiring.verify_legacy(signed, WSET, L, sig_ok)
    if not count:                           # vso throughout: one sig_ok, so the replay cache is shared
        r = wiring.observe(c, vh, lv, GPUB, LWP, vso)
        marks_of(c)                         # warm the replay cache: counted steps measure the new head only
        return r
    VCALLS[0] = HASHES[0] = 0
    with _count_eh_ctx():
        return wiring.observe(c, vh, lv, GPUB, LWP, vso)


def h2():
    return lw_head(2, H2), lw_level(2, H2)


def h4(ext=None, hh=None):
    hh = H4 if hh is None else hh
    return lw_head(4, hh), lw_level(4, hh, prev=(2, H2), ext=sk(E, 2, 4) if ext is None else ext)


def h7():
    return lw_head(7, H[7]), lw_level(7, H[7], prev=(4, H4), ext=sk(E7, 4, 7))


def marks_of(c):
    return [(m.size, m.root.hex()) for m in wiring.proven_marks(c, L, GPUB, LWP, vso)]


def kinds_of(c):
    return [tuple(r) for r in c.execute("SELECT tree_size, root, proof_kind FROM legacy_level_marks ORDER BY tree_size")]


def refused_clean(c, cls, fn, zero=True):
    """Typed refusal, nothing written; with zero=True also 0 verifies and
    0 entry_hash calls in observe."""
    s0 = snap(c)
    try: fn(); return False
    except Exception as e:
        if not isinstance(e, cls): return False
    return snap(c) == s0 and (not zero or (VCALLS[0] == 0 and HASHES[0] == 0))


def row_lw1_root():
    # LW-1: h2 observed, one mark (2, H2) with proof_kind root. A root head
    # carrying an extension is refused first, nothing written.
    c = db()
    if not refused_clean(c, hl.ExtensionRefused, lambda: lw_obs(c, lw_head(2, H2), lw_level(2, H2, ext=sk(E, 0, 1)), True)):
        return False
    try: r = lw_obs(c, *h2())
    except Exception: return False
    return r["status"] == "observed" and r["level"] == "single-operator" and kinds_of(c) == [(2, H2, "root")] \
        and marks_of(c) == [(2, H2)]


def row_lw2_advance():
    # LW-2 (the row that failed on 8078a11): h4 with the 2->4 skeletons is
    # observed and the latest mark is (4, H4), proof_kind chain; the
    # extension costs one entry_hash per skeleton.
    c = db()
    try:
        lw_obs(c, *h2())
        r = lw_obs(c, *h4(), count=True)
    except Exception: return False
    return (r["status"] == "observed" and r["level"] == "single-operator" and HASHES[0] == 2
            and kinds_of(c) == [(2, H2, "root"), (4, H4, "chain")] and marks_of(c) == [(2, H2), (4, H4)]
            and [x[0] for x in c.execute("SELECT seq FROM legacy_observed_heads ORDER BY seq")] == [2, 4])


def row_lw3_link():
    # LW-3: the first skeleton must link to the marked tip. (i) skeleton 3's
    # prev_hash changed; (ii) a self-consistent 3..4 from another base (tip
    # at 2 is not H2), its head signed with its own tip. Typed refusal,
    # nothing written, 0 verifies (the extension is checked before any
    # signature verify).
    c = db()
    try: lw_obs(c, *h2())
    except Exception: return False
    s3 = sk(E, 2, 4); s3[0] = dict(s3[0], prev_hash="ab" * 32)
    o4 = lw.entry_hash(O[3], L)
    return (refused_clean(c, hl.ExtensionRefused, lambda: lw_obs(c, *h4(ext=s3), count=True), zero=False) and VCALLS[0] == 0
            and refused_clean(c, hl.ExtensionRefused, lambda: lw_obs(c, *h4(ext=sk(O, 2, 4), hh=o4), count=True), zero=False)
            and VCALLS[0] == 0 and marks_of(c) == [(2, H2)])


def row_lw4_tail():
    # LW-4: skeletons that chain from H2 (sibling log F) but end at F's tip,
    # under a head signed with H4: refused (the tail must be head_hash).
    c = db()
    try: lw_obs(c, *h2())
    except Exception: return False
    return refused_clean(c, hl.ExtensionRefused, lambda: lw_obs(c, *h4(ext=sk(F, 2, 4)), count=True), zero=False) \
        and VCALLS[0] == 0 and marks_of(c) == [(2, H2)]


def row_lw5_span():
    # LW-5: exactly the headers m+1..n, header fields only. [E4] alone,
    # [E3, E4, E5'] padded, an extra key, a str agent_id: refused before any
    # entry_hash call (0 hashes, 0 verifies), nothing written. Direct: an
    # empty extension with a moved tip, and n < m, are refused.
    c = db()
    try: lw_obs(c, *h2())
    except Exception: return False
    e5 = lw.skeleton(build([{"kind": "hold", "agent": 41, "name": "x"}], base=E)[4])
    s34 = sk(E, 2, 4)
    bad = [s34[1:], s34 + [e5], [dict(s34[0], name="bob"), s34[1]], [dict(s34[0], x=1), s34[1]], [dict(s34[0], agent_id="9"), s34[1]]]
    ok = all(refused_clean(c, hl.ExtensionRefused, lambda q=q: lw_obs(c, *h4(ext=q), count=True)) for q in bad)
    return (ok and lw.verify_extension([], L, 2, H2, 2, H4)[0] is False
            and lw.verify_extension([], L, 4, H4, 2, H2)[0] is False and lw.verify_extension([], L, 2, H2, 2, H2)[0] is True)


def row_lw6_tamper_kind():
    # LW-6: kind flipped in skeleton 3: the recomputed entry_hash no longer
    # matches skeleton 4's prev_hash; refused, nothing written.
    c = db()
    try: lw_obs(c, *h2())
    except Exception: return False
    s = sk(E, 2, 4); s[0] = dict(s[0], kind="contest")
    return refused_clean(c, hl.ExtensionRefused, lambda: lw_obs(c, *h4(ext=s), count=True), zero=False) and VCALLS[0] == 0


def row_lw_tamper_link():
    # Villhaze tamper row: one header in the span with a broken prev_hash
    # link, its head SIGNED over the tampered tip (so only the link check can
    # catch it): refused, nothing written.
    c = db()
    try: lw_obs(c, *h2())
    except Exception: return False
    T = build([{"kind": "hold", "agent": 9, "name": "bob"},
               {"kind": "migrate-pending", "agent": 7, "aps": 2, "name": "alice", "prev": "cd" * 32}], base=E[:2])
    t4 = lw.entry_hash(T[3], L)
    return refused_clean(c, hl.ExtensionRefused, lambda: lw_obs(c, *h4(ext=sk(T, 2, 4), hh=t4), count=True), zero=False) \
        and VCALLS[0] == 0 and marks_of(c) == [(2, H2)]


def row_lw_gap():
    # Villhaze gap row: (i) 4 -> 7 with E6 missing: refused before any
    # hashing; (ii) a self-consistent chain whose 4th header is numbered 5
    # (an entry missing from the numbering), head SIGNED over its tip at
    # seq 4: refused (gap). Nothing written.
    c = db()
    try: lw_obs(c, *h2()); lw_obs(c, *h4())
    except Exception: return False
    s57 = sk(E7, 4, 7)
    i = refused_clean(c, hl.ExtensionRefused, lambda: lw_obs(c, lw_head(7, H[7]), lw_level(7, H[7], prev=(4, H4), ext=[s57[0], s57[2]]), True))
    c2 = db()
    try: lw_obs(c2, *h2())
    except Exception: return False
    Gp = build([{"kind": "hold", "agent": 9, "name": "bob"},
                {"kind": "migrate-pending", "agent": 7, "aps": 2, "name": "alice", "seq": 5}], base=E[:2])
    g4 = lw.entry_hash(Gp[3], L)
    ii = refused_clean(c2, hl.ExtensionRefused, lambda: lw_obs(c2, *h4(ext=sk(Gp, 2, 4), hh=g4), count=True), zero=False)
    return i and ii and marks_of(c2) == [(2, H2)]


def row_lw7_backlink():
    # LW-7: E4's agent_prev_seq=2 points across the mark and is accepted
    # (observe). Inside the span a back-link is exact; at or below the mark
    # it only needs 1 <= v <= m. Direct lw.verify_extension over real chains
    # (tip computed from each): in-span wrong, in-span missing, landing in
    # the span on another agent, 0, and a back-link with no agent: refused.
    c = db()
    try:
        lw_obs(c, *h2()); ok = lw_obs(c, *h4())["status"] == "observed"
    except Exception: return False
    def chain(specs):
        X = build(specs, base=E[:2]); return lw.verify_extension(sk(X, 2, 4), L, 2, H2, 4, lw.entry_hash(X[3], L))[0]
    bob = {"kind": "hold", "agent": 9, "name": "bob"}
    neg = [[bob, {"kind": "hold", "agent": 9, "aps": 2, "name": "bob"}],         # in-span, should be 3
           [bob, {"kind": "hold", "agent": 9, "name": "bob"}],                   # in-span, missing
           [bob, {"kind": "hold", "agent": 7, "aps": 3, "name": "alice"}],       # lands in span, wrong agent
           [bob, {"kind": "hold", "agent": 7, "aps": 0, "name": "alice"}],       # below 1
           [bob, {"kind": "window-close", "aps": 1}]]                            # no agent
    pos = [[bob, {"kind": "hold", "agent": 9, "aps": 3, "name": "bob"}], [bob, {"kind": "hold", "agent": 7, "aps": 1, "name": "alice"}]]
    return ok and not any(chain(n) for n in neg) and all(chain(p) for p in pos)


def row_lw8_fork():
    # LW-8: h2, h4, then h4' (sibling F, extension from mark 2): exactly one
    # contested record, every mark removed, nothing stored for h4'.
    c = db()
    f4 = lw.entry_hash(F[3], L)
    try:
        lw_obs(c, *h2()); lw_obs(c, *h4())
        r = lw_obs(c, *h4(ext=sk(F, 2, 4), hh=f4))
    except Exception: return False
    return (r["status"] == "contested" and count(c, "legacy_contested_heads") == 1 and count(c, "legacy_level_marks") == 0
            and [x[0] for x in c.execute("SELECT head_hash FROM legacy_observed_heads WHERE seq=4")] == [H4]
            and typed(wiring.LogContested, lambda: lw_obs(c, *h4(ext=sk(F, 2, 4), hh=f4))))


def row_lw9_replay():
    # LW-9: proven_marks rebuilds (4, H4) by re-verifying the stored
    # skeletons from the (2, H2) mark. One stored skeleton byte corrupted ->
    # MarkNotRootProven (and the next head is refused the same way). A
    # chain row stored as kind "consistency", and a root row carrying
    # skeletons, are refused too.
    def fresh():
        c = db(); lw_obs(c, *h2()); lw_obs(c, *h4()); wiring._MARK_CACHE.clear(); return c
    try:
        c = fresh(); good = marks_of(c) == [(2, H2), (4, H4)]
    except Exception: return False
    proof = c.execute("SELECT proof FROM legacy_level_marks WHERE tree_size=4").fetchone()[0]
    k = proof.index('"body_sha256": "') + len('"body_sha256": "')
    bad = proof[:k] + ("0" if proof[k] != "0" else "1") + proof[k + 1:]
    c.execute("UPDATE legacy_level_marks SET proof=? WHERE tree_size=4", (bad,)); wiring._MARK_CACHE.clear()
    ok = good and typed(wiring.MarkNotRootProven, lambda: marks_of(c)) and typed(wiring.MarkNotRootProven, lambda: lw_obs(c, *h7()))
    c = fresh(); c.execute("UPDATE legacy_level_marks SET proof_kind='consistency' WHERE tree_size=4"); wiring._MARK_CACHE.clear()
    ok = ok and typed(wiring.MarkNotRootProven, lambda: marks_of(c))
    c = fresh(); c.execute("UPDATE legacy_level_marks SET proof=? WHERE tree_size=2", (json.dumps(sk(E, 0, 1)),)); wiring._MARK_CACHE.clear()
    return ok and typed(wiring.MarkNotRootProven, lambda: marks_of(c))


BIG = gen_log("z", 262, base=E[:2])
def row_lw10_cap():
    # LW-10 (cap 256, Villhaze a73a009e): a 2 -> 259 advance (257 skeletons)
    # is refused before any entry_hash call, 0 hashes and 0 verifies: in
    # observe (MalformedLevel), in lw.verify_extension directly, and through
    # the route (0 verifies including the witness ones, no row). 256
    # worst-case skeletons fit the byte cap; the cap is exactly 256.
    c = db()
    try: lw_obs(c, *h2())
    except Exception: return False
    big = sk(BIG, 2, 259); t = lw.entry_hash(BIG[258], L)
    lv = lw_level(259, t, prev=(2, H2), ext=big)
    ok = refused_clean(c, wiring.MalformedLevel, lambda: lw_obs(c, lw_head(259, t), lv, True))
    HASHES[0] = 0
    with _count_eh_ctx():
        d = lw.verify_extension(big, L, 2, H2, 259, t)
    ok = ok and d[0] is False and HASHES[0] == 0
    reset_route_db()
    HASHES[0] = 0
    with _count_eh_ctx():
        r, _ = post({"head": lw_head(259, t), "level": lv})
    worst = [lw.skeleton(lw._worst_entry(False))] * lw.MAX_EXTENSION
    return (ok and r.status_code == 400 and "MalformedLevel" in r.text and VERIFIES[0] == 0 and HASHES[0] == 0
            and route_rows() == 0 and lw.MAX_EXTENSION == 256 and len(json.dumps(worst).encode()) <= lw.MAX_EXTENSION_BYTES)


def row_lw10_bytes():
    # LW-10 transport: skeletons travel in their own field under their own
    # byte cap: 3 entries over the byte cap -> MalformedLevel, 0 hashes,
    # 0 verifies, nothing written; the old "consistency" field is refused.
    c = db()
    try: lw_obs(c, *h2())
    except Exception: return False
    fat = [dict(s, kind="x" * (lw.MAX_EXTENSION_BYTES // 2)) for s in sk(E, 2, 4)]
    old = dict(h4()[1]); old["consistency"] = []
    return (refused_clean(c, wiring.MalformedLevel, lambda: lw_obs(c, *h4(ext=fat), count=True))
            and refused_clean(c, wiring.MalformedLevel, lambda: lw_obs(c, h4()[0], old, True)))


def row_fork_order():
    # Lodestar b5334563 / Villhaze 0ff5838c: marks at 2, 4, 7, then a signed
    # fork B@4 chained from mark 2 (and, separately, a root-head B@4 after
    # marks 4, 7): exactly one contested record, marks emptied, the log
    # refused afterwards. Not StaleHead.
    f4 = lw.entry_hash(F[3], L)
    c = db()
    try:
        lw_obs(c, *h2()); lw_obs(c, *h4()); lw_obs(c, *h7())
        r = lw_obs(c, *h4(ext=sk(F, 2, 4), hh=f4))
    except Exception: return False
    ok = (r["status"] == "contested" and count(c, "legacy_contested_heads") == 1 and count(c, "legacy_level_marks") == 0
          and typed(wiring.LogContested, lambda: lw_obs(c, *h7())))
    c = db()
    try:
        lw_obs(c, lw_head(4, H4), lw_level(4, H4)); lw_obs(c, *h7())
        r = lw_obs(c, lw_head(4, f4), lw_level(4, f4))
    except Exception: return False
    return ok and r["status"] == "contested" and count(c, "legacy_contested_heads") == 1 and count(c, "legacy_level_marks") == 0


LW_ROWS = [
    ("(LW-1) real log: h2 observed, one root mark (2, H2); a root head with an extension refused", row_lw1_root),
    ("(LW-2) real log: h4 with the 2->4 skeletons observed, latest mark (4, H4) kind chain", row_lw2_advance),
    ("(LW-3) first skeleton must link to the marked tip (changed prev_hash; other base): refused, 0 verifies", row_lw3_link),
    ("(LW-4) skeletons must end at head_hash (sibling tail under H4): refused", row_lw4_tail),
    ("(LW-5) exact span m+1..n, header fields only: short/padded/extra key/str field refused before hashing", row_lw5_span),
    ("(LW-6) tamper: kind flipped in skeleton 3 -> chain broken, refused", row_lw6_tamper_kind),
    ("(LW-T) Villhaze tamper: broken prev_hash link inside the span under a signed tip -> refused", row_lw_tamper_link),
    ("(LW-G) Villhaze gap: missing skeleton refused before hashing; renumbered (seq skip) chain under a signed tip refused", row_lw_gap),
    ("(LW-7) back-link across the mark accepted; in-span exact, below-mark range, no-agent rule refused", row_lw7_backlink),
    ("(LW-8) fork on the real log: one contested record, marks removed, nothing stored for h4'", row_lw8_fork),
    ("(LW-9) replay re-verifies stored skeletons: corrupted byte / wrong kind / root with skeletons -> MarkNotRootProven", row_lw9_replay),
    ("(LW-10) cap 256: 257 skeletons refused before any entry_hash, 0 hashes, 0 verifies (observe, lw, route)", row_lw10_cap),
    ("(LW-10b) extension byte cap and own transport field: MalformedLevel, 0 hashes, 0 verifies", row_lw10_bytes),
    ("(LF) Lodestar fork order: marks 2/4/7 then signed B@4 (chained and root) -> contested, marks emptied, log refused", row_fork_order),
]


ROWS = [
    ("(W-G) Bulwark gate: DuplicateCosign/MalformedCosign encodings leave no row of any kind; the clean encoding is stored", row_gate),
    ("(W-M) Lodestar mapping: stored seq == tree_size, observed (seq, head_hash) == mark (tree_size, root)", row_mapping),
    ("(W-S) Lodestar seeding: no mark + observed row at N; head at N+1 -> FirstContactRefused, nothing written", row_seeding),
    ("(W-R3) Bulwark rule 3: marks only from a root head or a chain extension from the latest proven mark", row_rule3),
    ("(W-F) fork: one contested record, empty mark, no second observed row; log stays contested", row_fork),
    ("(W-ST) stale head (below the latest mark, unstored seq) refused; stored-seq replay is a no-op; nothing written", row_stale),
    ("(W-E) Examiner: forged/non-root marks -> MarkNotRootProven before cheap_head sees the new head", row_examiner),
    ("(W-C1) 2-of-3 + 400 junk entries: refused, 0 verifies, 0 weak_reason, < 1 s", row_cost_oversize),
    ("(W-C2) 2-of-3 + unpinned entry: UnpinnedWitness, 0 verifies, 0 weak_reason", row_cost_unpinned),
    ("(W-C3) duplicate witness: DuplicateWitness, 0 verifies", row_cost_dup_witness),
    ("(W-N a) case-variant cosign pair through the wiring: DuplicateCosign, 0 verifies, nothing written to the three tables", row_ndup_cosign_wired),
    ("(W-N b) witness lower/UPPER pair, both orders: DuplicateWitness, 0 verifies, no row; lw.verify_head <= 1 verify for W", row_ndup_witness),
    ("(W-N c) UPPER/mixed pinned witnesses accepted exactly as lowercase (route + lw.verify_head)", row_norm_accept_witness),
    ("(W-N d) trailing newline/padded/non-hex/short witness: MalformedWitnessSig, 0 verifies; lw.verify_head refuses", row_norm_strict_witness),
    ("(W-LS) every stored pub is lowercase (cosigns observed in upper/mixed case)", row_stored_lower),
    ("(W-C4) lw.verify_head: one pinned key reused with bad sigs -> at most 1 verify for it", row_tried_once),
    ("(W-C5) weak pinned key refuses the whole pin at load (503); weak_reason not rerun per request", row_pin_weak),
    ("(W-F2) fork through the route: /witnessed shows contested evidence, no mark for that seq", row_route_fork),
] + LW_ROWS


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

OBS_INSERT_FIRST = ('    blob, ext = _level_shape(level)\n',
                    '    conn.execute("INSERT OR IGNORE INTO legacy_observed_heads VALUES (?,?,?,?)", (log_id, seq, head_hash, 1))\n'
                    '    blob, ext = _level_shape(level)\n')
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
    ("(W-R1) chain extension not checked", row_rule3, [mock.patch.object(lw, "verify_extension", lambda *a: (True, a[5]))]),
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
    ("(M-N1w) hl duplicate set over the raw pub, normalised afterwards", row_ndup_cosign_wired, [mock.patch.object(hl, "normalize_cosigns", src_fn(hl, '    if len({c["pub"] for c in out}) != len(out):\n        raise DuplicateCosign("at most one cosign per signer")\n', '    if len({c["pub"] for c in cosigns}) != len(cosigns):\n        raise DuplicateCosign("at most one cosign per signer")\n', "normalize_cosigns"))]),
    ("(M-N2) filter `seen` keyed on the raw witness, membership on the normalised one", row_ndup_witness, [mock.patch.object(wiring, "precheck_signatures", src_fn(wiring, '        if w in seen:\n            raise DuplicateWitness("at most one signature per witness")\n        seen.add(w)', '        if e["witness"] in seen:\n            raise DuplicateWitness("at most one signature per witness")\n        seen.add(e["witness"])', "precheck_signatures"))]),
    ("(M-N3) lw.verify_head `tried` keyed on the raw witness", row_ndup_witness, [mock.patch.object(lw, "verify_head", src_fn(lw, "w in eligible) or w in tried:\n            continue\n        tried.add(w)", "w in eligible) or s.get(\"witness\") in tried:\n            continue\n        tried.add(s.get(\"witness\"))", "verify_head"))]),
    ("(M-N5f) filter normalising dropped (uppercase witness refused)", row_norm_accept_witness, [mock.patch.object(wiring, "precheck_signatures", src_fn(wiring, '        w = e["witness"].lower()', '        w = e["witness"]', "precheck_signatures"))]),
    ("(M-N5l) lw.verify_head normalising dropped (uppercase witness refused)", row_norm_accept_witness, [mock.patch.object(lw, "verify_head", src_fn(lw, "            w = w.lower()\n", "            pass\n", "verify_head"))]),
    ("(M-N6f) filter fullmatch swapped for match", row_norm_strict_witness, [mock.patch.object(wiring, "precheck_signatures", src_fn(wiring, '        if lw.HEX64_RE.fullmatch(w) is None:      # strict check', '        if lw.HEX64_RE.match(w) is None:      # strict check', "precheck_signatures"))]),
    ("(M-N6l) lw.verify_head fullmatch swapped for match", row_norm_strict_witness, [mock.patch.object(lw, "verify_head", src_fn(lw, "            if HEX64_RE.fullmatch(w) is None:\n                raise WitnessRefused", "            if HEX64_RE.match(w) is None:\n                raise WitnessRefused", "verify_head"))]),
    ("(M-N7f) filter strict check skipped", row_norm_strict_witness, [mock.patch.object(wiring, "precheck_signatures", src_fn(wiring, '        if lw.HEX64_RE.fullmatch(w) is None:      # strict check', '        if False:      # strict check', "precheck_signatures"))]),
    ("(W-LS1) raw-case cosigns stored", row_stored_lower, [wmut('json.dumps(hl.normalize_cosigns(level["cosigns"]))', 'json.dumps(level["cosigns"])')]),
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


def lwx(old, new):
    """Mutant of lw.verify_extension (hl.extend_mark and the rows look it up
    on the lw module)."""
    return mock.patch.object(lw, "verify_extension", src_fn(lw, old, new, "verify_extension"))
BACKLINK = '''        if a is None:
            if v is not None:
                return False, f"agent back-link without an agent at seq {i}"
        elif a in last_of:
            if v != last_of[a]:
                return False, f"agent back-link wrong at seq {i}"
        elif v is not None and not 1 <= v <= m:
            return False, f"agent back-link out of range at seq {i}"
'''
EXT_CALL = '''        level_name, new_mark = hl.extend_mark(vmark, blob, level["genesis_sig"], genesis_pub,
                                              level["cosigns"], pins, sig_ok, ext)'''
LW_MUT = [
    ("(LW-1m) root head with an extension accepted", row_lw1_root, [wmut("        if ext:\n            raise ExtensionRefused", "        if False:\n            raise ExtensionRefused")]),
    ("(LW-2m) extension check always refuses", row_lw2_advance, [mock.patch.object(lw, "verify_extension", lambda *a: (False, "mutant"))]),
    ("(LW-2r) head_hash treated as an RFC 9162 root (consistency path over the skeleton hashes)", row_lw2_advance, [wmut(EXT_CALL, '''        level_name, new_mark = hl.advance_mark(vmark, blob, level["genesis_sig"], genesis_pub,
                                               level["cosigns"], pins, sig_ok, [bytes.fromhex(lw.entry_hash(e, log_id)) for e in ext])''')]),
    ("(LW-3m) first skeleton's link to the marked tip not checked", row_lw3_link, [lwx('    if skeletons[0]["prev_hash"] != tip_m:', "    if False:")]),
    ("(LW-3v) signature verify before the extension check", row_lw3_link, [mock.patch.object(hl, "extend_mark", src_fn(hl, "    h = cheap_head(blob, log_id_of(genesis_pub), prev)\n    ok, why",
        "    verify_head(blob, genesis_sig, genesis_pub, cosigns, pins, sig_ok, mark=prev, ruling=ruling)\n    h = cheap_head(blob, log_id_of(genesis_pub), prev)\n    ok, why", "extend_mark"))]),
    ("(LW-4m) tail == head_hash not checked", row_lw4_tail, [lwx('    if prev != tip_n:\n        return False, "extension does not end', '    if False:\n        return False, "extension does not end')]),
    ("(LW-5m) len == n - m check dropped", row_lw5_span, [lwx("    if len(skeletons) != n - m:\n", "    if False:\n")]),
    ("(LW-5k) extra skeleton keys allowed", row_lw5_span, [lwx("        if not isinstance(e, dict) or set(e) != set(HEADER_FIELDS):", "        if not isinstance(e, dict):")]),
    ("(LW-5s) skeleton shape check dropped", row_lw5_span, [lwx("        why = entry_shape_problem(e)\n        if why:\n            return False, f\"malformed skeleton", "        why = None\n        if why:\n            return False, f\"malformed skeleton")]),
    ("(LW-5e) empty extension accepted with a moved tip", row_lw5_span, [lwx('        return (True, tip_n) if tip_m == tip_n else (False, "no extension but the tip moved")', "        return (True, tip_n)")]),
    ("(LW-6m) skeleton hashes trusted, not recomputed (next prev_hash taken as the hash)", row_lw6_tamper_kind, [lwx("        prev = entry_hash(e, log_id)\n    if prev != tip_n:", '        prev = entry_hash(e, log_id) if i == n else skeletons[i - m]["prev_hash"]\n    if prev != tip_n:')]),
    ("(LW-Tm) prev_hash links inside the span not checked", row_lw_tamper_link, [lwx('        if prev is not None and e["prev_hash"] != prev:', "        if False:")]),
    ("(LW-Gm) seq numbering not checked", row_lw_gap, [lwx('        if e["seq"] != i:\n            return False, f"gap at seq {i}"', '        if False:\n            return False, f"gap at seq {i}"')]),
    ("(LW-Gl) len == n - m check dropped (gap)", row_lw_gap, [lwx("    if len(skeletons) != n - m:\n", "    if False:\n")]),
    ("(LW-7m) suffix checked with verify_chain's empty last_of (honest cross-mark back-link refused)", row_lw7_backlink, [lwx(BACKLINK, '        if v != (last_of.get(a) if a is not None else None):\n            return False, f"agent back-link wrong at seq {i}"\n')]),
    ("(LW-7e) in-span exact back-link check dropped", row_lw7_backlink, [lwx("        elif a in last_of:\n            if v != last_of[a]:", "        elif a in last_of:\n            if False:")]),
    ("(LW-7r) below-mark range check dropped", row_lw7_backlink, [lwx("        elif v is not None and not 1 <= v <= m:", "        elif False:")]),
    ("(LW-7n) back-link without an agent allowed", row_lw7_backlink, [lwx("            if v is not None:\n                return False, f\"agent back-link without", "            if False:\n                return False, f\"agent back-link without")]),
    ("(LW-8m) fork stores the second head as a mark", row_lw8_fork, [wmut(*FORK_STORE_BOTH)]),
    ("(LW-9m) replay trusts the stored (size, root)", row_lw9_replay, [mock.patch.object(wiring, "proven_marks", pm_trust_rows)]),
    ("(LW-9k) replay ignores the stored proof_kind above the root", row_lw9_replay, [mock.patch.object(wiring, "proven_marks", src_fn(wiring, "                if kind != PROOF_CHAIN:\n", "                if False:\n", "proven_marks"))]),
    ("(LW-9r) replay allows skeletons on the root row", row_lw9_replay, [mock.patch.object(wiring, "proven_marks", src_fn(wiring, "                if kind != PROOF_ROOT or ext != []:", "                if kind != PROOF_ROOT:", "proven_marks"))]),
    ("(LW-10w) wiring 256-skeleton cap removed", row_lw10_cap, [mock.patch.object(wiring, "_level_shape", src_fn(wiring, "    if len(ext) > lw.MAX_EXTENSION:", "    if False:", "_level_shape"))]),
    ("(LW-10l) lw.verify_extension cap removed", row_lw10_cap, [lwx("    if len(skeletons) > MAX_EXTENSION:\n", "    if False:\n")]),
    ("(LW-10r) route runs the witness verify before the level caps", row_lw10_cap, [mock.patch.object(wiring, "precheck_level", lambda level: None)]),
    ("(LW-10b) extension byte cap removed", row_lw10_bytes, [mock.patch.object(wiring, "_level_shape", src_fn(wiring, "    if len(json.dumps(ext).encode()) > lw.MAX_EXTENSION_BYTES:", "    if False:", "_level_shape"))]),
    ("(LF-m) current order: StaleHead raised before the stored-hash fork check", row_fork_order, [wmut("    latest = marks[-1] if marks else None\n", "    latest = marks[-1] if marks else None\n    if latest is not None and seq < latest.size:\n        raise StaleHead(\"mutant: stale first\")\n")]),
]

R_ = []
for label, fn in ROWS:
    try: ok = bool(fn())
    except Exception as e: ok = False; label += f" [ERROR {type(e).__name__}: {e}]"
    R_.append((label, ok)); print(f"  {'ok  ' if ok else 'FAIL'} {label}")
table = []
for name, row, patches in MUT + LW_MUT:
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
