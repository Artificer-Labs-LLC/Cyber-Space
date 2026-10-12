#!/usr/bin/env python3
# PROVENANCE (Examiner item 5): ported onto origin/villhaze/q1-name-fixes-r3
# @ 3cadf03 by cherry-pick, branch oracle/window-open-preconditions-r2.
# Source commits on oracle/window-open-preconditions (off 8e9291a):
#   86256ae (ART-40/41 minimal window_open) -> r2 3351f0f
#   7cc71a8 (board BLOCK fixes: mixed-order, chain-walk reserve, cap) -> r2 cf285cf
#   r2 follow-up: window close + naive/date-only e2e (Examiner items 6,7)
"""ART-40 / ART-41 belt for window_open.py (post-BLOCK). Scratch DB only."""
import os, sys, tempfile
os.environ["CYBERNET_DB_DIR"] = tempfile.mkdtemp(prefix="wop-")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import inspect  # noqa: E402
import core  # noqa: E402
core.init_db()
import core_serve  # noqa: E402,F401
from fed import ed25519 as _ed  # noqa: E402
import window_open as wo  # noqa: E402

PASS = FAIL = 0
def check(label, cond, extra=""):
    global PASS, FAIL
    if cond: PASS += 1; print(f"  ok  {label}")
    else: FAIL += 1; print(f"  FAIL {label} {extra}")

def order(P):
    Q, n = P, 1
    while Q != _ed._IDENT and n <= 8:
        Q = _ed._edwards(Q, P); n += 1
    return n

HONEST_P = _ed._scalarmult(_ed._BPOINT, 0x1234567)
GOOD = _ed._encodepoint(HONEST_P).hex()
T2 = (0, _ed._Q - 1)
T4 = (_ed._I, 0)
T8 = _ed._decodepoint_strict(bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"))
check("torsion orders 2/4/8", (order(T2), order(T4), order(T8)) == (2, 4, 8), (order(T2), order(T4), order(T8)))
MIXED = {n: _ed._encodepoint(_ed._edwards(HONEST_P, T)).hex() for n, T in ((2, T2), (4, T4), (8, T8))}
ZERO = "00" * 32
IDENT = "01" + "00" * 31
NONCANON = "ed" + "ff" * 30 + "7f"
check("honest key not weak", wo.weak_reason(GOOD) is None, wo.weak_reason(GOOD))
for n, k in MIXED.items():
    check(f"honest+order-{n} torsion -> mixed-order", wo.weak_reason(k) == "mixed-order", wo.weak_reason(k))
check("zero key small-order", wo.weak_reason(ZERO) == "small-order")
check("identity small-order", wo.weak_reason(IDENT) == "small-order")
check("y>=p non-canonical", wo.weak_reason(NONCANON) == "non-canonical")
check("bad hex weak", wo.weak_reason("zz") == "not-hex")

K = _ed.publickey(bytes.fromhex("77" * 32)).hex()
FUT, PAST = "2099-01-01T00:00:00+00:00", "2000-01-01T00:00:00+00:00"
with core._db_lock, core._db() as conn:
    wo.init_schema(conn)
    rows = [("alive", GOOD, FUT), ("zeroclaim", ZERO, FUT), ("oldgood", GOOD, PAST),
            ("rotzero", ZERO, FUT), ("rotmixed", MIXED[8], FUT),
            ("chain", MIXED[4], FUT), ("loop", MIXED[2], FUT), ("rotzero2", ZERO, FUT)]
    conn.executemany("INSERT INTO name_bindings (name,node_pubkey,issued_at,expires_at,signature) VALUES (?,?,?,?,?)",
                     [(n, p, PAST, e, "00" * 64) for n, p, e in rows])
    for nm, newk in (("rotzero", ZERO), ("rotmixed", MIXED[8])):
        conn.execute("INSERT INTO name_rotations (name,old_pubkey,new_pubkey,issued_at,signature,accepted_at) VALUES (?,?,?,?,?,?)",
                     (nm, K, newk, PAST, "00" * 64, PAST))
    # Loom chain: K -> Z1 (zero) -> Z2 (mixed-order); loop: M2 -> ID -> M2
    K2 = _ed.publickey(bytes.fromhex("88" * 32)).hex()
    FORGER = _ed.publickey(bytes.fromhex("99" * 32)).hex()
    conn.execute("INSERT INTO name_rotations (name,old_pubkey,new_pubkey,issued_at,signature,accepted_at) VALUES (?,?,?,?,?,?)",
                 ("rotzero2", K2, ZERO, PAST, "00" * 64, PAST))
    # Examiner: forged hop into "chain" with a backdated-but-newest-looking
    # issued_at and an OLDER node-side accepted_at -> must not win
    conn.execute("INSERT INTO name_rotations (name,old_pubkey,new_pubkey,issued_at,signature,accepted_at) VALUES (?,?,?,?,?,?)",
                 ("chain", FORGER, ZERO, "1990-01-01T00:00:00+00:00", "00" * 64, "2003-01-01T00:00:00+00:00"))
    # Lodestar/Cipher any-weak-hop rule: K->Z->A, K->Z1->A->Z2->B, K->Z->K2
    A_ = _ed.publickey(bytes.fromhex("aa" * 32)).hex()
    B_ = _ed.publickey(bytes.fromhex("bb" * 32)).hex()
    K3 = _ed.publickey(bytes.fromhex("cc" * 32)).hex()
    HK = [("hza", A_), ("hzazb", B_), ("hzk2", K2), ("pocz1", ZERO)]
    XATK = _ed.publickey(bytes.fromhex("dd" * 32)).hex()
    conn.executemany("INSERT INTO name_bindings (name,node_pubkey,issued_at,expires_at,signature) VALUES (?,?,?,?,?)",
                     [(n, p, PAST, FUT, "00" * 64) for n, p in HK])
    for nm, o, n_, t in (("hza", K3, ZERO, "2001"), ("hza", ZERO, A_, "2002"),
                         ("hzazb", K3, ZERO, "2001"), ("hzazb", ZERO, A_, "2002"),
                         ("hzazb", A_, MIXED[8], "2003"), ("hzazb", MIXED[8], B_, "2004"),
                         ("hzk2", K3, ZERO, "2001"), ("hzk2", ZERO, K2, "2002"),
                         ("pocz1", ZERO, XATK, "2001"), ("pocz1", XATK, ZERO, "2002")):
        conn.execute("INSERT INTO name_rotations (name,old_pubkey,new_pubkey,issued_at,signature,accepted_at) VALUES (?,?,?,?,?,?)",
                     (nm, o, n_, PAST, "00" * 64, t + "-01-01T00:00:00+00:00"))
    for nm, o, n_, t in (("chain", K, ZERO, "2001"), ("chain", ZERO, MIXED[4], "2002"),
                         ("loop", MIXED[2], IDENT, "2001"), ("loop", IDENT, MIXED[2], "2002")):
        conn.execute("INSERT INTO name_rotations (name,old_pubkey,new_pubkey,issued_at,signature,accepted_at) VALUES (?,?,?,?,?,?)",
                     (nm, o, n_, PAST, "00" * 64, t + "-01-01T00:00:00+00:00"))
    # Examiner item 1: Z1 claimed directly (no hop INTO Z1), then honest Z1->X.
    # Kills the mutant that fires only on weak new_pubkey.
    XH = _ed.publickey(bytes.fromhex("ee" * 32)).hex()
    conn.execute("INSERT INTO name_bindings (name,node_pubkey,issued_at,expires_at,signature) VALUES (?,?,?,?,?)",
                 ("z1claimx", XH, PAST, FUT, "00" * 64))
    conn.execute("INSERT INTO name_rotations (name,old_pubkey,new_pubkey,issued_at,signature,accepted_at) VALUES (?,?,?,?,?,?)",
                 ("z1claimx", ZERO, XH, PAST, "00" * 64, "2001-01-01T00:00:00+00:00"))
    # Repeat hops, modelling INSERT OR IGNORE on (name,old,new) (routes_social_serve.py:1327-1331):
    # K->Z1->X->Z1->X; repeats keep their FIRST accepted_at.
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS t_rot_dedup ON name_rotations(name,old_pubkey,new_pubkey)")
    conn.execute("INSERT INTO name_bindings (name,node_pubkey,issued_at,expires_at,signature) VALUES (?,?,?,?,?)",
                 ("repeat", XH, PAST, FUT, "00" * 64))
    for o, n_, t in ((K3, ZERO, "2001"), (ZERO, XH, "2002"), (XH, ZERO, "2003"), (ZERO, XH, "2004")):
        conn.execute("INSERT OR IGNORE INTO name_rotations (name,old_pubkey,new_pubkey,issued_at,signature,accepted_at) VALUES (?,?,?,?,?,?)",
                     ("repeat", o, n_, PAST, "00" * 64, t + "-01-01T00:00:00+00:00"))
    rep_rows = conn.execute("SELECT old_pubkey,new_pubkey,accepted_at FROM name_rotations WHERE name='repeat' ORDER BY rowid").fetchall()
    cc = wo._cols(conn, "name_conflicts")
    vals = {"name": "alive", "incumbent_pubkey": GOOD, "challenger_pubkey": MIXED[2]}
    for c in cc - set(vals) - {"id"}:
        vals[c] = "x"
    conn.execute(f"INSERT INTO name_conflicts ({','.join(vals)}) VALUES ({','.join('?'*len(vals))})", list(vals.values()))
    check("agents without agent_pubkey skipped", not any(r[0].startswith("agents") for r in wo.scan_weak(conn)))
    conn.execute("ALTER TABLE agents ADD COLUMN agent_pubkey TEXT")
    conn.executemany("INSERT INTO agents (name,api_key_hash,salt,created_at,agent_pubkey) VALUES (?,?,?,?,?)",
                     [("a1", "h", "s", PAST, GOOD), ("a2", "h", "s", PAST, NONCANON)])
    snap = wo.snapshot_bindings(conn)
held = {r[0] for r in snap["held"]}; refused = {r[0] for r in snap["refused"]}
reserved = {r["name"]: r["reserved_for"] for r in snap["reserved"]}
check("zero-key claim (no rotation) -> refused", "zeroclaim" in refused, refused)
check("K->Z->A (honest current) -> reserved for K", reserved.get("hza") == K3, reserved)
check("K->Z1->A->Z2->B -> reserved for K (earliest weak hop)", reserved.get("hzazb") == K3, reserved)
check("K->Z->K2 -> reserved for K, not K2", reserved.get("hzk2") == K3, reserved)
check("honest-current reserved names not held", not held & {"hza", "hzazb", "hzk2"}, held)
check("two names rotated to Z1: each reserved for its own key", reserved.get("rotzero") == K and reserved.get("rotzero2") == K2, reserved)
check("forged backdated hop does not change reserved key", reserved.get("chain") == K and FORGER not in reserved.values(), reserved)
check("chain K->Z1(zero)->Z2(mixed) -> reserved for K", reserved.get("chain") == K, reserved)
lp = [r for r in snap["refused"] if r[0] == "loop"]
check("loop chain (starts weak) -> refused + FLAG-VILLHAZE", lp and "starts on weak key" in lp[0][-1], lp)
poc = [r for r in snap["refused"] if r[0] == "pocz1"]
check("PoC Z1->X->Z1 -> refused, FLAG starts on weak key", poc and "starts on weak key" in poc[0][-1], poc)
check("PoC Z1->X->Z1 not reserved (not for attacker X)", "pocz1" not in reserved, reserved)
z1x = [r for r in snap["refused"] if r[0] == "z1claimx"]
check("Examiner item 1: Z1 claimed then Z1->X -> refused, FLAG starts on weak key", z1x and "FLAG-VILLHAZE: chain starts on weak key" in z1x[0][-1], z1x)
check("Examiner item 1: Z1 claimed then Z1->X not reserved, not held", "z1claimx" not in reserved and "z1claimx" not in held, (reserved, held))
check("repeat hops: INSERT OR IGNORE kept 3 rows, Z1->X keeps first accepted_at", len(rep_rows) == 3 and rep_rows[1][2].startswith("2002"), rep_rows)
check("repeat hops K->Z1->X->Z1->X -> reserved for K", reserved.get("repeat") == K3, reserved)
check("refused set exactly {zeroclaim, loop, pocz1, z1claimx}", refused == {"zeroclaim", "loop", "pocz1", "z1claimx"}, refused)
check("zero-key rotation from real K -> reserved for K", reserved.get("rotzero") == K, reserved)
check("mixed-order rotation from real K -> reserved for K", reserved.get("rotmixed") == K, reserved)
check("no weak key held", not held & ({"zeroclaim", "rotzero", "rotmixed"}), held)
check("snapshot: no SQL expires filter", "oldgood" in held, held)

# ART-41: no public `now`
check("open_window takes no caller now", "now" not in inspect.signature(wo.open_window).parameters)
check("record_start takes no caller now", "now" not in inspect.signature(wo.record_start).parameters)

def rows_for(acct):
    with core._db_lock, core._db() as conn:
        return conn.execute("SELECT COUNT(*) FROM legacy_migrations WHERE account=?", (acct,)).fetchone()[0]

def start(acct, kind="rotation"):
    try:
        wo.record_start(acct, kind); return 200
    except wo.StartRefused as e:
        return e.status_code

check("pre-open start refused 409", start("early") == 409)
check("pre-open refusal wrote no row", rows_for("early") == 0, rows_for("early"))

wo._now_hook = lambda: "2026-10-12T16:00:00+00:00"
e = wo.open_window("villhaze")
check("open_window records anchor", e["opened_at"] == "2026-10-12T16:00:00+00:00" and not e["already_open"], e)
check("open_window records 9 refused rows (7 bindings, 1 conflict, 1 agent)", e["refused_recorded"] == 9, e)
check("open_window idempotent", wo.open_window("someone")["already_open"])
with core._db_lock, core._db() as conn:
    srcs = {r[0] for r in conn.execute("SELECT source FROM window_refused_bindings")}
    check("refused entry covers all three columns", srcs == {"name_bindings.node_pubkey", "name_conflicts.challenger_pubkey", "agents.agent_pubkey"}, srcs)
    check("replay: pre-recorded row recognised", wo.is_prerecorded_refusal(conn, "name_bindings.node_pubkey", "zeroclaim", ZERO))
    check("replay: new weak row not pre-recorded", not wo.is_prerecorded_refusal(conn, "name_bindings.node_pubkey", "later", ZERO))

codes = [start("acct") for _ in range(3)]
wo._now_hook = lambda: "2020-01-01T00:00:00+00:00"  # backdated
codes.append(start("acct", "recovery"))
check("3 starts ok, backdated 4th refused 409", codes == [200, 200, 200, 409], codes)
check("refused 4th wrote no row", rows_for("acct") == 3, rows_for("acct"))
with core._db_lock, core._db() as conn:
    conn.executemany("INSERT INTO legacy_migrations (account,kind,started_at) VALUES (?,?,?)",
                     [("zfmt", "rotation", "2026-10-12T17:00:00Z"), ("zfmt", "rotation", "2026-10-12T17:00:00+00:00"),
                      ("zfmt", "rotation", "2000-01-01T00:00:00Z")])
wo._now_hook = lambda: "2026-10-13T00:00:00+00:00"
check("Z and +00:00 (and pre-window) rows all count: 4th refused 409", start("zfmt") == 409)
check("other account unaffected", start("other") == 200)

# Examiner item 6: naive and date-only timestamps, end to end
with core._db_lock, core._db() as conn:
    conn.executemany("INSERT INTO name_bindings (name,node_pubkey,issued_at,expires_at,signature) VALUES (?,?,?,?,?)",
                     [("naive", GOOD, "2026-10-12 10:00:00", "2099-01-01 00:00:00", "00" * 64),
                      ("dateonly", GOOD, "2026-10-12", "2099-01-01", "00" * 64),
                      ("naivezero", ZERO, "2026-10-12 10:00:00", "2099-01-01", "00" * 64),
                      ("naiveold", GOOD, "2000-01-01", "2000-01-02", "00" * 64)])
    conn.executemany("INSERT INTO legacy_migrations (account,kind,started_at) VALUES (?,?,?)",
                     [("fmt2", "rotation", "2026-10-12 17:00:00"), ("fmt2", "recovery", "2026-10-12"),
                      ("fmt2", "rotation", "2026-10-12T17:00:00")])
    snap2 = wo.snapshot_bindings(conn)
h2 = {r[0] for r in snap2["held"]}; f2 = {r[0] for r in snap2["refused"]}
check("e2e: naive/date-only honest bindings held (no expires parse/filter)", {"naive", "dateonly", "naiveold"} <= h2, h2)
check("e2e: naive-timestamp zero-key binding refused", "naivezero" in f2, f2)
check("e2e: naive + date-only + T-naive start rows all count (4th -> 409)", start("fmt2") == 409)
check("e2e: refused start wrote no row", rows_for("fmt2") == 3, rows_for("fmt2"))

# Examiner item 7: window close; late 4th start after close refused
check("late account has 2 starts before close", [start("late"), start("late")] == [200, 200])
wo._now_hook = lambda: "2026-10-20T00:00:00+00:00"
c = wo.close_window("villhaze")
check("close_window recorded", c["closed_at"] == "2026-10-20T00:00:00+00:00" and not c["already_closed"], c)
check("close_window idempotent", wo.close_window("x")["already_closed"])
check("start after close refused 409 (account under cap)", start("late") == 409)
check("late 4th start after close refused 409", start("acct") == 409)
check("post-close refusals wrote no rows", rows_for("late") == 2 and rows_for("acct") == 3, (rows_for("late"), rows_for("acct")))
wo._now_hook = None

# Board BLOCK on dd79315 (orphan pass): expired bindings are reaped by
# core._name_registry_has_room on any claim; the reservation must survive.
OK_ = _ed.publickey(bytes.fromhex("31" * 32)).hex()
OX = _ed.publickey(bytes.fromhex("32" * 32)).hex()
OXP = _ed.publickey(bytes.fromhex("33" * 32)).hex()
with core._db_lock, core._db() as conn:
    conn.executemany("INSERT INTO name_bindings (name,node_pubkey,issued_at,expires_at,signature) VALUES (?,?,?,?,?)",
                     [("orphk", ZERO, PAST, PAST, "00" * 64), ("orphz", ZERO, PAST, PAST, "00" * 64),
                      ("orphzx", OX, PAST, PAST, "00" * 64), ("orphre", ZERO, PAST, PAST, "00" * 64)])
    for nm, o, n_ in (("orphk", OK_, ZERO), ("orphzx", ZERO, OX), ("orphre", OK_, ZERO)):
        conn.execute("INSERT INTO name_rotations (name,old_pubkey,new_pubkey,issued_at,signature,accepted_at) VALUES (?,?,?,?,?,?)",
                     (nm, o, n_, PAST, "00" * 64, "2001-01-01T00:00:00+00:00"))
    core._name_registry_has_room(conn)  # the reap any claimer can trigger
    gone = {r[0] for r in conn.execute("SELECT name FROM name_bindings WHERE name LIKE 'orph%'")}
    conn.execute("INSERT INTO name_bindings (name,node_pubkey,issued_at,expires_at,signature) VALUES (?,?,?,?,?)",
                 ("orphre", OXP, PAST, FUT, "00" * 64))  # X' claims fresh
    osnap = wo.snapshot_bindings(conn)
ores = {r["name"]: r["reserved_for"] for r in osnap["reserved"]}
oref = {r[0]: r[-1] for r in osnap["refused"]}
ohel = {r[0] for r in osnap["held"]}
check("orphan: reap removed the expired bindings", not gone, gone)
check("orphan: K->Z1, Z1 reaped -> reserved for K", ores.get("orphk") == OK_, ores)
check("orphan: Z1 claimed directly, reaped, no history -> in no list", "orphz" not in ores and "orphz" not in oref and "orphz" not in ohel)
check("orphan: Z1->X, X reaped -> refused, FLAG starts on weak key", "starts on weak key" in str(oref.get("orphzx")), oref)
check("orphan: K->Z1, Z1 reaped, X' claims fresh -> reserved for K", ores.get("orphre") == OK_ and "orphre" not in ohel, (ores, ohel))
# Villhaze 5b1c941d (ART-40): a weak-key rotation from K merged in through
# GOSSIP is recorded with the mirror's local accepted_at and reserved for K.
from rotate_name import mint_rotation  # noqa: E402
GSEED = bytes.fromhex("ee" * 32)
GK = _ed.publickey(GSEED).hex()
grec = mint_rotation("gossipz", GSEED, ZERO, issued_at=PAST)
CSEED = bytes.fromhex("ab" * 32)
CK = _ed.publickey(CSEED).hex()
CMID = _ed.publickey(bytes.fromhex("ac" * 32)).hex()
gchain = [mint_rotation("gossipc", CSEED, CMID, issued_at=PAST)]
with core._db_lock, core._db() as conn:
    conn.executemany("INSERT INTO name_bindings (name,node_pubkey,issued_at,expires_at,signature) VALUES (?,?,?,?,?)",
                     [("gossipz", GK, PAST, FUT, "00" * 64), ("gossipc", CK, PAST, FUT, "00" * 64)])
    ok1 = core._gossiped_rotation_designates(grec, "gossipz", GK, ZERO, FUT, conn=conn)
    ok1b = core._gossiped_rotation_designates(grec, "gossipz", GK, ZERO, FUT, conn=conn)  # replayed gossip
    ok_no = core._gossiped_rotation_designates(grec, "gossipz", CK, ZERO, FUT, conn=conn)  # wrong holder
    # chain twin: CK -> CMID (honest) -> ZERO; hop 2 is signed by CMID's seed
    gchain.append(mint_rotation("gossipc", bytes.fromhex("ac" * 32), ZERO, issued_at=PAST))
    ok2 = core._gossiped_rotation_chain_designates(gchain, "gossipc", CK, ZERO, FUT, conn=conn)
    grows = conn.execute("SELECT old_pubkey,new_pubkey,issued_at,accepted_at FROM name_rotations WHERE name='gossipz'").fetchall()
    crows = conn.execute("SELECT COUNT(*) FROM name_rotations WHERE name='gossipc'").fetchone()[0]
    gsnap = wo.snapshot_bindings(conn)
gres = {r["name"]: r["reserved_for"] for r in gsnap["reserved"]}
gheld = {r[0] for r in gsnap["held"]}
check("gossip H3: weak new_pubkey K->Z1 refused by the merge (never bound)", not ok1 and not ok1b, (ok1, ok1b))
check("gossip: record from a non-holder designates nothing and writes nothing", not ok_no and len(grows) == 1)
check("gossip: one name_rotations row (INSERT OR IGNORE on replay)", len(grows) == 1 and grows[0][:2] == (GK, ZERO), grows)
check("gossip: accepted_at is LOCAL now, not the peer's issued_at", grows and grows[0][3] != PAST and grows[0][3][:4] >= "2026", grows)
check("gossip: weak-key rotation from K merged via gossip -> reserved for K", gres.get("gossipz") == GK, gres)
check("gossip chain H3: K->M->Z1 refused (weak tail), both hops recorded", not ok2 and crows == 2, (ok2, crows))
check("gossip chain: K->M->Z1 merged via gossip -> reserved for M (last non-weak)", gres.get("gossipc") == CMID, gres)
check("gossip: names with a recorded weak hop not held", not gheld & {"gossipz", "gossipc"}, gheld)

# Bulwark hostile rows (ART-40 44b3923c) on the gossip-merge INSERT.
HSEED = bytes.fromhex("e1" * 32); HK_ = _ed.publickey(HSEED).hex()
h1 = dict(mint_rotation("hostile1", HSEED, ZERO, issued_at=PAST), accepted_at="2001-01-01T00:00:00+00:00")
H2SEED = bytes.fromhex("e2" * 32); H2K = _ed.publickey(H2SEED).hex()
h2 = mint_rotation("hostile2", H2SEED, ZERO, issued_at=PAST)
H3SEED = bytes.fromhex("e3" * 32); H3K = _ed.publickey(H3SEED).hex()
h3 = mint_rotation("hostile3", H3SEED, MIXED[8], issued_at=PAST)
with core._db_lock, core._db() as conn:
    conn.executemany("INSERT INTO name_bindings (name,node_pubkey,issued_at,expires_at,signature) VALUES (?,?,?,?,?)",
                     [("hostile1", HK_, PAST, FUT, "00" * 64), ("hostile2", H2K, PAST, FUT, "00" * 64),
                      ("hostile3", H3K, PAST, FUT, "00" * 64)])
    core._gossiped_rotation_designates(h1, "hostile1", HK_, ZERO, FUT, conn=conn)
    h1row = conn.execute("SELECT accepted_at FROM name_rotations WHERE name='hostile1'").fetchall()
    # H2: peer's K->Z1 lands first; our route-style INSERT OR IGNORE is then ignored
    core._gossiped_rotation_designates(h2, "hostile2", H2K, ZERO, FUT, conn=conn)
    conn.execute("INSERT OR IGNORE INTO name_rotations (name,old_pubkey,new_pubkey,issued_at,signature,accepted_at) VALUES (?,?,?,?,?,?)",
                 ("hostile2", H2K, ZERO, h2["issued_at"], h2["signature"], core._now()))
    h2rows = conn.execute("SELECT accepted_at FROM name_rotations WHERE name='hostile2'").fetchall()
    h3ok = core._gossiped_rotation_designates(h3, "hostile3", H3K, MIXED[8], FUT, conn=conn)
    h3bound = conn.execute("SELECT node_pubkey FROM name_bindings WHERE name='hostile3'").fetchone()[0]
    hsnap = wo.snapshot_bindings(conn)
hres = {r["name"]: r["reserved_for"] for r in hsnap["reserved"]}
check("H1: peer accepted_at=2001 ignored, stored row has local _now()", len(h1row) == 1 and not h1row[0][0].startswith("2001") and h1row[0][0][:4] >= "2026", h1row)
check("H1: name stays reserved for K", hres.get("hostile1") == HK_, hres)
check("H2: one surviving row, local accepted_at", len(h2rows) == 1 and h2rows[0][0][:4] >= "2026", h2rows)
check("H2: anchor still K", hres.get("hostile2") == H2K, hres)
check("H3: mixed-order new_pubkey via gossip refused, binding unchanged", not h3ok and h3bound == H3K, (h3ok, h3bound))
check("H3: name flagged (reserved for K), not held", hres.get("hostile3") == H3K and "hostile3" not in {r[0] for r in hsnap["held"]}, hres)
print(f"{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
