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
                 ("chain", FORGER, ZERO, "2098-01-01T00:00:00+00:00", "00" * 64, "1999-01-01T00:00:00+00:00"))
    for nm, o, n_, t in (("chain", K, ZERO, "2001"), ("chain", ZERO, MIXED[4], "2002"),
                         ("loop", MIXED[2], IDENT, "2001"), ("loop", IDENT, MIXED[2], "2002")):
        conn.execute("INSERT INTO name_rotations (name,old_pubkey,new_pubkey,issued_at,signature,accepted_at) VALUES (?,?,?,?,?,?)",
                     (nm, o, n_, PAST, "00" * 64, t + "-01-01T00:00:00+00:00"))
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
check("two names rotated to Z1: each reserved for its own key", reserved.get("rotzero") == K and reserved.get("rotzero2") == K2, reserved)
check("forged backdated hop does not change reserved key", reserved.get("chain") == K and FORGER not in reserved.values(), reserved)
check("chain K->Z1(zero)->Z2(mixed) -> reserved for K", reserved.get("chain") == K, reserved)
lp = [r for r in snap["refused"] if r[0] == "loop"]
check("loop chain -> refused + FLAG-VILLHAZE", lp and "loops" in lp[0][-1], lp)
check("refused set exactly {zeroclaim, loop}", refused == {"zeroclaim", "loop"}, refused)
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
check("open_window records 8 refused rows (6 bindings, 1 conflict, 1 agent)", e["refused_recorded"] == 8, e)
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
print(f"{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
