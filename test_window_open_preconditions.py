#!/usr/bin/env python3
"""ART-40 / ART-41 belt for window_open.py. Scratch DB only."""
import os, sys, tempfile
os.environ["CYBERNET_DB_DIR"] = tempfile.mkdtemp(prefix="wop-")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
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

GOOD = _ed.publickey(bytes.fromhex("66" * 32)).hex()
ZERO = "00" * 32                       # y=0: small-order (order 4)
IDENT = "01" + "00" * 31               # identity point
NONCANON = "ed" + "ff" * 30 + "7f"     # y = p (>= p), non-canonical
check("good key not weak", wo.weak_reason(GOOD) is None)
check("zero key small-order", wo.weak_reason(ZERO) == "small-order", wo.weak_reason(ZERO))
check("identity small-order", wo.weak_reason(IDENT) == "small-order", wo.weak_reason(IDENT))
check("y>=p non-canonical", wo.weak_reason(NONCANON) == "non-canonical", wo.weak_reason(NONCANON))
check("bad hex weak", wo.weak_reason("zz") == "not-hex")

FUT, PAST = "2099-01-01T00:00:00+00:00", "2000-01-01T00:00:00+00:00"
with core._db_lock, core._db() as conn:
    wo.init_schema(conn)
    rows = [("alive", GOOD, FUT), ("zeroname", ZERO, FUT), ("identname", IDENT, FUT), ("oldgood", GOOD, PAST)]
    conn.executemany("INSERT INTO name_bindings (name,node_pubkey,issued_at,expires_at,signature) VALUES (?,?,?,?,?)",
                     [(n, p, PAST, e, "00" * 64) for n, p, e in rows])
    cc = wo._cols(conn, "name_conflicts")
    vals = {"name": "alive", "incumbent_pubkey": GOOD, "challenger_pubkey": ZERO}
    for c in cc - set(vals) - {"id"}:
        vals[c] = "x"
    conn.execute(f"INSERT INTO name_conflicts ({','.join(vals)}) VALUES ({','.join('?'*len(vals))})", list(vals.values()))
    # this tree's agents table has no agent_pubkey (api-key auth); scanner
    # must skip it cleanly, then pick it up once the identity column exists
    check("agents without agent_pubkey skipped", not any(r[0].startswith("agents") for r in wo.scan_weak(conn)))
    conn.execute("ALTER TABLE agents ADD COLUMN agent_pubkey TEXT")
    conn.executemany("INSERT INTO agents (name,api_key_hash,salt,created_at,agent_pubkey) VALUES (?,?,?,?,?)",
                     [("a1", "h", "s", PAST, GOOD), ("a2", "h", "s", PAST, NONCANON)])
    snap = wo.snapshot_bindings(conn)
held = [r[0] for r in snap["held"]]; refused = [r[0] for r in snap["refused"]]
check("snapshot: weak keys refused, never held", set(refused) == {"zeroname", "identname"} and not set(refused) & set(held), snap)
check("snapshot: no SQL expires filter (expired good row still read)", "oldgood" in held, held)

# ART-41 before open: no starts
with core._db_lock, core._db() as conn:
    ok, why = wo.check_start_cap(conn, "acct")
check("no start before open_window recorded", not ok and "not open" in why, why)

OPEN = "2026-10-12T16:00:00+00:00"
e = wo.open_window("villhaze", now=OPEN)
check("open_window records anchor", e["opened_at"] == OPEN and not e["already_open"], e)
check("open_window records 4 refused rows (2 bindings, 1 conflict, 1 agent)", e["refused_recorded"] == 4, e)
e2 = wo.open_window("someone", now="2030-01-01T00:00:00+00:00")
check("open_window idempotent (anchor unchanged)", e2["already_open"] and e2["opened_at"] == OPEN, e2)
with core._db_lock, core._db() as conn:
    srcs = sorted(r[0] for r in conn.execute("SELECT source FROM window_refused_bindings"))
    check("refused entry covers all three columns", set(srcs) == {"name_bindings.node_pubkey", "name_conflicts.challenger_pubkey", "agents.agent_pubkey"}, srcs)
    check("replay: pre-recorded row recognised", wo.is_prerecorded_refusal(conn, "name_bindings.node_pubkey", "zeroname", ZERO))
    check("replay: new weak row not pre-recorded", not wo.is_prerecorded_refusal(conn, "name_bindings.node_pubkey", "later", ZERO))
    # pre-window rows (e.g. TLS go-live era) do NOT count toward the cap
    conn.executemany("INSERT INTO legacy_migrations (account,kind,started_at) VALUES (?,?,?)",
                     [("acct", "rotation", "2026-10-01T00:00:00+00:00")] * 5)

TLS_GOLIVE = "2026-10-01T00:00:00+00:00"
res = [wo.record_start("acct", k, now=t) for k, t in
       [("rotation", "2026-10-12T16:00:00+00:00"), ("recovery", "2026-10-12T17:00:00+00:00"),
        ("rotation", "2026-10-13T00:00:00+00:00"), ("recovery", "2026-10-14T00:00:00+00:00")]]
check("anchor is open_window, not TLS: 5 pre-window rows ignored, 3 starts allowed", [r[0] for r in res[:3]] == [True]*3, res)
check("4th start since open_window refused (cap 3, all kinds counted)", res[3][0] is False and "cap reached" in res[3][1], res[3])
check("other account unaffected", wo.record_start("other", "rotation", now="2026-10-13T00:00:00+00:00")[0])
print(f"{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
