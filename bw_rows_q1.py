#!/usr/bin/env python3
"""Bulwark Q1 rows (floor fix 5 + refused-bindings filter), r5 50ce5cc.
GUARD rows kill mutants the existing belts let survive (they PASS on r5).
FINDING rows demonstrate defects (they FAIL on r5; the smallest fix makes them pass).
Run: ./venv/bin/python bw_rows_q1.py   (TREE=/path to point elsewhere)"""
import os, sys, tempfile, time, threading
from datetime import datetime, timedelta, timezone
TREE = os.environ.get("TREE") or os.path.dirname(os.path.abspath(__file__))
os.environ["CYBERNET_DB_DIR"] = tempfile.mkdtemp(prefix="bw-q1-rows-")
sys.path.insert(0, TREE)
import core; core.init_db()            # noqa: E402
import refused_bindings as rb          # noqa: E402
import fed.ed25519 as _fe              # noqa: E402
NOW = datetime.now(timezone.utc); iso = lambda d: d.strftime("%Y-%m-%dT%H:%M:%SZ")
RES = []
def row(rid, kind, ok, detail):
    RES.append((rid, kind, ok)); print(f"{rid:7s} {kind:7s} {'PASS' if ok else 'FAIL'}  {detail}")
def R(**k):
    d = dict(name="abcd", node_pubkey="a" * 64, issued_at="2026-10-01T00:00:00Z",
             expires_at="2027-10-01T00:00:00Z"); d.update(k); return d
M = {"abcd"}
# ---- GUARD rows (kill surviving mutants)
row("Q1-G1", "GUARD", rb.classify_binding(R(), M) is None
    and rb.classify_binding(R(expires_at="2027-10-01T00:00:01Z"), M) == "expiry-cap",
    "365d exactly is hold-eligible; 365d+1s is expiry-cap  [kills RM1 >= cap]")
row("Q1-G2", "GUARD", all(rb.classify_binding(R(issued_at=v), M) == "expiry-cap"
    for v in (None, "", "2026-10-01", "2026-10-01T00:00:00", 1790000000)) and
    rb.classify_binding({k: v for k, v in R().items() if k != "issued_at"}, M) == "expiry-cap",
    "missing/naive/date-only/int issued_at -> expiry-cap  [kills RM4 no-issued check]")
row("Q1-G3", "GUARD", rb.refused_leaf("ab", "AB" * 32, "length") == rb.refused_leaf("ab", "ab" * 32, "length"),
    "leaf pubkey is lowercased (one leaf per binding regardless of case)  [kills RM5]")
# gossip send-half: live canonical expiry + unparseable issued_at must not be gossiped
with core._db_lock, core._db() as conn:
    conn.execute("INSERT INTO name_bindings (name,node_pubkey,issued_at,expires_at,signature) VALUES (?,?,?,?,?)",
                 ("g1-bad-issued", "c" * 64, "2026-10-17T10:00:00", iso(NOW + timedelta(days=9)), "d" * 128))
    conn.execute("INSERT INTO name_bindings (name,node_pubkey,issued_at,expires_at,signature) VALUES (?,?,?,?,?)",
                 ("g1-good", "e" * 64, iso(NOW - timedelta(minutes=1)), iso(NOW + timedelta(days=9)), "f" * 128))
    cols = [r[1] for r in conn.execute("PRAGMA table_info(peers)")]
    vals = {c: "" for c in cols}; vals.update(node_pub="9" * 64, node_url="http://192.0.2.1:9", retired_at="", first_seen=iso(NOW))
    conn.execute(f"INSERT INTO peers ({','.join(vals)}) VALUES ({','.join('?' * len(vals))})", tuple(vals.values()))
SENT = []
_mk = core._fed_env.make_envelope
core._fed_env.make_envelope = lambda priv, pub, to, body: SENT.append(body) or _mk(priv, pub, to, body)
_T = threading.Thread
class _NoThread:
    def __init__(s, *a, **k): pass
    def start(s): pass
core.threading.Thread = _NoThread
core._names_gossip_out()
core.threading.Thread = _T
names = {b["name"] for body in SENT for b in body["bindings"]}
row("Q1-G4", "GUARD", "g1-good" in names and "g1-bad-issued" not in names,
    f"gossip-out skips row with unparseable issued_at (sent={sorted(names)})  [kills FM5]")
# ---- FINDING rows
row("Q1-F1", "FINDING", all(rb.classify_binding(R(node_pubkey=p), M) is not None
    for p in ("zz", None, 123, "aa\nreason=grammar", "g" * 64)) and
    rb.classify_binding({k: v for k, v in R().items() if k != "node_pubkey"}, M) is not None,
    "filter refuses non-64-hex/missing pubkey (no hold with a garbage key; no leaf-line injection)")
row("Q1-F2", "FINDING", rb.classify_binding(R(issued_at="2027-01-01T00:00:00Z", expires_at="2026-01-01T00:00:00Z"), M) is not None
    and rb.classify_binding(R(expires_at="2026-10-01T00:00:00Z"), M) is not None,
    "filter refuses expires_at <= issued_at (inverted/zero-life binding gets no hold)")
def _t(n):
    L = [f"n{i:06d}" for i in range(n)]; rows = [R(name=l) for l in L]
    t = time.perf_counter(); rb.snapshot_refused_bindings(rows, set(L)); return time.perf_counter() - t
a, b = _t(1000), _t(4000)
row("Q1-F3", "FINDING", b / max(a, 1e-9) < 8, f"snapshot cost linear in rows x manifest (4x input -> {b/a:.1f}x time; quadratic ~16x)")
# lazy GC parity with floor fix 5: two unparseable legacy rows must be treated alike
with core._db_lock, core._db() as conn:
    for nm, ex in (("gc-naive-past", "2026-01-01T00:00:00"), ("gc-garbage", "zzzz")):
        conn.execute("INSERT INTO name_bindings (name,node_pubkey,issued_at,expires_at,signature) VALUES (?,?,?,?,?)",
                     (nm, "1" * 64, ex, ex, "2" * 128))
    core._name_registry_has_room(conn)
    left = {r[0] for r in conn.execute("SELECT name FROM name_bindings WHERE name LIKE 'gc-%'")}
row("Q1-F4", "FINDING", len(left) in (0, 2), f"lazy GC (core.py _name_registry_has_room) treats unparseable rows alike; survivors={sorted(left)}")
cnt = [0]; _cv = _fe.checkvalid
def _c(*x): cnt[0] += 1; return _cv(*x)
_fe.checkvalid = _c
out = core.ingest_gossiped_binding(dict(name="ing-x", node_pubkey="a" * 64, issued_at="garbage",
                                        expires_at="garbage", signature="ab" * 64))
_fe.checkvalid = _cv
row("Q1-F5", "FINDING", cnt[0] == 0 and out == "dropped-malformed",
    f"gossip ingest refuses unparseable stamps before Ed25519 (got {out}, verifies={cnt[0]})")
f = [r for r, k, ok in RES if not ok]
print("---\nGUARD fails: %s | FINDING fails: %s" % ([r for r, k, ok in RES if k == "GUARD" and not ok],
                                                   [r for r, k, ok in RES if k == "FINDING" and not ok]))
sys.exit(1 if [r for r, k, ok in RES if k == "GUARD" and not ok] else 0)
