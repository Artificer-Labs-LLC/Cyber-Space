"""BW-DUPNAME-ANN (Bulwark, Research Board red-team).

EVIDENCE FOR A REJECTED OPTION, NOT A FIX.  Shows that a first-come HTTP 409
on fed_announce ("name already held by a different unretired node_pub")
makes a squat permanent: the attacker X announces the honest node P's name
first, and P can never get it back with its own key.

Method (copied from Lodestar's dupname_probe.py): drive the real
federation.fed_announce / fed_retire / fed_directory_delta handlers of the
tree at $TREE in a throwaway DB, node key from env var (no key file), then
run the exact invite SELECT read from routes_workspaces.py.  The 409 is an
in-memory wrapper around federation.fed_announce; no tree file is edited.

Usage (from the root of a Cyber-Space tree):  python bw_dupname_ann.py
        or  python bw_dupname_ann.py --tree <path>   or  TREE=<path> python bw_dupname_ann.py
        Tree precedence: --tree, then $TREE, then cwd.  DB root: $BW_DUPNAME_DB
        (default /workspace/bw-dupname/db).  Exit 0 only if every CONTROL and
        PATCHED row passes AND the mutant M-NO409 is killed by ANN-P-REFUSED;
        any unexpected FAIL or crash -> exit 1.
Scenarios: PATCHED, PATCHED_DELTA_OBS, CONTROL, M_NO409 (mutant).
"""
import hashlib, json, os, re, shutil, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
DBROOT = os.environ.get("BW_DUPNAME_DB", "/workspace/bw-dupname/db")
_a = sys.argv[1:]
TREE = os.path.abspath(_a[_a.index("--tree") + 1] if "--tree" in _a else os.environ.get("TREE") or os.getcwd())

def seed(label):  # fixed seeds -> byte-identical output across runs
    return hashlib.sha256(b"bw-dupname-ann/" + label.encode()).hexdigest()

# ----------------------------------------------------------------- worker
def worker(scn):
    db = os.path.join(DBROOT, scn)
    shutil.rmtree(db, ignore_errors=True); os.makedirs(db)   # always <DBROOT>/<SCENARIO>
    os.environ["CYBERNET_DB_DIR"] = db
    os.environ["CYBERNET_NODE_PRIVKEY"] = seed("local-node")
    from nacl.signing import SigningKey
    def kp(label):
        s = SigningKey(bytes.fromhex(seed(label)))
        return s.encode().hex(), s.verify_key.encode().hex()
    sys.path.insert(0, TREE); os.chdir(TREE)
    import core, federation
    from fastapi import HTTPException
    from fed import envelope as E
    core.init_db()
    core._check_rate = lambda *a, **k: None
    federation._check_rate = lambda *a, **k: None

    src = open(os.path.join(TREE, "routes_workspaces.py")).read().splitlines()
    Q = {}
    for i, l in enumerate(src, 1):
        m = re.search(r'"(SELECT node_pub, node_url FROM peers WHERE name=\? AND retired_at=\'\')"', l)
        if m: Q[i] = m.group(1)
    assert len(Q) == 3, Q

    # ---- the rejected option: first-come 409 on a taken name -------------
    orig_announce = federation.fed_announce
    ENFORCE = scn in ("PATCHED", "PATCHED_DELTA_OBS")   # M_NO409: wrapper present, guard removed
    def announce_409(env):
        if ENFORCE and isinstance(env, dict) and E.verify_envelope(env):
            body = env.get("body") or {}
            name, pub = str(body.get("name", "")), env.get("sender_pub")
            with core._db_lock, core._db() as c:
                held = c.execute("SELECT 1 FROM peers WHERE name=? AND retired_at=''"
                                 " AND node_pub<>?", (name, pub)).fetchone()
            if held:
                raise HTTPException(status_code=409, detail="name held by another node")
        return orig_announce(env)
    if scn != "CONTROL":
        federation.fed_announce = announce_409

    P, X, R = kp("P-honest"), kp("X-attacker"), kp("R-relay")
    LBL = {P[1]: "P", X[1]: "X", R[1]: "R"}
    U = "http://44.0.0.%d:8000"   # literal global IP: a3e6a08 SSRF gate refuses RFC1918; never dialled
    seqs = {}
    def call(fn, env):
        try:
            r = fn(env); return {"status": 200, **{k: v for k, v in r.items() if k in ("retired", "applied", "rejected", "stale", "note")}}
        except HTTPException as e:
            return {"status": e.status_code, "detail": e.detail}
    def announce(k, name, url):
        body = {"node_pub": k[1], "name": name, "node_url": url}
        return call(federation.fed_announce, E.make_envelope(k[0], k[1], "federation", body))
    def direct_retire(k):
        return call(federation.fed_retire, E.make_envelope(k[0], k[1], core._NODE_PUB, {"from_node_pub": k[1]}))
    def delta(relay, row_owner, signer, name, url, retire=False):
        seqs[row_owner[1]] = seqs.get(row_owner[1], 0) + 1; seq = seqs[row_owner[1]]
        row = {"node_pub": row_owner[1], "name": name, "node_url": url}
        sig = SigningKey(bytes.fromhex(signer[0])).sign(core._delta_payload(row, seq, retire)).signature.hex()
        body = {"from_node_pub": relay[1], "deltas": [{"row": row, "seq": seq, "sig": sig, "retire": retire}]}
        return call(federation.fed_directory_delta, E.make_envelope(relay[0], relay[1], core._NODE_PUB, body))
    def state():
        with core._db_lock, core._db() as c:
            rows = [(r["rowid"], LBL.get(r["node_pub"], "?"), r["name"], bool(r["retired_at"]), r["retire_origin"])
                    for r in c.execute("SELECT rowid, node_pub, name, retired_at, retire_origin FROM peers"
                                       " WHERE node_pub IN (?,?) ORDER BY rowid", (P[1], X[1]))]
            inv = {f"routes_workspaces.py:{ln}": LBL.get((c.execute(q, ("p",)).fetchone() or {"node_pub": None})["node_pub"])
                   for ln, q in Q.items()}
            live = [LBL.get(r[0]) for r in c.execute("SELECT node_pub FROM peers WHERE name='p' AND retired_at='' ORDER BY rowid")]
        return {"rows": rows, "invite": inv, "live_p": live}

    out = {"scenario": scn, "steps": {}}
    S = out["steps"]
    S["R_announce_relay"] = announce(R, "relay", U % 9)
    S["X_announce_p"] = announce(X, "p", U % 2)
    S["P_announce_p"] = announce(P, "p", U % 1)
    if scn == "CONTROL":
        S["state"] = state(); print(json.dumps(out, sort_keys=True)); return
    if scn == "PATCHED_DELTA_OBS":
        # informational: the 409 lives on fed_announce only; an owner-signed
        # relay-carried delta for P's name still inserts a second live row.
        S["P_delta_upsert_p_via_R"] = delta(R, P, P, "p", U % 1)
        S["state"] = state(); print(json.dumps(out, sort_keys=True)); return
    S["P_reannounce_p"] = announce(P, "p", U % 1)
    S["P_rows_before_retire"] = [r for r in state()["rows"] if r[1] == "P"]
    S["P_direct_retire_own"] = direct_retire(P)
    S["P_delta_retire_X_row_signed_by_P"] = delta(R, X, P, "p", U % 2, retire=True)
    S["P_delta_retire_own_key"] = delta(R, P, P, "p", U % 1, retire=True)
    S["P_announce_after_own_retire"] = announce(P, "p", U % 1)
    S["state"] = state()
    # Only X's key releases the name.
    S["X_direct_retire_own"] = direct_retire(X)
    S["P_announce_after_X_retire"] = announce(P, "p", U % 1)
    S["state_after_X_retire"] = state()
    print(json.dumps(out, sort_keys=True))

# ----------------------------------------------------------------- driver
def run(scn):
    p = subprocess.run([sys.executable, os.path.abspath(__file__), "--worker", scn], capture_output=True, text=True,
                       env={**os.environ, "TREE": TREE, "PYTHONDONTWRITEBYTECODE": "1"})
    if p.returncode != 0:
        return {"scenario": scn, "crash": p.stderr.strip().splitlines()[-1:]}
    return json.loads(p.stdout.strip().splitlines()[-1])

def evaluate(r):
    """Return list of (row, ok, observed). Never raises on a wrong value."""
    if "crash" in r:
        return [("CRASH", False, r["crash"])]
    s = r["steps"]; g = lambda k, f="status": (s.get(k) or {}).get(f)
    xs = lambda st: list(st["invite"].values())
    if r["scenario"] == "CONTROL":
        st = s["state"]
        return [("CTL-P-ACCEPTED", g("P_announce_p") == 200, g("P_announce_p")),
                ("CTL-BOTH-LIVE", st["live_p"] == ["X", "P"], st["live_p"]),
                ("CTL-INVITE-X", xs(st) == ["X"] * 3, st["invite"])]
    if r["scenario"] == "PATCHED_DELTA_OBS":
        st = s["state"]
        return [("OBS-DELTA-BYPASS (informational)", st["live_p"] == ["X", "P"],
                 {"delta": s["P_delta_upsert_p_via_R"], "live_p": st["live_p"], "invite": st["invite"]})]
    st, st2 = s["state"], s["state_after_X_retire"]
    return [
        ("ANN-X-FIRST-ACCEPTED", g("X_announce_p") == 200, g("X_announce_p")),
        ("ANN-P-REFUSED", g("P_announce_p") == 409, s["P_announce_p"]),
        ("ANN-P-REANNOUNCE-REFUSED", g("P_reannounce_p") == 409, s["P_reannounce_p"]),
        ("ANN-P-HAS-NO-ROW", s["P_rows_before_retire"] == [], s["P_rows_before_retire"]),
        ("ANN-P-DIRECT-RETIRE-404", g("P_direct_retire_own") == 404, s["P_direct_retire_own"]),
        ("ANN-P-CANNOT-RETIRE-X", g("P_delta_retire_X_row_signed_by_P", "rejected") == 1
            and "X" in st["live_p"], s["P_delta_retire_X_row_signed_by_P"]),
        ("ANN-P-OWN-RETIRE-NO-EFFECT", g("P_delta_retire_own_key", "retired") == 1
            and g("P_announce_after_own_retire") == 409 and st["live_p"] == ["X"],
            {"retire": s["P_delta_retire_own_key"], "announce_after": s["P_announce_after_own_retire"],
             "live_p": st["live_p"], "P_rows": [x for x in st["rows"] if x[1] == "P"]}),
        ("ANN-INVITE-X-ALL-3", xs(st) == ["X"] * 3, st["invite"]),
        ("ANN-ONLY-X-FREES", g("X_direct_retire_own", "retired") is True
            and g("P_announce_after_X_retire") == 200 and xs(st2) == ["P"] * 3,
            {"x_retire": s["X_direct_retire_own"], "p_announce": s["P_announce_after_X_retire"],
             "invite": st2["invite"]}),
    ]

def main():
    head = subprocess.run(["git", "-C", TREE, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip() or "n/a(no git)"
    fh = hashlib.sha256(open(os.path.join(TREE, "federation.py"), "rb").read()).hexdigest()
    print(f"BW-DUPNAME-ANN  tree_head={head}  federation.py_sha256={fh}")
    print("EVIDENCE FOR REJECTED OPTION (first-come 409 on peer names); not a fix.")
    summary = {}
    for scn in ("CONTROL", "PATCHED", "PATCHED_DELTA_OBS", "M_NO409"):
        print(f"\n[{scn}]" + ("  (mutant: 409 guard removed; expect ANN-P-REFUSED to FAIL)" if scn == "M_NO409" else ""))
        res = evaluate(run(scn))
        for name, ok, obs in res:
            print(f"  {'PASS' if ok else 'FAIL'}  {name}  observed={json.dumps(obs, sort_keys=True)}")
        summary[scn] = {n: ok for n, ok, _ in res}
    pt = summary["PATCHED"]; ct = summary["CONTROL"]; mt = summary["M_NO409"]
    killed = (not mt.get("ANN-P-REFUSED", True)) and "CRASH" not in mt
    print(f"\nSUMMARY control={sum(ct.values())}/{len(ct)} patched={sum(pt.values())}/{len(pt)}"
          f" mutant M-NO409={'KILLED by ANN-P-REFUSED (assertion, not exception)' if killed else 'SURVIVED/CRASH'}"
          f" mutant_fails={[n for n, ok in mt.items() if not ok]}")
    for scn in summary:   # throwaway per-scenario DBs removed
        shutil.rmtree(os.path.join(DBROOT, scn), ignore_errors=True)
    sys.exit(0 if all(pt.values()) and all(ct.values()) and killed else 1)

if __name__ == "__main__":
    worker(_a[_a.index("--worker") + 1]) if "--worker" in _a else main()
