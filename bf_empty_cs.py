"""BF-EMPTY-CS (Lodestar's row, built by Loom): a seat whose node_pub is ''
can never be countersigned; a pinned seat accepts only its pinned key.

Drives the REAL federation.fed_workspace_countersign of a tree copy in a
throwaway DB (node key from env var, never a key file). Envelope signing is
real (fed.envelope.make_envelope); countersign_sig is real Ed25519 over
core._countersign_payload by the sender's own key.

Modes (tree = --tree PATH, else cwd):
  --tree       the tree as-is. On a3e6a08 the receiver matches by name only
               (federation.py:883-899), so CS-EMPTY and CS-PIN-THIEF are RED
               BY DESIGN: this mode documents the live theft; exit 1 if it is.
  --candidate  copy with the fix: refuse if the seat key is empty or differs
               from sender_pub (Examiner's form: '' == '' can never pass). Exit 0 iff every row passes.
  --mutant     copy with M-CS-SKIP-EMPTY: check only when node_pub != ''.
               Exit 0 iff CS-EMPTY FAILS by assertion (mutant killed).
  --suite      run --candidate and --mutant; exit 0 iff both exit 0.
DB root: $BF_CS_DB (default /workspace/loom-bfcs/db)."""
import hashlib, os, shutil, subprocess, sys, tempfile
HERE = os.path.abspath(__file__)
a = sys.argv[1:]
TREE = os.path.abspath(a[a.index("--tree") + 1]) if "--tree" in a and len(a) > a.index("--tree") + 1 and not a[a.index("--tree") + 1].startswith("--") else os.getcwd()
DBROOT = os.environ.get("BF_CS_DB", "/workspace/loom-bfcs/db")
SEL_OLD = '"SELECT countersigned_at, struck_at FROM workspace_remote_members "'
SEL_NEW = '"SELECT countersigned_at, struck_at, node_pub FROM workspace_remote_members "'
STRUCK = '''                                detail="invite was struck; countersign refused.")
'''
FIX = {"candidate": '''        if not row["node_pub"] or row["node_pub"] != sender_pub:  # LOOM-CS-PIN
            raise HTTPException(status_code=403, detail="seat not pinned to this node key")
''', "mutant": '''        if row["node_pub"] and row["node_pub"] != sender_pub:  # M-CS-SKIP-EMPTY
            raise HTTPException(status_code=403, detail="seat not pinned to this node key")
'''}


def seed(l):
    return hashlib.sha256(b"loom-bf-empty-cs/" + l.encode()).hexdigest()


def patched(mode):
    d = tempfile.mkdtemp(prefix=f"bfcs-{mode}-") + "/tree"
    shutil.copytree(TREE, d, ignore=shutil.ignore_patterns(".git", "__pycache__", "*.key", "*.db"))
    p = os.path.join(d, "federation.py"); s = open(p).read()
    fn = s.index("def fed_workspace_countersign("); end = s.index("\n@router", fn)
    body = s[fn:end]
    if body.count(SEL_OLD) != 1 or body.count(STRUCK) != 1:
        sys.exit(f"BLOCK: anchors sel={body.count(SEL_OLD)} struck={body.count(STRUCK)}")
    body = body.replace(SEL_OLD, SEL_NEW).replace(STRUCK, STRUCK + FIX[mode])
    open(p, "w").write(s[:fn] + body + s[end:])
    return d


def rows(tree, tag):
    db = os.path.join(DBROOT, tag); shutil.rmtree(db, ignore_errors=True); os.makedirs(db)
    os.environ["CYBERNET_DB_DIR"] = db
    os.environ["CYBERNET_NODE_PRIVKEY"] = seed("home-node")
    sys.path.insert(0, tree); os.chdir(tree)
    from nacl.signing import SigningKey
    import core, federation
    from fastapi import HTTPException
    from fed import envelope as E
    core.init_db()
    core._check_rate = lambda *x, **k: None
    federation._check_rate = lambda *x, **k: None

    def kp(l):
        s = SigningKey(bytes.fromhex(seed(l))); return s.encode().hex(), s.verify_key.encode().hex()
    P, X = kp("P-honest"), kp("X-thief")
    charter = "loom bf-empty-cs charter"
    ch = hashlib.sha256(charter.encode()).hexdigest()
    with core._db_lock, core._db() as c:
        c.execute("INSERT INTO workspaces (name, charter, state, created_by, created_at) VALUES "
                  "('w', ?, 'live', 1, '2026-10-17T00:00:00+00:00')", (charter,))
        wid = c.execute("SELECT MAX(id) FROM workspaces").fetchone()[0]
        for k, url in ((P, "http://44.0.0.1:8000"), (X, "http://44.0.0.2:8000")):
            c.execute("INSERT INTO peers (node_pub, name, announced_at, first_seen, node_url) VALUES (?,?,?,?,?)",
                      (k[1], "p", "2026-10-17T00:00:00+00:00", "2026-10-17T00:00:00+00:00", url))
        seats = {"CS-EMPTY": ("a1" * 32, ""), "CS-PIN-THIEF": ("a2" * 32, P[1]), "CS-PIN-OK": ("a3" * 32, P[1])}
        for agent, pin in seats.values():
            c.execute("INSERT INTO workspace_remote_members (workspace_id, agent_pub, node_name, countersigned_at, struck_at, node_pub) "
                      "VALUES (?,?,?,NULL,NULL,?)", (wid, agent, "p", pin))
    res = {}

    def cs(sender, agent):
        sig = SigningKey(bytes.fromhex(sender[0])).sign(core._countersign_payload(wid, ch, sender[1], agent)).signature.hex()
        body = {"from_node_pub": sender[1], "workspace_id": wid, "charter_hash": ch,
                "invitee_agent_key": agent, "countersign_sig": sig}
        try:
            federation.fed_workspace_countersign(E.make_envelope(sender[0], sender[1], core._NODE_PUB, body)); return 200
        except HTTPException as e:
            return e.status_code

    def cs_at(agent):
        with core._db_lock, core._db() as c:
            return c.execute("SELECT countersigned_at FROM workspace_remote_members WHERE workspace_id=? AND agent_pub=?",
                             (wid, agent)).fetchone()[0]
    # CS-EMPTY-BOTH (Examiner): empty seat key AND empty sender key. The real
    # envelope check refuses sender_pub='' first, so bypass it for this call
    # only and plant a live peers row with node_pub='' named p.
    with core._db_lock, core._db() as c:
        c.execute("INSERT INTO peers (node_pub, name, announced_at, first_seen, node_url) VALUES ('', 'p', ?, ?, ?)",
                  ("2026-10-17T00:00:00+00:00", "2026-10-17T00:00:00+00:00", "http://44.0.0.3:8000"))
        c.execute("INSERT INTO workspace_remote_members (workspace_id, agent_pub, node_name, countersigned_at, struck_at, node_pub) "
                  "VALUES (?,?,?,NULL,NULL,'')", (wid, "a4" * 32, "p"))
    real_v = federation._fed_env.verify_envelope
    federation._fed_env.verify_envelope = lambda e, *x, **k: True
    try:
        env = {"sender_pub": "", "recipient": core._NODE_PUB, "sig": "", "ts": 0,
               "body": {"from_node_pub": "", "workspace_id": wid, "charter_hash": ch,
                        "invitee_agent_key": "a4" * 32, "countersign_sig": ""}}
        try:
            federation.fed_workspace_countersign(env); st = 200
        except HTTPException as e:
            st = e.status_code
    finally:
        federation._fed_env.verify_envelope = real_v
    at = cs_at("a4" * 32)
    res["CS-EMPTY-BOTH"] = "PASS" if (st != 200 and at is None) else "FAIL"
    print(f"{res['CS-EMPTY-BOTH']} CS-EMPTY-BOTH status={st} countersigned_at={'set' if at else 'NULL'}")
    for name, sender, want_ok in (("CS-EMPTY", X, False), ("CS-PIN-THIEF", X, False), ("CS-PIN-OK", P, True)):
        agent = seats[name][0]
        st = cs(sender, agent); at = cs_at(agent)
        ok = (st == 200 and at is not None) if want_ok else (st != 200 and at is None)
        res[name] = "PASS" if ok else "FAIL"
        print(f"{res[name]} {name} status={st} countersigned_at={'set' if at else 'NULL'}")
    print("ROWS", res)
    return res


def child(mode):
    tree = TREE if mode == "tree" else patched(mode)
    out = subprocess.run([sys.executable, HERE, "--_run", mode, "--tree", tree], capture_output=True, text=True)
    print(f"--- mode={mode}\n" + out.stdout + out.stderr[-2000:])
    line = [l for l in out.stdout.splitlines() if l.startswith("ROWS ")]
    return eval(line[-1][5:]) if line else None


if "--_run" in a:
    rows(TREE, a[a.index("--_run") + 1]); sys.exit(0)
mode = next((m[2:] for m in a if m in ("--candidate", "--mutant", "--suite")), "tree")
if mode == "suite":
    r1 = subprocess.run([sys.executable, HERE, "--candidate", "--tree", TREE]).returncode
    r2 = subprocess.run([sys.executable, HERE, "--mutant", "--tree", TREE]).returncode
    print(f"SUITE candidate_rc={r1} mutant_rc={r2}"); sys.exit(0 if r1 == 0 and r2 == 0 else 1)
r = child(mode)
if r is None: sys.exit(2)
if mode == "candidate": sys.exit(0 if all(v == "PASS" for v in r.values()) else 1)
if mode == "mutant":
    k = r.get("CS-EMPTY") == "FAIL"; print("MUTANT M-CS-SKIP-EMPTY", "KILLED (CS-EMPTY assertion)" if k else "SURVIVED"); sys.exit(0 if k else 1)
theft = r.get("CS-EMPTY") == "FAIL" or r.get("CS-PIN-THIEF") == "FAIL"
print("TREE AS-IS:", "countersign theft LIVE (red by design)" if theft else "no theft"); sys.exit(1 if theft else 0)
