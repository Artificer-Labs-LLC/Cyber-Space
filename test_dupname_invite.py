"""DUP-NAME repro (Loom): peers.name is not unique, and the workspace invite
lookups at routes_workspaces.py pick a peer by name with fetchone() and no
ORDER BY. Rows here show whose node_pub an invite to an honest node's name
reaches when a second key announces the same name.

These rows record CURRENT behaviour (they pass on a3e6a08 by asserting the
hole). In-process: throwaway DB dir, env-supplied node key, no network.
"""
import os, re, secrets, sys, tempfile
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ["CYBERNET_DB_DIR"] = tempfile.mkdtemp(prefix="loom-dupname-")
os.environ["CYBERNET_NODE_PRIVKEY"] = secrets.token_hex(32)

from fed import ed25519, envelope            # noqa: E402
import core                                   # noqa: E402
import federation                             # noqa: E402
core.init_db()

CASES = {"passed": 0, "failed": 0}
def check(name, cond, extra=""):
    CASES["passed" if cond else "failed"] += 1
    print(("  ok  " if cond else "  FAIL ") + name + ("" if cond else " " + extra))

SRC = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "routes_workspaces.py")).read()
INVITE_SQL = "SELECT node_pub, node_url FROM peers WHERE name=? AND retired_at=''"

def key():
    sk = secrets.token_bytes(32)
    return sk.hex(), ed25519.publickey(sk).hex()

def announce(sk, pk, name, url):
    body = {"node_pub": pk, "name": name, "node_url": url,
            "capabilities": [], "network": "cybernet", "version": "0.1.0"}
    env = envelope.make_envelope(sk, pk, "federation", body)
    return federation.fed_announce(env)

def invite_target(name):
    with core._db_lock, core._db() as conn:
        r = conn.execute(INVITE_SQL, (name,)).fetchone()
        n = conn.execute("SELECT COUNT(*) c FROM peers WHERE name=? AND retired_at=''",
                         (name,)).fetchone()["c"]
    return (r["node_pub"] if r else None), n

def rowid_of(pk):
    with core._db_lock, core._db() as conn:
        return conn.execute("SELECT rowid FROM peers WHERE node_pub=?", (pk,)).fetchone()[0]

print("source pins:")
check("DUP-SQL invite query appears 3x verbatim in routes_workspaces.py",
      SRC.count('"' + INVITE_SQL + '"') == 3, str(SRC.count(INVITE_SQL)))
_here = os.path.dirname(os.path.abspath(__file__))
_srcs = [open(os.path.join(_here, f)).read() for f in os.listdir(_here)
         if f.endswith(".py") and not f.startswith("test_")]
check("DUP-NOINDEX no index created ON peers in any non-test module",
      not any(re.search(r"\bON\s+peers\b", t) for t in _srcs))
with core._db_lock, core._db() as conn:
    _idx = conn.execute("SELECT sql FROM sqlite_master WHERE type='index' AND tbl_name='peers'").fetchall()
check("DUP-NOUNIQUE live schema: peers has only its node_pub PK autoindex",
      all(r[0] is None for r in _idx), str([r[0] for r in _idx]))

print("P first, then attacker X, then P refreshes:")
sp, pp = key(); sx, px = key()
announce(sp, pp, "victim", "http://93.184.216.34")
announce(sx, px, "victim", "http://93.184.216.35")
tgt, n = invite_target("victim")
check("DUP-PFIRST-TWO two live rows share the name", n == 2, str(n))
r0 = rowid_of(pp)
announce(sp, pp, "victim", "http://93.184.216.34")
check("DUP-PFIRST-ROWID honest refresh keeps its rowid (upsert in place)",
      rowid_of(pp) == r0, f"{r0}->{rowid_of(pp)}")
tgt, _ = invite_target("victim")
check("DUP-PFIRST-HONEST invite resolves to P when P registered first", tgt == pp)

print("attacker X first (squat before P joins), then P:")
sp2, pp2 = key(); sx2, px2 = key()
announce(sx2, px2, "latecomer", "http://93.184.216.35")
announce(sp2, pp2, "latecomer", "http://93.184.216.34")
announce(sp2, pp2, "latecomer", "http://93.184.216.34")
tgt, n = invite_target("latecomer")
check("DUP-XFIRST-TWO two live rows share the name", n == 2, str(n))
check("DUP-XFIRST-HIJACK invite to P's name reaches attacker X (the hole)",
      tgt == px2, f"got {tgt[:12] if tgt else None}")

print("no admission needed: X was never a known peer before announcing")
check("DUP-NOADMIT announce from fresh key accepted",
      announce(*key(), "victim", "http://93.184.216.36").get("ok") is True)

print(f"\n{CASES['passed']} passed, {CASES['failed']} failed")
sys.exit(1 if CASES["failed"] else 0)
