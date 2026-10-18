"""BF-AMBIG (Lodestar): the seat node_pub backfill must not pin a key for a
name that has 2+ live peers rows. Pure SQLite; no keys, no network, no tree writes.
SQL source:  --tree <path>  extracts the backfill UPDATE from <path>/core_serve.py (or core.py)
             --candidate    uses CANDIDATE below (the HAVING COUNT(*)=1 guard)
             --mutant       CANDIDATE with the guard swapped back to LIMIT 1
Exit 0 iff every row passes."""
import re, sqlite3, sys, os
CANDIDATE = """
                UPDATE workspace_remote_members
                SET node_pub = COALESCE(
                    (SELECT MIN(node_pub) FROM peers
                     WHERE peers.name = workspace_remote_members.node_name
                       AND peers.retired_at = ''
                     GROUP BY peers.name HAVING COUNT(*) = 1), '')
                WHERE node_pub = ''
"""
MUTANT = CANDIDATE.replace("SELECT MIN(node_pub)", "SELECT node_pub").replace("GROUP BY peers.name HAVING COUNT(*) = 1", "LIMIT 1")
def from_tree(t):
    for f in ('core_serve.py', 'core.py'):
        p = os.path.join(t, f)
        if not os.path.exists(p): continue
        m = re.findall(r'"""(\s*UPDATE workspace_remote_members\s+SET node_pub\b.*?)"""', open(p).read(), re.S)
        if len(m) == 1: return m[0], f
        if len(m) > 1: sys.exit(f"BLOCK: {len(m)} backfill UPDATEs in {f}, expected 1")
    sys.exit("BLOCK: no seat node_pub backfill UPDATE found in tree")
a = sys.argv[1:]
if a[:1] == ['--tree']: SQL, src = from_tree(a[1])
elif a[:1] == ['--mutant']: SQL, src = MUTANT, 'mutant(LIMIT 1)'
else: SQL, src = CANDIDATE, 'candidate'
print("sql source:", src)
X, P, Q, Z, W = ('aa'*32, 'bb'*32, 'cc'*32, 'dd'*32, 'ee'*32)
def run(order):
    c = sqlite3.connect(':memory:')
    c.execute("CREATE TABLE peers (node_pub TEXT PRIMARY KEY, name TEXT, node_url TEXT, retired_at TEXT NOT NULL DEFAULT '')")
    # pre-migration seat schema (main 4047c74, core.py:1071-1079)
    c.execute("CREATE TABLE workspace_remote_members (workspace_id INTEGER NOT NULL, agent_pub TEXT NOT NULL, node_name TEXT NOT NULL DEFAULT '', countersigned_at TEXT, struck_at TEXT, PRIMARY KEY (workspace_id, agent_pub))")
    rows = {'squat': [(X, 'p'), (P, 'p')], 'honest': [(P, 'p'), (X, 'p')]}[order]
    for k, n in rows: c.execute("INSERT INTO peers (node_pub,name,node_url) VALUES (?,?,?)", (k, n, 'http://44.0.0.1'))
    c.execute("INSERT INTO peers (node_pub,name,node_url) VALUES (?,?,?)", (Q, 'q', 'http://44.0.0.2'))
    c.execute("INSERT INTO peers (node_pub,name,node_url,retired_at) VALUES (?,?,?,?)", (Z, 'w', 'http://44.0.0.3', '2026-10-01'))
    c.execute("INSERT INTO peers (node_pub,name,node_url) VALUES (?,?,?)", (W, 'w', 'http://44.0.0.4'))
    for i, n in enumerate(['p', 'q', 'w', 'r']):
        c.execute("INSERT INTO workspace_remote_members (workspace_id,agent_pub,node_name) VALUES (1,?,?)", (f'{i:02x}'*32, n))
    c.execute("ALTER TABLE workspace_remote_members ADD COLUMN node_pub TEXT NOT NULL DEFAULT ''")
    c.execute(SQL)
    seat = dict(c.execute("SELECT node_name,node_pub FROM workspace_remote_members"))
    report = [r[0] for r in c.execute("SELECT node_name FROM workspace_remote_members WHERE node_pub='' ORDER BY node_name")]
    return seat, report
ok = True
def row(name, cond, got):
    global ok; ok &= cond; print(('PASS' if cond else 'FAIL'), name, 'got', got)
for order in ('squat', 'honest'):
    seat, report = run(order)
    row(f'BF-AMBIG[{order}-first] seat for 2-live name stays empty', seat['p'] == '', seat['p'][:8] or "''")
    row(f'BF-SINGLE[{order}-first] seat for 1-live name gets that key', seat['q'] == Q, seat['q'][:8] or "''")
    row(f'BF-RETIRED[{order}-first] retired row ignored, live one pinned', seat['w'] == W, seat['w'][:8] or "''")
    row(f'BF-NONE[{order}-first] seat for unknown name stays empty', seat['r'] == '', seat['r'][:8] or "''")
    row(f'BF-REPORT[{order}-first] operator list = ambiguous + unknown', report == ['p', 'r'], report)
sys.exit(0 if ok else 1)
