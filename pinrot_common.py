"""Shared helpers for the pin-rotation v2 belt files (split by mutant group
so no single file approaches the run_tests.sh timeout)."""

import contextlib
import inspect
import json
import os
import re
import secrets
import sqlite3
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone

os.environ["CYBERNET_DB_DIR"] = tempfile.mkdtemp(prefix="pinrot-v2-")
os.environ["CYBERNET_NODE_PRIVKEY"] = secrets.token_hex(32)
for k in ("CYBERNET_OOB_NODE_PINS", "CYBERNET_GENESIS_NAME_PIN",
          "CYBERNET_SECOND_MIRROR", "CYBERNET_PEER_ALLOWLIST",
          "CYBERNET_NAME_ROTATION_ROUND_SEC"):
    os.environ.pop(k, None)
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from fastapi.testclient import TestClient  # noqa: E402
import core  # noqa: E402
import core_serve  # noqa: E402
core.init_db()
import app as appmod  # noqa: E402
import federation  # noqa: E402
import name_fork as nf  # noqa: E402
from fed import ed25519 as _ed  # noqa: E402
from fed import envelope as _fed_env  # noqa: E402

client = TestClient(appmod.app)
STATE = {"pass": 0, "fail": 0}
MUTANTS = []


def check(label, cond, extra=""):
    if cond:
        STATE["pass"] += 1
        print(f"  ok  {label}", flush=True)
    else:
        STATE["fail"] += 1
        print(f"  FAIL {label} {extra}", flush=True)


def mutant(name, row, real_ok, mutant_ok):
    """real_ok: the row passes on production. mutant_ok: the row passes
    under the mutant. The mutant is killed when the row fails under it."""
    killed = real_ok and not mutant_ok
    MUTANTS.append((name, row, real_ok, not mutant_ok))
    check(f"MUTANT {name}: row '{row}' passes real, fails mutant", killed,
          (real_ok, mutant_ok))


@contextlib.contextmanager
def patched(obj, attr, repl):
    old = getattr(obj, attr)
    setattr(obj, attr, repl)
    try:
        yield
    finally:
        setattr(obj, attr, old)


def iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")


NOW = datetime.now(timezone.utc)
ISSUED = iso(NOW - timedelta(minutes=2))
EXPIRES = iso(NOW + timedelta(days=30))
ROUND = nf.round_seconds()
T0 = time.time()


def seed():
    return secrets.token_bytes(32)


def pub(s):
    return _ed.publickey(s).hex()


def binding(name, s, issued=ISSUED, expires=EXPIRES):
    p = pub(s)
    sig = _ed.sign(core._name_claim_payload(name, p, issued, expires), s,
                   bytes.fromhex(p)).hex()
    return {"name": name, "node_pubkey": p, "issued_at": issued,
            "expires_at": expires, "signature": sig}


def claim_gate_pin(name, s, conn=None, **kw):
    """What the claim route does after its gates: write the binding and
    pin it with claim_gate provenance."""
    b = binding(name, s, **kw)

    def go(c):
        c.execute("INSERT OR REPLACE INTO name_bindings (name, node_pubkey,"
                  " issued_at, expires_at, signature) VALUES (?,?,?,?,?)",
                  (name, b["node_pubkey"], b["issued_at"], b["expires_at"],
                   b["signature"]))
        return nf.pin_initial(c, name, b["node_pubkey"], source="claim_gate",
                              binding=b)
    if conn is not None:
        go(conn)
    else:
        with core._db_lock, core._db() as c:
            go(c)
    return b


def head(name, conn=None):
    if conn is not None:
        return nf.current_state(conn, name)
    with core._db_lock, core._db() as c:
        return nf.current_state(c, name)


def cert_next(name, old_seed, new_pub, conn=None, seq=None, prev=None):
    st = head(name, conn)
    return nf.mint_cert(name, old_seed, new_pub,
                        st[1] + 1 if seq is None else seq,
                        st[2] if prev is None else prev, issued_at=ISSUED)


def ingest(certs, sender="aa" * 32, now=None, conn=None, rb=None):
    if conn is not None:
        return nf.ingest_rotation_round(conn, certs, sender, round_bindings=rb,
                                        now=now)
    with core._db_lock, core._db() as c:
        return nf.ingest_rotation_round(c, certs, sender, round_bindings=rb,
                                        now=now)


def db(q, args=()):
    with core._db_lock, core._db() as c:
        return c.execute(q, args).fetchall()


def contested(name):
    with core._db_lock, core._db() as c:
        return nf.is_contested(c, name)


def mem_conn():
    conn = sqlite3.connect(":memory:")
    conn.executescript("""
        CREATE TABLE name_bindings (name TEXT PRIMARY KEY, node_pubkey TEXT
          NOT NULL, issued_at TEXT NOT NULL, expires_at TEXT NOT NULL,
          signature TEXT NOT NULL);
        CREATE TABLE name_rotations (name TEXT NOT NULL, old_pubkey TEXT NOT
          NULL, new_pubkey TEXT NOT NULL, issued_at TEXT NOT NULL, signature
          TEXT NOT NULL, accepted_at TEXT NOT NULL,
          PRIMARY KEY (name, old_pubkey, new_pubkey));""")
    nf.ensure_schema(conn)
    return conn


def rnd(k):
    return T0 + k * ROUND


_round_k = [10]


def next_round():
    _round_k[0] += 2
    return rnd(_round_k[0])


ZERO = "00" * 32
# An order-8 point (RFC 8032 small-order list / Chalkias et al. table).
ORDER8 = "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"


def mixed_pub(s):
    """Honest key + an order-8 torsion component (passes strict checkvalid,
    fails weak_reason)."""
    A = _ed._decodepoint_strict(bytes.fromhex(pub(s)))
    T = _ed._decodepoint_strict(bytes.fromhex(ORDER8))
    return _ed._encodepoint(_ed._edwards(A, T)).hex()


def reset_rates():
    with core._db_lock:
        core._hits.clear()
        core_serve._hits.clear()
        core._gossip_verify_times.clear()


src_nf = open(os.path.join(HERE, "name_fork.py")).read()
doc = open(os.path.join(HERE, "docs", "RESOLVER.md")).read()
_flat_nf = " ".join(src_nf.split())
_flat_doc = " ".join(doc.split())


sk6 = secrets.token_hex(32)
pk6 = pub(bytes.fromhex(sk6))


def add_peer(p, url="http://198.51.100.7:8471"):
    now = core._now()
    with core._db_lock, core._db() as c:
        c.execute("""INSERT OR IGNORE INTO peers (node_pub, name, network,
            version, genesis, capabilities, announced_at, first_seen,
            retired_at, node_url) VALUES (?,?,?,?,?,?,?,?,?,?)""",
                  (p, "peer", "cybernet", "0.1.0", 0, "[]", now, now, "", url))
    cur = os.environ.get("CYBERNET_PEER_ALLOWLIST", "")
    os.environ["CYBERNET_PEER_ALLOWLIST"] = ",".join(
        [x for x in cur.split(",") if x] + [p])


_next_env_ts = [int(time.time()) - 1]


def env_ts():
    """Adopted test clock: strictly increasing and never behind wall time,
    so no envelope falls outside MAX_SKEW_SEC on a slow run."""
    _next_env_ts[0] = max(int(time.time()), _next_env_ts[0] + 1)
    return _next_env_ts[0]


def post(certs, bindings=None, sk=sk6, pk=pk6):
    body = {"from_node_pub": pk, "bindings": bindings or [], "rotations": certs}
    env = _fed_env.make_envelope(sk, pk, core._NODE_PUB, body,
                                 ts=env_ts(), kind="names-gossip")
    return client.post("/fed/names/gossip", json=env)



def finish():
    print()
    print("mutant table:")
    for name, row, real_ok, killed in MUTANTS:
        print(f"  {'KILLED' if real_ok and killed else 'SURVIVED':8} {name}  [{row}]")
    print(f"--- {STATE['pass']} passed, {STATE['fail']} failed ---")
    sys.exit(1 if STATE["fail"] else 0)
