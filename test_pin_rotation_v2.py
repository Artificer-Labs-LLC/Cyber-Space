#!/usr/bin/env python3
"""Belt: pin-rotation v2 composed onto names-gossip-hardening (ART-29/42).

Every row runs the production rule; each named MUTANT replaces exactly one
guard and must make its row fail. Scratch DB only; no live route, no test
hook in production code. Rows are grouped by the build items 1-12.

Chain depth is never a tiebreak.
"""
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
PASS = FAIL = 0
MUTANTS = []


def check(label, cond, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok  {label}")
    else:
        FAIL += 1
        print(f"  FAIL {label} {extra}")


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


# ================================================================ item 1
print("item 1: weak-key and strict checks in _norm_cert")
params = list(inspect.signature(nf.ingest_rotation_round).parameters)
check("signature is ingest_rotation_round(conn, certs, sender_pub, ...)",
      params[:3] == ["conn", "certs", "sender_pub"], params)
check("ORDER8 premise: canonical and order 8",
      nf._strict_point_ok(bytes.fromhex(ORDER8))
      and _ed._is_small_order(_ed._decodepoint_strict(bytes.fromhex(ORDER8))))


def row_weak_new(target, label):
    def run():
        nm = f"w{secrets.token_hex(4)}"
        k1 = seed()
        claim_gate_pin(nm, k1)
        c = cert_next(nm, k1, target)
        r = ingest([c], now=next_round())
        return r["accepted"] == {} and head(nm)[0] == pub(k1)
    real = run()
    check(f"{label} new key refused; pin unmoved", real)
    with patched(nf, "_keys_ok", lambda rec: True), \
            patched(nf, "_weak", lambda p: None):
        mut = run()
    mutant(f"weak/strict key checks dropped from _norm_cert ({label})",
           f"{label} refused", real, mut)


row_weak_new(ZERO, "zero-key seed")
row_weak_new(ORDER8, "order-8 torsion")
row_weak_new(mixed_pub(seed()), "mixed-order")

# small-order OLD key with a forged signature is refused before verify
nm = "wold"
v0 = nf._verify_calls
forged = {"v": 2, "kind": "name-rotate", "tag": nf.TAG.decode(), "name": nm,
          "old_pubkey": ORDER8, "new_pubkey": pub(seed()), "issued_at": ISSUED,
          "seq": 1, "prev_hash": "11" * 32, "signature": "00" * 64}
check("order-8 OLD key refused before verify (0 verifies)",
      nf._norm_cert(forged) is None and nf._verify_calls == v0)

# non-OOB relay of an unpinned name: binding refused, rotation never pins
sender = pub(seed())
b = binding("relayname", seed())


def run_relay():
    out = core.ingest_gossiped_binding(dict(b), sender_pub=sender)
    pinned = head("relayname") is not None
    return out == "dropped-unpinned" and not pinned


real = run_relay()
check("non-OOB relay of an unpinned name is refused and not pinned", real)
with patched(nf, "sender_may_introduce", lambda s: True):
    mut = run_relay()
mutant("introducer check dropped (any sender introduces)",
       "non-OOB relay refused", real, mut)
os.environ["CYBERNET_OOB_NODE_PINS"] = sender
b2 = binding("oobname", seed())
check("OOB-allowlisted relay inserts and pins with oob_allowlist provenance",
      core.ingest_gossiped_binding(dict(b2), sender_pub=sender) == "inserted"
      and db("SELECT source FROM name_pin_log WHERE name='oobname'")[0][0]
      == "oob_allowlist")
os.environ.pop("CYBERNET_OOB_NODE_PINS")

# ================================================================ item 2
print("item 2: a cert never introduces a name; E1")


def run_unknown():
    nm = f"ghost{secrets.token_hex(3)}"
    k1 = seed()
    c = nf.mint_cert(nm, k1, pub(seed()), 1, "22" * 32, issued_at=ISSUED)
    e0 = nf.evidence_count(sqlite3.connect(":memory:")) if False else \
        db("SELECT COUNT(*) FROM name_cert_evidence")[0][0]
    r = ingest([c], sender=pub(seed()), now=next_round())
    e1 = db("SELECT COUNT(*) FROM name_cert_evidence")[0][0]
    return head(nm) is None and r["accepted"] == {} and e1 == e0 + 1


real = run_unknown()
check("unknown-name cert refused as a pin and kept as evidence", real)


def introduce(conn, rec, sender, now=None):
    rec = dict(rec)
    conn.execute(
        "INSERT INTO name_pin_log (name, pubkey, seq, prev_pubkey,"
        " cert_signature, recorded_at, kind, source, head_hash, cert)"
        " VALUES (?,?,?,?,?,?,'rotate','rotation',?,?)",
        (rec["name"], rec["new_pubkey"], rec["seq"], rec["old_pubkey"],
         rec["signature"], nf._now(), rec["cert_hash"],
         json.dumps(nf._wire(rec))))
    return "evidence"


with patched(nf, "_keep_evidence", introduce):
    mut = run_unknown()
mutant("cert introduces the name", "unknown-name cert refused", real, mut)


def run_e1():
    nm = f"e1n{secrets.token_hex(3)}"
    k1 = seed()
    prev = secrets.token_hex(32)
    pair = [nf.mint_cert(nm, k1, pub(seed()), 1, prev, issued_at=ISSUED),
            nf.mint_cert(nm, k1, pub(seed()), 1, prev, issued_at=ISSUED)]
    ingest(pair, sender=pub(seed()), now=next_round())
    unc = not contested(nm)
    reset_rates()
    hb = binding(nm, seed(), issued=iso(datetime.now(timezone.utc)
                                         - timedelta(seconds=5)))
    r = client.post("/api/v1/names/claim", data=hb)
    return unc and r.status_code == 200


real = run_e1()
check("E1: two self-made certs leave an unknown name uncontested; honest claim 200",
      real)
with patched(nf, "birth_contest_allowed", lambda *a: True), \
        patched(nf, "birth_contest_needs_origin", lambda: False):
    mut = run_e1()
mutant("E1 current branch (contested from birth on any two certs)",
       "E1 self-made certs leave name uncontested", real, mut)

# E1 positive: the node HOLDS a binding for the certs' old key
nm = "e1held"
k1 = seed()
hb = binding(nm, k1)
with core._db_lock, core._db() as c:
    c.execute("INSERT INTO name_bindings (name, node_pubkey, issued_at,"
              " expires_at, signature) VALUES (?,?,?,?,?)",
              (nm, hb["node_pubkey"], hb["issued_at"], hb["expires_at"],
               hb["signature"]))
oh = nf.origin_hash(nm, hb["node_pubkey"], hb["issued_at"], hb["expires_at"],
                    hb["signature"])
pair = [nf.mint_cert(nm, k1, pub(seed()), 1, oh, issued_at=ISSUED),
        nf.mint_cert(nm, k1, pub(seed()), 1, oh, issued_at=ISSUED)]
ingest(pair, now=next_round())
check("E1: held binding for the old key + two certs on its origin -> contested, no pin",
      contested(nm) and head(nm) is None)

# ================================================================ item 3
print("item 3: evidence store capped, charged before write")


def run_flood():
    tag = secrets.token_hex(2)
    senders = [pub(seed()) for _ in range(4)]
    before = db("SELECT COUNT(*) FROM name_cert_evidence")[0][0]
    log0 = db("SELECT COUNT(*) FROM name_pin_log")[0][0]
    con0 = db("SELECT COUNT(*) FROM name_contested")[0][0]
    t_flood = next_round()
    for i in range(128):
        nm = f"junk{tag}{i}"
        k = seed()
        prev = secrets.token_hex(32)
        pair = [nf.mint_cert(nm, k, pub(seed()), 1, prev, issued_at=ISSUED),
                nf.mint_cert(nm, k, pub(seed()), 1, prev, issued_at=ISSUED)]
        ingest(pair, sender=senders[i % 4], now=t_flood + i)
    after = db("SELECT COUNT(*) FROM name_cert_evidence")[0][0]
    grown = after - before
    return (grown <= 4 * nf.EVIDENCE_PER_SENDER and after <= nf.EVIDENCE_GLOBAL
            and db("SELECT COUNT(*) FROM name_pin_log")[0][0] == log0
            and db("SELECT COUNT(*) FROM name_contested")[0][0] == con0), grown


with core._db_lock, core._db() as c:
    c.execute("DELETE FROM name_cert_evidence")
(real, g_real) = run_flood()
check(f"128 POSTs of junk pairs: store <= cap ({g_real}), no contested, no pin log",
      real, g_real)
with core._db_lock, core._db() as c:
    c.execute("DELETE FROM name_cert_evidence")
with patched(nf, "evidence_has_room", lambda *a: True):
    (mut, g_mut) = run_flood()
mutant("evidence store uncapped", "junk flood stays under cap", real, mut)
with core._db_lock, core._db() as c:
    c.execute("DELETE FROM name_cert_evidence")
ttl_ok = True
with core._db_lock, core._db() as c:
    c.execute("INSERT INTO name_cert_evidence (name, sender, cert_hash, cert,"
              " recorded_ts) VALUES ('old','s','h1','{}',?)",
              (time.time() - nf.EVIDENCE_TTL_SEC - 5,))
    nf._prune(c, time.time())
    ttl_ok = c.execute("SELECT COUNT(*) FROM name_cert_evidence").fetchone()[0] == 0
check("evidence expires after EVIDENCE_TTL_SEC", ttl_ok)

# ================================================================ item 4
print("item 4: v2 payload, chain, forks keyed on (name, prev_hash)")
nm = "abac"
kA, kB, kC = seed(), seed(), seed()
claim_gate_pin(nm, kA)
origin = head(nm)[2]
c1 = cert_next(nm, kA, pub(kB))
check("first link's prev_hash is the pinning binding's hash", c1["prev_hash"] == origin)
ingest([c1], now=next_round())
c2 = cert_next(nm, kB, pub(kA))
ingest([c2], now=next_round())
c3 = cert_next(nm, kA, pub(kC))
ingest([c3], now=next_round())
st = head(nm)
check("A->B->A->C accepted at head 3", st[0] == pub(kC) and st[1] == 3
      and not contested(nm), st)


def run_replay():
    r = ingest([c1], now=next_round())
    return (r["outcomes"] == ["refused-replay"] and head(nm)[0] == pub(kC)
            and not contested(nm))


real = run_replay()
check("replaying A->B after A->B->A(->C) is refused, pin unmoved, not contested", real)
with patched(nf, "is_replay", lambda link, rec: False):
    mut = run_replay()
mutant("replay check removed", "replay A->B refused", real, mut)
with core._db_lock, core._db() as c:
    c.execute("DELETE FROM name_contested WHERE name=?", (nm,))


def run_fork():
    n2 = f"fork{secrets.token_hex(3)}"
    k1 = seed()
    claim_gate_pin(n2, k1)
    x = cert_next(n2, k1, pub(seed()))
    y = cert_next(n2, k1, pub(seed()))
    ingest([x], now=next_round())
    r = ingest([y], now=next_round())
    return contested(n2) and n2 in r["contested"]


real = run_fork()
check("same prev_hash, different new keys -> CONTESTED", real)
with patched(nf, "second_cert_contests", lambda *a: False):
    mut = run_fork()
mutant("fork ignored (local winner kept)", "same prev_hash forks contest", real, mut)


def run_same_seq():
    n2 = f"seq{secrets.token_hex(3)}"
    k1 = seed()
    claim_gate_pin(n2, k1)
    st = head(n2)
    stray = nf.mint_cert(n2, k1, pub(seed()), st[1] + 1, secrets.token_hex(32),
                         issued_at=ISSUED)
    good = cert_next(n2, k1, pub(seed()))
    r1 = ingest([stray], now=next_round())
    r2 = ingest([good], now=next_round())
    return (r1["outcomes"] == ["pending"] and r2["outcomes"] == ["accepted"]
            and not contested(n2))


def seq_keyed(conn, rec, sender, pulls, now=None):
    st = nf.current_state(conn, rec["name"])
    if st and rec["seq"] == st[1] + 1:
        nf._mark_contested(conn, rec["name"], "seq-keyed mutant")
        return "contested"
    return "pending"


real = run_same_seq()
check("same seq, different prev_hash: judged against the local head (pending, then link)",
      real)
with patched(nf, "_hold_pending", seq_keyed):
    mut = run_same_seq()
mutant("fork keyed on seq instead of prev_hash", "same seq judged vs head", real, mut)


def run_noncontig():
    n2 = f"nc{secrets.token_hex(3)}"
    k1, k9 = seed(), seed()
    claim_gate_pin(n2, k1)
    bad = cert_next(n2, k9, pub(seed()))
    r = ingest([bad], now=next_round())
    return r["outcomes"] == ["refused-noncontiguous"] and head(n2)[0] == pub(k1)


real = run_noncontig()
check("non-contiguous move (old_pub != current pin) refused", real)
with patched(nf, "contiguous", lambda rec, pin, seq: True):
    mut = run_noncontig()
mutant("non-contiguous pin move accepted", "old_pub != pin refused", real, mut)

v1 = {"name": "abac", "old_pubkey": pub(kC), "new_pubkey": pub(seed()),
      "issued_at": ISSUED, "signature": "ab" * 64}
check("a v1 certificate is refused on a v2 node", nf._norm_cert(v1) is None)

# two nodes, different order and time -> same head
nA, nB = mem_conn(), mem_conn()
k1, k2, k3 = seed(), seed(), seed()
bb = binding("conv", k1)
for cn in (nA, nB):
    cn.execute("INSERT INTO name_bindings VALUES (?,?,?,?,?)",
               ("conv", bb["node_pubkey"], bb["issued_at"], bb["expires_at"],
                bb["signature"]))
nf.pin_initial(nA, "conv", bb["node_pubkey"], source="claim_gate", binding=bb)
nf.pin_initial(nB, "conv", bb["node_pubkey"], source="oob_allowlist", binding=bb)
x1 = cert_next("conv", k1, pub(k2), conn=nA)
nrec = nf._norm_cert(x1)
x2 = nf.mint_cert("conv", k2, pub(k3), 2, nrec["cert_hash"], issued_at=ISSUED)
ingest([x1], conn=nA, now=rnd(1000))
ingest([x2], conn=nA, now=rnd(1002))
ingest([x2], conn=nB, now=rnd(5000))          # pending on B
ingest([x1], conn=nB, now=rnd(5001))
nf.drain_pending(nB, "conv", now=rnd(5002))
check("two nodes, different order and time -> same head hash",
      nf.current_state(nA, "conv") == nf.current_state(nB, "conv")
      and nf.current_state(nA, "conv")[1] == 2,
      (nf.current_state(nA, "conv"), nf.current_state(nB, "conv")))
check("first rotation over a gossip-set (oob) pin verifies on an independently pinned node",
      nf.current_state(nB, "conv")[0] == pub(k3))

# ================================================================ item 5
print("item 5: canonical encoding before hashing")
from fed.ed25519 import _L, _Q  # noqa: E402

n5 = "canon"
k5 = seed()
claim_gate_pin(n5, k5)
good = cert_next(n5, k5, pub(seed()))
sig = bytes.fromhex(good["signature"])
S = int.from_bytes(sig[32:], "little")
variants = {}
variants["S+L"] = dict(good, signature=(sig[:32] + (S + _L).to_bytes(32, "little")).hex())
yR = (_Q + 1).to_bytes(32, "little")
variants["R y>=p"] = dict(good, signature=(yR + sig[32:]).hex())
xzero = bytearray((1).to_bytes(32, "little"))
xzero[31] |= 0x80
variants["R x=0 sign"] = dict(good, signature=(bytes(xzero) + sig[32:]).hex())
# non-canonical key: a non-canonical encoding of the new key slot, signed
# validly by the old key so only the encoding check can refuse it.
nc_key = (_Q + 1).to_bytes(32, "little").hex()
variants["non-canonical key"] = nf.mint_cert(n5, k5, nc_key, head(n5)[1] + 1,
                                             head(n5)[2], issued_at=ISSUED)
twin_key = nf.mint_cert(n5, k5, pub(seed()), head(n5)[1] + 1, head(n5)[2],
                        issued_at=ISSUED)


def run_canon():
    ok = True
    for label, v in variants.items():
        h0 = nf._hash_calls
        refused = nf._norm_cert(v) is None
        if not (refused and nf._hash_calls == h0):
            ok = False
    return ok


real = run_canon()
check("S+L, R y>=p, R x=0+sign, non-canonical key: each refused before prev_hash",
      real)
real_norm = nf._norm_cert


def hash_first(raw):
    rec = nf._shape(raw) if isinstance(raw, dict) else None
    if rec is not None:
        try:
            nf.cert_hash(rec)
        except Exception:
            pass
    return real_norm(raw)


with patched(nf, "_norm_cert", hash_first):
    mut = run_canon()
mutant("hash raw bytes before strict decode", "non-canonical refused before hash",
       real, mut)
check("each canonical twin links", nf._norm_cert(good) is not None
      and nf._norm_cert(twin_key) is not None
      and ingest([good], now=next_round())["outcomes"] == ["accepted"])

# ================================================================ item 6
print("item 6: pre-verify charge per cert, before _norm_cert, outside the lock")
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


add_peer(pk6)
n6 = "budget"
k6 = seed()
claim_gate_pin(n6, k6)
flood = [nf.mint_cert(n6, k6, pub(seed()), head(n6)[1] + 1, head(n6)[2],
                      issued_at=ISSUED) for _ in range(128)]


def post(certs, bindings=None, sk=sk6, pk=pk6):
    body = {"from_node_pub": pk, "bindings": bindings or [], "rotations": certs}
    env = _fed_env.make_envelope(sk, pk, core._NODE_PUB, body,
                                 kind="names-gossip")
    return client.post("/fed/names/gossip", json=env)


def run_budget():
    reset_rates()
    v0 = nf._verify_calls
    r = post(flood)
    return r.status_code == 200 and (nf._verify_calls - v0) <= \
        core.NAMES_GOSSIP_VERIFY_PER_CALL, nf._verify_calls - v0


real, vr = run_budget()
check(f"128 rotation certs in one POST cost <= NAMES_GOSSIP_VERIFY_PER_CALL verifies ({vr})",
      real)


def norm_then_charge(certs, sender_pub, verify_box):
    for raw in certs:
        nf._norm_cert(raw)
    adm = []
    for raw in certs:
        if not core._charge_one_rotation(sender_pub, verify_box):
            return adm, True
        adm.append(raw)
    return adm, False


with patched(core, "charge_rotation_certs", norm_then_charge):
    mut, vm = run_budget()
mutant("charge after _norm_cert", "128 certs cost <= per-call verifies", real, mut)


def run_namefork_first():
    reset_rates()
    with core._db_lock:
        core._hits[f"namefork:{pk6}"] = [time.time()] * 32
    v0 = nf._verify_calls
    r = post(flood[:1])
    return r.status_code == 429 and nf._verify_calls == v0


real = run_namefork_first()
check("flooding sender is charged and stopped before the first verify (429, 0 verifies)",
      real)
with patched(core, "charge_rotation_certs", norm_then_charge):
    mut = run_namefork_first()
mutant("namefork charged after the first verify", "flooding sender 0 verifies",
       real, mut)
src = inspect.getsource(federation.fed_names_gossip)
check("rotation pre-pass is called outside the DB lock in the route",
      "ingest_rotation_certs(" in src and "_db_lock" not in src.split(
          "ingest_rotation_certs(")[0].split("verify_box = [0]")[-1])

# ================================================================ item 7
print("item 7: persisted per-name round limit (RATE BOUND)")


def run_rate():
    n7 = f"rate{secrets.token_hex(3)}"
    k1, k2 = seed(), seed()
    claim_gate_pin(n7, k1)
    t = next_round()
    a = cert_next(n7, k1, pub(k2))
    ingest([a], now=t)
    b = cert_next(n7, k2, pub(seed()))
    r = ingest([b], now=t + 1)          # second POST, same round
    return head(n7)[0] == pub(k2) and head(n7)[1] == 1 and \
        r["outcomes"] == ["rate-held"]


real = run_rate()
check("two POSTs in one round cannot move a pin A->B->C (persisted in DB)", real)
with patched(nf, "rotations_per_round", lambda: 2):
    mut = run_rate()
mutant("per-POST rounds (rate bound not persisted)", "two POSTs move one hop",
       real, mut)
src_nf = open(os.path.join(HERE, "name_fork.py")).read()
doc = open(os.path.join(HERE, "docs", "RESOLVER.md")).read()
_flat_nf = " ".join(src_nf.split())
_flat_doc = " ".join(doc.split())
check("round limit labelled RATE BOUND (not a fork gate) in code and docs",
      "RATE BOUND" in _flat_nf and "not a fork gate" in _flat_nf
      and "RATE BOUND" in _flat_doc and "not a fork gate" in _flat_doc)

# ================================================================ item 8
print("item 8: kind binding")
n8 = "kind"
k8 = seed()
claim_gate_pin(n8, k8)
base = cert_next(n8, k8, pub(seed()))
relabel_kind = dict(base, kind="name-claim")
other_tag = b"cyberspace-name-claim/v2"
st8 = head(n8)
p8 = pub(seed())
payload = nf.cert_payload(n8, pub(k8), p8, ISSUED, st8[1] + 1, st8[2], tag=other_tag)
osig = _ed.sign(payload, k8, bytes.fromhex(pub(k8))).hex()
relabel_tag = dict(base, new_pubkey=p8, signature=osig, tag=other_tag.decode())


def run_kind():
    return nf._norm_cert(relabel_kind) is None and nf._norm_cert(relabel_tag) is None


real = run_kind()
check("cert relabelled with another kind or tag is rejected", real)
with patched(nf, "_tag_ok", lambda raw: True), \
        patched(nf, "_signing_tag", lambda raw: str(raw.get("tag")).encode()):
    mut = run_kind()
mutant("kind binding dropped", "relabelled cert rejected", real, mut)
check("run_tests.sh runs the fed/envelope.py self-test",
      re.search(r"fed/envelope\.py", open(os.path.join(HERE, "run_tests.sh")).read())
      is not None)

# ================================================================ item 9
print("item 9: pending queue and catch-up")


def run_pending():
    n9 = f"pend{secrets.token_hex(3)}"
    k1 = seed()
    claim_gate_pin(n9, k1)
    s9 = pub(seed())
    t = next_round()
    pulls = 0
    for _ in range(40):
        c = nf.mint_cert(n9, k1, pub(seed()), head(n9)[1] + 1,
                         secrets.token_hex(32), issued_at=ISSUED)
        pulls += len(ingest([c], sender=s9, now=t)["pulls"])
    with core._db_lock, core._db() as cn:
        pc = nf.pending_count(cn, n9)
    good = cert_next(n9, k1, pub(seed()))
    r = ingest([good], sender=s9, now=t)
    return (pc <= nf.PENDING_PER_NAME and pulls <= nf.PENDING_PER_NAME
            and r["outcomes"] == ["accepted"] and not contested(n9)), (pc, pulls)


(real, pinfo) = run_pending()
check(f"made-up prev_hash flood: pending capped, pulls bounded, real cert lands {pinfo}",
      real)
with patched(nf, "pending_has_room", lambda *a: True):
    (mut, minfo) = run_pending()
mutant("unbounded pending queue", "pending capped", real, mut)
check("an unknown prev_hash never marks the name CONTESTED", real)
with core._db_lock, core._db() as c:
    c.execute("INSERT OR REPLACE INTO name_pending (name, sender, prev_hash,"
              " cert_hash, cert, recorded_ts) VALUES ('x','s','p','hx','{}',?)",
              (time.time() - nf.pending_ttl() - 5,))
    nf._prune(c, time.time())
    gone = c.execute("SELECT COUNT(*) FROM name_pending WHERE cert_hash='hx'").fetchone()[0] == 0
check("pending entries expire", gone)

# catch-up: missed A->B, got B->C, pulls A->B from the sender, accepts both
skp = secrets.token_hex(32)
pkp = pub(bytes.fromhex(skp))
add_peer(pkp)
ncu = "catchup"
kA, kB, kC = seed(), seed(), seed()
src_node = mem_conn()
bcu = claim_gate_pin(ncu, kA)
src_node.execute("INSERT INTO name_bindings VALUES (?,?,?,?,?)",
                 (ncu, bcu["node_pubkey"], bcu["issued_at"], bcu["expires_at"],
                  bcu["signature"]))
nf.pin_initial(src_node, ncu, bcu["node_pubkey"], source="claim_gate", binding=bcu)
ab = cert_next(ncu, kA, pub(kB), conn=src_node)
ingest([ab], conn=src_node, now=rnd(100))
bc = cert_next(ncu, kB, pub(kC), conn=src_node)
ingest([bc], conn=src_node, now=rnd(102))
r = ingest([bc], sender=pkp, now=next_round())
pulls = r["pulls"]
check("B->C with unknown prev_hash is PENDING with one pull aimed at the sender",
      r["outcomes"] == ["pending"] and len(pulls) == 1 and pulls[0]["sender"] == pkp)
calls = []


def fetch(url, name, peer):
    calls.append((url, name, peer))
    return nf.chain_for(src_node, name)


v = core.pull_name_chain(pkp, ncu, fetch=fetch)
check("catch-up fetches A->B and accepts both (head 2 = C)",
      v == "accepted" and head(ncu)[0] == pub(kC) and head(ncu)[1] == 2
      and len(calls) == 1 and calls[0][2] == pkp, (v, head(ncu)))


def run_stale_path():
    n2 = f"stalep{secrets.token_hex(3)}"
    kA, kZ, kB, kC = seed(), seed(), seed(), seed()
    claim_gate_pin(n2, kA)
    other = mem_conn()
    bz = binding(n2, kZ)
    other.execute("INSERT INTO name_bindings VALUES (?,?,?,?,?)",
                  (n2, bz["node_pubkey"], bz["issued_at"], bz["expires_at"],
                   bz["signature"]))
    nf.pin_initial(other, n2, bz["node_pubkey"], source="claim_gate", binding=bz)
    zb = cert_next(n2, kZ, pub(kB), conn=other)
    ingest([zb], conn=other, now=rnd(200))
    bc2 = cert_next(n2, kB, pub(kC), conn=other)
    ingest([bc2], conn=other, now=rnd(202))
    ch = nf.chain_for(other, n2)
    with core._db_lock, core._db() as c:
        verdict = nf.accept_catchup(c, n2, ch["rotations"], now=next_round())
    return verdict == "refused" and head(n2)[0] == pub(kA) and not contested(n2)


real = run_stale_path()
check("fetched path starting from a stale pin is refused whole; not contested", real)


def internal_only(conn, name, path):
    recs = [nf._norm_cert(r) for r in path]
    if not recs or any(r is None for r in recs):
        return None
    for a, b in zip(recs, recs[1:]):
        if b["prev_hash"] != a["cert_hash"]:
            return None
    return recs


with patched(nf, "path_accept_rule", internal_only):
    mut = run_stale_path()
mutant("accept any path that chains internally", "stale-pin path refused", real, mut)

# both branches verify from the real head -> contested
nbr = "branches"
kA, kB, kX = seed(), seed(), seed()
claim_gate_pin(nbr, kA)
held = cert_next(nbr, kA, pub(kB))
with core._db_lock, core._db() as c:
    nf._store_fork(c, nf._norm_cert(held))
alt = cert_next(nbr, kA, pub(kX))
with core._db_lock, core._db() as c:
    vb = nf.accept_catchup(c, nbr, [alt], now=next_round())
check("catch-up path from the real head with a competing verified branch -> CONTESTED",
      vb == "contested" and contested(nbr))
parity_src = open(os.path.join(HERE, "test_fed_route_parity.py")).read()
check("new route POST /fed/names/chain is in the route-parity REQUIRED set",
      '("POST", "/fed/names/chain")' in parity_src)

# ================================================================ item 10
print("item 10: pins are permanent; PIN-STALE")


def run_stale():
    n10 = f"lapse{secrets.token_hex(3)}"
    k1, k2 = seed(), seed()
    old_iss = iso(NOW - timedelta(days=400))
    old_exp = iso(NOW - timedelta(days=91))
    claim_gate_pin(n10, k1, issued=old_iss, expires=old_exp)
    reset_rates()
    nb = binding(n10, k2, issued=iso(datetime.now(timezone.utc)
                                      - timedelta(seconds=5)))
    r = client.post("/api/v1/names/claim", data=nb)
    res = client.get(f"/api/v1/names/{n10}")
    marked = db("SELECT COUNT(*) FROM name_pin_log WHERE name=? AND kind='stale-mark'",
                (n10,))[0][0] == 1
    return (r.status_code == 409 and "PIN-STALE" in r.text
            and res.status_code == 409 and marked
            and head(n10)[0] == pub(k1)), (r.status_code, res.status_code)


real, si = run_stale()
check(f"lapse + day-90 + different key with no cert -> PIN-STALE, neither key served {si}",
      real)


def release(conn, name, pin, new_pub):
    nf.unpin(conn, name, "mutant: released")
    return "released"


with patched(nf, "stale_policy", release):
    mut, sm = run_stale()
mutant("lapse releases the pin (new key served)", "PIN-STALE refuses", real, mut)
n10b = "lapse-early"
k1, k2 = seed(), seed()
claim_gate_pin(n10b, k1, issued=iso(NOW - timedelta(days=200)),
               expires=iso(NOW - timedelta(days=10)))
reset_rates()
r = client.post("/api/v1/names/claim", data=binding(n10b, k2, issued=iso(
    datetime.now(timezone.utc) - timedelta(seconds=5))))
check("before the day-90 release a different key is refused (pin holds), not PIN-STALE",
      r.status_code == 400 and head(n10b)[0] == pub(k1)
      and not db("SELECT 1 FROM name_pin_stale WHERE name=?", (n10b,)))

# ================================================================ item 11
print("item 11: pin provenance and the startup guard")
with core._db_lock, core._db() as c:
    out = nf.pin_initial(c, "rotseed", pub(seed()), source="rotation",
                         binding=binding("rotseed", seed()))
check("a rotation can never create a pin (pin_initial refuses source=rotation)",
      out == "refused-source" and head("rotseed") is None)
first = db("SELECT source, origin_hash FROM name_pin_log WHERE name='abac'"
           " ORDER BY id LIMIT 1")[0]
check("first pin-log entry records source + hash of the binding",
      first[0] == "claim_gate" and first[1] == origin)
with core._db_lock, core._db() as c:
    cnt = nf._pin_count(c)
with patched(nf, "pin_cap", lambda: cnt):
    with core._db_lock, core._db() as c:
        capped = nf.pin_initial(c, "overcap", pub(seed()), source="claim_gate",
                                binding=binding("overcap", seed()))
check("pin cap holds (same cap as name_bindings)", capped in ("refused-cap",)
      or capped == "refused-source", capped)
bcap = binding("overcap2", seed())
with patched(nf, "pin_cap", lambda: cnt):
    with core._db_lock, core._db() as c:
        capped2 = nf.pin_initial(c, "overcap2", bcap["node_pubkey"],
                                 source="claim_gate", binding=bcap)
check("pin cap refuses a new pin at the cap", capped2 == "refused-cap", capped2)


def plant(name, pubkey, source, ohash, origin_row=None):
    with core._db_lock, core._db() as c:
        if origin_row:
            c.execute("INSERT OR REPLACE INTO name_pin_origins (origin_hash,"
                      " source, name, pubkey, issued_at, expires_at, signature,"
                      " recorded_at) VALUES (?,?,?,?,?,?,?,?)",
                      (ohash, source, *origin_row, nf._now()))
        c.execute("INSERT INTO name_pin_log (name, pubkey, seq, prev_pubkey,"
                  " cert_signature, recorded_at, kind, source, origin_hash,"
                  " head_hash) VALUES (?,?,0,'','',?,'pin',?,?,?)",
                  (name, pubkey, nf._now(), source, ohash, ohash))


def guard():
    with core._db_lock, core._db() as c:
        return dict(nf.startup_guard(c))


def planted_cases():
    tag = secrets.token_hex(2)
    cases = {}
    # no provenance
    plant(f"np{tag}", pub(seed()), "", "")
    cases["no provenance"] = f"np{tag}"
    # source=rotation pointing at a REAL binding (only the source check stops it)
    kr = seed()
    br = binding(f"rs{tag}", kr)
    ohr = nf.origin_hash(br["name"], br["node_pubkey"], br["issued_at"],
                         br["expires_at"], br["signature"])
    plant(br["name"], br["node_pubkey"], "rotation", ohr,
          (br["name"], br["node_pubkey"], br["issued_at"], br["expires_at"],
           br["signature"]))
    cases["source=rotation"] = br["name"]
    # fake label: claim_gate, hash points at no stored binding
    plant(f"fl{tag}", pub(seed()), "claim_gate", secrets.token_hex(32))
    cases["fake label"] = f"fl{tag}"
    # hash points at a binding for a different key
    kw, kp = seed(), seed()
    bw = binding(f"wk{tag}", kw)
    ohw = nf.origin_hash(bw["name"], bw["node_pubkey"], bw["issued_at"],
                         bw["expires_at"], bw["signature"])
    plant(bw["name"], pub(kp), "claim_gate", ohw,
          (bw["name"], bw["node_pubkey"], bw["issued_at"], bw["expires_at"],
           bw["signature"]))
    cases["wrong binding"] = bw["name"]
    # valid key, junk signature (hash computed over the junk, so it matches)
    kj = seed()
    junk = "ab" * 64
    ohj = nf.origin_hash(f"js{tag}", pub(kj), ISSUED, EXPIRES, junk)
    plant(f"js{tag}", pub(kj), "claim_gate", ohj,
          (f"js{tag}", pub(kj), ISSUED, EXPIRES, junk))
    cases["junk signature"] = f"js{tag}"
    # control: an honest claim_gate pin survives
    good = f"ok{tag}"
    claim_gate_pin(good, seed())
    cases["control"] = good
    return cases


def run_guard(which):
    cases = planted_cases()
    refused = guard()
    ok_ctl = cases["control"] not in refused and head(cases["control"]) is not None
    hit = cases[which] in refused and head(cases[which]) is None
    return ok_ctl and hit


for which in ("no provenance", "source=rotation", "fake label",
              "wrong binding", "junk signature"):
    check(f"startup guard refuses a planted pin: {which}", run_guard(which))

real_src = run_guard("source=rotation")
with patched(nf, "guard_check", lambda conn, name: nf.guard_resolve(
        conn, name, nf._latest(conn, name)[2], nf._latest(conn, name)[6])):
    mut_src = run_guard("source=rotation")
mutant("guard has no source check", "source=rotation pin refused", real_src, mut_src)
real_fl = run_guard("fake label") and run_guard("wrong binding")
with patched(nf, "guard_resolve", lambda *a: None):
    mut_fl = run_guard("fake label") and run_guard("wrong binding")
mutant("guard checks the label, not the hash", "fake label / wrong binding refused",
       real_fl, mut_fl)
real_js = run_guard("junk signature")
with patched(nf, "guard_sig_ok", lambda *a: True):
    mut_js = run_guard("junk signature")
mutant("guard runs checkvalid on the key but skips the signature verify",
       "junk signature refused", real_js, mut_js)


def run_unpin_reclaim():
    tag = secrets.token_hex(2)
    nm = f"rc{tag}"
    plant(nm, pub(seed()), "claim_gate", secrets.token_hex(32))
    guard()
    rows = db("SELECT kind FROM name_pin_log WHERE name=? ORDER BY id", (nm,))
    kinds = [r[0] for r in rows]
    reset_rates()
    hb = binding(nm, seed(), issued=iso(datetime.now(timezone.utc)
                                         - timedelta(seconds=5)))
    r = client.post("/api/v1/names/claim", data=hb)
    return (kinds == ["pin", "unpin"] and r.status_code == 200
            and head(nm)[0] == hb["node_pubkey"]), (kinds, r.status_code)


real, ui = run_unpin_reclaim()
check(f"refused pin -> UNPINNED by an appended entry; original kept; re-claim works {ui}",
      real)


def delete_unpin(conn, name, reason):
    conn.execute("DROP TRIGGER IF EXISTS name_pin_log_no_delete")
    conn.execute("DELETE FROM name_pin_log WHERE name=?", (name,))
    nf._sync_cache(conn, name)


with patched(nf, "unpin", delete_unpin):
    mut, um = run_unpin_reclaim()
with core._db_lock, core._db() as c:
    nf.ensure_schema(c)
mutant("trigger dropped; refused pin deleted", "log keeps original + refusal",
       real, mut)
trig_ok = False
with core._db_lock, core._db() as c:
    try:
        c.execute("DELETE FROM name_pin_log WHERE name='abac'")
    except sqlite3.DatabaseError:
        trig_ok = True
check("name_pin_log DELETE aborts (insert-only trigger)", trig_ok)

# ================================================================ item 12
print("item 12: binding path, /reach, gossip-out, RESOLVER.md")
sb = pub(seed())


def run_binding_gate():
    nm = f"bg{secrets.token_hex(3)}"
    b = binding(nm, seed())
    v0 = core._gossip_binding_verifies
    out = core.ingest_gossiped_binding(dict(b), sender_pub=sb)
    reset_rates()
    v1 = core._gossip_binding_verifies
    nm2 = f"bg{secrets.token_hex(3)}"
    r = post([], bindings=[binding(nm2, seed())])
    v2 = core._gossip_binding_verifies
    return (out == "dropped-unpinned" and v1 == v0 and r.status_code == 200
            and r.json()["outcomes"] == ["dropped-unpinned"] and v2 == v1)


real = run_binding_gate()
check("unpinned name from a non-OOB sender: 0 verifies on both gossip paths", real)
with patched(core, "_binding_pin_gate", lambda *a: None):
    mut = run_binding_gate()
mutant("pin gate after verify on the binding path", "0 verifies for unpinned", real, mut)
check("sender_pub=None is refused",
      core.ingest_gossiped_binding(binding("nosender", seed())) == "dropped-no-sender")

ncon = "contested-reach"
kq = seed()
claim_gate_pin(ncon, kq)
with core._db_lock, core._db() as c:
    nf._mark_contested(c, ncon, "belt")


def run_reach():
    return client.get(f"/api/v1/names/{ncon}/reach").status_code == 409


real = run_reach()
check("/names/{name}/reach returns 409 for a contested name", real)
import routes_social_serve as rss  # noqa: E402
with patched(nf, "is_contested", lambda conn, name: False):
    mut = run_reach()
mutant("reach ignores contested", "/reach 409", real, mut)

sent = []


def run_gossip_out():
    sent.clear()
    with patched(core, "_post_to_peer_path", lambda url, path, env: sent.append(env)):
        core._names_gossip_out()
        time.sleep(0.5)
    names = set()
    for env in sent:
        for b in env["body"].get("bindings", []):
            names.add(b["name"])
    return bool(sent) and ncon not in names and "abac" in names


real = run_gossip_out()
check("gossip-out skips contested names' bindings", real)
with patched(nf, "is_contested", lambda conn, name: False):
    mut = run_gossip_out()
mutant("gossip-out includes contested names", "contested skipped", real, mut)
check("RESOLVER.md states contested behaviour honestly (no recovery path in this build)",
      "no recovery path" in " ".join(doc.split()) and "CONTESTED" in doc)

print()
print("mutant table:")
for name, row, real_ok, killed in MUTANTS:
    print(f"  {'KILLED' if real_ok and killed else 'SURVIVED':8} {name}  [{row}]")
print(f"--- {PASS} passed, {FAIL} failed ---")
sys.exit(1 if FAIL else 0)
