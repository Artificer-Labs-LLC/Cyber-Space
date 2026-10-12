#!/usr/bin/env python3
"""ART-29 / ART-42 belt for the pin-rotation gate (Villhaze 524ef05b +
2dcc893c, rulings 392140b7), rebuilt after the Cipher (b0fa3fae), Bulwark
(35c9c527) and Lodestar BLOCKs on b606d2e.

In-process only. No live route hook. Every gate row runs the production
rule and at least one mutant that must fail that row:

  G0  namefork charged per cert before _norm_cert, outside the lock
  G1  weak_reason on the old key and on the new key, before verify;
      v1 records move no pin; seq and prev_hash are inside the signature
  G2  a cert never introduces a name; introducer check on unpinned names
  G3  a contested name never moves, never silently un-contests
  G4  contiguity (old key, seq, prev_hash); replay A->B, B->A, A->B refused
  G5  F3: one rotation per name per gossip round, held in the DB across calls
  F1  split, F2 boot, F4 overflow; V1-V3 pin rows; PIN-STALE; envelope kind;
      RESOLVER.md honesty lines

Chain depth is never a tiebreak.
"""
import inspect
import os
import sqlite3
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone

os.environ["CYBERNET_DB_DIR"] = tempfile.mkdtemp(prefix="art29-fork-")
os.environ.pop("CYBERNET_OOB_NODE_PINS", None)
os.environ.pop("CYBERNET_GENESIS_NAME_PIN", None)
os.environ.pop("CYBERNET_SECOND_MIRROR", None)
os.environ.pop("CYBERNET_ANNOUNCE_INTERVAL", None)
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from fastapi import HTTPException  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
import core  # noqa: E402
core.init_db()
import core_serve  # noqa: E402
import app as appmod  # noqa: E402
from fed import ed25519 as _ed  # noqa: E402
from fed import envelope as _env  # noqa: E402
import name_fork  # noqa: E402
import rotate_name  # noqa: E402
from rotate_name import (_rotate_payload, pin_anchor_hash,  # noqa: E402
                         rotation_cert_hash)
import window_open as wo  # noqa: E402

client = TestClient(appmod.app)
PASS = FAIL = 0
NOW = datetime.now(timezone.utc)
ISSUED = (NOW - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S+00:00")
FAR = "2099-01-01T00:00:00+00:00"
SENDER = "ab" * 32        # a known gossip peer, not pinned out of band
OOB = "cd" * 32           # a node key pinned out of band
ZERO_PUB = "00" * 32
MUTANTS = []


def check(label, cond, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok  {label}")
    else:
        FAIL += 1
        print(f"  FAIL {label} {extra}")


def record_mutant(name, real_ok, mutant_fails):
    MUTANTS.append((name, bool(real_ok), bool(mutant_fails)))
    check(f"MUTANT {name}: real passes and mutant fails the row",
          real_ok and mutant_fails, (real_ok, mutant_fails))


class patched:
    """Swap module attributes for one mutant arm, always restored."""

    def __init__(self, *triples):
        self.triples = triples
        self.saved = []

    def __enter__(self):
        for mod, attr, val in self.triples:
            self.saved.append((mod, attr, getattr(mod, attr)))
            setattr(mod, attr, val)

    def __exit__(self, *exc):
        for mod, attr, val in reversed(self.saved):
            setattr(mod, attr, val)
        return False


def pub_of(seed_hex):
    return _ed.publickey(bytes.fromhex(seed_hex)).hex()


def cert(name, old_seed, new_pub, seq=1, prev=None, issued=ISSUED):
    """A v2 cert signed with whatever payload rotate_name currently
    installs (so a payload mutant signs and verifies under the mutant)."""
    old_pub = pub_of(old_seed)
    prev = prev if prev is not None else pin_anchor_hash(name, old_pub)
    sig = _ed.sign(
        rotate_name._rotate_payload_v2(name, old_pub, new_pub, issued, seq, prev),
        bytes.fromhex(old_seed), bytes.fromhex(old_pub)).hex()
    return {"v": 2, "name": name, "old_pubkey": old_pub, "new_pubkey": new_pub,
            "issued_at": issued, "seq": seq, "prev_hash": prev, "signature": sig}


def chash(c):
    return rotation_cert_hash(c)


def fresh_conn():
    conn = sqlite3.connect(":memory:")
    conn.executescript(
        """
        CREATE TABLE name_bindings (
            name TEXT PRIMARY KEY,
            node_pubkey TEXT NOT NULL,
            issued_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            signature TEXT NOT NULL
        );
        CREATE TABLE name_rotations (
            name TEXT NOT NULL,
            old_pubkey TEXT NOT NULL,
            new_pubkey TEXT NOT NULL,
            issued_at TEXT NOT NULL,
            signature TEXT NOT NULL,
            accepted_at TEXT NOT NULL,
            PRIMARY KEY (name, old_pubkey, new_pubkey)
        );
        """)
    name_fork.ensure_schema(conn)
    return conn


def bind(conn, name, pub, expires=FAR):
    conn.execute(
        "INSERT OR REPLACE INTO name_bindings (name, node_pubkey, issued_at,"
        " expires_at, signature) VALUES (?,?,?,?,?)",
        (name, pub, ISSUED, expires, "ab" * 64))


def age_round(conn, name):
    """Move the name's last accepted round back one full gossip round."""
    conn.execute(
        "UPDATE name_pins SET last_round_at = last_round_at - ? WHERE name=?",
        (name_fork.round_seconds() + 1, name))


def ingest(conn, certs, sender=SENDER):
    return name_fork.ingest_rotation_round(conn, certs, sender)


def pin_of(conn, name):
    return name_fork.current_pin(conn, name)


def moves(conn, name):
    return name_fork.pin_log_moves(conn, name)


T2 = (0, _ed._Q - 1)


def mixed_pub(scalar):
    P = _ed._edwards(_ed._scalarmult(_ed._BPOINT, scalar), T2)
    return _ed._encodepoint(P).hex()


def forge_mixed_cert(name, scalar, new_pub, seq=1):
    """A v2 cert from a mixed-order old key a*B+T2 that passes strict
    checkvalid (even challenge). weak_reason is what refuses it."""
    old_pub = mixed_pub(scalar)
    prev = pin_anchor_hash(name, old_pub)
    msg = rotate_name._rotate_payload_v2(name, old_pub, new_pub, ISSUED, seq, prev)
    pub = bytes.fromhex(old_pub)
    for r in range(1, 10000):
        R = _ed._encodepoint(_ed._scalarmult(_ed._BPOINT, r))
        h = int.from_bytes(_ed._H(R + pub + msg), "little")
        if h % 2 == 0:
            S = (r + h * scalar) % _ed._L
            sig = (R + _ed._encodeint(S)).hex()
            return {"v": 2, "name": name, "old_pubkey": old_pub,
                    "new_pubkey": new_pub, "issued_at": ISSUED, "seq": seq,
                    "prev_hash": prev, "signature": sig}, msg
    raise RuntimeError("no even challenge")


K1, K2, K3, K4 = "11" * 32, "44" * 32, "55" * 32, "66" * 32
KX, KY = "22" * 32, "33" * 32
p1, p2, p3, p4 = pub_of(K1), pub_of(K2), pub_of(K3), pub_of(K4)
px, py = pub_of(KX), pub_of(KY)
real_weak = name_fork._weak_reason


# ================================================================ G1
print("G1: weak_reason on both keys, before verify")
MXS = 0x2468ACE
mx_cert, mx_msg = forge_mixed_cert("weakold", MXS, p2)
MX = mx_cert["old_pubkey"]
check("premise: the mixed-order old key passes strict checkvalid, fails weak_reason",
      _ed.checkvalid(bytes.fromhex(mx_cert["signature"]), mx_msg, bytes.fromhex(MX))
      and wo.weak_reason(MX) == "mixed-order")


def weak_old_row():
    conn = fresh_conn()
    name_fork.pin_initial(conn, "weakold", MX)  # a legacy weak pin
    res = ingest(conn, [mx_cert])
    return (res["accepted"] == {} and pin_of(conn, "weakold") == MX
            and moves(conn, "weakold") == 0)


g1_old = weak_old_row()
check("G1 weak OLD key: cert refused, pin unmoved, no pin-log row", g1_old)
with patched((name_fork, "_old_key_weak", lambda pub: False)):
    g1_old_m = weak_old_row()
record_mutant("G1 old-key weak_reason removed", g1_old, not g1_old_m)


def weak_new_rows():
    out = []
    for name, new in (("zeronew", ZERO_PUB), ("mixnew", mixed_pub(0x13579))):
        conn = fresh_conn()
        name_fork.pin_initial(conn, name, p1)
        bind(conn, name, p1)
        res = ingest(conn, [cert(name, K1, new)], sender=OOB)
        out.append(res["accepted"] == {} and pin_of(conn, name) == p1
                   and moves(conn, name) == 0)
    return all(out)


os.environ["CYBERNET_OOB_NODE_PINS"] = OOB
g1_new = weak_new_rows()
check("G1 weak NEW key (all-zero, mixed-order): refused even from an introducer", g1_new)
with patched((name_fork, "_new_key_weak", lambda pub: False)):
    g1_new_m = weak_new_rows()
record_mutant("G1 new-key weak_reason removed", g1_new, not g1_new_m)
os.environ.pop("CYBERNET_OOB_NODE_PINS", None)

verifies = []
real_verify = name_fork._verify


def counting_verify(rec):
    verifies.append(rec["name"])
    return real_verify(rec)


def verify_first_norm(rec):
    """Mutant: verify before the weak checks (the b606d2e order)."""
    if not isinstance(rec, dict):
        return None
    base = dict(rec)
    if not name_fork._verify(base):
        return None
    if name_fork._old_key_weak(base["old_pubkey"]) or name_fork._new_key_weak(base["new_pubkey"]):
        return None
    base["cert_hash"] = chash(base)
    return name_fork._Prepared(base)


def weak_costs_no_verify():
    verifies.clear()
    name_fork.prepare_round([cert("ordz", K1, ZERO_PUB), mx_cert])
    return verifies == []


with patched((name_fork, "_verify", counting_verify)):
    g1_order = weak_costs_no_verify()
    with patched((name_fork, "_norm_cert", verify_first_norm)):
        g1_order_m = weak_costs_no_verify()
src_norm = inspect.getsource(name_fork._norm_cert)
check("G1 order: a weak cert costs zero signature verifies; weak checks precede _verify in source",
      g1_order and src_norm.index("_old_key_weak(") < src_norm.index("_verify(")
      and src_norm.index("_new_key_weak(") < src_norm.index("_verify("), verifies)
record_mutant("G1 verify before weak_reason", g1_order, not g1_order_m)

conn = fresh_conn()
name_fork.pin_initial(conn, "v1rec", p1)
v1 = {"name": "v1rec", "old_pubkey": p1, "new_pubkey": p2, "issued_at": ISSUED,
      "signature": _ed.sign(_rotate_payload("v1rec", p1, p2, ISSUED),
                            bytes.fromhex(K1), bytes.fromhex(p1)).hex()}
check("G1 a v1 record verifies as history but moves no pin",
      rotate_name.verify_rotation(v1) is None and ingest(conn, [v1])["accepted"] == {}
      and pin_of(conn, "v1rec") == p1)


def relabel_rows():
    """seq and prev_hash are inside the signature: relabeling either one on
    a validly signed cert does not verify."""
    conn = fresh_conn()
    name_fork.pin_initial(conn, "relabel", p1)
    c_seq = cert("relabel", K1, p2, seq=5)
    c_seq["seq"] = 1
    r1 = ingest(conn, [c_seq])["accepted"] == {}
    conn2 = fresh_conn()
    name_fork.pin_initial(conn2, "relabel", p1)
    c_prev = cert("relabel", K1, p2, seq=1, prev="ee" * 32)
    c_prev["prev_hash"] = pin_anchor_hash("relabel", p1)
    r2 = ingest(conn2, [c_prev])["accepted"] == {}
    return r1, r2


real_payload = rotate_name._rotate_payload_v2
rl_seq, rl_prev = relabel_rows()
check("G1 seq relabel on a signed cert is refused", rl_seq)
check("G1 prev_hash relabel on a signed cert is refused", rl_prev)


def payload_no_seq(name, old, new, issued, seq, prev):
    return real_payload(name, old, new, issued, 0, prev)


def payload_no_prev(name, old, new, issued, seq, prev):
    return real_payload(name, old, new, issued, seq, "00" * 32)


with patched((rotate_name, "_rotate_payload_v2", payload_no_seq)):
    m_seq, _ = relabel_rows()
with patched((rotate_name, "_rotate_payload_v2", payload_no_prev)):
    _, m_prev = relabel_rows()
record_mutant("G1 seq dropped from the signed payload", rl_seq, not m_seq)
record_mutant("G1 prev_hash dropped from the signed payload", rl_prev, not m_prev)


# ================================================================ G2
print("G2: a cert never introduces a name; introducer check on unpinned names")


def unknown_rows():
    conn = fresh_conn()
    certs = [cert(f"squat{i}", K1, p2) for i in range(20)]
    res = ingest(conn, certs, sender=OOB)
    boot = ingest(conn, [cert("squatboot", K1, px), cert("squatboot", K1, py)], sender=OOB)
    pinned = conn.execute("SELECT COUNT(*) FROM name_pins").fetchone()[0]
    contested = conn.execute("SELECT COUNT(*) FROM name_contested").fetchone()[0]
    forks = conn.execute("SELECT COUNT(*) FROM name_fork_certs").fetchone()[0]
    return (res["accepted"] == {} and res["refused"].get("unknown-name") == 20
            and boot["contested"] == set() and pinned == 0 and contested == 0
            and forks == 0)


os.environ["CYBERNET_OOB_NODE_PINS"] = OOB
g2_unknown = unknown_rows()
check("G2 unknown name: 20 certs (even from an OOB sender) pin nothing, contest nothing",
      g2_unknown)
with patched((name_fork, "cert_introduces_name", lambda: True)):
    g2_unknown_m = unknown_rows()
record_mutant("G2 cert introduces an unknown name", g2_unknown, not g2_unknown_m)
os.environ.pop("CYBERNET_OOB_NODE_PINS", None)

# The real owner is not squatted: after the refused certs, a gossiped
# binding for the name is not dropped as a pin mismatch.
now = datetime.now(timezone.utc)
claim_issued = now.strftime("%Y-%m-%dT%H:%M:%S+00:00")
claim_expires = (now + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%S+00:00")


def binding_for(name, seed):
    pub = pub_of(seed)
    sig = _ed.sign(
        core._name_claim_payload(name, pub, claim_issued, claim_expires),
        bytes.fromhex(seed), bytes.fromhex(pub)).hex()
    return {"name": name, "node_pubkey": pub, "issued_at": claim_issued,
            "expires_at": claim_expires, "signature": sig}


os.environ["CYBERNET_OOB_NODE_PINS"] = OOB
squat = core.ingest_names_gossip(
    {"rotations": [cert("ownerok", K1, ZERO_PUB), cert("ownerok", K1, p2)],
     "bindings": []}, OOB)
owner = core.ingest_gossiped_binding(binding_for("ownerok", "93" * 32), sender_pub=OOB)
with core._db_lock, core._db() as conn:
    owner_pin = name_fork.current_pin(conn, "ownerok")
os.environ.pop("CYBERNET_OOB_NODE_PINS", None)
check("G2 the real owner's binding still lands after squat certs (no dropped-pin)",
      squat["accepted_rotations"] == 0 and owner == "inserted"
      and owner_pin == pub_of("93" * 32), (squat, owner, owner_pin))


def introducer_rows():
    out = {}
    for label, env in (("unset", None), ("empty", ""), ("blank", " , "),
                       ("other", "ef" * 32)):
        if env is None:
            os.environ.pop("CYBERNET_OOB_NODE_PINS", None)
        else:
            os.environ["CYBERNET_OOB_NODE_PINS"] = env
        conn = fresh_conn()
        bind(conn, "intro", p1)
        res = ingest(conn, [cert("intro", K1, p2)], sender=SENDER)
        out[label] = (res["accepted"] == {} and pin_of(conn, "intro") is None
                      and res["refused"].get("unpinned-sender") == 1)
    conn = fresh_conn()
    bind(conn, "intro", p1)
    out["none-sender"] = (ingest(conn, [cert("intro", K1, p2)], sender=None)["accepted"] == {})
    os.environ["CYBERNET_OOB_NODE_PINS"] = OOB
    conn = fresh_conn()
    bind(conn, "intro", p1)
    res = ingest(conn, [cert("intro", K1, p2)], sender=OOB)
    log = conn.execute(
        "SELECT seq, pubkey FROM name_pin_log WHERE name='intro' ORDER BY seq").fetchall()
    out["oob"] = (res["accepted"] == {"intro": p2} and pin_of(conn, "intro") == p2
                  and log == [(0, p1), (1, p2)])
    os.environ.pop("CYBERNET_OOB_NODE_PINS", None)
    return out


g2_intro = introducer_rows()
g2_intro_ok = all(g2_intro.values())
check("G2 unpinned bound name: non-OOB, unset/empty/blank allowlist, and no sender all refuse;"
      " an OOB introducer anchors the binding key at seq 0", g2_intro_ok, g2_intro)
with patched((name_fork, "sender_may_introduce", lambda s: True)):
    g2_intro_m = introducer_rows()
record_mutant("G2 introducer check removed", g2_intro_ok,
              not (g2_intro_m["other"] and g2_intro_m["unset"]))


# ================================================================ G4
print("G4: contiguity, replay, fork evidence")


def noncontig_rows():
    conn = fresh_conn()
    name_fork.pin_initial(conn, "nc", p1)
    anchor = pin_anchor_hash("nc", p1)
    gap = ingest(conn, [cert("nc", K1, p2, seq=2, prev=anchor)])["accepted"] == {}
    badprev = ingest(conn, [cert("nc", K1, p2, seq=1, prev="ee" * 32)])["accepted"] == {}
    notpin = ingest(conn, [cert("nc", K2, p3, seq=1, prev=anchor)])["accepted"] == {}
    still = pin_of(conn, "nc") == p1 and moves(conn, "nc") == 0
    good = ingest(conn, [cert("nc", K1, p2, seq=1)])["accepted"] == {"nc": p2}
    return {"gap": gap, "badprev": badprev, "notpin": notpin,
            "still": still, "good": good}


g4 = noncontig_rows()
g4_ok = all(g4.values())
check("G4 non-contiguous: seq gap, wrong prev_hash, signer not the pin all refused;"
      " the contiguous cert is accepted", g4_ok, g4)
with patched((name_fork, "_contiguous", lambda st, r: True)):
    g4_any = noncontig_rows()
record_mutant("G4 non-contiguous move accepted (Cipher)", g4_ok, not all(g4_any.values()))
with patched((name_fork, "_contiguous", lambda st, r: r["old_pubkey"] == st["pubkey"]
              and r["prev_hash"] == st["head"])):
    g4_noseq = noncontig_rows()
record_mutant("G4 seq not enforced", g4_ok, not g4_noseq["gap"])
with patched((name_fork, "_contiguous", lambda st, r: r["old_pubkey"] == st["pubkey"]
              and r["seq"] == st["seq"] + 1)):
    g4_noprev = noncontig_rows()
record_mutant("G4 prev_hash not enforced", g4_ok, not g4_noprev["badprev"])
with patched((name_fork, "_contiguous", lambda st, r: r["seq"] == st["seq"] + 1
              and r["prev_hash"] == st["head"])):
    g4_noold = noncontig_rows()
record_mutant("G4 signer-is-pin not enforced", g4_ok, not g4_noold["notpin"])


def replay_row():
    conn = fresh_conn()
    name_fork.pin_initial(conn, "rp", p1)
    ab = cert("rp", K1, p2, seq=1)
    r1 = ingest(conn, [ab])
    age_round(conn, "rp")
    ba = cert("rp", K2, p1, seq=2, prev=chash(ab))
    r2 = ingest(conn, [ba])
    age_round(conn, "rp")
    r3 = ingest(conn, [ab])
    age_round(conn, "rp")
    r4 = ingest(conn, [ab, ba])
    return (r1["accepted"] == {"rp": p2} and r2["accepted"] == {"rp": p1}
            and r3["accepted"] == {} and r4["accepted"] == {}
            and r3["refused"].get("replay") == 1
            and pin_of(conn, "rp") == p1 and name_fork.current_seq(conn, "rp") == 2
            and moves(conn, "rp") == 2 and not name_fork.is_contested(conn, "rp")), r3


g4_replay, r3 = replay_row()
check("G4 replay: A->B, B->A, replay A->B refused; pin stays A at seq 2; not contested",
      g4_replay, r3)
with patched((name_fork, "_is_historical", lambda st, r: False),
             (name_fork, "_contiguous", lambda st, r: r["old_pubkey"] == st["pubkey"])):
    g4_replay_m, _ = replay_row()
record_mutant("G4 seq/prev_hash discipline dropped (b606d2e replay)", g4_replay,
              not g4_replay_m)

# A later legitimate A->B at seq 3 is a new generation, not a fork.
conn = fresh_conn()
name_fork.pin_initial(conn, "aba", p1)
ab = cert("aba", K1, p2, seq=1)
ingest(conn, [ab])
age_round(conn, "aba")
ba = cert("aba", K2, p1, seq=2, prev=chash(ab))
ingest(conn, [ba])
age_round(conn, "aba")
ab3 = cert("aba", K1, p2, seq=3, prev=chash(ba), issued=NOW.strftime("%Y-%m-%dT%H:%M:%S+00:00"))
r = ingest(conn, [ab3])
check("G4 a fresh A->B at seq 3 continues the chain (no false fork)",
      r["accepted"] == {"aba": p2} and not name_fork.is_contested(conn, "aba")
      and name_fork.current_seq(conn, "aba") == 3, r)


def split_exchange(conn_b, conn_c, cert_x, cert_y):
    ingest(conn_b, [cert_x])
    ingest(conn_c, [cert_y])
    ingest(conn_b, [cert_y])
    ingest(conn_c, [cert_x])


def node_clean_winner(conn, name, winner):
    return (not name_fork.is_contested(conn, name)
            and name_fork.current_pin(conn, name) == winner)


def split_nodes():
    b = fresh_conn()
    c = fresh_conn()
    for n in (b, c):
        name_fork.pin_initial(n, "split", p1)
    split_exchange(b, c, cert("split", K1, px), cert("split", K1, py))
    return b, c


b, c = split_nodes()
f1_nodes = (
    name_fork.is_contested(b, "split") and name_fork.is_contested(c, "split")
    and name_fork.fork_cert_count(b, "split") == 2
    and name_fork.fork_cert_count(c, "split") == 2
    and name_fork.current_pin(b, "split") == px
    and name_fork.current_pin(c, "split") == py)
with core._db_lock, core._db() as conn:
    name_fork.pin_initial(conn, "splitserve", p1)
    ingest(conn, [cert("splitserve", K1, px)])
    ingest(conn, [cert("splitserve", K1, py)])
    conn.execute(
        "INSERT OR REPLACE INTO name_bindings "
        "(name, node_pubkey, issued_at, expires_at, signature) VALUES (?,?,?,?,?)",
        ("splitserve", px, ISSUED, "2027-10-01T00:00:00+00:00", "ab" * 64))
r = client.get("/api/v1/names/splitserve")
f1_serve = (r.status_code == 409 and r.json().get("detail") == "name contested"
            and px not in r.text and py not in r.text)
f1_real = f1_nodes and f1_serve
check("F1-split: two valid certs at one (name, prior key, seq): both nodes CONTESTED; resolve 409",
      f1_real, (f1_nodes, r.status_code, r.text))
with patched((name_fork, "second_cert_contests", lambda *a, **k: False)):
    mb, mc = split_nodes()
    f1_mutant_clean = (node_clean_winner(mb, "split", px)
                       and node_clean_winner(mc, "split", py))
record_mutant("F1-split", f1_real, f1_mutant_clean)


# ================================================================ G3
print("G3: contested never moves, never silently un-contests")


def contested_row():
    conn = fresh_conn()
    name_fork.pin_initial(conn, "frozen", p1)
    cx = cert("frozen", K1, px)
    ingest(conn, [cx])
    ingest(conn, [cert("frozen", K1, py)])
    age_round(conn, "frozen")
    nxt = cert("frozen", KX, p3, seq=2, prev=chash(cx))
    r = ingest(conn, [nxt, cx])
    return (name_fork.is_contested(conn, "frozen") and r["accepted"] == {}
            and pin_of(conn, "frozen") == px and moves(conn, "frozen") == 1)


g3 = contested_row()
check("G3 a contested name ignores a contiguous next cert and a replay; stays contested", g3)
with patched((name_fork, "_frozen", lambda conn, name, contested: False)):
    g3_m = contested_row()
record_mutant("G3 contested name may move", g3, not g3_m)


# ================================================================ F2
print("F2: contested from birth")


def boot_row():
    os.environ["CYBERNET_OOB_NODE_PINS"] = OOB
    try:
        conn = fresh_conn()
        bind(conn, "boot", p1)
        res = ingest(conn, [cert("boot", K1, px), cert("boot", K1, py)], sender=OOB)
        return conn, res
    finally:
        os.environ.pop("CYBERNET_OOB_NODE_PINS", None)


boot, boot_result = boot_row()
f2_real = ("boot" in boot_result["contested"] and name_fork.is_contested(boot, "boot")
           and name_fork.current_pin(boot, "boot") is None
           and name_fork.fork_cert_count(boot, "boot") == 2
           and boot.execute("SELECT COUNT(*) FROM name_rotations WHERE name='boot'").fetchone()[0] == 0)
check("F2-boot: two continuations of one generation in one round stay contested, no first-seen",
      f2_real, boot_result)
with patched((name_fork, "bootstrap_picks_first", lambda: True)):
    mboot, _ = boot_row()
    f2_mutant_picks = node_clean_winner(mboot, "boot", px)
record_mutant("F2-boot", f2_real, f2_mutant_picks)


# ================================================================ G5 / F3
print("G5 / F3: one rotation per name per gossip round, across calls")
chain = [cert("burst", K1, p2, seq=1)]
chain.append(cert("burst", K2, p3, seq=2, prev=chash(chain[0])))
chain.append(cert("burst", K3, p4, seq=3, prev=chash(chain[1])))


def burst_row():
    conn = fresh_conn()
    name_fork.pin_initial(conn, "burst", p1)
    res = ingest(conn, chain)
    return (res["accepted"] == {"burst": p2} and pin_of(conn, "burst") == p2
            and "burst" in res["deferred"] and moves(conn, "burst") == 1), res


f3_burst, burst_res = burst_row()
check("F3-burst: one batch walks one hop; chain depth is not a tiebreak", f3_burst, burst_res)
with patched((name_fork, "round_gate_open", lambda st, now: True)):
    f3_burst_m, _ = burst_row()
record_mutant("F3-burst round gate removed", f3_burst, not f3_burst_m)


def cross_call_row():
    conn = fresh_conn()
    name_fork.pin_initial(conn, "burst", p1)
    a = ingest(conn, [chain[0]])
    b_ = ingest(conn, [chain[1]])
    held = (a["accepted"] == {"burst": p2} and b_["accepted"] == {}
            and "burst" in b_["deferred"] and pin_of(conn, "burst") == p2)
    stored = name_fork.last_round_at(conn, "burst") is not None
    age_round(conn, "burst")
    later = ingest(conn, [chain[1]])
    walked = later["accepted"] == {"burst": p3} and moves(conn, "burst") == 2
    return held and stored and walked, (a, b_, later)


f3_cross, cross_detail = cross_call_row()
check("F3 across calls: the second POST in one round is held (round stored in the DB);"
      " after a round the chain continues", f3_cross, cross_detail)
with patched((name_fork, "_persist_round", lambda conn, name, now: None)):
    f3_cross_m, _ = cross_call_row()
record_mutant("F3 round per POST, not persisted (Bulwark row 2)", f3_cross, not f3_cross_m)

# Same thing through the receive half, two POSTs from one peer.
with core._db_lock, core._db() as conn:
    name_fork.pin_initial(conn, "twopost", p1)
tp1 = cert("twopost", K1, p2, seq=1)
tp2 = cert("twopost", K2, p3, seq=2, prev=chash(tp1))
g_a = core.ingest_names_gossip({"rotations": [tp1], "bindings": []}, "a1" * 32)
g_b = core.ingest_names_gossip({"rotations": [tp2], "bindings": []}, "a1" * 32)
with core._db_lock, core._db() as conn:
    tp_pin = name_fork.current_pin(conn, "twopost")
check("F3 two gossip POSTs give one hop", g_a["accepted_rotations"] == 1
      and g_b["accepted_rotations"] == 0 and g_b["deferred_names"] == ["twopost"]
      and tp_pin == p2, (g_a, g_b))


# ================================================================ G0 / F4
print("G0 / F4: namefork budget before _norm_cert, outside the lock")
with core._db_lock, core._db() as conn:
    name_fork.pin_initial(conn, "overflow", p1)
overs = [cert("overflow", K1, pub_of(s)) for s in ("71" * 32, "72" * 32, "73" * 32, "74" * 32)]
fsender = "ab" * 32
before = len(core._hits[f"namefork:{fsender}"])
f4 = core.ingest_names_gossip({"rotations": overs, "bindings": []}, fsender)
with core._db_lock, core._db() as conn:
    stored = name_fork.fork_cert_count(conn, "overflow")
    extra = name_fork.overflow_count(conn, "overflow")
    contested = name_fork.is_contested(conn, "overflow")
after = len(core._hits[f"namefork:{fsender}"])
check("F4: first two fork certs stored, the rest counted", stored == 2 and extra == 2
      and contested, (stored, extra, contested, f4))
check("F4 + G0: bucket grew by one per cert (4) plus one per overflow cert (2)",
      after == before + len(overs) + extra, (before, after, extra))

pinned_name = "budget"
with core._db_lock, core._db() as conn:
    name_fork.pin_initial(conn, pinned_name, p1)
flood = [cert(pinned_name, K1, pub_of(f"{i:02x}" * 32), issued=ISSUED) for i in range(0x80, 0x80 + 40)]
lock_seen = []
real_check = core._check_rate


def watching_check(bucket, *a, **k):
    if bucket.startswith("namefork:"):
        lock_seen.append(core._db_lock.locked())
    return real_check(bucket, *a, **k)


def flood_row():
    verifies.clear()
    lock_seen.clear()
    sender = os.urandom(32).hex()
    code = None
    try:
        core.ingest_names_gossip({"rotations": flood, "bindings": []}, sender)
    except HTTPException as e:
        code = e.status_code
    spent = len(core._hits[f"namefork:{sender}"])
    with core._db_lock, core._db() as conn:
        untouched = (name_fork.current_pin(conn, pinned_name) == p1
                     and not name_fork.is_contested(conn, pinned_name))
    return (code == 429 and verifies == [] and spent == core.NAMEFORK_LIMIT
            and untouched and lock_seen and not any(lock_seen)), (code, len(verifies), spent)


def charge_after_norm(certs, charge=None):
    """Mutant: normalize (verify) first, charge after — the b606d2e order."""
    out = [r for r in (name_fork._norm_cert(c) for c in (certs or [])) if r is not None]
    if charge is not None:
        for _ in certs or []:
            charge()
    return out


with patched((name_fork, "_verify", counting_verify), (core, "_check_rate", watching_check)):
    g0, g0_detail = flood_row()
    with patched((name_fork, "prepare_round", charge_after_norm)):
        g0_m, g0_m_detail = flood_row()
check(f"G0: 40 certs past a {core.NAMEFORK_LIMIT}-token budget -> 429 with zero verifies,"
      " charged outside the DB lock, nothing written", g0, g0_detail)
record_mutant("G0 namefork charged after _norm_cert", g0, not g0_m)
src_ing = inspect.getsource(core.ingest_names_gossip)
check("G0 source order: prepare_round (charge + G1) precedes the DB lock",
      src_ing.index("prepare_round(") < src_ing.index("with _db_lock"))
check("send half never exceeds one peer's namefork budget per POST",
      "[:NAMEFORK_LIMIT]" in inspect.getsource(core._names_gossip_rotations))


# ================================================================ route
print("rotate route: v2 only, contiguous, one per round")


def reset_rate():
    with core._db_lock:
        core_serve._hits.clear()


def claim_sig(name, seed, issued, expires):
    pub = pub_of(seed)
    return _ed.sign(core._name_claim_payload(name, pub, issued, expires),
                    bytes.fromhex(seed), bytes.fromhex(pub)).hex()


def rot_form(name, old_seed, new_seed, seq, prev, v2=True):
    old_pub, new_pub = pub_of(old_seed), pub_of(new_seed)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")
    exp = (datetime.now(timezone.utc) + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%S+00:00")
    c = cert(name, old_seed, new_pub, seq=seq, prev=prev, issued=stamp)
    form = {"name": name, "old_pubkey": old_pub, "new_pubkey": new_pub,
            "rotation_issued_at": stamp, "rotation_signature": c["signature"],
            "binding_issued_at": stamp, "binding_expires_at": exp,
            "binding_signature": claim_sig(name, new_seed, stamp, exp)}
    if v2:
        form["rotation_seq"] = str(seq)
        form["rotation_prev_hash"] = prev
    else:
        form["rotation_signature"] = _ed.sign(
            _rotate_payload(name, old_pub, new_pub, stamp),
            bytes.fromhex(old_seed), bytes.fromhex(old_pub)).hex()
    return form, c


reset_rate()
cl_issued = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")
cl_exp = (datetime.now(timezone.utc) + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%S+00:00")
r = client.post("/api/v1/names/claim", data={
    "name": "routev2", "node_pubkey": p1, "issued_at": cl_issued,
    "expires_at": cl_exp, "signature": claim_sig("routev2", K1, cl_issued, cl_exp)})
check("route: claim pins the key at seq 0", r.status_code == 200, r.text[:200])
reset_rate()
anchor = pin_anchor_hash("routev2", p1)
f_v1, _ = rot_form("routev2", K1, K2, 1, anchor, v2=False)
r_v1 = client.post("/api/v1/names/rotate", data=f_v1)
check("route: a v1 record (no rotation_seq) is 400", r_v1.status_code == 400
      and "v2" in r_v1.text, (r_v1.status_code, r_v1.text[:200]))
reset_rate()
f1_, c1_ = rot_form("routev2", K1, K2, 1, anchor)
r_ok = client.post("/api/v1/names/rotate", data=f1_)
chain_doc = client.get("/api/v1/names/routev2/rotations").json()
check("route: v2 seq 1 rotates; /rotations serves seq, prev_hash, pin_seq, pin_head",
      r_ok.status_code == 200 and chain_doc.get("pin_seq") == 1
      and chain_doc.get("pin_head") == chash(c1_)
      and chain_doc["rotations"][0].get("seq") == 1
      and rotate_name.verify_rotation({**chain_doc["rotations"][0], "name": "routev2"}) is None,
      (r_ok.status_code, r_ok.text[:200], chain_doc))
reset_rate()
f2_, _ = rot_form("routev2", K2, K3, 2, chash(c1_))
r_held = client.post("/api/v1/names/rotate", data=f2_)
check("route: a second rotation in the same round is held (429)",
      r_held.status_code == 429 and "per gossip round" in r_held.text,
      (r_held.status_code, r_held.text[:200]))
with core._db_lock, core._db() as conn:
    age_round(conn, "routev2")
reset_rate()
f_rp, _ = rot_form("routev2", K1, K2, 1, anchor)
r_rp = client.post("/api/v1/names/rotate", data=f_rp)
check("route: a replayed seq-1 cert is refused (old key no longer holds the name)",
      r_rp.status_code == 400, (r_rp.status_code, r_rp.text[:200]))
reset_rate()
f2b, _ = rot_form("routev2", K2, K3, 2, chash(c1_))
r_next = client.post("/api/v1/names/rotate", data=f2b)
with core._db_lock, core._db() as conn:
    rv_pin = name_fork.current_pin(conn, "routev2")
    rv_seq = name_fork.current_seq(conn, "routev2")
check("route: after a round, seq 2 continues the chain",
      r_next.status_code == 200 and rv_pin == p3 and rv_seq == 2,
      (r_next.status_code, r_next.text[:200], rv_pin, rv_seq))


# ================================================================ V1-V3
print("V1-V3: pins on the resolve and binding paths")
fresh_key = "99" * 32
verify_calls = []
real_bverify = core._name_binding_verify


def counting_bverify(*args, **kwargs):
    verify_calls.append(args)
    return real_bverify(*args, **kwargs)


with patched((core, "_name_binding_verify", counting_bverify)):
    os.environ["CYBERNET_GENESIS_NAME_PIN"] = "46b62b6c" + "11" * 28
    with core._db_lock, core._db() as conn:
        refused = name_fork.pin_refuses_before_signature(conn, "genesis", fresh_key)
src = inspect.getsource(core.resolve_cyberspace)
pin_at = src.index("pin_refuses_before_signature")
verify_at = src.index("_name_binding_verify")
check("V1: pin refuses a fresh genesis key before any signature count",
      refused and verify_calls == [] and pin_at < verify_at,
      (refused, verify_calls, pin_at, verify_at))
live_at = src.index("live_pin")
live_verify = src.index("_name_binding_verify", live_at)
check("V2: live-agreement pin match precedes the live signature count",
      live_at < live_verify and "live_pub != live_pin" in src)

os.environ.pop("CYBERNET_OOB_NODE_PINS", None)
free = binding_for("v3free", "81" * 32)
dropped = core.ingest_gossiped_binding(free, sender_pub="ab" * 32)
legacy = core.ingest_gossiped_binding(free, sender_pub=None)
with core._db_lock, core._db() as conn:
    name_fork.pin_initial(conn, "v3free", "cc" * 32)
wrong = binding_for("v3free", "82" * 32)
pinned_drop = core.ingest_gossiped_binding(wrong, sender_pub="ab" * 32)
os.environ["CYBERNET_OOB_NODE_PINS"] = "ab" * 32
intro = binding_for("v3oob", "83" * 32)
introduced = core.ingest_gossiped_binding(intro, sender_pub="ab" * 32)
with core._db_lock, core._db() as conn:
    intro_pin = name_fork.current_pin(conn, "v3oob")
later = binding_for("v3oob", "84" * 32)
later_drop = core.ingest_gossiped_binding(later, sender_pub="ab" * 32)
with core._db_lock, core._db() as conn:
    intro_pin_after = name_fork.current_pin(conn, "v3oob")
os.environ.pop("CYBERNET_OOB_NODE_PINS", None)
check("V3: unpinned gossip without an out-of-band sender is refused",
      dropped == "dropped-unpinned", dropped)
check("V3: a direct caller with no sender still merges", legacy == "inserted", legacy)
check("V3: a pinned name refuses a key that is not the pin",
      pinned_drop == "dropped-pin", pinned_drop)
check("V3: an out-of-band sender may introduce, and that key sticks",
      introduced == "inserted" and intro_pin == intro["node_pubkey"]
      and later_drop == "dropped-pin" and intro_pin_after == intro_pin,
      (introduced, intro_pin, later_drop, intro_pin_after))


# ================================================================ PIN-STALE
print("PIN-STALE: pins never auto-expire (392140b7)")
lapsed = (datetime.now(timezone.utc) - timedelta(days=100)).strftime("%Y-%m-%dT%H:%M:%S+00:00")
recent = (datetime.now(timezone.utc) - timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%S+00:00")
with core._db_lock, core._db() as conn:
    name_fork.pin_initial(conn, "lapsed", p1)
    name_fork.pin_initial(conn, "recent", p1)
    for n, exp in (("lapsed", lapsed), ("recent", recent)):
        conn.execute(
            "INSERT OR REPLACE INTO name_bindings (name, node_pubkey, issued_at,"
            " expires_at, signature) VALUES (?,?,?,?,?)",
            (n, p1, "2025-01-01T00:00:00+00:00", exp, "ab" * 64))
results = {}
for n in ("lapsed", "recent"):
    reset_rate()
    st = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")
    ex = (datetime.now(timezone.utc) + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%S+00:00")
    results[n] = client.post("/api/v1/names/claim", data={
        "name": n, "node_pubkey": p2, "issued_at": st, "expires_at": ex,
        "signature": claim_sig(n, K2, st, ex)})
with core._db_lock, core._db() as conn:
    lapsed_stale = name_fork.is_pin_stale(conn, "lapsed")
    recent_stale = name_fork.is_pin_stale(conn, "recent")
    lapsed_pin = name_fork.current_pin(conn, "lapsed")
r_res = client.get("/api/v1/names/lapsed")
check("PIN-STALE: lapsed past day 90 + new key, no cert -> refused, marked, pin kept, resolve 409",
      results["lapsed"].status_code == 400 and "PIN-STALE" in results["lapsed"].text
      and lapsed_stale and lapsed_pin == p1 and r_res.status_code == 409
      and "pin-stale" in r_res.text,
      (results["lapsed"].status_code, results["lapsed"].text[:160], r_res.status_code))
check("PIN-STALE: inside 90 days it is the ordinary pin refusal, not stale",
      results["recent"].status_code == 400 and "does not match the pin" in results["recent"].text
      and not recent_stale, (results["recent"].status_code, results["recent"].text[:160]))


# ================================================================ envelope
print("envelope: kind is bound (python -m fed.envelope runs in the suite)")
st = subprocess.run([sys.executable, "-m", "fed.envelope"], cwd=HERE,
                    capture_output=True, text=True)
check("python -m fed.envelope self-test passes", st.returncode == 0
      and "kind binding: OK" in st.stdout, st.stdout[-300:] + st.stderr[-300:])
runner = open(os.path.join(HERE, "run_tests.sh"), encoding="utf-8").read()
check("run_tests.sh runs the fed/envelope.py self-test", "-m fed.envelope" in runner)
real_canonical = _env._canonical


def relabel_row():
    seed = "5a" * 32
    pub = pub_of(seed)
    body = {"from_node_pub": pub, "bindings": [], "rotations": []}
    e = _env.make_envelope(seed, pub, core._NODE_PUB, body, kind="announce")
    e["kind"] = "names-gossip"
    r = client.post("/fed/names/gossip", json=e)
    return r.status_code == 400 and "invalid envelope" in r.text


env_real = relabel_row()
check("a re-labeled kind is refused on /fed/names/gossip", env_real)
with patched((_env, "_canonical", lambda ts, rcpt, bh, kind=None: real_canonical(ts, rcpt, bh, None))):
    env_m = relabel_row()
record_mutant("envelope kind binding dropped (R7)", env_real, not env_m)


# ================================================================ honesty
print("honesty")
rule_src = open(os.path.join(HERE, "name_fork.py"), encoding="utf-8").read()
resolver = open(os.path.join(HERE, "docs", "RESOLVER.md"), encoding="utf-8").read()
check("fork rule states chain depth is never a tiebreak",
      "Chain depth is never a tiebreak" in name_fork.FORK_RULE
      and "Chain depth is never a tiebreak" in rule_src
      and "Chain depth is never a tiebreak" in resolver)
check("RESOLVER.md: per-node consistency, no mirror agreement, no stolen-key recovery",
      "buys per-node consistency" in resolver
      and "does not buy mirror agreement after a fork" in resolver
      and "does not recover a stolen key" in resolver)
check("RESOLVER.md: a contested name has no recovery path in this build (Villhaze 2dcc893c row 5)",
      "has no recovery path in this build" in resolver
      and "contested-recovery spec is an open board item" in resolver)
check("RESOLVER.md: pins never auto-expire; PIN-STALE on lapse",
      "Pins never expire automatically" in resolver and "PIN-STALE" in resolver)

print("mutant table:")
for name, real, killed in MUTANTS:
    print(f"  {'killed' if real and killed else 'SURVIVED'}  {name}")
print("---")
print(f"SUMMARY: {PASS} passed, {FAIL} failed ({len(MUTANTS)} mutants)")
sys.exit(1 if FAIL else 0)
