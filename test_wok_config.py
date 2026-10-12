#!/usr/bin/env python3
"""Window-open witness kinds, split 8/8: Examiner ca4e0404 witness config
and Loom's orphans_root (PENDING Villhaze ratification).

Witness set: N independent keys, no Genesis node key, threshold pinned
with no default and a strict majority (2-of-3 reference). ORPHANS: the
orphan leaves are witness-signed under orphans_root; node B compares them
leaf for leaf with the clean chains that have no bound leaf. Every mutant
here is killed by a row in this file."""
import os

import hop_certs as hc
from wok_common import (FUT, b_accepts, b_proof, bind, check, core, finish, finish_window,
                        keypair, lw, open_or, record_mutant, sign_with, wipe, wo)
import routes_legacy_witness as rlw

ISS = "2026-01-01T00:00:00+00:00"
NODE = core._NODE_PUB.lower()
W3 = [keypair(bytes([0xF0 + j]) * 32) for j in range(3)]
LOG = "ef" * 32


def mutate(mod, attr, value, fn):
    real = getattr(mod, attr)
    setattr(mod, attr, value)
    try:
        return fn()
    finally:
        setattr(mod, attr, real)


def load(pubs, t):
    try:
        return True, lw.load_witness_set(",".join(pubs), t)
    except ValueError as e:
        return False, str(e)


# ---------------------------------------------------------------- witness set at config load
ok23, ws23 = load(W3, "2")
check("2-of-3 independent witness keys load", ok23 and ws23.threshold == 2, ws23)


def head(signers):
    h = {"log_id": LOG, "witness_set": ws23.id, "seq": 3, "head_hash": "ab" * 32,
         "window_open_seq": 1, "window_close_seq": 2, "window_state": "closed",
         **{k: "00" * 32 for k in lw.HEAD_ROOT_FIELDS}}
    s = lw.sign_head(h, [lambda m, _p=p: (_p, sign_with(_p, m)) for p in signers])
    try:
        lw.verify_head(s, ws23, LOG)
        return True
    except lw.WitnessRefused:
        return False


check("2-of-3: a head signed by 2 of the 3 witnesses is accepted", head(W3[:2]))
check("2-of-3: a head signed by 1 of the 3 witnesses is refused", not head(W3[:1]))


def genesis_row():
    return load(W3[:2] + [NODE], "2")


g_ok, g_why = genesis_row()
real_g = (not g_ok) and g_why == lw.GENESIS_IN_SET
check("(config) a witness set containing the Genesis node key is refused at load", real_g, g_why)
mg = mutate(lw, "genesis_in_set", lambda pubs: False, genesis_row)
record_mutant("skip the Genesis-key check at config load", "(config) Genesis key in set refused",
              real_g, mg[0])
d_ok, d_why = load([W3[0], W3[0], W3[1]], "2")
check("(config) duplicate keys (not independent) refused at load", not d_ok and "independent" in d_why, d_why)
for t in (None, "", "x", "0", "1", "4"):
    t_ok, t_why = load(W3, t)
    check(f"(config) threshold {t!r} with 3 keys refused at load", not t_ok, t_why)

# pinned() reads the env: unset threshold fails closed (503 path).
os.environ["CYBERNET_GENESIS_WITNESSES"] = ",".join(W3)
os.environ["CYBERNET_GENESIS_LOG_ID"] = LOG
os.environ.pop("CYBERNET_GENESIS_WITNESS_THRESHOLD", None)
check("(config) unset CYBERNET_GENESIS_WITNESS_THRESHOLD: route unpinned (fail closed)",
      rlw.pinned() is None)
os.environ["CYBERNET_GENESIS_WITNESS_THRESHOLD"] = "2"
check("(config) threshold 2 of 3 pinned: route pinned", rlw.pinned() is not None)
os.environ["CYBERNET_GENESIS_WITNESSES"] = ",".join(W3[:2] + [NODE])
check("(config) Genesis key in CYBERNET_GENESIS_WITNESSES: route unpinned", rlw.pinned() is None)
for k in ("CYBERNET_GENESIS_WITNESSES", "CYBERNET_GENESIS_LOG_ID",
          "CYBERNET_GENESIS_WITNESS_THRESHOLD"):
    os.environ.pop(k, None)


# ---------------------------------------------------------------- orphans_root (Loom, PENDING Villhaze)
def v2_chain(conn, name, keys):
    prev = hc.claim_anchor(name, keys[0])
    for j in range(len(keys) - 1):
        old, new = keys[j], keys[j + 1]
        sig = sign_with(old, hc.v2_payload(name, j, prev, old, new, ISS))
        conn.execute(
            "INSERT INTO name_rotations (name,old_pubkey,new_pubkey,issued_at,signature,"
            "accepted_at,cert_v,cert_seq,prev_hash) VALUES (?,?,?,?,?,?,2,?,?)",
            (name, old, new, ISS, sig, f"2001-01-01T00:{j:02d}:00+00:00", j, prev))
        prev = hc.cert_hash({"name": name, "i": j, "old": old, "new": new, "issued_at": ISS,
                             "sig": sig, "v": 2, "seq": j, "prev_hash": prev})


BK = [keypair(bytes([0x60 + j]) * 32) for j in range(3)]
OK_ = [keypair(bytes([0x68 + j]) * 32) for j in range(3)]
FAKE = keypair(bytes([0x6F]) * 32)


def scenario(with_orphan, lie=None):
    wipe()
    with core._db_lock, core._db() as conn:
        wo.init_schema(conn)
        v2_chain(conn, "bk", BK)
        bind(conn, "bk", BK[-1], FUT)
        if with_orphan:
            v2_chain(conn, "orp", OK_)           # clean chain, no binding: an orphan
    real = wo.export_orphan_leaves
    if lie:
        wo.export_orphan_leaves = lambda conn: lie(real(conn))
    try:
        open_or("config")
        finish_window()
        return b_proof()
    finally:
        wo.export_orphan_leaves = real


def accepts(proof, orphans):
    hc._CACHE.clear()
    return b_accepts(*proof, orphans=orphans)


clean = scenario(False)
with_o = scenario(True)
check("orphans_root is a witness-signed head field (PENDING Villhaze ratification)",
      "orphans_root=" in lw.head_bytes(clean[0]["head"]["head"]).decode()
      and clean[0]["head"]["head"]["orphans_root"] == hc.orphans_root(clean[0]["orphans"]))
check("honest writer ships the orphan leaf", with_o[0]["orphans"] == [["orp", OK_[-1]]],
      with_o[0]["orphans"])

saved = os.environ.pop("CYBERNET_GENESIS_ORPHANS", None)
hc._CACHE.clear()
try:
    lw._rules(clean[0], "imp", clean[1], clean[2])
    u_ok, u_why = True, None
except lw.WitnessRefused as e:
    u_ok, u_why = False, str(e)
check("(orphans) ORPHANS unset at node B: refused", not u_ok and "pinned sizing" in u_why, u_why)
if saved is not None:
    os.environ["CYBERNET_GENESIS_ORPHANS"] = saved

c_ok, c_why = accepts(clean, 0)
check("(orphans) pin 0, no orphans: accepted", c_ok, c_why)
z_ok, z_why = accepts(with_o, 0)
check("(orphans) pin 0 with an orphan: refused", not z_ok, z_why)
t_ok, t_why = accepts(with_o, 1)
check("(orphans) pin 1 with the honest orphan leaf: accepted", t_ok, t_why)

swap = scenario(True, lie=lambda leaves: [["inv", FAKE]])     # drop orp, invent inv
s_ok, s_why = accepts(swap, 1)
real_sw = (not s_ok) and "orphan leaves do not match" in (s_why or "")
check("(orphans) true count, one orphan dropped and one invented: refused", real_sw, s_why)
ms = mutate(hc, "orphans_match", lambda mine, shipped: len(mine) == len(shipped),
            lambda: accepts(swap, 1))
record_mutant("compare the orphan count only (skip the leaf compare)",
              "(orphans) dropped+invented orphan refused", real_sw, ms[0])

# ---------------------------------------------------------------- Loom row 2: v1_frozen_root membership
LK = [keypair(bytes([0x50 + j]) * 32) for j in range(4)]


def v1row(i, old, new):
    return {"name": "lm", "i": i, "old": old, "new": new, "issued_at": ISS, "v": 1, "seq": None,
            "prev_hash": None, "sig": sign_with(old, hc.v1_payload("lm", old, new, ISS))}


def v2row(i, old, new, prev):
    return {"name": "lm", "i": i, "old": old, "new": new, "issued_at": ISS, "v": 2, "seq": i,
            "prev_hash": prev, "sig": sign_with(old, hc.v2_payload("lm", i, prev, old, new, ISS))}


r0 = v1row(0, LK[0], LK[1])
ghost = v1row(1, LK[1], LK[2])                     # a real-looking v1 cert never shipped
good = [r0, v2row(2, LK[2], LK[3], hc.cert_hash(r0))]
bad = [r0, v2row(2, LK[2], LK[3], hc.cert_hash(ghost))]
check("(loom-2) v1_frozen_root's leaf is the full last v1 cert, signature included",
      hc.v1_frozen_root(good) == hc._merkle([hc.cert_hash(r0)])
      and hc.v1_frozen_root([dict(r0, sig="00" * 64)]) != hc.v1_frozen_root([r0]))


def lm(rows):
    hc._KEY_OK.clear()
    return hc.verify_hops(rows, [["lm", LK[3]]], set(), (1, 1, 0))


g_ok, g_why = lm(good)
check("(loom-2) first v2 cert chaining onto a frozen v1 cert: accepted", g_ok, g_why)
b_ok, b_why = lm(bad)
real_l2 = (not b_ok) and "not in v1_frozen_root" in (b_why or "")
check("(loom-2) first v2 cert chaining onto a v1 cert not in v1_frozen_root: refused",
      real_l2, b_why)
ml2 = mutate(hc, "v1_member", lambda *a: True, lambda: lm(bad))
record_mutant("prev_hash checked without the v1_frozen_root membership check",
              "(loom-2) v1 cert not in v1_frozen_root refused", real_l2, ml2[0])

finish("config")
