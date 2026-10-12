#!/usr/bin/env python3
"""Window-open witness kinds, split 6/6: Villhaze ART-42 ruling 64157549.

(2) witness quorum: strict majority of the legacy-log signer set, Genesis
node key never counts; (5) ORPHANS pin required; (1) a name's first v2
prev_hash is over that name's full last v1 cert (signature included), and
v1_frozen_root is witness-signed in the head. Every mutant here is killed
by a row in this file."""
import json
import os

import hop_certs as hc
from wok_common import (FUT, POOL, b_accepts, b_proof, bind, check, core, finish,
                        finish_window, keypair, lw, open_or, record_mutant, rot, sign_with,
                        wipe, wo)

ISS = "2026-01-01T00:00:00+00:00"
NODE = core._NODE_PUB.lower()
W = [keypair(bytes([0xB0 + j]) * 32) for j in range(4)]
LOG = "cd" * 32


def head_with(wset, signer_pubs):
    h = {"log_id": LOG, "witness_set": wset.id, "seq": 3, "head_hash": "ab" * 32,
         "window_open_seq": 1, "window_close_seq": 2, "window_state": "closed",
         "hops_root": "00" * 32, "bound_root": "00" * 32, "v1_frozen_root": "00" * 32, "orphans_root": "00" * 32}

    def node_sign(msg):
        return NODE, wo._ed.sign(msg, bytes.fromhex(core._NODE_PRIV), bytes.fromhex(NODE)).hex()

    signers = [node_sign if p == NODE else (lambda m, _p=p: (_p, sign_with(_p, m)))
               for p in signer_pubs]
    return lw.sign_head(h, signers)


def head_ok(wset, signer_pubs):
    try:
        lw.verify_head(head_with(wset, signer_pubs), wset, LOG)
        return True, None
    except lw.WitnessRefused as e:
        return False, str(e)


def mutate(mod, attr, value, fn):
    real = getattr(mod, attr)
    setattr(mod, attr, value)
    try:
        return fn()
    finally:
        setattr(mod, attr, real)


# ---------------------------------------------------------------- (2) witness quorum
SET_A = lw.WitnessSet(1, [NODE])                 # node key listed, nothing else
SET_B = lw.WitnessSet(1, W)                      # four witnesses
SET_C = lw.WitnessSet(1, [NODE] + W[:3])         # node key listed + three witnesses
a_ok, a_why = head_ok(SET_A, [NODE])
b_ok, b_why = head_ok(SET_B, W[:2])
c_ok, c_why = head_ok(SET_C, W[:2])
real_a = (not a_ok) and "strict majority" in a_why
real_b = (not b_ok) and "strict majority" in b_why
real_c = c_ok
check("(2a) a head signed only by the Genesis node key is refused (node key never counts)",
      real_a, a_why)
check("(2b) exactly half of the witness set (2 of 4) is refused", real_b, b_why)
check("(2c) a strict majority of non-node keys (2 of 3; node key listed, unsigned) is accepted",
      real_c, c_why)
count_node = lambda pubs: set(pubs)  # noqa: E731
ma = mutate(lw, "eligible_witnesses", count_node, lambda: head_ok(SET_A, [NODE])[0])
mc = mutate(lw, "eligible_witnesses", count_node, lambda: head_ok(SET_C, W[:2])[0])
record_mutant("witness quorum counts the Genesis node key",
              "(2a) node-key-only head refused", real_a, ma)
record_mutant("witness quorum counts the Genesis node key",
              "(2c) 2 of 3 non-node keys accepted (node key listed)", real_c, not mc)
SET_D = lw.WitnessSet(1, [NODE] + W[:2])         # node key + two witnesses
d_ok, d_why = head_ok(SET_D, [NODE, W[0]])
real_d = (not d_ok) and "strict majority" in d_why
check("(2d) a head that reaches a majority only by counting the node key (node + 1 of 2) "
      "is refused", real_d, d_why)
md = mutate(lw, "eligible_witnesses", count_node, lambda: head_ok(SET_D, [NODE, W[0]])[0])
record_mutant("witness quorum counts the Genesis node key",
              "(2d) majority only with the node key: refused", real_d, md)
mb = mutate(lw, "head_quorum", lambda g, e: e > 0 and 2 * g >= e,
            lambda: head_ok(SET_B, W[:2])[0])
record_mutant("witness quorum uses >= (half counts)", "(2b) exactly half refused", real_b, mb)


# ---------------------------------------------------------------- (5) ORPHANS pin required
def plain_proof():
    wipe()
    with core._db_lock, core._db() as conn:
        wo.init_schema(conn)
        rot(conn, "pp", POOL[0], POOL[1])
        bind(conn, "pp", POOL[1], FUT)
    open_or("orph-pin")
    finish_window()
    return b_proof()


pp = plain_proof()
os.environ["CYBERNET_GENESIS_LEGACY_ACCOUNTS"] = "1"
os.environ["CYBERNET_GENESIS_LIVE_BINDINGS"] = str(len(pp[0]["bound"]))


def env_accepts(orphans):
    if orphans is None:
        os.environ.pop("CYBERNET_GENESIS_ORPHANS", None)
    else:
        os.environ["CYBERNET_GENESIS_ORPHANS"] = orphans
    hc._CACHE.clear()
    try:
        return True, lw._rules(pp[0], "imp", pp[1], pp[2])[2]
    except lw.WitnessRefused as e:
        return False, str(e)


u_ok, u_why = env_accepts(None)
real_u = (not u_ok) and "no pinned sizing" in u_why
check("(5) CYBERNET_GENESIS_ORPHANS unset: refused", real_u, u_why)
z_ok, z_why = env_accepts("0")
check("(5) CYBERNET_GENESIS_ORPHANS pinned 0: an honest orphan-free log is accepted",
      z_ok, z_why)
real_ps = lw.pinned_sizing


def default_zero():
    if "CYBERNET_GENESIS_ORPHANS" not in os.environ:
        os.environ["CYBERNET_GENESIS_ORPHANS"] = "0"
        try:
            return real_ps()
        finally:
            os.environ.pop("CYBERNET_GENESIS_ORPHANS", None)
    return real_ps()


mu = mutate(lw, "pinned_sizing", default_zero, lambda: env_accepts(None)[0])
record_mutant("ORPHANS pin defaults to 0 when unset", "(5) ORPHANS unset: refused", real_u, mu)
for k in ("CYBERNET_GENESIS_LEGACY_ACCOUNTS", "CYBERNET_GENESIS_LIVE_BINDINGS",
          "CYBERNET_GENESIS_ORPHANS"):
    os.environ.pop(k, None)


# ---------------------------------------------------------------- (1) first v2 prev_hash over the full last v1 cert
V1_ISS = "2000-01-01T00:00:00+00:00"


def plant_link(name, prev_fn):
    def plant(conn):
        rot(conn, name, POOL[10], POOL[11], "2001-01-01T00:00:00+00:00")
        v1 = {"name": name, "i": 0, "old": POOL[10], "new": POOL[11], "issued_at": V1_ISS,
              "v": 1, "seq": None, "prev_hash": None,
              "sig": sign_with(POOL[10], hc.v1_payload(name, POOL[10], POOL[11], V1_ISS))}
        prev = prev_fn(v1)
        sig = sign_with(POOL[11], hc.v2_payload(name, 1, prev, POOL[11], POOL[12], ISS))
        conn.execute(
            "INSERT INTO name_rotations (name,old_pubkey,new_pubkey,issued_at,signature,"
            "accepted_at,cert_v,cert_seq,prev_hash) VALUES (?,?,?,?,?,?,2,1,?)",
            (name, POOL[11], POOL[12], ISS, sig, "2001-01-01T00:30:00+00:00", prev))
        bind(conn, name, POOL[12], FUT)
    return plant


def link_proof(name, prev_fn):
    wipe()
    with core._db_lock, core._db() as conn:
        wo.init_schema(conn)
        plant_link(name, prev_fn)(conn)
    open_or("link")
    finish_window()
    return b_proof()


def accepts(proof):
    hc._CACHE.clear()
    return b_accepts(*proof)


def unsigned_hash(row):
    """Hash of the v1 cert WITHOUT its signature (what the ruling forbids)."""
    body = json.dumps([row["v"], row["name"], row.get("seq"), row.get("prev_hash"),
                       row["old"], row["new"], row["issued_at"]],
                      separators=(",", ":"), ensure_ascii=True)
    return __import__("hashlib").sha256(hc.CERT_DOMAIN + body.encode("ascii")).hexdigest()


full = link_proof("lk", hc.cert_hash)
f_ok, f_why = accepts(full)
check("(1) first v2 prev_hash = cert_hash(full last v1 cert, signature included): accepted; "
      "v1_frozen_root is a witness-signed head field",
      f_ok and full[0]["head"]["head"]["v1_frozen_root"] == hc.v1_frozen_root(full[0]["hops"])
      and "v1_frozen_root=" in lw.head_bytes(full[0]["head"]["head"]).decode(), f_why)
nosig = link_proof("lk", unsigned_hash)
n_ok, n_why = accepts(nosig)
real_ns = (not n_ok) and "prev_hash" in n_why
check("(1) first v2 prev_hash over the last v1 cert without its signature: refused",
      real_ns, n_why)
def prev_unsigned(r, prev_row):
    want = unsigned_hash(prev_row) if prev_row is not None else hc.claim_anchor(r["name"], r["old"])
    return r["prev_hash"] == want


# Loom row 2's v1_frozen_root membership is a second guard on this row; the
# mutant removes both (the shipped v1 cert, signature included, is the leaf).
ms = mutate(hc, "check_prev", prev_unsigned,
            lambda: mutate(hc, "v1_member", lambda *a: True, lambda: accepts(nosig)[0]))
record_mutant("prev_hash computed over the v1 cert without its signature",
              "(1) prev_hash over v1 cert without signature: refused", real_ns, ms)
other = link_proof("lk", lambda v1: hc.cert_hash(dict(v1, name="zz", sig=sign_with(
    POOL[10], hc.v1_payload("zz", POOL[10], POOL[11], V1_ISS)))))
o_ok, o_why = accepts(other)
check("(1) first v2 prev_hash over another name's v1 cert: refused",
      (not o_ok) and "prev_hash" in o_why, o_why)
v1h = json.loads(json.dumps(full[0]))
v1h["head"]["head"]["v1_frozen_root"] = hc.EMPTY_ROOT
t_ok, t_why = accepts((v1h, full[1], full[2]))
check("(1) v1_frozen_root changed in the head under the original signatures: refused",
      (not t_ok) and "witness signature" in t_why, t_why)

# ---------------------------------------------------------------- Lodestar: chain head dropped
def v2_chain(name, keys):
    rows = []
    for j in range(len(keys) - 1):
        old, new = keys[j], keys[j + 1]
        p = hc.cert_hash(rows[-1]) if rows else hc.claim_anchor(name, old)
        rows.append({"name": name, "i": j, "old": old, "new": new, "issued_at": ISS,
                     "sig": sign_with(old, hc.v2_payload(name, j, p, old, new, ISS)),
                     "v": 2, "seq": j, "prev_hash": p})
    return rows


HD = v2_chain("hd", [POOL[20], POOL[21], POOL[22]])


def head_drop_proof():
    """Lying writer: drops hd's first (claim-anchored) hop and renumbers,
    so the chain appears to start at POOL[21]."""
    wipe()
    with core._db_lock, core._db() as conn:
        wo.init_schema(conn)
        bind(conn, "hd", POOL[22], FUT)
    real = wo.snapshot_bindings

    def lying(conn):
        snap = real(conn)
        tail = [dict(r) for r in HD[1:]]
        for j, r in enumerate(tail):
            r["i"] = j
        snap["hop_rows"] = snap["hop_rows"] + tail
        return snap
    wo.snapshot_bindings = lying
    try:
        open_or("hd")
    finally:
        wo.snapshot_bindings = real
    finish_window()
    return b_proof()


hd = head_drop_proof()
h_ok, h_why = accepts(hd)
real_hd = (not h_ok) and "prev_hash" in h_why
check("(Lodestar) chain with its first (claim-anchor) hop dropped is refused", real_hd, h_why)
real_cp = hc.check_prev


def skip_anchor(r, prev_row):
    return True if prev_row is None else real_cp(r, prev_row)


mh = mutate(hc, "check_prev", skip_anchor,
            lambda: mutate(hc, "v1_member", lambda *a: True, lambda: accepts(hd)[0]))
record_mutant("first-hop claim anchor skipped", "(Lodestar) chain head dropped: refused",
              real_hd, mh)

finish("test_wok_ruling.py")
