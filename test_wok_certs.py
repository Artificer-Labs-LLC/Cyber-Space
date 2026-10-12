#!/usr/bin/env python3
"""Window-open witness kinds, split 5/5: hop certs at node B (Examiner's
hop-row BLOCK, board-recommended path).

Every proof goes through the real _rules with a real signed head. A lying
writer is modelled by rewriting the snapshot's hop rows / bound leaves
BEFORE open_window commits them, so hops_root, the hold-closure and the
head are all consistent with the lie and only the per-hop rules can catch
it. Each mutant below is killed by a row in this file."""
import json

import hop_certs as hc
from wok_common import (WITNESS_SIGNERS, FUT, POOL, ZERO, b_accepts, b_proof, bind, check, clean_chain, core,
                        finish, finish_window, lw, open_or, record_mutant, rot, sign_with,
                        wipe, wo)

ISS = "2026-01-01T00:00:00+00:00"
real_snapshot = wo.snapshot_bindings


def v2_rows(name, keys, seq0=0, prev=None):
    """Honest v2 certs keys[0] -> keys[1] -> ... each signed by its old key."""
    rows = []
    for j in range(len(keys) - 1):
        old, new = keys[j], keys[j + 1]
        p = prev if j == 0 and prev is not None else (
            hc.cert_hash(rows[-1]) if rows else hc.claim_anchor(name, old))
        seq = seq0 + j
        sig = sign_with(old, hc.v2_payload(name, seq, p, old, new, ISS))
        rows.append({"name": name, "i": seq, "old": old, "new": new, "issued_at": ISS,
                     "sig": sig, "v": 2, "seq": seq, "prev_hash": p})
    return rows


def store_v2(conn, rows):
    for j, r in enumerate(rows):
        conn.execute(
            "INSERT INTO name_rotations (name,old_pubkey,new_pubkey,issued_at,signature,"
            "accepted_at,cert_v,cert_seq,prev_hash) VALUES (?,?,?,?,?,?,2,?,?)",
            (r["name"], r["old"], r["new"], r["issued_at"], r["sig"],
             f"2001-01-01T00:{j:02d}:00+00:00", r["seq"], r["prev_hash"]))


def scenario(plant, rows_fn=None, leaves_fn=None):
    """Plant, open (optionally through a lying writer), finish, -> proof."""
    wipe()
    with core._db_lock, core._db() as conn:
        wo.init_schema(conn)
        plant(conn)

    def lying(conn):
        snap = real_snapshot(conn)
        if rows_fn:
            snap["hop_rows"] = rows_fn(snap["hop_rows"])
        if leaves_fn:
            snap["bound_leaves"] = leaves_fn(snap["bound_leaves"])
        return snap
    wo.snapshot_bindings = lying
    try:
        open_or("certs")
    finally:
        wo.snapshot_bindings = real_snapshot
    finish_window()
    return b_proof()


def accepts(proof, pins=None, orphans=0, keep_cache=False):
    if not keep_cache:
        hc._CACHE.clear()
    ok, why = b_accepts(*proof, pins=pins, orphans=orphans)
    return ok, why


def mutate(mod, attr, value, fn):
    real = getattr(mod, attr)
    setattr(mod, attr, value)
    try:
        return fn()
    finally:
        setattr(mod, attr, real)


CH = [POOL[0], POOL[1], POOL[2], POOL[3]]


def plant_ch(conn):
    store_v2(conn, v2_rows("ch", CH))
    bind(conn, "ch", CH[-1], FUT)


def replace_name(name, new_rows):
    return lambda rows: [r for r in rows if r["name"] != name] + new_rows


# ---------------------------------------------------------------- baseline
honest = scenario(plant_ch)
h_ok, h_why = accepts(honest)
check("(certs) an honest v2 chain re-verifies hop by hop and proves into bound_root",
      h_ok, h_why)

# ---------------------------------------------------------------- tail dropped
tail = scenario(plant_ch, rows_fn=lambda rows: [r for r in rows if not (r["name"] == "ch"
                                                                         and r["i"] == 2)])
t_ok, t_why = accepts(tail)
real_tail = (not t_ok) and "bound_root" in t_why
check("(tail) chain with its last cert dropped is refused (does not prove into bound_root)",
      real_tail, t_why)
mt = mutate(hc, "bound_ok", lambda *a: True, lambda: accepts(tail)[0])
record_mutant("bound_root proof skipped", "tail dropped: refused", real_tail, mt)

# ---------------------------------------------------------------- middle removed + renumbered (v1)
MV = [POOL[10], POOL[11], POOL[12], POOL[13]]


def plant_mv(conn):
    for j in range(3):
        rot(conn, "mv", MV[j], MV[j + 1], f"2001-01-01T00:{j:02d}:00+00:00")
    bind(conn, "mv", MV[-1], FUT)


def drop_middle(rows):
    keep = [r for r in rows if not (r["name"] == "mv" and r["i"] == 1)]
    j = 0
    for r in keep:
        if r["name"] == "mv":
            r["i"] = j
            j += 1
    return keep


mid = scenario(plant_mv, rows_fn=drop_middle)
m_ok, m_why = accepts(mid)
real_mid = (not m_ok) and "does not continue" in m_why
check("(middle) a middle cert removed and the rest renumbered is refused", real_mid, m_why)
mm = mutate(hc, "continues", lambda *a: True, lambda: accepts(mid)[0])
record_mutant("hop continuity check skipped", "middle hop removed and renumbered: refused",
              real_mid, mm)

# ---------------------------------------------------------------- invented hop
def invent(rows):
    chain = [r for r in rows if r["name"] == "ch"]
    last = chain[-1]
    old, new = last["new"], POOL[20]
    p = hc.cert_hash(last)
    fake = {"name": "ch", "i": 3, "old": old, "new": new, "issued_at": ISS,
            "sig": sign_with(POOL[21], hc.v2_payload("ch", 3, p, old, new, ISS)),
            "v": 2, "seq": 3, "prev_hash": p}
    return rows + [fake]


inv = scenario(plant_ch, rows_fn=invent,
               leaves_fn=lambda lv: [[n, POOL[20] if n == "ch" else p] for n, p in lv])
i_ok, i_why = accepts(inv)
real_inv = (not i_ok) and "signature does not verify" in i_why
check("(invented) a hop signed by a key that never held the name is refused", real_inv, i_why)
mi = mutate(hc, "verify_sig", lambda *a: True, lambda: accepts(inv)[0])
record_mutant("cert verify always passes", "invented hop: refused", real_inv, mi)

# ---------------------------------------------------------------- two certs swapped (v2)
A, B = POOL[30], POOL[31]
SW = v2_rows("sw", [A, B, A, B, A])


def plant_sw(conn):
    bind(conn, "sw", A, FUT)


def swap13(rows):
    c = [dict(r) for r in SW]
    c[1], c[3] = c[3], c[1]
    for j, r in enumerate(c):
        r["i"] = j          # positions renumbered; each cert keeps its signed seq
    return rows + c


sw = scenario(plant_sw, rows_fn=swap13)
s_ok, s_why = accepts(sw)
real_sw = (not s_ok) and "prev_hash" in s_why
check("(swap) two certs swapped (continuity and signatures intact) is refused on prev_hash",
      real_sw, s_why)
ms = mutate(hc, "check_prev", lambda *a: True, lambda: accepts(sw)[0])
record_mutant("prev_hash check skipped", "two certs swapped: refused", real_sw, ms)

# ---------------------------------------------------------------- A->B replayed after A->B->A
RP = v2_rows("rp", [A, B, A])


def plant_rp(conn):
    bind(conn, "rp", B, FUT)


def replay(rows):
    again = dict(RP[0])
    again["i"] = 2
    return rows + [dict(r) for r in RP] + [again]


rp = scenario(plant_rp, rows_fn=replay)
r_ok, r_why = accepts(rp)
real_rp = (not r_ok) and "prev_hash" in r_why
check("(replay) A->B replayed after A->B->A is refused", real_rp, r_why)
mr = mutate(hc, "check_prev", lambda *a: True, lambda: accepts(rp)[0])
record_mutant("prev_hash check skipped", "A->B replayed after A->B->A: refused", real_rp, mr)

# ---------------------------------------------------------------- v1 presented as v2
V = [POOL[40], POOL[41]]


def plant_v1v2(conn):
    rot(conn, "vv", V[0], V[1])
    bind(conn, "vv", V[1], FUT)


def as_v2(rows):
    for r in rows:
        if r["name"] == "vv":
            r.update(v=2, seq=0, prev_hash=hc.claim_anchor("vv", r["old"]))
    return rows


vv = scenario(plant_v1v2, rows_fn=as_v2)
v_ok, v_why = accepts(vv)
real_vv = (not v_ok) and "signature does not verify" in v_why
check("(v1-as-v2) a v1 cert relabelled v2 is refused", real_vv, v_why)
real_cert = hc._cert_sig_ok


def either_payload(r):
    if real_cert(r):
        return True
    return hc.verify_sig(hc.norm(r["old"]),
                         hc.v1_payload(r["name"], r["old"], r["new"], r["issued_at"]), r["sig"])


mv_ = mutate(hc, "_cert_sig_ok", either_payload, lambda: accepts(vv)[0])
record_mutant("v2 row also accepted over the v1 payload", "v1 cert presented as v2: refused",
              real_vv, mv_)

# ---------------------------------------------------------------- v1 after the v2 cutover
def plant_cut(conn):
    store_v2(conn, v2_rows("ct", [POOL[50], POOL[51]]))
    conn.execute("INSERT INTO name_rotations (name,old_pubkey,new_pubkey,issued_at,signature,"
                 "accepted_at) VALUES (?,?,?,?,?,?)",
                 ("ct", POOL[51], POOL[52], ISS,
                  sign_with(POOL[51], hc.v1_payload("ct", POOL[51], POOL[52], ISS)),
                  "2001-01-01T00:59:00+00:00"))
    bind(conn, "ct", POOL[52], FUT)


ct = scenario(plant_cut)
c_ok, c_why = accepts(ct)
check("(cutover) a v1 cert after a v2 cert in the same chain is refused",
      (not c_ok) and "v1 cert after the v2 cutover" in c_why, c_why)

# ---------------------------------------------------------------- v1 then v2: first v2 links to last v1
def plant_link(conn):
    rot(conn, "ln", POOL[55], POOL[56], "2001-01-01T00:00:00+00:00")
    v1 = {"name": "ln", "i": 0, "old": POOL[55], "new": POOL[56], "issued_at": "2000-01-01T00:00:00+00:00",
          "v": 1, "seq": None, "prev_hash": None,
          "sig": sign_with(POOL[55], hc.v1_payload("ln", POOL[55], POOL[56],
                                                   "2000-01-01T00:00:00+00:00"))}
    nxt = v2_rows("ln", [POOL[56], POOL[57]], seq0=1, prev=hc.cert_hash(v1))
    for r in nxt:
        conn.execute(
            "INSERT INTO name_rotations (name,old_pubkey,new_pubkey,issued_at,signature,"
            "accepted_at,cert_v,cert_seq,prev_hash) VALUES (?,?,?,?,?,?,2,?,?)",
            (r["name"], r["old"], r["new"], r["issued_at"], r["sig"],
             "2001-01-01T00:30:00+00:00", r["seq"], r["prev_hash"]))
    bind(conn, "ln", POOL[57], FUT)


ln = scenario(plant_link)
l_ok, l_why = accepts(ln)
check("(v1->v2) first v2 prev_hash = hash of the last v1 cert: accepted; v1 frozen under "
      "v1_frozen_root", l_ok and ln[0]["head"]["head"]["v1_frozen_root"] != hc.EMPTY_ROOT, l_why)

# ---------------------------------------------------------------- chain not proving into bound_root
nb = scenario(plant_ch, leaves_fn=lambda lv: [[n, POOL[9] if n == "ch" else p] for n, p in lv])
n_ok, n_why = accepts(nb)
real_nb = (not n_ok) and "bound_root" in n_why
check("(bound) a chain whose last key is not its bound leaf is refused", real_nb, n_why)
mn = mutate(hc, "bound_ok", lambda *a: True, lambda: accepts(nb)[0])
record_mutant("bound_root proof skipped", "chain not proving into bound_root: refused",
              real_nb, mn)


# ---------------------------------------------------------------- head bound_root changed, original sigs
def plant_pl(conn):
    plant_ch(conn)
    bind(conn, "pl", POOL[60], FUT)


base = scenario(plant_pl)
p2 = json.loads(json.dumps(base[0]))
p2["bound"] = [[n, POOL[61] if n == "pl" else p] for n, p in p2["bound"]]
p2["head"]["head"]["bound_root"] = hc.bound_root(p2["bound"])
hb_ok, hb_why = accepts((p2, base[1], base[2]))
real_hb = (not hb_ok) and "witness signature" in hb_why
check("(head) bound_root swapped in the head under the original witness signatures is refused",
      real_hb, hb_why)
real_hbytes = lw.head_bytes


def old_head_bytes(h):
    return real_hbytes(dict(h, **{k: "0" * 64 for k in lw.HEAD_ROOT_FIELDS}))


mh = mutate(lw, "head_bytes", old_head_bytes,
            lambda: (accepts((json.loads(json.dumps(p2)), base[1], base[2]))[0]))
# The mutant signs and checks the same (root-less) bytes, so re-sign the
# honest head under it the way a pre-change witness would have.
if not mh:
    def resign():
        pr = json.loads(json.dumps(base[0]))
        h = pr["head"]["head"]
        pr["head"] = lw.sign_head(h, WITNESS_SIGNERS)
        pr["bound"] = p2["bound"]
        pr["head"]["head"]["bound_root"] = p2["head"]["head"]["bound_root"]
        return accepts((pr, base[1], base[2]))[0]
    mh = mutate(lw, "head_bytes", old_head_bytes, resign)
record_mutant("roots left out of head_bytes",
              "head with bound_root changed but original sigs: refused", real_hb, mh)

# ---------------------------------------------------------------- same proof twice: cache
hc._CACHE.clear()
hc.STATS["verifies"] = 0
accepts(honest, keep_cache=True)
first = hc.STATS["verifies"]
accepts(honest, keep_cache=True)
second = hc.STATS["verifies"] - first
real_cache = first > 0 and second == 0
check(f"(cache) same proof twice: {first} verifies, then {second}", real_cache, (first, second))


class NoStore(dict):
    def __setitem__(self, k, v):
        pass


def nocache():
    hc.STATS["verifies"] = 0
    accepts(honest, keep_cache=True)
    a = hc.STATS["verifies"]
    accepts(honest, keep_cache=True)
    return hc.STATS["verifies"] - a


mc = mutate(hc, "_CACHE", NoStore(), nocache)
record_mutant("no verify cache", "same proof twice: 0 verifies the second time",
              real_cache, mc > 0)

# ---------------------------------------------------------------- per-source charge before any verify
seen = []
hc._CACHE.clear()
hc._KEY_OK.clear()
hc.STATS["verifies"] = 0
hc.STATS["weak"] = 0
try:
    lw._rules(honest[0], "imp", honest[1], honest[2], (1, len(honest[0]["bound"]), 0),
              charge=lambda n: seen.append((n, hc.STATS["verifies"], hc.STATS["weak"])))
except lw.WitnessRefused as e:
    seen.append(str(e))
check("(charge) the per-source bucket is charged 2*weak_reason+verify per cert before any weak_reason or verify",
      seen == [(len(honest[0]["hops"]) * hc.CERT_COST_US, 0, 0)] and hc.STATS["verifies"] > 0, seen)

# ---------------------------------------------------------------- libsodium stubbed out
hc.STATS["verifies"] = 0
so_ok, so_why = mutate(hc, "sodium", lambda: None, lambda: accepts(honest))
real_so = (not so_ok) and so_why == "hop certs: " + hc.LIBSODIUM_MISSING \
    and "libsodium is not installed" in so_why and hc.STATS["verifies"] == 0
check("(sodium) libsodium missing: refused before any verify", real_so,
      (so_why, hc.STATS["verifies"]))


def pure_python(pub_hex, msg, sig_hex):
    hc.STATS["verifies"] += 1
    return wo._ed.checkvalid(bytes.fromhex(sig_hex), msg, bytes.fromhex(pub_hex))


def with_fallback():
    hc.STATS["verifies"] = 0
    return mutate(hc, "sodium", lambda: None, lambda: accepts(honest)), hc.STATS["verifies"]


hc.ALLOW_FALLBACK = True
try:
    (mso_ok, _w), mso_n = mutate(hc, "_fallback_verify", pure_python, with_fallback)
finally:
    hc.ALLOW_FALLBACK = False
record_mutant("pure-Python fallback allowed", "libsodium stubbed: refused before any verify",
              real_so, mso_ok or mso_n > 0)

# ---------------------------------------------------------------- held name omitted: no FLAG / FLAG
drop_leaf = lambda name: (lambda lv: [x for x in lv if x[0] != name])  # noqa: E731
# Pins here are the shipped leaf count, so the leaf-count check (Loom's
# pair below) does not mask the diff under test.
# The lying writer also hides the dropped name from the orphan leaves
# (orphans_root), so the proof stays inside the pinned orphan count.
_real_orph = wo.export_orphan_leaves
wo.export_orphan_leaves = lambda conn: []
try:
    om = scenario(plant_pl, leaves_fn=drop_leaf("ch"))
finally:
    wo.export_orphan_leaves = _real_orph
o_ok, o_why = accepts(om)
real_om = (not o_ok) and "without a bound leaf" in o_why
check("(omit) a held name dropped from bound_root without a FLAG is refused", real_om, o_why)


def plant_fl(conn):
    plant_pl(conn)
    last = clean_chain(conn, "fl", 64)
    rot(conn, "fl", last, ZERO, "2002-01-01T00:00:00+00:00")
    bind(conn, "fl", ZERO, FUT)


fl = scenario(plant_fl, leaves_fn=drop_leaf("fl"))
f_ok, f_why = accepts(fl)
real_fl = f_ok
check("(omit) a FLAGged (hop-cap) name dropped from bound_root is accepted", real_fl, f_why)
# bound_diff and the orphan-leaf compare are now two guards on this row;
# the mutant removes both.
mo = mutate(hc, "bound_diff", lambda *a: None,
            lambda: mutate(hc, "orphans_match", lambda *a: True, lambda: accepts(om)[0]))
record_mutant("bound diff and orphan-leaf compare always pass", "held name omitted without a FLAG: refused",
              real_om and real_fl, mo)

# ---------------------------------------------------------------- 66-row bound
check("max_hop_rows is 66 per pinned name (PER_NAME_HOP_CAP + 2)",
      lw.HOP_ROWS_PER_NAME == 66 and lw.max_hop_rows(1, 0) == 66 and lw.max_hop_rows(2, 1) == 198)


def plant_big(conn):
    plant_ch(conn)
    last = clean_chain(conn, "big", 67)
    bind(conn, "big", last, FUT)


def all67(rows):
    hops = [(POOL[j], POOL[j + 1]) for j in range(67)]
    full = [{"name": "big", "i": j, "old": o, "new": n, "issued_at": "2000-01-01T00:00:00+00:00",
             "v": 1, "seq": None, "prev_hash": None,
             "sig": sign_with(o, hc.v1_payload("big", o, n, "2000-01-01T00:00:00+00:00"))}
            for j, (o, n) in enumerate(hops)]
    return replace_name("big", full)(rows)


big = scenario(plant_big, rows_fn=all67)
bg_ok, bg_why = accepts(big)
real_big = (not bg_ok) and "exceed 66" in bg_why
check("(66) a name shipping 67 hop rows is refused", real_big, bg_why)
mb = mutate(lw, "HOP_ROWS_PER_NAME", 10 ** 6, lambda: accepts(big)[0])
record_mutant("per-name 66-row bound removed", "67 hop rows on one name: refused", real_big, mb)

# ---------------------------------------------------------------- Loom's pair
def plant_two(conn):
    plant_ch(conn)
    bind(conn, "pl", POOL[60], FUT)


gone = scenario(plant_two, rows_fn=lambda rows: [r for r in rows if r["name"] != "ch"],
                leaves_fn=drop_leaf("ch"))
g_ok, g_why = accepts(gone, pins=(1, 2, 0))
real_gone = (not g_ok) and "pinned bindings" in g_why
check("(Loom) a whole bound name dropped (leaf and chain) is refused against pinned bindings=2",
      real_gone, g_why)
mg = mutate(hc, "leaf_count_ok", lambda *a: True, lambda: accepts(gone, pins=(1, 2, 0))[0])
record_mutant("leaf count not checked against pinned bindings",
              "whole bound name dropped: refused", real_gone, mg)


def plant_orphan(conn):
    plant_ch(conn)
    rot(conn, "orph", POOL[70], POOL[71])     # rotation history, no binding row


o_hon = scenario(plant_orphan)
oh_ok, oh_why = accepts(o_hon)                # ORPHANS at its default (0)
o_drop = scenario(plant_orphan, rows_fn=lambda rows: [r for r in rows if r["name"] != "orph"])
od_ok, od_why = accepts(o_drop)
print(f"  RECORD (Loom) honest orphan, ORPHANS=0: accepted={oh_ok} ({oh_why})")
print(f"  RECORD (Loom) orphan dropped, ORPHANS=0: accepted={od_ok} "
      f"({od_why if not od_ok else 'identity returned'})")
check("(Loom) recorded: with ORPHANS at its default 0, an honest orphan is refused and a "
      "dropped orphan is accepted (known gap until the orphan pin is set)",
      (not oh_ok) and od_ok, (oh_why, od_why))
oo_ok, oo_why = accepts(o_hon, orphans=1)
check("(Loom) with ORPHANS pinned to 1 the honest orphan is accepted and the drop is refused",
      oo_ok and not accepts(o_drop, orphans=1)[0], oo_why)

finish("test_wok_certs.py")
