#!/usr/bin/env python3
"""Pin-rotation v2 on the KINDS cert format (Villhaze ruling ART-42
64157549; hop_certs.py from oracle/window-open-witness-kinds-hopcerts
7b15ca9). Rows from Cipher, Examiner, Bulwark and Loom:
  * a real frozen v1 cert, then a v2 cert whose prev_hash covers the WHOLE
    v1 cert, is accepted (v1 frozen, not refused)
  * the v1 graft runs like v2: charged first, outside _db_lock, libsodium
  * a v2 cert chaining onto a v1 cert outside v1_frozen_root is refused
  * rotate path and KINDS import give a byte-identical hops_root
  * no weak_reason / is_weak on the rotation path (serializer only)
"""
from pinrot_common import *  # noqa: F401,F403
from pinrot_common import _round_k, _ed  # noqa: F401
import hashlib  # noqa: E402
import hop_certs  # noqa: E402
import window_open  # noqa: E402

REAL_VERIFY_V1 = nf._verify_v1
REAL_GRAFT = nf._graft_v1
REAL_GRAFT_OK = nf._v1_graft_ok


class TrackingLock:
    def __init__(self, inner):
        self.inner, self.held = inner, 0

    def __enter__(self):
        self.inner.acquire()
        self.held += 1
        return self

    def __exit__(self, *a):
        self.held -= 1
        self.inner.release()


def v1_cert(name, old_seed, new_pub):
    old = pub(old_seed)
    sig = _ed.sign(hop_certs.v1_payload(name, old, new_pub, ISSUED), old_seed,
                   bytes.fromhex(old)).hex()
    return {"v": 1, "name": name, "old_pubkey": old, "new_pubkey": new_pub,
            "issued_at": ISSUED, "signature": sig}


def freeze_v1(c, v1):
    """The node's legacy history: a v1 cert recorded before the cutover."""
    nf.ensure_schema(c)
    c.execute("INSERT INTO name_rotations (name, old_pubkey, new_pubkey,"
              " issued_at, signature, accepted_at, cert_v) VALUES (?,?,?,?,?,?,1)",
              (v1["name"], v1["old_pubkey"], v1["new_pubkey"], v1["issued_at"],
               v1["signature"], "2026-01-01T00:00:00+00:00"))


def graft_setup(frozen=True):
    """A->B is a real v1 cert; the node pins B; B->C is the first v2 hop."""
    nm = f"g{secrets.token_hex(3)}"
    kA, kB, kC = seed(), seed(), seed()
    v1 = v1_cert(nm, kA, pub(kB))
    claim_gate_pin(nm, kB)
    if frozen:
        with core._db_lock, core._db() as c:
            freeze_v1(c, v1)
    full = hop_certs.cert_hash(nf.hop_row(v1))
    v2 = nf.mint_cert(nm, kB, pub(kC), 1, full, issued_at=ISSUED)
    v2["prev_v1"] = v1
    return nm, v1, v2, kB, kC


# ===================================================== v1 graft
print("v1 frozen, not refused: first v2 hop over the full v1 cert", flush=True)


def run_graft():
    reset_rates()
    nm, v1, v2, kB, kC = graft_setup()
    lock = TrackingLock(core._db_lock)
    cnt = {"v1": 0, "v1_in_lock": 0, "pure": 0}
    real_pure = _ed.checkvalid

    def v1w(v):
        cnt["v1"] += 1
        if lock.held:
            cnt["v1_in_lock"] += 1
        return nf_verify_v1_impl[0](v)

    def pure(*a):
        cnt["pure"] += 1
        return real_pure(*a)
    with patched(core, "_db_lock", lock), patched(nf, "_verify_v1", v1w), \
            patched(_ed, "checkvalid", pure):
        box = [0]
        out = core.ingest_rotation_certs([v2], pk6, box)
    with core._db_lock, core._db() as c:
        st = nf.current_state(c, nm)
    return (out["outcomes"] == ["accepted"] and st[0] == pub(kC) and st[1] == 1
            and out["charged"] == 1 and box[0] == 2 and cnt["v1"] == 1 and cnt["v1_in_lock"] == 0
            and cnt["pure"] == 0), (out["outcomes"], cnt)


nf_verify_v1_impl = [REAL_VERIFY_V1]
add_peer(pk6)
real, info = run_graft()
check("real v1 A->B, then v2 B->C with prev_hash = cert_hash(full v1): accepted; "
      "v1 charged as a 2nd unit, verified once, by libsodium, outside _db_lock",
      real, info)


def payload_only(v1):
    return hashlib.sha256(hop_certs.v1_payload(v1["name"], v1["old_pubkey"],
                                               v1["new_pubkey"],
                                               v1["issued_at"])).hexdigest()


with patched(nf, "_v1_cert_hash", payload_only):
    mut, _ = run_graft()
mutant("prev_hash over the v1 payload only (no signature)",
       "v1 then v2 over the full v1 cert accepted", real, mut)
with patched(nf, "_graft_v1", lambda rec, raw: None):
    mut, _ = run_graft()
mutant("v1 refused (no graft)", "v1 then v2 over the full v1 cert accepted",
       real, mut)

nf_verify_v1_impl[0] = lambda v: _ed.checkvalid(
    bytes.fromhex(v["signature"]),
    hop_certs.v1_payload(v["name"], v["old_pubkey"], v["new_pubkey"], v["issued_at"]),
    bytes.fromhex(v["old_pubkey"]))
mut, minfo = run_graft()
nf_verify_v1_impl[0] = REAL_VERIFY_V1
print("   pure-Python v1 mutant:", minfo, flush=True)
mutant("v1 verified with the pure-Python checker",
       "v1 verified once, by libsodium, outside _db_lock", real, mut)


def defer(rec, raw):
    rec["_raw_v1"] = raw
    return rec["prev_hash"]


def graft_in_lock(conn, rec, seq):
    v = nf._v1_shape(rec.get("_raw_v1"), rec["name"])
    if v is None or not nf._verify_v1(v):
        return False
    return REAL_GRAFT_OK(conn, dict(rec, _v1_hash=nf._v1_cert_hash(v)), seq)


with patched(nf, "_graft_v1", defer), patched(nf, "_v1_graft_ok", graft_in_lock):
    mut, minfo = run_graft()
print("   v1-inside-the-lock mutant:", minfo, flush=True)
mutant("v1 verified inside _db_lock",
       "v1 verified once, by libsodium, outside _db_lock", real, mut)

# ===================================================== Loom: membership
print("Loom: a v1 cert outside v1_frozen_root cannot anchor v2", flush=True)


def run_member():
    nm, v1, v2, kB, kC = graft_setup(frozen=False)
    r = ingest([v2], now=next_round())
    with core._db_lock, core._db() as c:
        st = nf.current_state(c, nm)
        root = hop_certs.v1_frozen_root(nf.v1_frozen_rows(c, nm))
    return (r["accepted"] == {} and st[0] == pub(kB)
            and root == hop_certs.EMPTY_ROOT), r["outcomes"]


real, info = run_member()
check("first v2 hop on a valid v1 cert NOT in v1_frozen_root: refused, pin "
      "unmoved", real, info)
with patched(nf, "v1_member", lambda conn, name, h: True):
    mut, _ = run_member()
mutant("skip the v1_frozen_root membership check",
       "v2 on a non-frozen v1 refused", real, mut)

# ===================================================== Loom: hops_root
print("Loom: rotate path vs KINDS import, byte-identical hops_root", flush=True)


def kinds_import_rows(conn, name):
    """KINDS import, copied from window_open.py at 7b15ca9 (_all_certs
    :289-298 and committed_hop_rows :264-286; every hop of a short chain
    is committed)."""
    certs, hops = [], []
    for o, n, iss, sig, v, seq, prev in conn.execute(
            "SELECT old_pubkey, new_pubkey, issued_at, signature, cert_v,"
            " cert_seq, prev_hash FROM name_rotations WHERE name=?"
            " ORDER BY accepted_at ASC, rowid ASC", (name,)):
        hops.append((o, n))
        certs.append({"issued_at": iss, "signature": sig, "cert_v": v,
                      "cert_seq": seq, "prev_hash": prev})
    out = []
    for i in range(len(hops)):
        c = certs[i]
        v = int(c.get("cert_v") or 1)
        out.append({"name": name, "i": i, "old": hops[i][0], "new": hops[i][1],
                    "issued_at": c.get("issued_at", ""), "sig": c.get("signature", ""),
                    "v": v, "seq": c.get("cert_seq") if v == 2 else None,
                    "prev_hash": c.get("prev_hash") if v == 2 else None})
    return out


reset_rates()
nmR, v1R, v2R, kBR, kCR = graft_setup()
outR = core.ingest_rotation_certs([v2R], pk6, [0])
kDR = seed()
with core._db_lock, core._db() as c:
    c3 = cert_next(nmR, kCR, pub(kDR), conn=c)
ingest([c3], now=next_round())


def run_roots():
    with core._db_lock, core._db() as c:
        a = nf.hop_rows(c, nmR)
        b = kinds_import_rows(c, nmR)
        ok_chain = hop_certs._verify_uncached(
            b, [[nmR, pub(kDR)]], set(), (1, 1, 0), lambda p: False)
    ra, rb = hop_certs.hops_root(a), hop_certs.hops_root(b)
    return (len(a) == 3 and ra.encode() == rb.encode()
            and hop_certs.v1_frozen_root(a) == hop_certs.v1_frozen_root(b)
            and ok_chain == (True, None)), (len(a), ra[:16], rb[:16], ok_chain)


real, info = run_roots()
check("v1 + two v2 hops: hops_root(rotate path) == hops_root(KINDS import), "
      "byte-identical; KINDS chain check passes", real, info)
real_hop_row = nf.hop_row


def old_leaf(rec, i=0):
    r = real_hop_row(rec, i)
    return dict(r, sig="", seq=None, prev_hash=None)      # {name, i, old, new}


with patched(nf, "hop_row", old_leaf):
    mut, _ = run_roots()
mutant("old leaf encoding on the rotate path", "hops_root byte-identical", real, mut)

# ===================================================== Bulwark: no weak_reason
print("Bulwark: serializer only; no weak_reason / is_weak per cert", flush=True)


def run_no_weak():
    reset_rates()
    nm = f"nw{secrets.token_hex(3)}"
    kA = seed()
    claim_gate_pin(nm, kA)
    certc = cert_next(nm, kA, pub(seed()))
    nf._weak_ok_cache.clear()
    n = {"weak": 0, "is_weak": 0}
    rw, ri = window_open.weak_reason, window_open.is_weak_pubkey

    def cw(p):
        n["weak"] += 1
        return rw(p)

    def ci(p):
        n["is_weak"] += 1
        return ri(p)
    with patched(window_open, "weak_reason", cw), \
            patched(window_open, "is_weak_pubkey", ci):
        out = core.ingest_rotation_certs([certc], pk6, [0])
    return (out["outcomes"] == ["accepted"] and n == {"weak": 0, "is_weak": 0}), \
        (out["outcomes"], n)


real, info = run_no_weak()
check("rotation path: weak_reason 0 and is_weak 0 calls per cert", real, info)
REAL_VERIFY = nf._verify


def via_hop_certs(rec, tag):
    row = nf.hop_row(rec)
    row["prev_hash"] = hop_certs.claim_anchor(rec["name"], rec["old_pubkey"]) \
        if row["prev_hash"] is None else row["prev_hash"]
    hop_certs._verify_uncached([row], [], {rec["name"]}, (0, 0, 0),
                               window_open.is_weak_pubkey)
    return REAL_VERIFY(rec, tag)


with patched(nf, "_verify", via_hop_certs):
    mut, minfo = run_no_weak()
print("   hop_certs verify-path mutant:", minfo, flush=True)
mutant("route verify through hop_certs._verify_uncached",
       "weak_reason 0 / is_weak 0 per cert", real, mut)

check("one serializer: name_fork.cert_payload is hop_certs.v2_payload",
      nf.cert_payload("n", "aa" * 32, "bb" * 32, ISSUED, 3, "cc" * 32)
      == hop_certs.v2_payload("n", 3, "cc" * 32, "aa" * 32, "bb" * 32, ISSUED)
      == ("name-rotate/v2|n|3|" + "cc" * 32 + "|" + "aa" * 32 + "|" + "bb" * 32
          + "|" + ISSUED).encode())
import rotate_name  # noqa: E402
check("rotate_name v1 payload is hop_certs.v1_payload",
      rotate_name._rotate_payload("n", "aa" * 32, "bb" * 32, ISSUED)
      == hop_certs.v1_payload("n", "aa" * 32, "bb" * 32, ISSUED))

finish()
