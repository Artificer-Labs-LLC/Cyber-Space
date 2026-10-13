#!/usr/bin/env python3
"""Pin-rotation v2 belt, items45 (split from test_pin_rotation_v2.py)."""
from pinrot_common import *  # noqa: F401,F403
from pinrot_common import _round_k, _flat_nf, _flat_doc, _ed, _fed_env  # noqa: F401
import hop_certs  # noqa: E402

# ================================================================ item 4
print("item 4: v2 payload, chain, forks keyed on (name, prev_hash)", flush=True)
nm = "abac"
kA, kB, kC = seed(), seed(), seed()
claim_gate_pin(nm, kA)
origin = head(nm)[2]
c1 = cert_next(nm, kA, pub(kB))
check("first link's prev_hash is hop_certs.claim_anchor(name, pin) (KINDS anchor)",
      c1["prev_hash"] == origin == hop_certs.claim_anchor(nm, pub(kA)))
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

_v1_new = pub(seed())
v1 = {"v": 1, "name": "abac", "old_pubkey": pub(kC), "new_pubkey": _v1_new,
      "issued_at": ISSUED,
      "signature": _ed.sign(hop_certs.v1_payload("abac", pub(kC), _v1_new, ISSUED),
                            kC, bytes.fromhex(pub(kC))).hex()}
_v1_sig_ok = _ed.checkvalid_sodium(
    bytes.fromhex(v1["signature"]),
    hop_certs.v1_payload("abac", pub(kC), _v1_new, ISSUED), bytes.fromhex(pub(kC)))
_h0 = head("abac")
_r1 = ingest([v1], now=next_round())
check("a REAL v1 cert (libsodium-valid signature) is frozen, not refused: never "
      "a new hop, pin unmoved",
      _v1_sig_ok and _r1["outcomes"] == ["v1-frozen"] and _r1["refused"] == 0
      and head("abac") == _h0 and nf._norm_cert(v1) is None, (_v1_sig_ok, _r1["outcomes"]))

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
nf.drain_pending(nB, "conv", now=rnd(5002),
                 prenormalized={rid: nf._norm_cert(c) for rid, c, _ in nf.pending_rows(nB, "conv")})
check("two nodes, different order and time -> same head hash",
      nf.current_state(nA, "conv") == nf.current_state(nB, "conv")
      and nf.current_state(nA, "conv")[1] == 2,
      (nf.current_state(nA, "conv"), nf.current_state(nB, "conv")))
check("first rotation over a gossip-set (oob) pin verifies on an independently pinned node",
      nf.current_state(nB, "conv")[0] == pub(k3))

# ================================================================ item 5
print("item 5: canonical encoding before hashing", flush=True)
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


finish()
