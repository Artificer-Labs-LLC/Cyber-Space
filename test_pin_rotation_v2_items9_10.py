#!/usr/bin/env python3
"""Pin-rotation v2 belt, items9_10 (split from test_pin_rotation_v2.py)."""
from pinrot_common import *  # noqa: F401,F403
from pinrot_common import _round_k, _flat_nf, _flat_doc, _ed, _fed_env  # noqa: F401

# ================================================================ item 9
print("item 9: pending queue and catch-up", flush=True)


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
        verdict = nf.accept_catchup(c, n2, ch["rotations"], now=next_round(),
                                   prenormalized=norm(ch["rotations"]))
    return verdict == "refused" and head(n2)[0] == pub(kA) and not contested(n2)


real = run_stale_path()
check("fetched path starting from a stale pin is refused whole; not contested", real)


def internal_only(conn, name, path, prenormalized=None):
    recs = list(prenormalized) if prenormalized is not None else [nf._norm_cert(r) for r in path]
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
    vb = nf.accept_catchup(c, nbr, [alt], now=next_round(),
                           prenormalized=norm([alt]))
check("catch-up path from the real head with a competing verified branch -> CONTESTED",
      vb == "contested" and contested(nbr))
parity_src = open(os.path.join(HERE, "test_fed_route_parity.py")).read()
check("new route POST /fed/names/chain is in the route-parity REQUIRED set",
      '("POST", "/fed/names/chain")' in parity_src)

# ================================================================ item 10
print("item 10: pins are permanent; PIN-STALE", flush=True)


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


finish()
