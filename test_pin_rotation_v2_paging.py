#!/usr/bin/env python3
"""Pin-rotation v2: stateless catch-up paging (board ruling on the 32-cert
cap), fork pages (Loom) with the settle window (Bulwark/Loom), replay across
pages, and the direct _db_lock-not-held-during-_norm_cert assert
(Examiner)."""
from pinrot_common import *  # noqa: F401,F403
from pinrot_common import _round_k, _ed  # noqa: F401

F = {"t": time.time()}
STEP = max(61, ROUND + 1)          # > 60 s bucket window and > one FORK GATE round
PX, PY = secrets.token_hex(32), secrets.token_hex(32)
add_peer(PX)
add_peer(PY)


def clk():
    return F["t"]


def tick(dt=STEP):
    F["t"] += dt
    return F["t"]


def mint_chain(name, k0, n, start_seq=1, prev=None):
    """n valid hops from (k0, prev). Returns certs, seeds, cert hashes."""
    seeds = [k0] + [seed() for _ in range(n)]
    prev = prev or head(name)[2]
    certs, hashes = [], []
    for i in range(1, n + 1):
        c = nf.mint_cert(name, seeds[i - 1], pub(seeds[i]), start_seq + i - 1,
                         prev, issued_at=ISSUED)
        prev = nf._norm_cert(c)["cert_hash"]
        certs.append(c)
        hashes.append(prev)
    return certs, seeds, hashes


CHARGES = []
_real_charge = core.charge_catchup


def spy_charge(sender, n):
    r = _real_charge(sender, n)
    if r is None:
        CHARGES.append((sender, n, clk()))
    return r


def max_per_60(sender):
    ev = [(t, n) for s, n, t in CHARGES if s == sender]
    return max([sum(n2 for t2, n2 in ev if t <= t2 < t + 60) for t, _ in ev] or [0])


def page_in(sender, name, certs, max_pulls=12):
    log = []
    for _ in range(max_pulls):
        v = core.pull_name_chain(sender, name, now=tick(),
                                 fetch=lambda u, n, p: {"rotations": certs})
        log.append(v)
        if head(name)[1] >= certs[-1]["seq"] or v not in ("accepted", "partial", "rate-limited"):
            break
    return log


def fresh(prefix):
    nm = f"{prefix}{secrets.token_hex(3)}"
    k0 = seed()
    b = claim_gate_pin(nm, k0)
    return nm, k0, b


def direct_load(nm, b, certs):
    m = mem_conn()
    m.execute("INSERT INTO name_bindings VALUES (?,?,?,?,?)",
              (nm, b["node_pubkey"], b["issued_at"], b["expires_at"], b["signature"]))
    nf.pin_initial(m, nm, b["node_pubkey"], source="claim_gate", binding=b)
    v = nf.accept_catchup(m, nm, certs, now=tick(1),
                          prenormalized=core.normalize_rotation_certs(certs))
    return v, nf.current_state(m, nm)


with patched(core, "_clock", clk), patched(nf, "_wall", clk), \
        patched(core, "charge_catchup", spy_charge):
    reset_rates()

    # ================================================= paging
    print("Board: stateless paging, 33- and 100-cert paths from two peers",
          flush=True)

    def run_paging():
        out = {}
        for sender, n in ((PX, 33), (PY, 100)):
            nm, k0, b = fresh("pg")
            certs, seeds, hashes = mint_chain(nm, k0, n)
            dv, dstate = direct_load(nm, b, certs)
            c0 = len(CHARGES)
            log = page_in(sender, nm, certs)
            pages = [k for _, k, _ in CHARGES[c0:]]
            out[n] = (head(nm), dstate, dv, log, max_per_60(sender),
                      (pub(seeds[-1]), n, hashes[-1]), pages)
        return out

    res = run_paging()
    for n, (got, dstate, dv, log, mx, want, _) in res.items():
        check(f"{n}-cert path paged in -> same pin/seq/head as a direct load; "
              f"sender <= 32 certs per 60 s",
              dv == "accepted" and got == dstate == want and mx <= 32,
              (n, log, mx, got == dstate, dstate == want))
    check("33-cert path took pages [32, 1], 100-cert path [32, 32, 32, 4]; one "
          "page per pull window",
          res[33][6] == [32, 1] and res[100][6] == [32, 32, 32, 4],
          (res[33][6], res[100][6], res[33][3], res[100][3]))

    def buffered_pull(sender, name, fetch=None, now=None):
        """MUTANT: page whose predecessor has not arrived is buffered (held
        pending) until it does, instead of being refused."""
        chain = fetch(None, name, sender)["rotations"]
        with core._db_lock, core._db() as c:
            i = nf.catchup_start(c, name, chain)
        page = chain[i:i + nf.CATCHUP_PAGE] if i >= 0 else chain[:nf.CATCHUP_PAGE]
        v = core.ingest_catchup_page(sender, name, page, now=now)
        if v == "junk":
            recs = core.normalize_rotation_certs(page, sender)
            with core._db_lock, core._db() as c:
                for r in recs:
                    if r:
                        nf._hold_pending(c, r, sender, [], now)
            return "pending"
        return v

    # ================================================= over-length
    nm, k0, b = fresh("ol")
    certs, _, _ = mint_chain(nm, k0, 33)
    reset_rates()
    nn = {"n": 0}
    _rn = nf._norm_cert

    def count_norm(raw):
        nn["n"] += 1
        return _rn(raw)
    with patched(nf, "_norm_cert", count_norm):
        v33 = core.ingest_catchup_page(PX, nm, certs, now=tick())
        vj = core.ingest_catchup_page(PX, nm, [{"prev_hash": "ab" * 32}], now=tick())
    check("a 33-cert page gets 'over-length' (distinct from 'junk'), unparsed, "
          "pin unmoved", v33 == "over-length" and vj == "junk" and nn["n"] == 0
          and head(nm)[1] == 0, (v33, vj, nn))

    # ================================================= junk / unlinked
    print("Board: a page linking to no committed cert", flush=True)

    def run_junk(ingest_page=None):
        reset_rates()
        nm, k0, _ = fresh("jk")
        good, seeds, _ = mint_chain(nm, k0, 3)
        # Signed by the pin key, seq = head+1, internally chained: only the
        # first prev_hash is wrong (links to no committed cert).
        bad, _, _ = mint_chain(nm, k0, 3, prev="cd" * 32)
        cnt = {"norm": 0, "verify": 0}
        rn, rv = nf._norm_cert, nf._verify

        def n_(raw):
            cnt["norm"] += 1
            return rn(raw)

        def v_(rec, tag):
            cnt["verify"] += 1
            return rv(rec, tag)
        before = len(CHARGES)
        with patched(nf, "_norm_cert", n_), patched(nf, "_verify", v_):
            if ingest_page:
                v = ingest_page(PX, nm, fetch=lambda u, n, p: {"rotations": bad},
                                now=tick())
            else:
                v = core.pull_name_chain(PX, nm, fetch=lambda u, n, p: {"rotations": bad},
                                         now=tick())
        with core._db_lock, core._db() as c:
            stored = (nf.pending_count(c, nm), nf.fork_cert_count(c, nm),
                      len(nf.late_forks(c, nm)), nf.is_contested(c, nm),
                      c.execute("SELECT COUNT(*) FROM name_cert_evidence WHERE name=?",
                                (nm,)).fetchone()[0])
        ok = (v == "junk" and cnt == {"norm": 0, "verify": 0}
              and len(CHARGES) == before and stored == (0, 0, 0, False, 0)
              and head(nm)[1] == 0)
        return ok, (v, cnt, len(CHARGES) - before, stored, head(nm)[1])

    real, info = run_junk()
    check("unlinked page: 'junk' at constant cost (0 parse, 0 verify, 0 charge), "
          "no stored state, pin unmoved", real, info)
    mut, minfo = run_junk(buffered_pull)
    print("   buffer-until-predecessor mutant:", minfo, flush=True)
    mutant("a page is buffered until its predecessor arrives",
           "unlinked page refused, no stored state", real, mut)
    with patched(nf, "_links_tip", lambda c, pin, head: True):
        mut, minfo = run_junk()
    print("   unlinked-accepted mutant:", minfo, flush=True)
    mutant("an unlinked page is accepted", "unlinked page refused, no stored state",
           real, mut)

    # ================================================= replay A->B->A
    print("Board item 4: seq + prev_hash in every cert; replay A->B->A refused",
          flush=True)
    check("seq and prev_hash are inside the signed payload (tampering either "
          "breaks the signature)",
          all(nf._norm_cert(dict(c, **kv)) is None for c in [mint_chain(*fresh("sq")[:2], 1)[0][0]]
              for kv in ({"seq": 2}, {"prev_hash": "ef" * 32})))

    def run_replay():
        reset_rates()
        nm, kA, _ = fresh("rp")
        kB = seed()
        h0 = head(nm)[2]
        c1 = nf.mint_cert(nm, kA, pub(kB), 1, h0, issued_at=ISSUED)
        h1 = nf._norm_cert(c1)["cert_hash"]
        c2 = nf.mint_cert(nm, kB, pub(kA), 2, h1, issued_at=ISSUED)
        log = page_in(PX, nm, [c1, c2])
        st = head(nm)                          # A again, seq 2
        # Same key (A is the pin again), seq = head+1, but prev_hash is the
        # OLD cert_hash (h0), not the tip's.
        rp = nf.mint_cert(nm, kA, pub(kB), 3, h0, issued_at=ISSUED)
        v1 = core.ingest_catchup_page(PX, nm, [rp], now=tick())
        v2 = core.ingest_catchup_page(PX, nm, [c1], now=tick())   # literal replay
        ok = (st[0] == pub(kA) and st[1] == 2 and head(nm) == st
              and v1 == "replay" and v2 == "replay" and not contested(nm))
        return ok, (log, v1, v2, head(nm)[1], contested(nm))

    real, info = run_replay()
    check("replayed old cert, same key, wrong cert_hash (A->B->A): refused, pin "
          "stays A at seq 2, not contested", real, info)
    with patched(nf, "_links_tip",
                 lambda c, pin, head: isinstance(c, dict) and c.get("old_pubkey") == pin):
        mut, minfo = run_replay()
    print("   key-instead-of-cert_hash mutant:", minfo, flush=True)
    mutant("prev_hash check compares the key, not cert_hash",
           "replay A->B->A refused", real, mut)

    # ================================================= fork (Loom)
    print("Loom: fork page inside the settle window", flush=True)

    def run_fork():
        reset_rates()
        nm, k0, _ = fresh("fk")
        A, seeds, hashes = mint_chain(nm, k0, 40)
        log = page_in(PX, nm, A)
        tipA = head(nm)
        B, _, _ = mint_chain(nm, seeds[29], 5, start_seq=30, prev=hashes[28])
        v = core.ingest_catchup_page(PY, nm, B, now=tick(1))
        with core._db_lock, core._db() as c:
            ev = nf.fork_cert_count(c, nm)
        r = client.get(f"/api/v1/names/{nm}")
        ok = (tipA[1] == 40 and head(nm) == tipA and v == "fork-recorded"
              and ev >= 1 and contested(nm) and r.status_code == 409
              and "contested" in r.text)
        return ok, (log, v, tipA[1], head(nm) == tipA, ev, contested(nm),
                    r.status_code)

    real, info = run_fork()
    check("X pages A to seq 40; Y's valid seq-30 branch-B page: pin stays on A, "
          "fork recorded, name resolves 'contested'", real, info)
    _cls = nf.classify_page

    def fork_as_junk(conn, name, page):
        k = _cls(conn, name, page)
        return "junk" if k == "fork" else k
    with patched(nf, "classify_page", fork_as_junk):
        mut, minfo = run_fork()
    print("   fork-as-junk mutant:", minfo, flush=True)
    mutant("fork page refused as junk with no evidence",
           "fork recorded, contested", real, mut)

    # ================================================= late fork
    print("Bulwark/Loom: fork after the settle window", flush=True)

    def run_late():
        reset_rates()
        nm, k0, _ = fresh("lf")
        A, seeds, hashes = mint_chain(nm, k0, 40)
        page_in(PX, nm, A)
        tipA = head(nm)
        with core._db_lock, core._db() as c:
            ev0 = nf.fork_cert_count(c, nm)
        tick(nf.settle_seconds() + STEP)       # the window has closed
        # seeds[29] is the key retired at seq 30 (it signed A's seq-30 hop).
        B, _, _ = mint_chain(nm, seeds[29], 5, start_seq=30, prev=hashes[28])
        v1 = core.ingest_catchup_page(PY, nm, B, now=tick())
        v2 = core.ingest_catchup_page(PY, nm, B, now=tick())
        with core._db_lock, core._db() as c:
            late = nf.late_forks(c, nm)
            ev = nf.fork_cert_count(c, nm)
        r = client.get(f"/api/v1/names/{nm}/rotations")
        h = client.get(f"/api/v1/names/{nm}/head")
        owner_view = (r.json().get("late_fork_evidence") or []) if r.status_code == 200 else []
        ok = (head(nm) == tipA and not contested(nm) and v1 == "late-fork"
              and v2 == "late-fork-duplicate" and len(late) == 1 and ev == ev0
              and late[0]["seq"] == 30 and late[0]["prev_hash"] == hashes[28]
              and len(owner_view) == 1 and h.status_code == 200)
        return ok, (v1, v2, len(late), ev, contested(nm), r.status_code,
                    len(owner_view), h.status_code)

    real, info = run_late()
    check("key retired at seq 30 sends a branch-B page after the window: name "
          "stays live, evidence recorded exactly once, owner-readable on "
          "GET /api/v1/names/{name}/rotations", real, info)

    def key_current_at_fork_seq(conn, name, rec, now):
        row = conn.execute("SELECT pubkey FROM name_pin_log WHERE name=? AND"
                           " head_hash=?", (name, rec["prev_hash"])).fetchone()
        return row is not None and str(row[0]).lower() == rec["old_pubkey"]
    with patched(nf, "fork_window_open", key_current_at_fork_seq):
        mut, minfo = run_late()
    print("   window-dropped (key-current check kept) mutant:", minfo, flush=True)
    mutant("window check dropped, key-current-at-fork-seq kept",
           "late fork: live, evidence once", real, mut)
    check("late fork evidence is capped per name and per sender",
          nf.LATE_FORK_PER_NAME <= 8 and nf.LATE_FORK_PER_SENDER <= 32)

    # ================================================= lock-held assert
    print("Examiner: _db_lock is never held during _norm_cert", flush=True)

    def run_lock():
        reset_rates()
        seen = {"calls": 0, "held": 0}
        rn = nf._norm_cert

        def n_(raw):
            seen["calls"] += 1
            if core._db_lock.locked():
                seen["held"] += 1
            return rn(raw)
        with patched(nf, "_norm_cert", n_):
            nm, k0, _ = fresh("lk")
            A, seeds, hashes = mint_chain(nm, k0, 5)
            seen["calls"] = 0                     # minting is not under test
            page_in(PX, nm, A)                     # tip pages: accept_catchup
            B, _, _ = mint_chain(nm, seeds[2], 1, start_seq=3, prev=hashes[1])
            seen["calls"] -= 1
            core.ingest_catchup_page(PY, nm, B, now=tick(1))   # fork: ingest path
            # Both former inline-fallback sites, called with no prenormalized
            # under the lock: refused, never normalized there.
            nm2 = fresh("lk")[0]
            k2 = seed()
            c2 = nf.mint_cert(nm2, k2, pub(seed()), 1, head(nm2)[2], issued_at=ISSUED)
            with core._db_lock, core._db() as c:
                r1 = nf.ingest_rotation_round(c, [c2], PX, now=tick(1))
                r2 = nf.accept_catchup(c, nm2, [c2], PX, now=tick(1))
        ok = seen["held"] == 0 and seen["calls"] >= 6 \
            and r1["outcomes"] == ["refused-invalid"] and r2 == "refused"
        return ok, (seen, r1["outcomes"], r2)

    real, info = run_lock()
    check("_db_lock not held in any _norm_cert call (tip pages, fork page); both "
          "former inline sites refuse unnormalized input", real, info)
    _acc = nf.accept_catchup

    def norm_in_lock(conn, name, path, sender_pub=None, now=None, prenormalized=None):
        return _acc(conn, name, path, sender_pub, now=now,
                    prenormalized=[nf._norm_cert(r) for r in path])
    with patched(nf, "accept_catchup", norm_in_lock):
        mut, minfo = run_lock()
    print("   _norm_cert-under-lock mutant:", minfo, flush=True)
    mutant("_norm_cert runs under the lock", "lock not held during _norm_cert",
           real, mut)

finish()
