#!/usr/bin/env python3
"""Pin-rotation v2 successor of e03f90e: Bulwark N1 + N2 (6c9ade34), Cipher
condition 3 (a8e70392), Examiner raise-when-pre-is-None.

N1  POST /names/rotate normalizes OUTSIDE _db_lock and hands the record in
    as prenormalized; consider_rotation / accept_catchup / path_accept_rule
    RAISE when prenormalized is None (no inline fallback). Direct
    norm_in_lock == 0 assert on the route, with the inline-fallback mutant.
N2  Junk peers sending 32-cert tip-linked pages with bad signatures fill
    the 64-unit catch-up slice; an honest 1-cert catch-up is still accepted
    from the small-pull reserve (2 and 3 junk peers)."""
from pinrot_common import *  # noqa: F401,F403

PH = secrets.token_hex(32)
JUNK = [secrets.token_hex(32) for _ in range(3)]
for p in [PH] + JUNK:
    add_peer(p)


def fresh(prefix):
    nm = f"{prefix}{secrets.token_hex(3)}"
    k0 = seed()
    claim_gate_pin(nm, k0)
    return nm, k0


class LockSpy:
    """Counts _norm_cert and _verify calls, and how many ran with
    core._db_lock held."""
    def __init__(self):
        self.c = {"norm": 0, "norm_in_lock": 0, "verify": 0, "verify_in_lock": 0}

    def __enter__(self):
        rn, rv = nf._norm_cert, nf._verify
        c = self.c

        def n_(raw):
            c["norm"] += 1
            c["norm_in_lock"] += int(core._db_lock.locked())
            return rn(raw)

        def v_(rec, tag):
            c["verify"] += 1
            c["verify_in_lock"] += int(core._db_lock.locked())
            return rv(rec, tag)
        self._p = [patched(nf, "_norm_cert", n_), patched(nf, "_verify", v_)]
        for p in self._p:
            p.__enter__()
        return c

    def __exit__(self, *a):
        for p in reversed(self._p):
            p.__exit__(*a)


# ===================================================================== N1
print("Bulwark N1 / Cipher condition 3: /names/rotate, no _norm_cert under _db_lock",
      flush=True)


def rotate_once():
    reset_rates()
    nm, k0 = fresh("n1r")
    k1 = seed()
    st = head(nm)
    c = nf.mint_cert(nm, k0, pub(k1), st[1] + 1, st[2], issued_at=ISSUED)
    b = binding(nm, k1)
    form = {"name": nm, "old_pubkey": pub(k0), "new_pubkey": pub(k1),
            "rotation_seq": str(st[1] + 1), "rotation_prev_hash": st[2],
            "rotation_issued_at": ISSUED, "rotation_signature": c["signature"],
            "binding_issued_at": b["issued_at"], "binding_expires_at": b["expires_at"],
            "binding_signature": b["signature"]}
    with LockSpy() as cnt:
        try:
            r = client.post("/api/v1/names/rotate", data=form)
            code = r.status_code
        except Exception as e:          # TestClient re-raises server errors
            code = type(e).__name__
    moved = head(nm)
    ok = (code == 200 and cnt["norm"] >= 1 and cnt["norm_in_lock"] == 0
          and cnt["verify_in_lock"] == 0 and moved[0] == pub(k1) and moved[1] == st[1] + 1)
    return ok, (code, dict(cnt), moved[1])


real, info = rotate_once()
check("POST /names/rotate (legit v2 rotation): 200, pin moved, norm_in_lock == 0 "
      "and verify_in_lock == 0 (direct assert)", real, info)

_cr = nf.consider_rotation


def inline_fallback(conn, rec, sender_pub=None, prenormalized=None):
    """MUTANT (49292ba shape): the cert is normalized again inside the lock."""
    return _cr(conn, rec, sender_pub, prenormalized=[nf._norm_cert(rec)])


with patched(nf, "consider_rotation", inline_fallback):
    mut, minfo = rotate_once()
print("   inline-fallback mutant:", minfo, flush=True)
mutant("consider_rotation normalizes inline under _db_lock",
       "rotate: norm_in_lock == 0", real, mut)


def drop_pre(conn, rec, sender_pub=None, prenormalized=None):
    """MUTANT: the route's prenormalized record is not passed through."""
    return _cr(conn, rec, sender_pub, prenormalized=None)


with patched(nf, "consider_rotation", drop_pre):
    mut, minfo = rotate_once()
print("   pre-dropped mutant:", minfo, flush=True)
mutant("route drops pre=[rec] at consider_rotation", "rotate: norm_in_lock == 0",
       real, mut)


def raises_without_pre():
    reset_rates()
    nm, k0 = fresh("n1p")
    c = cert_next(nm, k0, pub(seed()))
    out = {}
    with LockSpy() as cnt:
        for fn, call in (("consider_rotation", lambda conn: nf.consider_rotation(conn, c)),
                         ("accept_catchup", lambda conn: nf.accept_catchup(conn, nm, [c])),
                         ("path_accept_rule", lambda conn: nf.path_accept_rule(conn, nm, [c]))):
            with core._db_lock, core._db() as conn:
                try:
                    call(conn)
                    out[fn] = "no-raise"
                except nf.PrenormalizedRequired:
                    out[fn] = "raised"
    ok = (set(out.values()) == {"raised"} and cnt["norm"] == 0 and cnt["verify"] == 0
          and head(nm)[1] == 0)
    return ok, (out, dict(cnt))


real, info = raises_without_pre()
check("consider_rotation / accept_catchup / path_accept_rule RAISE "
      "PrenormalizedRequired when pre is None: 0 normalize, 0 verify, pin unmoved",
      real, info)

_acr = nf.accept_catchup


def refuse_not_raise(conn, name, path, sender_pub=None, now=None, prenormalized=None):
    """MUTANT (e03f90e shape): unnormalized input refused quietly."""
    if prenormalized is None:
        return "refused"
    return _acr(conn, name, path, sender_pub, now=now, prenormalized=prenormalized)


with patched(nf, "accept_catchup", refuse_not_raise):
    mut, minfo = raises_without_pre()
print("   refuse-instead-of-raise mutant:", minfo, flush=True)
mutant("accept_catchup refuses instead of raising on pre=None",
       "raise when pre is None", real, mut)

# ===================================================================== N2
print("Bulwark N2: honest 1-cert catch-up under junk x 32 pages", flush=True)


def junk_page(nm, k0, n=32):
    """Tip-linked (passes classify_page) but every signature is bad."""
    st = head(nm)
    out, prev, s = [], st[2], k0
    for i in range(n):
        s2 = seed()
        c = nf.mint_cert(nm, s, pub(s2), st[1] + 1 + i, prev, issued_at=ISSUED)
        prev = nf._norm_cert(c)["cert_hash"]
        c = dict(c, signature="11" * 64)
        out.append(c)
        s = s2
    return out


def run_n2(n_junk):
    reset_rates()
    nm, k0 = fresh("n2j")
    good = cert_next(nm, k0, pub(seed()))
    jp = junk_page(nm, k0)
    jv = [core.ingest_catchup_page(j, nm, jp) for j in JUNK[:n_junk]]
    slice_full = len(core._catchup_times) == core.CATCHUP_GLOBAL_SLICE
    hv = core.ingest_catchup_page(PH, nm, [good])
    ok = (slice_full and hv == "accepted" and head(nm)[1] == 1
          and all(v == "refused" for v in jv[:2]) and all(v == "rate-limited" for v in jv[2:]))
    return ok, (n_junk, jv, slice_full, hv, head(nm)[1])


for k in (2, 3):
    real, info = run_n2(k)
    check(f"{k} junk peers x 32 tip-linked bad-sig certs fill the slice; honest "
          f"1-cert catch-up still ACCEPTED (small-pull reserve)", real, info)
    with patched(core, "_small_reserve_ok", lambda q, n: False):
        mut, minfo = run_n2(k)
    print(f"   no-reserve mutant ({k} junk):", minfo, flush=True)
    mutant(f"small-pull reserve removed ({k} junk)", "honest 1-cert accepted under junk",
           real, mut)


def reserve_bounded():
    reset_rates()
    nm, k0 = fresh("n2b")
    jp = junk_page(nm, k0)
    core.ingest_catchup_page(JUNK[0], nm, jp)
    core.ingest_catchup_page(JUNK[1], nm, jp)
    # a 3-cert junk page never draws on the reserve
    v3 = core.ingest_catchup_page(JUNK[2], nm, junk_page(nm, k0, 3))
    r_after3 = sum(len(d) for d in core._catchup_small_times.values())
    # one junk sender may take at most CATCHUP_SMALL_PER_SENDER reserve units
    one = junk_page(nm, k0, 1)
    vs = [core.ingest_catchup_page(JUNK[2], nm, one) for _ in range(4)]
    used = sum(len(d) for d in core._catchup_small_times.values())
    ok = (v3 == "rate-limited" and r_after3 == 0
          and vs[:2] == ["refused", "refused"] and vs[2:] == ["rate-limited"] * 2
          and used == core.CATCHUP_SMALL_PER_SENDER
          and core.CATCHUP_GLOBAL_SLICE + core.CATCHUP_SMALL_RESERVE <= 72
          and core.CATCHUP_SMALL_MAX == 2)
    return ok, (v3, r_after3, vs, used)


real, info = reserve_bounded()
check("reserve is only for 1-2 cert paths, capped per sender (2) and total (8); "
      "catch-up never exceeds slice + reserve = 72 / 60 s", real, info)
_sro = core._small_reserve_ok
with patched(core, "_small_reserve_ok", lambda q, n: True):
    mut, minfo = reserve_bounded()
print("   unbounded-reserve mutant:", minfo, flush=True)
mutant("reserve open to any path size / any sender share", "reserve bounded", real, mut)

finish()
