#!/usr/bin/env python3
"""Pin-rotation v2: catch-up charging and lock discipline (Bulwark HIGH),
libsodium-only /names/rotate key check (Bulwark MEDIUM), and Cipher's
golden-vector conformance against 7b15ca9."""
from pinrot_common import *  # noqa: F401,F403
from pinrot_common import _round_k, _ed  # noqa: F401
import threading  # noqa: E402
import hop_certs  # noqa: E402
import window_open  # noqa: E402
import routes_social_serve as rss  # noqa: E402
import nacl.signing  # noqa: E402

add_peer(pk6)


class TimedLock:
    """Wraps core._db_lock: total hold time and verify calls while held."""
    def __init__(self, inner):
        self.inner, self.held, self.total, self.t0 = inner, 0, 0.0, 0.0

    def acquire(self, *a, **k):
        r = self.inner.acquire(*a, **k)
        if r:
            self.held += 1
            if self.held == 1:
                self.t0 = time.perf_counter()
        return r

    def release(self):
        if self.held == 1:
            self.total += time.perf_counter() - self.t0
        self.held -= 1
        self.inner.release()

    __enter__ = lambda self: (self.acquire(), self)[1]  # noqa: E731

    def __exit__(self, *a):
        self.release()


def junk_chain(name, pin_seed, n):
    """n well-shaped certs from the head: canonical keys, canonical (R, S)
    from a real signature over other bytes, so each costs a full verify."""
    with core._db_lock, core._db() as c:
        seq, head = nf.current_state(c, name)[1:]
    sk = nacl.signing.SigningKey.generate()
    sig = sk.sign(b"other bytes").signature.hex()
    old = pub(pin_seed)
    out = []
    for i in range(n):
        new = nacl.signing.SigningKey.generate().verify_key.encode().hex()
        out.append({"v": 2, "kind": nf.KIND, "tag": nf.TAG.decode(), "name": name,
                    "old_pubkey": old, "new_pubkey": new, "issued_at": ISSUED,
                    "seq": seq + 1 + i, "prev_hash": head if i == 0 else "ab" * 32,
                    "signature": sig})
        old = new
    return {"rotations": out}


def old_pull_name_chain(sender_pub, name, fetch=None):
    """MUTANT: the pre-fix pull, normalizing (and verifying) under the lock
    with no charge."""
    fetch = fetch or core._fetch_name_chain
    with core._db_lock, core._db() as conn:
        row = conn.execute("SELECT node_url FROM peers WHERE node_pub=? AND"
                           " retired_at=''", (str(sender_pub).lower(),)).fetchone()
        head_ = nf.head_hash(conn, name)
    if row is None or head_ is None:
        return "no-peer"
    chain = fetch(row[0], name, str(sender_pub).lower())
    path = nf.path_after(chain, head_)
    path = path[:core.NAMES_GOSSIP_ROTATION_CAP]
    with core._db_lock, core._db() as conn:
        return nf.accept_catchup(conn, name, path, sender_pub,
                                 prenormalized=[nf._norm_cert(r) for r in path])


# ===================================================== burst
print("Bulwark HIGH: catch-up burst, 32 pulls x 128 certs", flush=True)


def run_burst(pull=None):
    reset_rates()
    nm = f"cb{secrets.token_hex(3)}"
    kA = seed()
    claim_gate_pin(nm, kA)
    chain = junk_chain(nm, kA, 128)
    lock = TimedLock(core._db_lock)
    cnt = {"verify_in_lock": 0, "norm": 0}
    rv, rn = nf._verify, nf._norm_cert

    def v(rec, tag):
        if lock.held:
            cnt["verify_in_lock"] += 1
        return rv(rec, tag)

    def n(raw):
        cnt["norm"] += 1
        return rn(raw)
    waits, stop = [], threading.Event()

    def writer():
        while not stop.is_set():
            t = time.perf_counter()
            with core._db_lock:
                waits.append(time.perf_counter() - t)
            time.sleep(0.005)
    fn = pull or core.pull_name_chain
    with patched(core, "_db_lock", lock), patched(nf, "_verify", v), \
            patched(nf, "_norm_cert", n):
        th = threading.Thread(target=writer)
        th.start()
        t0 = time.perf_counter()
        verdicts = [fn(pk6, nm, fetch=lambda u, nme, p: chain) for _ in range(32)]
        wall = time.perf_counter() - t0
        stop.set()
        th.join()
    # The writer's own holds are microseconds; subtract nothing (conservative).
    mw = max(waits) if waits else 0.0
    ok = lock.total < 1.0 and mw <= 0.25 and cnt["verify_in_lock"] == 0
    return ok, {"lock_s": round(lock.total, 3), "max_wait_s": round(mw, 3),
                "verify_in_lock": cnt["verify_in_lock"], "norm": cnt["norm"],
                "wall_s": round(wall, 2), "verdicts": sorted(set(verdicts))}


real, info = run_burst()
check("32 pulls x 128 certs: _db_lock held < 1 s total, concurrent write waits "
      "<= 250 ms, 0 verifies under the lock", real, info)
mut, minfo = run_burst(old_pull_name_chain)
print("   normalize-inside-lock mutant:", minfo, flush=True)
mutant("catch-up normalizes back inside the lock (old pull)",
       "burst: lock < 1 s, write wait <= 250 ms, 0 verifies in lock", real, mut)
check("burst: only the first 32-cert page is ever parsed (<= 32 _norm_cert "
      "calls); every later pull is refused before any parse",
      info["norm"] <= 32 and set(info["verdicts"]) <= {"refused", "rate-limited"}
      and info["verdicts"].count("refused") <= 1, info)

# ===================================================== per-sender first
print("Bulwark: catch-up charges the sender's bucket, then a reserved slice",
      flush=True)
honest_peer = secrets.token_hex(32)
add_peer(honest_peer)


def run_buckets():
    reset_rates()
    nm = f"cs{secrets.token_hex(3)}"
    kA = seed()
    claim_gate_pin(nm, kA)
    chain = junk_chain(nm, kA, 128)
    reasons = []
    real_charge = core.charge_catchup

    def spy(sender, n):
        r = real_charge(sender, n)
        reasons.append(r)
        return r
    with patched(core, "charge_catchup", spy):
        for _ in range(32):
            core.pull_name_chain(pk6, nm, fetch=lambda u, nme, p: chain)
    shared = (len(core._gossip_verify_times), len(core._catchup_times))
    # Honest peer: a 1-cert rotation by gossip in the same window.
    nh = f"ch{secrets.token_hex(3)}"
    kh = seed()
    claim_gate_pin(nh, kh)
    ch = cert_next(nh, kh, pub(seed()))
    out = core.ingest_rotation_certs([ch], honest_peer, [0])
    # One 32-cert page fits the junk peer's own bucket; every later page is
    # refused at that bucket, so the shared counters never pass 32.
    return (reasons.count(None) == 1 and set(reasons) == {None, "sender"}
            and shared[0] <= 32 and shared[1] <= 32
            and out["outcomes"] == ["accepted"]), (sorted(set(map(str, reasons))),
                                                    shared, out["outcomes"])


real, info = run_buckets()
check("junk peer 32 x 128: one page charged, every later pull refused at ITS "
      "OWN bucket (shared counters <= 32); honest peer's 1-cert rotation accepted", real, info)
with patched(core, "_catchup_sender_ok", lambda q, n: True):
    mut, minfo = run_buckets()
print("   per-sender-dropped mutant:", minfo, flush=True)
mutant("per-sender catch-up bucket dropped",
       "junk refused at its own bucket; honest accepted", real, mut)
check("catch-up slice reserves the rest of the global budget for gossip",
      core.CATCHUP_GLOBAL_SLICE < core.GOSSIP_VERIFY_GLOBAL_LIMIT
      and core.GOSSIP_VERIFY_GLOBAL_LIMIT == 256
      and core.NAMES_GOSSIP_VERIFY_PER_CALL == 32)

# ===================================================== /names/rotate
print("Bulwark MEDIUM: /names/rotate key check is libsodium-only", flush=True)


def run_rotate_route():
    k_old, k_new = seed(), seed()
    form = {"name": f"rr{secrets.token_hex(3)}", "old_pubkey": pub(k_old),
            "new_pubkey": pub(k_new), "rotation_issued_at": ISSUED,
            "rotation_signature": "11" * 64, "binding_issued_at": ISSUED,
            "binding_expires_at": EXPIRES, "binding_signature": "22" * 64}
    n = {"weak": 0, "is_weak": 0, "key_check": 0}
    rw, ri, rk = window_open.weak_reason, window_open.is_weak_pubkey, nf._key_check

    def cw(p):
        n["weak"] += 1
        return rw(p)

    def ci(p):
        n["is_weak"] += 1
        return ri(p)

    def ck(p):
        n["key_check"] += 1
        return rk(p)
    reset_rates()
    with patched(window_open, "weak_reason", cw), \
            patched(window_open, "is_weak_pubkey", ci), patched(nf, "_key_check", ck):
        r = client.post("/api/v1/names/rotate", data=form)
    return (n["weak"] == 0 and n["is_weak"] == 0 and n["key_check"] >= 2), \
        (r.status_code, n)


real, info = run_rotate_route()
check("POST /names/rotate: 0 weak_reason, 0 is_weak; libsodium key check ran", real, info)
with patched(rss, "_rotate_weak_reason", lambda p: window_open.weak_reason(p)):
    mut, minfo = run_rotate_route()
print("   weak_reason-restored mutant:", minfo, flush=True)
mutant("weak_reason restored on /names/rotate", "0 weak_reason / 0 is_weak", real, mut)

# ===================================================== golden vectors
print("Cipher: golden vectors vs hop_certs.py / legacy_witness.py at 7b15ca9",
      flush=True)
# Computed from `git show 7b15ca9:hop_certs.py` and legacy_witness.py
# (:184 HOPS_ROOT_DOMAIN, :656-671 hop_row_hash/hops_root) on
# oracle/window-open-witness-kinds-hopcerts. Do not regenerate from this
# branch: they pin the KINDS bytes.
G_NAME, G_ISS = "golden", "2026-10-12T00:00:00+00:00"
G_OLD, G_NEW, G_PREV, G_SIG = "22" * 32, "33" * 32, "11" * 32, "44" * 64
G_V1 = {"name": G_NAME, "i": 0, "old": "55" * 32, "new": G_OLD, "issued_at": G_ISS,
        "sig": "66" * 64, "v": 1, "seq": None, "prev_hash": None}
GOLD = {
    "v2_payload": ("6e616d652d726f746174652f76327c676f6c64656e7c337c3131313131313131313131"
                   "3131313131313131313131313131313131313131313131313131313131313131313131"
                   "3131313131313131313131313131313131317c32323232323232323232323232323232"
                   "3232323232323232323232323232323232323232323232323232323232323232323232"
                   "323232323232323232323232327c333333333333333333333333333333333333333333"
                   "3333333333333333333333333333333333333333333333333333333333333333333333"
                   "33333333333333337c323032362d31302d31325430303a30303a30302b30303a3030"),
    "cert_hash_v2": "970a9a515e004eeb5ba0d38b12c2c60399f19a6a31da3081a5b7200486ee9c07",
    "cert_hash_v1": "9ab029f7a964a640807bdaae89b4faebe170a2c30e7e71848d16f3e6b4ddb72c",
    "claim_anchor": "e0008fa1b15508adbb5e7cd29a9e3f6b05a9ad95085f79d356ffd6b02eef572f",
    "leaf_v2": "0cbd65209429498475fb749dc63a844762ac6d48909ca8f4fdd5431569270bf7",
    "hops_root": "53d82945983e5ea6de22908fe4e274e130141fdbe8d3bd0baf80b839a2d42d41",
}


def golden():
    rec = {"name": G_NAME, "old_pubkey": G_OLD, "new_pubkey": G_NEW,
           "issued_at": G_ISS, "seq": 3, "prev_hash": G_PREV, "signature": G_SIG}
    v2row = nf.hop_row(rec, 1)
    got = {
        "v2_payload": nf.cert_payload(G_NAME, G_OLD, G_NEW, G_ISS, 3, G_PREV).hex(),
        "cert_hash_v2": nf.cert_hash(rec),
        "cert_hash_v1": hop_certs.cert_hash(G_V1),
        "claim_anchor": nf.claim_anchor(G_NAME, G_OLD),
        "leaf_v2": hop_certs.hop_row_hash(v2row),
        "hops_root": hop_certs.hops_root([G_V1, v2row]),
    }
    bad = {k: got[k] for k in GOLD if got[k] != GOLD[k]}
    return not bad, bad


real, info = golden()
check("golden: v2_payload, cert_hash (v1+v2), claim_anchor, hop leaf and "
      "hops_root byte-identical to 7b15ca9", real, info)
real_v2 = hop_certs.v2_payload


def one_byte_serializer(*a):
    b = bytearray(real_v2(*a))
    b[b.index(b"|")] = ord(":")       # one serializer byte
    return bytes(b)


with patched(hop_certs, "v2_payload", one_byte_serializer):
    mut, _ = golden()
mutant("one serializer byte changed (v2_payload '|' -> ':')",
       "golden vectors byte-identical", real, mut)
with patched(hop_certs, "HOPS_ROOT_DOMAIN", b"cyberspace-hops-root/v1\n"):
    mut, _ = golden()
mutant("one HOPS_ROOT_DOMAIN byte changed (v0 -> v1)",
       "golden vectors byte-identical", real, mut)

finish()
