#!/usr/bin/env python3
"""Pin-rotation v2 belt: the round pause as a FORK GATE, and the round
slot written only on acceptance (ART-42 rows from Examiner, Bulwark,
Cipher and Loom). The round clock is pinned: every ingest passes an
explicit `now` inside one round, never wall time."""
from pinrot_common import *  # noqa: F401,F403
from pinrot_common import _round_k, _ed  # noqa: F401


def slot(conn, name):
    row = conn.execute("SELECT last_round FROM name_rotation_round WHERE name=?",
                       (name,)).fetchone()
    return None if row is None else row[0]


def log_rows(conn, name):
    return conn.execute("SELECT pubkey, seq FROM name_pin_log WHERE name=?"
                        " ORDER BY rowid", (name,)).fetchall()


def snapshot(conn, name):
    return (nf.current_state(conn, name), slot(conn, name), log_rows(conn, name),
            conn.execute("SELECT COUNT(*) FROM name_fork_evidence WHERE name=?",
                         (name,)).fetchone()[0],
            nf.is_contested(conn, name))


# ===================================================== fork gate
print("fork gate: round pause holds a fast chain until fork evidence lands",
      flush=True)


def run_fast_chain():
    """A->B, then B->C in the SAME round, then fork evidence A->B' in the
    same round. Contested; C never resolves and never reaches the log."""
    nm = f"fg{secrets.token_hex(3)}"
    kA, kB, kC = seed(), seed(), seed()
    claim_gate_pin(nm, kA)
    t = next_round()                       # pinned round clock
    with core._db_lock, core._db() as c:
        origin = nf.head_hash(c, nm)
        ab = cert_next(nm, kA, pub(kB), conn=c)
        r1 = ingest([ab], now=t, conn=c)
        bc = cert_next(nm, kB, pub(kC), conn=c)
        r2 = ingest([bc], now=t + 1, conn=c)
        ab2 = nf.mint_cert(nm, kA, pub(seed()), 1, origin, issued_at=ISSUED)
        r3 = ingest([ab2], now=t + 2, conn=c)
        same_round = len({nf.current_round(t + i) for i in range(3)}) == 1
        st = nf.current_state(c, nm)
        logged_c = [p for p, _ in log_rows(c, nm) if p == pub(kC)]
        ok = (same_round and r1["outcomes"] == ["accepted"]
              and nf.is_contested(c, nm)
              and (st is None or st[0] != pub(kC))
              and not logged_c)
        return ok, (r1["outcomes"], r2["outcomes"], r3["outcomes"],
                    nf.is_contested(c, nm), len(logged_c))


real, info = run_fast_chain()
check("fast A->B->C + fork A->B' in one round: contested, C unresolved, C not in "
      "name_pin_log (unmutated control)", real, info)
with patched(nf, "_round_held", lambda conn, name, rnd: False):
    mut, minfo = run_fast_chain()
mutant("round pause: wall-clock check always passes",
       "fast chain + pending fork -> contested, C never logged", real, mut)
print("   mutant run:", minfo, flush=True)

# ===================================================== slot rule
print("slot rule: the round slot is written only on acceptance", flush=True)

REAL_VERIFY = nf._verify
REAL_ACCEPT = nf._accept_hop


def bad_sig(cert):
    c = dict(cert)
    sig = bytearray(bytes.fromhex(c["signature"]))
    sig[40] ^= 0x01                         # S changed, still < L odds aside
    c["signature"] = sig.hex()
    return c


def non_canonical(cert):
    c = dict(cert)
    sig = bytes.fromhex(c["signature"])
    s = int.from_bytes(sig[32:], "little") + _ed._L   # S + L: same scalar mod L
    c["signature"] = (sig[:32] + s.to_bytes(32, "little")).hex()
    return c


def mut_before_verify(conn, t):
    def v(rec, tag):
        nf._note_round(conn, rec["name"], nf.current_round(t))
        return REAL_VERIFY(rec, tag)
    return v


def mut_after_verify(conn, t):
    def v(rec, tag):
        ok = REAL_VERIFY(rec, tag)
        if ok:
            nf._note_round(conn, rec["name"], nf.current_round(t))
        return ok
    return v


def run_bulwark(mutate=None):
    """Junk certs (bad signature, non-canonical S) in round t, then the
    owner's valid A->B in the same round: junk refused, owner accepted."""
    nm = f"sb{secrets.token_hex(3)}"
    kA, kB = seed(), seed()
    claim_gate_pin(nm, kA)
    t = next_round()
    with core._db_lock, core._db() as c:
        junk_src = cert_next(nm, kA, pub(seed()), conn=c)
        good = cert_next(nm, kA, pub(kB), conn=c)
        ctx = patched(nf, "_verify", mutate(c, t)) if mutate else \
            contextlib.nullcontext()
        with ctx:
            rj = ingest([bad_sig(junk_src), non_canonical(junk_src)], now=t, conn=c)
            slot_after_junk = slot(c, nm)
            rg = ingest([good], now=t + 1, conn=c)
        st = nf.current_state(c, nm)
        return (rj["outcomes"] == ["refused-invalid", "refused-invalid"]
                and slot_after_junk is None
                and rg["outcomes"] == ["accepted"] and st[0] == pub(kB)
                and slot(c, nm) == nf.current_round(t)), (rj["outcomes"],
                                                          rg["outcomes"])


def run_cipher_replay(mutate=None):
    """Old genuine cert A->B replayed after A->B->A, in the round where the
    owner's A->C lands: replay refused, slot untouched, owner accepted."""
    nm = f"sr{secrets.token_hex(3)}"
    kA, kB, kC = seed(), seed(), seed()
    claim_gate_pin(nm, kA)
    with core._db_lock, core._db() as c:
        ab = cert_next(nm, kA, pub(kB), conn=c)
        ingest([ab], now=next_round(), conn=c)
        ba = cert_next(nm, kB, pub(kA), conn=c)
        ingest([ba], now=next_round(), conn=c)
        t = next_round()
        slot0 = slot(c, nm)
        ac = cert_next(nm, kA, pub(kC), conn=c)
        ctx = patched(nf, "_verify", mutate(c, t)) if mutate else \
            contextlib.nullcontext()
        with ctx:
            rr = ingest([ab], now=t, conn=c)
            slot_after = slot(c, nm)
            ro = ingest([ac], now=t + 1, conn=c)
        st = nf.current_state(c, nm)
        return (rr["outcomes"] == ["refused-replay"] and slot_after == slot0
                and ro["outcomes"] == ["accepted"] and st[0] == pub(kC)
                and not nf.is_contested(c, nm)), (rr["outcomes"], ro["outcomes"])


def run_cipher_weak(mutate=None):
    """A correctly signed cert to a weak (mixed-order) new_pub in round t,
    then the owner's valid rotation in the same round."""
    nm = f"sw{secrets.token_hex(3)}"
    kA, kB = seed(), seed()
    claim_gate_pin(nm, kA)
    t = next_round()
    with core._db_lock, core._db() as c:
        weak = cert_next(nm, kA, mixed_pub(seed()), conn=c)
        good = cert_next(nm, kA, pub(kB), conn=c)
        ctx = patched(nf, "_verify", mutate(c, t)) if mutate else \
            contextlib.nullcontext()
        with ctx:
            rw = ingest([weak], now=t, conn=c)
            slot_after = slot(c, nm)
            rg = ingest([good], now=t + 1, conn=c)
        st = nf.current_state(c, nm)
        return (rw["outcomes"] == ["refused-invalid"] and slot_after is None
                and rg["outcomes"] == ["accepted"]
                and st[0] == pub(kB)), (rw["outcomes"], rg["outcomes"])


def mut_commit_before_log(conn, rec, rnd):
    """MUTANT: slot and chain committed before the log append."""
    nf._store_fork(conn, rec)
    nf._note_round(conn, rec["name"], rnd)
    conn.commit()
    try:
        nf._append_rotation(conn, rec)
    except sqlite3.Error:
        return False
    return True


def run_loom(accept=None):
    """The name_pin_log insert raises: nothing changes (head, slot, log,
    evidence). A retry in the same round is accepted."""
    nm = f"sl{secrets.token_hex(3)}"
    kA, kB = seed(), seed()
    claim_gate_pin(nm, kA)
    t = next_round()
    with core._db_lock, core._db() as c:
        good = cert_next(nm, kA, pub(kB), conn=c)
        before = snapshot(c, nm)
        c.execute("CREATE TEMP TRIGGER loom_log_fail BEFORE INSERT ON"
                  " name_pin_log BEGIN SELECT RAISE(ABORT, 'loom: log insert"
                  " fails'); END")
        def ctx():
            return patched(nf, "_accept_hop", accept) if accept else \
                contextlib.nullcontext()
        try:
            with ctx():
                r1 = ingest([good], now=t, conn=c)
        finally:
            c.execute("DROP TRIGGER IF EXISTS temp.loom_log_fail")
        after = snapshot(c, nm)
        with ctx():
            r2 = ingest([good], now=t + 1, conn=c)
        st = nf.current_state(c, nm)
        return (r1["accepted"] == {} and after == before
                and r2["outcomes"] == ["accepted"] and st[0] == pub(kB)
                and nf.current_round(t) == nf.current_round(t + 1)), \
            (r1["outcomes"], r2["outcomes"], before == after)


rows = [
    ("Bulwark: junk certs don't consume the slot; owner accepted same round",
     run_bulwark),
    ("Cipher: replay of an old genuine cert doesn't consume the slot",
     run_cipher_replay),
    ("Cipher: weak new_pub cert doesn't consume the slot", run_cipher_weak),
]
results = {}
for label, fn in rows:
    ok, info = fn()
    results[label] = ok
    check(label, ok, info)
ok_loom, info_loom = run_loom()
check("Loom: log insert raises -> nothing changes; same-round retry accepted",
      ok_loom, info_loom)

for mname, mk in (("slot: record the round before verify", mut_before_verify),
                  ("slot: record the slot right after verify", mut_after_verify)):
    killed_by = []
    for label, fn in rows:
        mok, minfo = fn(mk)
        if results[label] and not mok:
            killed_by.append(label)
        print(f"   {mname} vs '{label}': row {'FAILS' if not mok else 'passes'}"
              f" {minfo}", flush=True)
    mutant(mname, " | ".join(killed_by) if killed_by else "(none)",
           all(results.values()), not killed_by)

mok, minfo = run_loom(mut_commit_before_log)
print("   commit-before-log mutant:", minfo, flush=True)
mutant("slot: commit the slot and chain before the log append",
       "Loom: log insert raises -> nothing changes; retry accepted", ok_loom, mok)

check("acceptance is one SAVEPOINT: evidence, chain, log, slot",
      "SAVEPOINT accept_hop" in inspect.getsource(nf._accept_hop)
      and inspect.getsource(nf._accept_hop).index("_append_rotation")
      < inspect.getsource(nf._accept_hop).index("_note_round"))

# ===================================================== verify outside the lock
print("Bulwark: _norm_cert (and verify) runs outside _db_lock", flush=True)


class TrackingLock:
    """Stands in for core._db_lock and counts verify calls made while held."""
    def __init__(self, inner):
        self.inner, self.held = inner, 0

    def __enter__(self):
        self.inner.acquire()
        self.held += 1
        return self

    def __exit__(self, *a):
        self.held -= 1
        self.inner.release()

    def acquire(self, *a, **k):
        r = self.inner.acquire(*a, **k)
        if r:
            self.held += 1
        return r

    def release(self):
        self.held -= 1
        self.inner.release()


def run_lock_row():
    reset_rates()
    nm = f"lk{secrets.token_hex(3)}"
    kA = seed()
    claim_gate_pin(nm, kA)
    certs = [bad_sig(cert_next(nm, kA, pub(seed()))) for _ in range(32)]
    lock = TrackingLock(core._db_lock)
    counts = {"in_lock": 0, "total": 0, "weak_in_lock": 0, "weak_total": 0}
    real_weak = nf._weak

    def w(p):
        counts["weak_total"] += 1
        if lock.held:
            counts["weak_in_lock"] += 1
        return real_weak(p)

    def v(rec, tag):
        counts["total"] += 1
        if lock.held:
            counts["in_lock"] += 1
        return REAL_VERIFY(rec, tag)
    with patched(core, "_db_lock", lock), patched(nf, "_verify", v), \
            patched(nf, "_weak", w):
        out = core.ingest_rotation_certs(certs, pk6, [0])
    return (counts["in_lock"] == 0 and counts["weak_in_lock"] == 0
            and counts["total"] == 32 and counts["weak_total"] == 64
            and out["outcomes"].count("refused-invalid") == 32), counts


real, info = run_lock_row()
check("32 well-shaped bad-signature certs: 0 weak_reason and 0 verify calls "
      "while _db_lock is held (64 + 32 outside)", real, info)
with patched(core, "normalize_rotation_certs", lambda admitted, sender_pub=None: None):
    mut, minfo = run_lock_row()
print("   normalize-inside-lock mutant:", minfo, flush=True)
mutant("normalize inside the lock",
       "32 bad-sig certs: 0 weak_reason and 0 verify calls under _db_lock", real, mut)

with patched(_ed, "SODIUM_ERROR", _ed.SODIUM_MISSING):
    nmx = f"sx{secrets.token_hex(3)}"
    kX = seed()
    claim_gate_pin(nmx, kX)
    rx = ingest([cert_next(nmx, kX, pub(seed()))], now=next_round())
fail_closed = rx["outcomes"] == ["refused-invalid"]
check("libsodium missing: a valid rotation cert fails closed", fail_closed, rx)

# ===================================================== weak pre-check vs libsodium
print("Cipher: weak_reason pre-check before the libsodium verify", flush=True)


def run_mixed_new():
    nm = f"mx{secrets.token_hex(3)}"
    kA = seed()
    claim_gate_pin(nm, kA)
    c = cert_next(nm, kA, mixed_pub(seed()))
    rec = nf._shape(c)
    sig_ok = _ed.checkvalid_sodium(bytes.fromhex(rec["signature"]),
                                   nf.cert_payload(rec["name"], rec["old_pubkey"],
                                                   rec["new_pubkey"], rec["issued_at"],
                                                   rec["seq"], rec["prev_hash"],
                                                   tag=nf.TAG),
                                   bytes.fromhex(rec["old_pubkey"]))
    r = ingest([c], now=next_round())
    return (sig_ok and r["outcomes"] == ["refused-invalid"]
            and head(nm)[0] == pub(kA)), (sig_ok, r["outcomes"])


real, info = run_mixed_new()
check("mixed-order new_pub with a VALID libsodium signature is refused", real, info)
with patched(nf, "_weak", lambda p: None):
    mut, minfo = run_mixed_new()
mutant("drop the weak_reason pre-check",
       "mixed-order new_pub, valid libsodium sig, refused", real, mut)

wc = nf._weak_calls
nf._weak_ok_cache.clear()
good_pub, weak_pub = pub(seed()), mixed_pub(seed())
tok = nf._cur_sender.set("cc" * 32)
try:
    a1 = nf._weak(good_pub); a2 = nf._weak(good_pub)
    b1 = nf._weak(weak_pub); b2 = nf._weak(weak_pub)
finally:
    nf._cur_sender.reset(tok)
per = nf._weak_ok_cache.get("cc" * 32, {})
check("weak cache: pass cached (1 call for 2 checks), refusal never cached "
      "(2 calls for 2 checks), bounded per sender",
      a1 is None and a2 is None and b1 is not None and b2 is not None
      and nf._weak_calls - wc == 3 and good_pub in per and weak_pub not in per
      and len(per) <= nf.WEAK_OK_CACHE_PER_SENDER,
      (nf._weak_calls - wc, len(per)))

# ===================================================== libsodium key check
print("Cipher fast path: is_valid_point vs weak_reason", flush=True)
import window_open  # noqa: E402

_P = 2 ** 255 - 19


def _enc(y, xs=0):
    return (y | (xs << 255)).to_bytes(32, "little")


SMALL = [_enc(1), _enc(_P - 1), _enc(0), _enc(0, 1),
         bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
         bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"),
         bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
         bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85")]
IDENTITY = [_enc(1)]
NONCANON = [_enc(_P), _enc(_P + 1), _enc(2 ** 255 - 1), _enc(_P + 1, 1)]
with open(os.path.join(HERE, "rfc8032_vectors.json")) as _f:
    RFC = [bytes.fromhex(v["pk"])
           for v in json.load(_f)]
HONEST = [bytes.fromhex(pub(seed())) for _ in range(12)]
MIXED = [bytes.fromhex(mixed_pub(seed())) for _ in range(8)]


def with_torsion(t_enc):
    A = _ed._decodepoint_strict(bytes.fromhex(pub(seed())))
    return _ed._encodepoint(_ed._edwards(A, _ed._decodepoint_strict(t_enc)))


# Examiner: separate mixed-order rows, torsion of order 2, 4 and 8.
T2 = _enc(_P - 1)          # (0, -1), order 2
T4 = _enc(0)               # (x, 0), order 4
T8 = bytes.fromhex(ORDER8)
MIXED2 = [with_torsion(T2) for _ in range(3)]
MIXED4 = [with_torsion(T4) for _ in range(3)]
MIXED8 = [with_torsion(T8) for _ in range(3)]
RANDOM = [secrets.token_bytes(32) for _ in range(12)]
CORPUS = {"small-order": SMALL, "identity": IDENTITY, "non-canonical": NONCANON,
          "rfc8032": RFC, "honest": HONEST, "mixed-order": MIXED, "random": RANDOM,
          "mixed order-2": MIXED2, "mixed order-4": MIXED4,
          "mixed order-8": MIXED8}
for _lbl, _ks in (("order-2", MIXED2), ("order-4", MIXED4), ("order-8", MIXED8)):
    check(f"mixed-order row ({_lbl} torsion): is_valid_point refuses, "
          "weak_reason refuses",
          all(not nf._key_check(k.hex()) is None for k in _ks)
          and all(window_open.weak_reason(k.hex()) is not None for k in _ks))


def key_pass(raw):
    return nf._key_check(raw.hex()) is None


dis = [(g, k.hex()) for g, ks in CORPUS.items() for k in ks
       if key_pass(k) != (window_open.weak_reason(k.hex()) is None)]
check(f"equivalence: is_valid_point == weak_reason on {sum(map(len, CORPUS.values()))}"
      " keys, 0 disagreements either way", not dis and len(RFC) == 5, dis)


def mixed_row():
    return (all(not key_pass(k) for k in MIXED + MIXED2 + MIXED4 + MIXED8)
            and all(key_pass(k) for k in HONEST))


real = mixed_row()
check("mixed-order keys refused, honest keys pass (libsodium path)", real)


def no_subgroup(pub_hex):
    raw = bytes.fromhex(pub_hex)
    if not nf._strict_point_ok(raw):
        return "non-canonical"
    return "small" if _ed._is_small_order(_ed._decodepoint_strict(raw)) else None


with patched(nf, "_key_check", no_subgroup):
    mut = mixed_row()
mutant("drop the subgroup test (canonical + small-order only)",
       "mixed-order keys refused", real, mut)


def run_no_nacl():
    """PyNaCl bindings stubbed out: admission refused, weak_reason never
    called."""
    calls = [0]
    real_wr = window_open.weak_reason

    def counting(p):
        calls[0] += 1
        return real_wr(p)
    nm = f"nn{secrets.token_hex(3)}"
    kA = seed()
    claim_gate_pin(nm, kA)
    c = cert_next(nm, kA, pub(seed()))
    nf._weak_ok_cache.clear()
    with patched(_ed, "_sodium_valid_point", None), \
            patched(window_open, "weak_reason", counting):
        r = ingest([c], now=next_round())
    return (r["outcomes"] == ["refused-invalid"] and calls[0] == 0
            and head(nm)[0] == pub(kA)), (r["outcomes"], calls[0])


real, info = run_no_nacl()
check("bindings stubbed: admission refused, weak_reason called 0 times", real, info)
REAL_KEY_CHECK = nf._key_check


def fallback_check(pub_hex):
    r = REAL_KEY_CHECK(pub_hex)
    if r == nf.SODIUM_KEY_MISSING:
        return window_open.weak_reason(pub_hex)
    return r


with patched(nf, "_key_check", fallback_check):
    mut, minfo = run_no_nacl()
print("   fallback mutant:", minfo, flush=True)
mutant("fallback to weak_reason when PyNaCl is missing",
       "bindings stubbed: refused, weak_reason 0 calls", real, mut)


def run_version(ver):
    nm = f"vv{secrets.token_hex(3)}"
    kA = seed()
    claim_gate_pin(nm, kA)
    c = cert_next(nm, kA, pub(seed()))
    nf._weak_ok_cache.clear()
    with patched(_ed, "sodium_version", lambda: ver):
        r = ingest([c], now=next_round())
    return r["outcomes"] == ["refused-invalid"] and head(nm)[0] == pub(kA), r["outcomes"]


print("libsodium version at runtime (explicit binding, no PyNaCl inference):",
      _ed.sodium_version(), flush=True)
assert _ed.sodium_version() is not None, "runtime must read a real sodium_version_string"
real, info = run_version((1, 0, 17))
check("libsodium version stubbed to 1.0.17: admission refused", real, info)
ok18, info18 = run_version((1, 0, 18))
check("libsodium 1.0.18 (control): admission not refused by the gate", not ok18, info18)
# Unreadable version string (Cipher: no inference) also refuses closed.
real_none, info_none = run_version(None)
check("libsodium version unreadable (None): admission refused", real_none, info_none)
with patched(_ed, "sodium_version_ok", lambda: True):
    mut, _ = run_version((1, 0, 17))
mutant("drop the libsodium version gate", "version 1.0.17 -> admission refused",
       real, mut)

finish()
