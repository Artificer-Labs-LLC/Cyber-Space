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

finish()
