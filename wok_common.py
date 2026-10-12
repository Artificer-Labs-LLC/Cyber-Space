"""Shared harness for the split window-open witness-kinds belts.

Not a test file. Each test_wok_*.py imports this first, so each file gets
its own scratch DB (CYBERNET_DB_DIR is set before core is imported) and
runs in its own process under run_tests.sh. The split is by mutant group:
every mutant is killed inside the one file that holds its row.
"""
import json
import os
import sys
import tempfile
import time

os.environ["CYBERNET_DB_DIR"] = tempfile.mkdtemp(prefix="wok-")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import core  # noqa: E402
core.init_db()
import legacy_witness as lw  # noqa: E402
import window_open as wo  # noqa: E402
from fed import ed25519 as _ed  # noqa: E402

PAST = "2000-01-01T00:00:00+00:00"
FUT = "2099-01-01T00:00:00+00:00"
ZERO = "00" * 32
SIG = "00" * 64
KINDS_IN = ("reserve-hold", "name-refused", "origin-pin", "origin-handoff")

import hop_certs  # noqa: E402
import nacl.signing  # noqa: E402

SEEDS = {}


def keypair(seed: bytes) -> str:
    pub = nacl.signing.SigningKey(seed).verify_key.encode().hex()
    SEEDS[pub] = seed
    return pub


def sign_with(pub: str, msg: bytes) -> str:
    """Real Ed25519 (libsodium) signature by a test key; zeros for keys the
    belt holds no seed for (weak keys cannot sign)."""
    seed = SEEDS.get(pub.strip().lower())
    if seed is None:
        return SIG
    return nacl.signing.SigningKey(seed).sign(msg).signature.hex()


K = keypair(bytes.fromhex("71" * 32))
X = keypair(bytes.fromhex("72" * 32))
PLAIN = keypair(bytes.fromhex("73" * 32))
K_UP = K.upper()

_state = {"pass": 0, "fail": 0, "mutants": [], "t0": time.monotonic()}


def check(label, cond, extra=""):
    if cond:
        _state["pass"] += 1
        print(f"  ok  {label}")
    else:
        _state["fail"] += 1
        print(f"  FAIL {label} {extra}")


def record_mutant(name, row, real_ok, mutant_fails):
    _state["mutants"].append((name, row, real_ok, mutant_fails))
    check(f"MUTANT {name}: real passes and mutant fails the row",
          real_ok and mutant_fails, (real_ok, mutant_fails))


def finish(file_label):
    print("mutant table:")
    print("  mutant | row | real passes | mutant fails | killed")
    for name, row, real_ok, mutant_fails in _state["mutants"]:
        print(f"  {name} | {row} | {bool(real_ok)} | {bool(mutant_fails)} | "
              f"{'KILLED' if real_ok and mutant_fails else 'NOT KILLED'}")
    el = time.monotonic() - _state["t0"]
    print(f"{file_label}: {_state['pass']} passed, {_state['fail']} failed in {el:.1f}s")
    sys.exit(1 if _state["fail"] else 0)


def wipe():
    with core._db_lock, core._db() as conn:
        wo.init_schema(conn)
        for table in ("window_open_log", "window_refused_bindings", "window_kind_source",
                      "window_hop_rows", "window_bound_leaves", "legacy_migration_log", "legacy_log_meta",
                      "name_bindings", "name_rotations", "window_close_log", "legacy_migrations"):
            conn.execute(f"DELETE FROM {table}")


def bind(conn, name, pub, exp=PAST):
    conn.execute(
        "INSERT INTO name_bindings (name,node_pubkey,issued_at,expires_at,signature) "
        "VALUES (?,?,?,?,?)",
        (name, pub, PAST, exp, SIG))


def rot(conn, name, old, new, at=PAST):
    """One stored v1 rotation cert, signed by the old key when the belt
    holds its seed."""
    sig = sign_with(old, hop_certs.v1_payload(name, old, new, PAST))
    conn.execute(
        "INSERT INTO name_rotations "
        "(name,old_pubkey,new_pubkey,issued_at,signature,accepted_at) VALUES (?,?,?,?,?,?)",
        (name, old, new, PAST, sig, at))


def reap():
    with core._db_lock, core._db() as conn:
        core._name_registry_has_room(conn)


def counts():
    with core._db_lock, core._db() as conn:
        wo.init_schema(conn)
        return {
            "window": conn.execute("SELECT COUNT(*) FROM window_open_log").fetchone()[0],
            "log": conn.execute("SELECT COUNT(*) FROM legacy_migration_log").fetchone()[0],
            "kinds": conn.execute("SELECT COUNT(*) FROM window_kind_source").fetchone()[0],
        }


def exported():
    """Node B's input: the log bytes, round-tripped, with no database."""
    with core._db_lock, core._db() as conn:
        log_id, entries = wo.export_log(conn)
    return log_id, json.loads(json.dumps(entries))


def exported_hops():
    with core._db_lock, core._db() as conn:
        return json.loads(json.dumps(wo.export_hop_rows(conn)))


def rebuilt():
    log_id, entries = exported()
    ok, why = lw.verify_chain(entries, log_id)
    return log_id, entries, ok, why, lw.rebuild_window_kinds(entries)


def open_or(by="kinds"):
    try:
        return wo.open_window(by), None
    except wo.WindowRefused as e:
        return None, str(e)


def for_name(view, kind, name):
    return [r for r in view[kind] if r.get("name") == name]


# A pool of real prime-order keys, so every clean hop is genuinely clean.
POOL = [keypair(bytes([0x10 + (i % 200)]) * 31 + bytes([i])) for i in range(90)]
assert all(not wo.is_weak_pubkey(k) for k in POOL)


def clean_chain(conn, name, n, base=0, minute0=0):
    """n clean hops POOL[base] -> POOL[base+1] -> ... ; returns the last key."""
    for h in range(n):
        rot(conn, name, POOL[base + h], POOL[base + h + 1],
            f"2001-01-01T{(minute0 + h) // 60:02d}:{(minute0 + h) % 60:02d}:00+00:00")
    return POOL[base + n]


class fast_sign:
    """Context: replace ed25519 signing with a constant stub. Only for
    mutant runs whose row reads dispositions, never signatures (the pure
    Python signer costs ~0.18 s per call and the global-overflow mutant
    writes ~1000 entries)."""

    def __enter__(self):
        self.real = _ed.sign
        _ed.sign = lambda msg, sk, pk: b"\0" * 64
        return self

    def __exit__(self, *exc):
        _ed.sign = self.real
        return False


# ---------------------------------------------------------------- node B proofs
class _Clock:
    def __init__(self, t):
        self.t = t

    def time(self):
        return self.t


IMP_NAME = "imp"
IMP_ACCOUNT = "imp-acct"
IMP_K0 = _ed.publickey(bytes.fromhex("74" * 32)).hex()
B_WSET = None


def finish_window(fillers=0):
    """After open_window: append the edges and one import path for IMP_NAME
    (window-open, hold, migrate-pending, window-close 30 days on, cutover),
    on a stubbed log clock. `fillers` extra holds pad the log length."""
    real_time = wo.time
    clk = _Clock(int(time.time()))
    wo.time = clk
    try:
        with core._db_lock, core._db() as conn:
            for i in range(fillers):
                wo.append_log_entry(conn, kind="hold", account=f"fill-{i}", name=f"fill{i:03d}",
                                    detail={"name": f"fill{i:03d}"})
            wo.append_log_entry(conn, kind="window-open")
            wo.append_log_entry(conn, kind="hold", account=IMP_ACCOUNT, name=IMP_NAME,
                                detail={"name": IMP_NAME})
            wo.append_log_entry(conn, kind="migrate-pending", account=IMP_ACCOUNT,
                                migration_id=1, k0_pub=IMP_K0, detail={"account": IMP_ACCOUNT})
            clk.t += lw.WINDOW_SEC
            close = wo.append_log_entry(conn, kind="window-close")
            wo.append_log_entry(conn, kind="cutover", account=IMP_ACCOUNT, migration_id=1,
                                k0_pub=IMP_K0, detail={"window_close_seq": close["seq"]})
    finally:
        wo.time = real_time


# Villhaze ART-42 64157549: the head needs a strict majority of the
# legacy-log signer set, and the Genesis node key never counts. Belt set:
# three witness keys (the node key not listed); heads carry two of three.
WITNESS_PUBS = [keypair(bytes([0xA0 + j]) * 32) for j in range(3)]
WITNESS_SET = lw.WitnessSet(1, WITNESS_PUBS)


def witness_signer(pub):
    def sign(msg, _pub=pub):
        return _pub, sign_with(_pub, msg)
    return sign


WITNESS_SIGNERS = [witness_signer(p) for p in WITNESS_PUBS[:2]]


def b_proof():
    """(proof, wset, log_id) exactly as node B receives it: signed head,
    full span, hop rows. Round-tripped through JSON."""
    log_id, entries = exported()
    with core._db_lock, core._db() as conn:
        roots = wo.head_roots(conn)
        leaves = wo.export_bound_leaves(conn)
        orphans = wo.export_orphan_leaves(conn)
    wset = WITNESS_SET
    kinds = [e["kind"] for e in entries]
    head = {"log_id": log_id, "witness_set": wset.id, "seq": len(entries),
            "head_hash": entries[-1]["entry_hash"],
            "window_open_seq": kinds.index("window-open") + 1,
            "window_close_seq": kinds.index("window-close") + 1, "window_state": "closed",
            **roots}

    proof = {"head": lw.sign_head(head, WITNESS_SIGNERS), "span": [lw.full(e) for e in entries],
             "hops": exported_hops(), "bound": leaves, "orphans": orphans}
    return json.loads(json.dumps(proof)), wset, log_id


def b_accepts(proof, wset, log_id, pins=None, orphans=0, held_names=None):
    """(accepted, ident-or-reason) through node B's real _rules. Default
    pins: one account, bindings = the shipped leaf count, orphans 0.
    held_names: names B holds witnessed state for (ART-42 35e546b9)."""
    if pins is None:
        pins = (1, len(proof.get("bound", [])), orphans)
    try:
        return True, lw._rules(proof, IMP_NAME, wset, log_id, pins,
                               held_names=held_names)[2]
    except lw.WitnessRefused as e:
        return False, str(e)


class Probe:
    """Counts entry/row hashing and hop counting while active."""
    NAMES = (("lw", "entry_hash"), ("lw", "rows_root"), ("lw", "hop_row_hash"),
             ("wo", "counted_hops"))

    def __enter__(self):
        self.n = {"hashed": 0, "counted": 0}
        self.saved = []
        for mod_name, attr in self.NAMES:
            mod = lw if mod_name == "lw" else wo
            real = getattr(mod, attr)
            key = "counted" if attr == "counted_hops" else "hashed"

            def spy(*a, _real=real, _key=key, **k):
                self.n[_key] += 1
                return _real(*a, **k)
            self.saved.append((mod, attr, real))
            setattr(mod, attr, spy)
        return self

    def __exit__(self, *exc):
        for mod, attr, real in self.saved:
            setattr(mod, attr, real)
        return False
