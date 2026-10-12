#!/usr/bin/env python3
"""ART-29 belt: Bulwark F1-split, F2-boot, F3-burst, plus F4 and pin V1–V3.

In-process only. No live route, no test hook. Each fork row runs the
production rule and a mutant that must fail that row.

Chain depth is never a tiebreak.
"""
import inspect
import os
import sqlite3
import sys
import tempfile
from datetime import datetime, timedelta, timezone

os.environ["CYBERNET_DB_DIR"] = tempfile.mkdtemp(prefix="art29-fork-")
os.environ.pop("CYBERNET_OOB_NODE_PINS", None)
os.environ.pop("CYBERNET_GENESIS_NAME_PIN", None)
os.environ.pop("CYBERNET_SECOND_MIRROR", None)
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from fastapi.testclient import TestClient  # noqa: E402
import core  # noqa: E402
core.init_db()
import app as appmod  # noqa: E402
from fed import ed25519 as _ed  # noqa: E402
import name_fork  # noqa: E402
from rotate_name import _rotate_payload  # noqa: E402

client = TestClient(appmod.app)
PASS = FAIL = 0
ISSUED = "2026-10-12T12:00:00+00:00"


def check(label, cond, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok  {label}")
    else:
        FAIL += 1
        print(f"  FAIL {label} {extra}")


def record_mutant(name, real_ok, mutant_fails):
    check(f"MUTANT {name}: real passes and mutant fails the row",
          real_ok and mutant_fails, (real_ok, mutant_fails))


def pub_of(seed_hex):
    return _ed.publickey(bytes.fromhex(seed_hex)).hex()


def cert(name, old_seed, new_pub, issued=ISSUED):
    old_pub = pub_of(old_seed)
    sig = _ed.sign(
        _rotate_payload(name, old_pub, new_pub, issued),
        bytes.fromhex(old_seed), bytes.fromhex(old_pub)).hex()
    return {"name": name, "old_pubkey": old_pub, "new_pubkey": new_pub,
            "issued_at": issued, "signature": sig}


def fresh_conn():
    conn = sqlite3.connect(":memory:")
    conn.executescript(
        """
        CREATE TABLE name_bindings (
            name TEXT PRIMARY KEY,
            node_pubkey TEXT NOT NULL,
            issued_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            signature TEXT NOT NULL
        );
        CREATE TABLE name_rotations (
            name TEXT NOT NULL,
            old_pubkey TEXT NOT NULL,
            new_pubkey TEXT NOT NULL,
            issued_at TEXT NOT NULL,
            signature TEXT NOT NULL,
            accepted_at TEXT NOT NULL,
            PRIMARY KEY (name, old_pubkey, new_pubkey)
        );
        """)
    name_fork.ensure_schema(conn)
    return conn


def split_exchange(conn_b, conn_c, name, cert_x, cert_y):
    name_fork.ingest_rotation_round(conn_b, [cert_x])
    name_fork.ingest_rotation_round(conn_c, [cert_y])
    name_fork.ingest_rotation_round(conn_b, [cert_y])
    name_fork.ingest_rotation_round(conn_c, [cert_x])


def node_clean_winner(conn, name, winner):
    return (not name_fork.is_contested(conn, name)
            and name_fork.current_pin(conn, name) == winner)


# ---------------------------------------------------------------- F1-split
K1 = "11" * 32
KX = "22" * 32
KY = "33" * 32
px = pub_of(KX)
py = pub_of(KY)
cert_x = cert("split", K1, px)
cert_y = cert("split", K1, py)

b = fresh_conn()
c = fresh_conn()
split_exchange(b, c, "split", cert_x, cert_y)
f1_nodes = (
    name_fork.is_contested(b, "split")
    and name_fork.is_contested(c, "split")
    and name_fork.fork_cert_count(b, "split") == 2
    and name_fork.fork_cert_count(c, "split") == 2
    and name_fork.current_pin(b, "split") == px
    and name_fork.current_pin(c, "split") == py)
# The local pin moved on the first cert. Resolve must still refuse it.
with core._db_lock, core._db() as conn:
    name_fork.ingest_rotation_round(conn, [cert("splitserve", K1, px)])
    name_fork.ingest_rotation_round(conn, [cert("splitserve", K1, py)])
    conn.execute(
        "INSERT OR REPLACE INTO name_bindings "
        "(name, node_pubkey, issued_at, expires_at, signature) "
        "VALUES (?,?,?,?,?)",
        ("splitserve", px, ISSUED, "2027-10-01T00:00:00+00:00", "ab" * 64))
r = client.get("/api/v1/names/splitserve")
f1_serve = (r.status_code == 409 and r.json().get("detail") == "name contested"
            and px not in r.text and py not in r.text)
f1_real = f1_nodes and f1_serve
check("F1-split: both nodes hold fork evidence and CONTESTED; resolve refuses",
      f1_real, (f1_nodes, r.status_code, r.text, name_fork.fork_cert_count(b, "split")))

real_second = name_fork.second_cert_contests
name_fork.second_cert_contests = lambda *a, **k: False
try:
    mb = fresh_conn()
    mc = fresh_conn()
    split_exchange(mb, mc, "split", cert_x, cert_y)
    f1_mutant_clean = (node_clean_winner(mb, "split", px)
                       and node_clean_winner(mc, "split", py))
finally:
    name_fork.second_cert_contests = real_second
record_mutant("F1-split", f1_real, f1_mutant_clean)


# ---------------------------------------------------------------- F2-boot
boot_x = cert("boot", K1, px)
boot_y = cert("boot", K1, py)
boot = fresh_conn()
boot_result = name_fork.ingest_rotation_round(boot, [boot_x, boot_y])
f2_real = (
    "boot" in boot_result["contested"]
    and name_fork.is_contested(boot, "boot")
    and name_fork.current_pin(boot, "boot") is None
    and name_fork.fork_cert_count(boot, "boot") == 2
    and boot.execute(
        "SELECT COUNT(*) FROM name_rotations WHERE name='boot'").fetchone()[0] == 0)
check("F2-boot: two certs at seed stay contested, no first-seen winner",
      f2_real, (boot_result, name_fork.current_pin(boot, "boot")))

real_boot = name_fork.bootstrap_picks_first
name_fork.bootstrap_picks_first = lambda: True
try:
    mutant_boot = fresh_conn()
    name_fork.ingest_rotation_round(mutant_boot, [boot_x, boot_y])
    f2_mutant_picks = node_clean_winner(mutant_boot, "boot", px)
finally:
    name_fork.bootstrap_picks_first = real_boot
record_mutant("F2-boot", f2_real, f2_mutant_picks)


# ---------------------------------------------------------------- F3-burst
K2, K3, K4 = "44" * 32, "55" * 32, "66" * 32
p1, p2, p3, p4 = pub_of(K1), pub_of(K2), pub_of(K3), pub_of(K4)
chain = [cert("burst", K1, p2), cert("burst", K2, p3), cert("burst", K3, p4)]


def seed_burst(conn):
    name_fork.pin_initial(conn, "burst", p1)
    conn.execute(
        "INSERT INTO name_bindings (name, node_pubkey, issued_at, expires_at, signature) "
        "VALUES (?,?,?,?,?)",
        ("burst", p1, ISSUED, "2027-10-01T00:00:00+00:00", "cd" * 64))


burst = fresh_conn()
seed_burst(burst)
burst_result = name_fork.ingest_rotation_round(burst, chain)
burst_rows = burst.execute(
    "SELECT COUNT(*) FROM name_rotations WHERE name='burst'").fetchone()[0]
f3_real = (
    burst_result["accepted"].get("burst") == p2
    and name_fork.current_pin(burst, "burst") == p2
    and name_fork.current_pin(burst, "burst") != p4
    and burst_rows == 1
    and "burst" not in burst_result["contested"])
check("F3-burst: one rotation per round; chain depth is not a tiebreak",
      f3_real, (burst_result, name_fork.current_pin(burst, "burst"), burst_rows))

real_limit = name_fork.rotations_per_round
name_fork.rotations_per_round = lambda: 99
try:
    mutant_burst = fresh_conn()
    seed_burst(mutant_burst)
    name_fork.ingest_rotation_round(mutant_burst, chain)
    f3_mutant_walks = name_fork.current_pin(mutant_burst, "burst") == p4
finally:
    name_fork.rotations_per_round = real_limit
record_mutant("F3-burst", f3_real, f3_mutant_walks)


# ---------------------------------------------------------------- F4
overs = [cert("overflow", K1, pub_of(s)) for s in
         ("71" * 32, "72" * 32, "73" * 32, "74" * 32)]
sender = "ab" * 32
before = len(core._hits[f"namefork:{sender}"])
f4 = core.ingest_names_gossip({"rotations": overs, "bindings": []}, sender)
with core._db_lock, core._db() as conn:
    stored = name_fork.fork_cert_count(conn, "overflow")
    extra = name_fork.overflow_count(conn, "overflow")
    contested = name_fork.is_contested(conn, "overflow")
after = len(core._hits[f"namefork:{sender}"])
check("F4: first two fork certs stored, the rest counted",
      stored == 2 and extra == 2 and contested,
      (stored, extra, contested, f4))
# overflow_n is consumed inside ingest_names_gossip (charged, not returned).
check("F4: per-peer namefork bucket grew by the overflow count",
      after == before + extra and extra == 2, (before, after, extra))


# ---------------------------------------------------------------- V1
fresh_key = "99" * 32
verify_calls = []
real_verify = core._name_binding_verify


def counting_verify(*args, **kwargs):
    verify_calls.append(args)
    return real_verify(*args, **kwargs)


core._name_binding_verify = counting_verify
try:
    os.environ["CYBERNET_GENESIS_NAME_PIN"] = "46b62b6c" + "11" * 28
    with core._db_lock, core._db() as conn:
        refused = name_fork.pin_refuses_before_signature(conn, "genesis", fresh_key)
finally:
    core._name_binding_verify = real_verify
src = inspect.getsource(core.resolve_cyberspace)
pin_at = src.index("pin_refuses_before_signature")
verify_at = src.index("_name_binding_verify")
check("V1: pin refuses a fresh genesis key before any signature count",
      refused and verify_calls == [] and pin_at < verify_at,
      (refused, verify_calls, pin_at, verify_at))


# ---------------------------------------------------------------- V2
live_at = src.index("live_pin")
live_verify = src.index("_name_binding_verify", live_at)
check("V2: live-agreement pin match precedes the live signature count",
      live_at < live_verify and "live_pub != live_pin" in src)


# ---------------------------------------------------------------- V3
now = datetime.now(timezone.utc)
claim_issued = now.strftime("%Y-%m-%dT%H:%M:%S+00:00")
claim_expires = (now + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%S+00:00")


def binding_for(name, seed):
    pub = pub_of(seed)
    sig = _ed.sign(
        core._name_claim_payload(name, pub, claim_issued, claim_expires),
        bytes.fromhex(seed), bytes.fromhex(pub)).hex()
    return {"name": name, "node_pubkey": pub, "issued_at": claim_issued,
            "expires_at": claim_expires, "signature": sig}


os.environ.pop("CYBERNET_OOB_NODE_PINS", None)
free = binding_for("v3free", "81" * 32)
dropped = core.ingest_gossiped_binding(free, sender_pub="ab" * 32)
legacy = core.ingest_gossiped_binding(free, sender_pub=None)
with core._db_lock, core._db() as conn:
    name_fork.pin_initial(conn, "v3free", "cc" * 32)
wrong = binding_for("v3free", "82" * 32)
pinned_drop = core.ingest_gossiped_binding(wrong, sender_pub="ab" * 32)
os.environ["CYBERNET_OOB_NODE_PINS"] = "ab" * 32
intro = binding_for("v3oob", "83" * 32)
introduced = core.ingest_gossiped_binding(intro, sender_pub="ab" * 32)
with core._db_lock, core._db() as conn:
    intro_pin = name_fork.current_pin(conn, "v3oob")
later = binding_for("v3oob", "84" * 32)
later_drop = core.ingest_gossiped_binding(later, sender_pub="ab" * 32)
with core._db_lock, core._db() as conn:
    intro_pin_after = name_fork.current_pin(conn, "v3oob")
check("V3: unpinned gossip without an out-of-band sender is refused",
      dropped == "dropped-unpinned", dropped)
check("V3: a direct caller with no sender still merges",
      legacy == "inserted", legacy)
check("V3: a pinned name refuses a key that is not the pin",
      pinned_drop == "dropped-pin", pinned_drop)
check("V3: an out-of-band sender may introduce, and that key sticks",
      introduced == "inserted" and intro_pin == intro["node_pubkey"]
      and later_drop == "dropped-pin" and intro_pin_after == intro_pin,
      (introduced, intro_pin, later_drop, intro_pin_after))


# ---------------------------------------------------------------- honesty
rule_src = open(os.path.join(HERE, "name_fork.py"), encoding="utf-8").read()
resolver = open(os.path.join(HERE, "docs", "RESOLVER.md"), encoding="utf-8").read()
check("fork rule states chain depth is never a tiebreak",
      "Chain depth is never a tiebreak" in name_fork.FORK_RULE
      and "Chain depth is never a tiebreak" in rule_src
      and "Chain depth is never a tiebreak" in resolver)
check("RESOLVER.md: per-node consistency, no mirror agreement, no stolen-key recovery",
      "buys per-node consistency" in resolver
      and "does not buy mirror agreement after a fork" in resolver
      and "does not recover a stolen key" in resolver)

print("---")
print(f"SUMMARY: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
