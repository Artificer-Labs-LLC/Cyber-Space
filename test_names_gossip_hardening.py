#!/usr/bin/env python3
"""Belt for the /fed/names/gossip hardening layer (ART-29 d9ff58e3, ART-42).

Scratch DB only. Adversarial rows call ingest in-process or the real route
against that DB. No live-route test hook.

Items, each with a belt row and one mutant:
  1. replay seen-set on (sender_pub, envelope sig), kept 2×MAX_SKEW,
     refused before ingest with no row written, memory capped.
  2. per-peer cap on NEW-name inserts per gossip call; over-cap new
     names are dropped-peer-cap; updates of existing names still apply.
"""
import os
import secrets
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone

os.environ["CYBERNET_DB_DIR"] = tempfile.mkdtemp(prefix="names-gossip-hard-")
os.environ.pop("CYBERNET_PEER_ALLOWLIST", None)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient  # noqa: E402

import core  # noqa: E402
import core_serve  # noqa: E402
core.init_db()
import app as appmod  # noqa: E402
import federation  # noqa: E402
from fed import ed25519 as _ed  # noqa: E402
from fed import envelope as _fed_env  # noqa: E402

PASS = FAIL = 0
MUTANTS = []
client = TestClient(appmod.app)


def check(label, cond, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok  {label}")
    else:
        FAIL += 1
        print(f"  FAIL {label} {extra}")


def reset_hits():
    with core._db_lock:
        core._hits.clear()
        core_serve._hits.clear()


def iso(dt):
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


NOW = datetime.now(timezone.utc)
ISSUED = iso(NOW - timedelta(minutes=1))
EXPIRES = iso(NOW + timedelta(days=30))
_next_env_ts = int(time.time()) - 120


def mint(name, priv_hex, issued=ISSUED, expires=EXPIRES):
    pub = _ed.publickey(bytes.fromhex(priv_hex)).hex()
    sig = _ed.sign(core._name_claim_payload(name, pub, issued, expires),
                   bytes.fromhex(priv_hex), bytes.fromhex(pub)).hex()
    return {"name": name, "node_pubkey": pub, "issued_at": issued,
            "expires_at": expires, "signature": sig}


def node_key():
    priv = secrets.token_hex(32)
    pub = _ed.publickey(bytes.fromhex(priv)).hex()
    return priv, pub


def add_peer(pub, retired=""):
    now = core._now()
    with core._db_lock, core._db() as conn:
        conn.execute(
            """INSERT INTO peers (node_pub, name, network, version, genesis,
                                  capabilities, announced_at, first_seen,
                                  retired_at)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (pub, "peer", "cybernet", "0.1.0", 0, "[]", now, now, retired))


def binding_count(name=None):
    with core._db_lock, core._db() as conn:
        if name is None:
            return conn.execute("SELECT COUNT(*) FROM name_bindings").fetchone()[0]
        return conn.execute(
            "SELECT COUNT(*) FROM name_bindings WHERE name=?", (name,)).fetchone()[0]


def binding_row(name):
    with core._db_lock, core._db() as conn:
        row = conn.execute(
            "SELECT node_pubkey, signature FROM name_bindings WHERE name=?",
            (name,)).fetchone()
    return None if row is None else tuple(row)


def gossip_env(sender_priv, sender_pub, bindings, ts=None):
    global _next_env_ts
    if ts is None:
        _next_env_ts += 1
        ts = _next_env_ts
    body = {"from_node_pub": sender_pub, "bindings": bindings}
    return _fed_env.make_envelope(sender_priv, sender_pub, core._NODE_PUB, body, ts=ts)


def post(env):
    return client.post("/fed/names/gossip", json=env)


def detail(resp):
    try:
        return resp.json().get("detail")
    except Exception:
        return resp.text


def record_mutant(name, row, real_ok, mutant_fails):
    MUTANTS.append((name, row, real_ok, mutant_fails))
    check(f"MUTANT {name}: real holds and the skip lets the row through",
          real_ok and mutant_fails, (real_ok, mutant_fails, row))


# ---------------------------------------------------------------- replay
print("replay:")
federation._gossip_seen.clear()
reset_hits()
sender_priv, sender_pub = node_key()
add_peer(sender_pub)

fresh = mint("replayname", secrets.token_hex(32))
env = gossip_env(sender_priv, sender_pub, [fresh])
r = post(env)
check("first delivery inserts",
      r.status_code == 200 and r.json().get("outcomes") == ["inserted"]
      and binding_row("replayname") == (fresh["node_pubkey"], fresh["signature"]),
      (r.status_code, r.text[:300]))
before = binding_row("replayname")
n_before = binding_count()
r = post(env)
check("byte-identical replay -> 400 replay",
      r.status_code == 400 and detail(r) == "replay", (r.status_code, detail(r)))
check("replay writes no row and does not change the stored binding",
      binding_count() == n_before and binding_row("replayname") == before,
      (binding_count(), binding_row("replayname"), before))

again = gossip_env(sender_priv, sender_pub, [fresh])
r = post(again)
check("same binding, new envelope sig -> kept, not replay",
      r.status_code == 200 and r.json().get("outcomes") == ["kept"]
      and binding_row("replayname") == before,
      (r.status_code, r.text[:300]))

# A seen envelope that never ingested still writes nothing.
absent = mint("replayabsent", secrets.token_hex(32))
absent_env = gossip_env(sender_priv, sender_pub, [absent])
federation._gossip_mark_seen(sender_pub, absent_env["sig"])
n_before = binding_count()
r = post(absent_env)
check("pre-seen envelope refused before ingest, name stays absent",
      r.status_code == 400 and detail(r) == "replay"
      and binding_count() == n_before and binding_row("replayabsent") is None,
      (r.status_code, detail(r), binding_count()))

# Horizon is 2×MAX_SKEW, keyed on (sender, sig), and the map is capped.
print("seen-set:")
federation._gossip_seen.clear()
horizon = federation._GOSSIP_SEEN_HORIZON_SEC
check("horizon is 2× MAX_SKEW",
      horizon == 2 * _fed_env.MAX_SKEW_SEC and horizon == 600, horizon)
t0 = 1_700_000_000.0
sig_a = "ab" * 64
sig_b = "cd" * 64
other = "11" * 32
check("first sight is not a replay",
      federation._gossip_is_replay(sender_pub, sig_a, t0) is False)
federation._gossip_mark_seen(sender_pub, sig_a, t0)
check("same pair inside the horizon is a replay",
      federation._gossip_is_replay(sender_pub, sig_a, t0 + horizon) is True)
check("same sig from another sender is not a replay",
      federation._gossip_is_replay(other, sig_a, t0 + 1) is False)
check("same sender, other sig is not a replay",
      federation._gossip_is_replay(sender_pub, sig_b, t0 + 1) is False)
check("just past 2× MAX_SKEW the pair is forgotten",
      federation._gossip_is_replay(sender_pub, sig_a, t0 + horizon + 1) is False)

federation._gossip_seen.clear()
cap = federation._GOSSIP_SEEN_CAP
for i in range(cap + 25):
    federation._gossip_mark_seen(sender_pub, f"{i:0128x}"[-128:], t0)
check("seen-set stays within its cap",
      len(federation._gossip_seen) <= cap, len(federation._gossip_seen))
check("oldest pair is evicted once the cap is exceeded",
      federation._gossip_is_replay(sender_pub, f"{0:0128x}"[-128:], t0) is False)
newest = f"{cap + 24:0128x}"[-128:]
check("newest pair is still retained",
      federation._gossip_is_replay(sender_pub, newest, t0) is True)

# Future-edge envelope: still inside skew at exactly 2×MAX_SKEW, so the
# seen-set (not the skew check) is what refuses the replay.
print("route horizon:")
federation._gossip_seen.clear()
reset_hits()
edge_binding = mint("replayedge", secrets.token_hex(32))
edge_ts = int(time.time()) + _fed_env.MAX_SKEW_SEC
edge_env = gossip_env(sender_priv, sender_pub, [edge_binding], ts=edge_ts)
r = post(edge_env)
check("future-edge envelope inserts",
      r.status_code == 200 and binding_row("replayedge") is not None,
      (r.status_code, r.text[:200]))
# Observe the second post at exactly ts + MAX_SKEW. Skew still accepts
# (the reject is `>`, not `>=`), and that instant is exactly one horizon
# after a sight recorded at ts - MAX_SKEW, so the seen-set — not skew —
# is what refuses it. Wall clock is frozen so prune cannot slip past the
# boundary between the rewind and the check.
frozen_now = float(edge_ts + _fed_env.MAX_SKEW_SEC)
seen_key = federation._gossip_seen_key(sender_pub, edge_env["sig"])
federation._gossip_seen[seen_key] = frozen_now - horizon
n_before = binding_count()
real_time = time.time
time.time = lambda: frozen_now
try:
    r = post(edge_env)
finally:
    time.time = real_time
check("replay at exactly 2× MAX_SKEW is still refused, no new row",
      r.status_code == 400 and detail(r) == "replay"
      and binding_count() == n_before,
      (r.status_code, detail(r)))

# ---------------------------------------------------------------- mutant
print("mutant:")
federation._gossip_seen.clear()
reset_hits()
mut_binding = mint("replaymut", secrets.token_hex(32))
mut_env = gossip_env(sender_priv, sender_pub, [mut_binding])
federation._gossip_mark_seen(sender_pub, mut_env["sig"])
real = post(mut_env)
real_ok = (real.status_code == 400 and detail(real) == "replay"
           and binding_row("replaymut") is None)
real_is_replay = federation._gossip_is_replay
federation._gossip_is_replay = lambda *a, **k: False
try:
    mutant = post(mut_env)
    mutant_fails = (mutant.status_code == 200
                    and binding_row("replaymut") is not None
                    and binding_row("replaymut")[0] == mut_binding["node_pubkey"])
finally:
    federation._gossip_is_replay = real_is_replay
record_mutant("replay seen-set skipped",
              "pre-seen envelope writes no name_bindings row",
              real_ok, mutant_fails)
# The mutant inserted the row. A further identical post, with the check
# restored, must refuse and leave that one row in place.
n_after = binding_count("replaymut")
r = post(mut_env)
check("replay check restored: identical envelope refused, row count unchanged",
      r.status_code == 400 and detail(r) == "replay"
      and binding_count("replaymut") == n_after,
      (r.status_code, detail(r), binding_count("replaymut"), n_after))

# ------------------------------------------------------- per-peer new cap
print("peer new-name cap:")
federation._gossip_seen.clear()
reset_hits()
cap = federation.NAMES_GOSSIP_NEW_CAP
check("new-name cap is below the binding cap and the registry cap",
      0 < cap < federation.NAMES_GOSSIP_RECV_CAP < 1024, cap)

seed_priv = secrets.token_hex(32)
seed_issued = iso(NOW - timedelta(minutes=30))
seed = mint("capupdate", seed_priv, issued=seed_issued)
check("seed existing name in-process",
      core.ingest_gossiped_binding(seed) == "inserted"
      and binding_row("capupdate") == (seed["node_pubkey"], seed["signature"]))

# Ingest itself: allow_new False drops an absent name after verification
# and does not touch an existing one.
absent = mint("capabsent", secrets.token_hex(32))
n_before = binding_count()
check("allow_new False on an absent name -> dropped-peer-cap, no row",
      core.ingest_gossiped_binding(absent, allow_new=False) == "dropped-peer-cap"
      and binding_row("capabsent") is None and binding_count() == n_before)
bad = dict(absent)
bad["signature"] = ("0" if bad["signature"][0] != "0" else "1") + bad["signature"][1:]
check("allow_new False still verifies: tampered sig is dropped-unverifiable",
      core.ingest_gossiped_binding(bad, allow_new=False) == "dropped-unverifiable"
      and binding_row("capabsent") is None)
renew = mint("capupdate", seed_priv, issued=ISSUED)
check("allow_new False still replaces an existing same-key renewal",
      core.ingest_gossiped_binding(renew, allow_new=False) == "replaced"
      and binding_row("capupdate") == (renew["node_pubkey"], renew["signature"]))

fresh = [mint(f"capnew{i}", secrets.token_hex(32)) for i in range(cap)]
extra = mint("capextra", secrets.token_hex(32))
bad_new = mint("capbad", secrets.token_hex(32))
bad_new["signature"] = (
    "0" if bad_new["signature"][0] != "0" else "1") + bad_new["signature"][1:]
# Later than the renewal above (ISSUED is now-1min); still inside 24h.
later = iso(NOW - timedelta(seconds=30))
update = mint("capupdate", seed_priv, issued=later)
batch = fresh + [extra, update, bad_new]
r = post(gossip_env(sender_priv, sender_pub, batch))
outcomes = r.json().get("outcomes") if r.status_code == 200 else None
want = (["inserted"] * cap) + ["dropped-peer-cap", "replaced", "dropped-unverifiable"]
check("over-cap new name dropped, update replaced, bad sig still unverifiable",
      r.status_code == 200 and outcomes == want,
      (r.status_code, outcomes, want))
check("the dropped new name has no row; the update landed",
      binding_row("capextra") is None
      and binding_row("capbad") is None
      and binding_row("capupdate") == (update["node_pubkey"], update["signature"])
      and all(binding_row(b["name"]) is not None for b in fresh))
check("inserted count matches the cap and dropped counts the two refusals",
      r.status_code == 200 and r.json().get("inserted") == cap
      and r.json().get("replaced") == 1 and r.json().get("dropped") == 2,
      r.text[:400])

# ---------------------------------------------------------------- mutant
print("mutant new-name cap:")
federation._gossip_seen.clear()
reset_hits()
real_allow = federation._allow_new_name
mut_fresh = [mint(f"mutnew{i}", secrets.token_hex(32)) for i in range(cap)]
mut_extra = mint("mutextra", secrets.token_hex(32))
federation._allow_new_name = lambda inserted_so_far: True
try:
    mutant = post(gossip_env(sender_priv, sender_pub, mut_fresh + [mut_extra]))
    mutant_outcomes = mutant.json().get("outcomes") if mutant.status_code == 200 else None
    mutant_fails = (mutant_outcomes == ["inserted"] * (cap + 1)
                    and binding_row("mutextra") is not None)
finally:
    federation._allow_new_name = real_allow
# Real gate, a different over-cap batch: the extra name stays absent.
real_fresh = [mint(f"realnew{i}", secrets.token_hex(32)) for i in range(cap)]
real_extra = mint("realextra", secrets.token_hex(32))
real = post(gossip_env(sender_priv, sender_pub, real_fresh + [real_extra]))
real_outcomes = real.json().get("outcomes") if real.status_code == 200 else None
real_ok = (real_outcomes == ["inserted"] * cap + ["dropped-peer-cap"]
           and binding_row("realextra") is None)
record_mutant("per-peer new-name cap skipped",
              "one extra new name past the cap is not inserted",
              real_ok, mutant_fails)

print("mutant results:")
for name, row, real_ok, mutant_fails in MUTANTS:
    print(f"  {name}: row={row!r} real_holds={real_ok} mutant_lets_it_through={mutant_fails}")

print(f"--- {PASS} passed, {FAIL} failed ---")
if FAIL:
    sys.exit(1)
