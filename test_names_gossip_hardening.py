#!/usr/bin/env python3
"""Belt for the /fed/names/gossip hardening layer (ART-29 d9ff58e3, ART-42).

Scratch DB only. Adversarial rows call ingest in-process or the real route
against that DB. No live-route test hook.

Items, each with a belt row and one mutant:
  1. replay seen-set on (sender_pub, envelope sig), kept 2×MAX_SKEW,
     refused before ingest with no row written, memory capped.
  2. per-peer cap on NEW-name inserts per gossip call; over-cap new
     names are dropped-peer-cap; updates of existing names still apply.
  3. route check order: size, per-source bucket, envelope verify,
     known-peer and allowlist, binding-count 400, replay, per-peer
     bucket, ingest. More than 128 bindings is 400, not a truncation.
  4. ingest uses strict checkvalid and weak_reason. The zero key and a
     small-order key are dropped on an empty DB, with no row written.
"""
import json
import os
import secrets
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone

os.environ["CYBERNET_DB_DIR"] = tempfile.mkdtemp(prefix="names-gossip-hard-")
os.environ.pop("CYBERNET_PEER_ALLOWLIST", None)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi import HTTPException  # noqa: E402
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


def hits(bucket):
    with core._db_lock:
        q = core._hits.get(bucket)
        return 0 if not q else len(q)


def call_direct(env, request=None):
    try:
        out = federation.fed_names_gossip(env, request)
        return 200, out
    except HTTPException as exc:
        return exc.status_code, exc.detail


def flip_hex(h):
    return ("0" if h[0] != "0" else "1") + h[1:]


class _LenReq:
    """Enough of a Request for the size cap and request_source."""

    def __init__(self, n):
        self.headers = {"content-length": str(n)}
        self.client = None


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

# --------------------------------------------------------- check order
print("check order:")
federation._gossip_seen.clear()
reset_hits()
saved_limit = federation.FED_SOURCE_LIMIT
peer_bucket = f"fednamesgossip:{sender_pub}"

federation.FED_SOURCE_LIMIT = 1
try:
    huge = {"pad": "x" * (federation.NAMES_GOSSIP_BODY_CAP + 1)}
    status, why = call_direct(huge)
    one = mint("sizecheck", secrets.token_hex(32))
    env128 = gossip_env(sender_priv, sender_pub, [one] * 128)
    wire = len(json.dumps(env128).encode("utf-8"))
    check("a 128-binding envelope is under the size cap",
          wire < federation.NAMES_GOSSIP_BODY_CAP, wire)
    nxt, out = call_direct(env128)
    check("oversize -> 413 and does not spend the per-source token",
          status == 413 and why == "Request body too large"
          and nxt == 200 and out.get("outcomes", [None])[0] == "inserted",
          (status, why, nxt, out if isinstance(out, str) else out.get("outcomes", [])[:2]))
finally:
    federation.FED_SOURCE_LIMIT = saved_limit

reset_hits()
federation._gossip_seen.clear()
federation.FED_SOURCE_LIMIT = 1
try:
    status, why = call_direct({"v": "tiny-but-claimed-huge"},
                              _LenReq(federation.NAMES_GOSSIP_BODY_CAP + 10))
    follow = mint("clenfollow", secrets.token_hex(32))
    nxt, out = call_direct(gossip_env(sender_priv, sender_pub, [follow]),
                           _LenReq(100))
    check("lying Content-Length -> 413 before the source bucket",
          status == 413 and why == "Request body too large"
          and nxt == 200 and isinstance(out, dict)
          and out.get("outcomes") == ["inserted"],
          (status, why, nxt, out if isinstance(out, str) else str(out)[:200]))
finally:
    federation.FED_SOURCE_LIMIT = saved_limit

reset_hits()
federation._gossip_seen.clear()
federation.FED_SOURCE_LIMIT = 1
try:
    spent = mint("sourcespent", secrets.token_hex(32))
    ok_status, _ok = call_direct(gossip_env(sender_priv, sender_pub, [spent]))
    bad_status, bad_why = call_direct({"v": "not-an-envelope"})
    check("source bucket exhausted -> 429 even for an invalid envelope",
          ok_status == 200 and bad_status == 429 and bad_status != 400,
          (ok_status, bad_status, bad_why))
finally:
    federation.FED_SOURCE_LIMIT = saved_limit

reset_hits()
federation._gossip_seen.clear()
stranger_priv, stranger_pub = node_key()
bad_env = gossip_env(stranger_priv, stranger_pub,
                     [mint("strangername", secrets.token_hex(32))])
bad_env["sig"] = flip_hex(bad_env["sig"])
r = post(bad_env)
check("bad signature from an unknown sender -> 400, not 404",
      r.status_code == 400 and detail(r) == "invalid envelope",
      (r.status_code, detail(r)))

os.environ["CYBERNET_PEER_ALLOWLIST"] = sender_pub
try:
    unk = gossip_env(stranger_priv, stranger_pub,
                     [mint("unkallow", secrets.token_hex(32))])
    r = post(unk)
    check("unknown sender with the allowlist set -> 404, not 403",
          r.status_code == 404 and detail(r) == "unknown peer",
          (r.status_code, detail(r)))
finally:
    os.environ.pop("CYBERNET_PEER_ALLOWLIST", None)

reset_hits()
federation._gossip_seen.clear()
os.environ["CYBERNET_PEER_ALLOWLIST"] = "ab" * 32
held = mint("allowheld", secrets.token_hex(32))
held_env = gossip_env(sender_priv, sender_pub, [held])
try:
    r = post(held_env)
    refused = (r.status_code == 403
               and "allowlist" in (detail(r) or ""))
    untouched = hits(peer_bucket) == 0 and binding_row("allowheld") is None
finally:
    os.environ.pop("CYBERNET_PEER_ALLOWLIST", None)
r2 = post(held_env)
check("unlisted peer -> 403 without spending the per-peer bucket or the seen-set",
      refused and untouched and r2.status_code == 200
      and r2.json().get("outcomes") == ["inserted"],
      (r.status_code, detail(r), hits(peer_bucket), r2.status_code, r2.text[:200]))

reset_hits()
federation._gossip_seen.clear()
filler = mint("orderfill", secrets.token_hex(32))
codes = [post(gossip_env(sender_priv, sender_pub, [filler])).status_code
         for _ in range(core.RATE_LIMIT)]
blocked = mint("orderblocked", secrets.token_hex(32))
r = post(gossip_env(sender_priv, sender_pub, [blocked]))
check("per-peer bucket exhausted -> 429 and the new name is not written",
      codes == [200] * core.RATE_LIMIT and r.status_code == 429
      and binding_row("orderblocked") is None,
      (codes[:3], codes[-1:], r.status_code, detail(r)))

# The per-peer bucket is still exhausted. The binding-count gate is
# earlier, so 129 bindings are 400 rather than 429, and nothing is written.
many = [mint(f"over{i:03d}", secrets.token_hex(32))
        for i in range(federation.NAMES_GOSSIP_RECV_CAP + 1)]
r = post(gossip_env(sender_priv, sender_pub, many))
none_written = (binding_row(many[0]["name"]) is None
                and binding_row(many[-1]["name"]) is None)
over_real_ok = (r.status_code == 400
                and detail(r) == f"bindings exceed {federation.NAMES_GOSSIP_RECV_CAP}"
                and none_written)
check(">128 bindings -> 400 before the per-peer bucket, no row written",
      over_real_ok, (r.status_code, detail(r), none_written))

reset_hits()
exact = mint("exact128", secrets.token_hex(32))
r = post(gossip_env(sender_priv, sender_pub, [exact] * federation.NAMES_GOSSIP_RECV_CAP))
check("exactly 128 bindings -> 200",
      r.status_code == 200 and r.json().get("outcomes", [None])[0] == "inserted"
      and len(r.json().get("outcomes", [])) == 128
      and binding_row("exact128") is not None,
      (r.status_code, r.text[:200]))

print("mutant binding cap:")
federation._gossip_seen.clear()
reset_hits()
real_too_many = federation._too_many_bindings
mut_names = [mint(f"mutover{i:03d}", secrets.token_hex(32))
             for i in range(federation.NAMES_GOSSIP_RECV_CAP + 1)]
federation._too_many_bindings = lambda count: False
try:
    mutant = post(gossip_env(sender_priv, sender_pub, mut_names))
    mutant_fails = (mutant.status_code == 200
                    and binding_row(mut_names[0]["name"]) is not None)
finally:
    federation._too_many_bindings = real_too_many
record_mutant("binding-count gate skipped",
              "129 bindings are refused before any row is written",
              over_real_ok, mutant_fails)

# -------------------------------------------- zero and small-order keys
print("weak keys on an empty node:")
# Throwaway empty DB. Adversarial rows call ingest in-process; they do
# not ride the HTTP route.
_saved_db = (core.DB_PATH, core_serve.DB_PATH)
_empty_path = os.path.join(tempfile.mkdtemp(prefix="names-gossip-empty-"),
                           "cybernet.db")
core.DB_PATH = _empty_path
core_serve.DB_PATH = _empty_path
core.init_db()

ZERO_KEY = "00" * 32
# Identity, the first canonical small-order encoding (8*P == identity).
IDENTITY_KEY = "01" + ("00" * 31)
ZERO_SIG = "00" * 64


def raw_binding(name, pub, sig=ZERO_SIG):
    return {"name": name, "node_pubkey": pub, "issued_at": ISSUED,
            "expires_at": EXPIRES, "signature": sig}


def empty_count():
    with core._db_lock, core._db() as conn:
        return conn.execute("SELECT COUNT(*) FROM name_bindings").fetchone()[0]


import window_open  # noqa: E402

check("empty node starts with no name bindings", empty_count() == 0, empty_count())
for label, pub in (("zero key", ZERO_KEY), ("identity small-order key", IDENTITY_KEY)):
    check(f"premise: {label} fails strict checkvalid",
          _ed.checkvalid(bytes.fromhex(ZERO_SIG),
                         core._name_claim_payload(label.replace(" ", ""), pub, ISSUED, EXPIRES),
                         bytes.fromhex(pub)) is False)
    check(f"premise: {label} is small-order under weak_reason",
          window_open.weak_reason(pub) == "small-order")

zero_b = raw_binding("zerokey", ZERO_KEY)
ident_b = raw_binding("identkey", IDENTITY_KEY)
zero_out = core.ingest_gossiped_binding(zero_b)
ident_out = core.ingest_gossiped_binding(ident_b)
dropped = {"dropped-unverifiable", "dropped-weak"}
check("zero key dropped on an empty node, no row",
      zero_out in dropped and binding_row("zerokey") is None
      and empty_count() == 0,
      (zero_out, empty_count()))
check("small-order identity key dropped on an empty node, no row",
      ident_out in dropped and binding_row("identkey") is None
      and empty_count() == 0,
      (ident_out, empty_count()))

print("mutant both key gates:")
real_verify = core._name_binding_verify
real_weak = core._gossip_claim_weak
mut_b = raw_binding("mutzero", ZERO_KEY)
core._name_binding_verify = lambda *a, **k: True
core._gossip_claim_weak = lambda *a, **k: None
try:
    mut_out = core.ingest_gossiped_binding(mut_b)
    mutant_fails = (mut_out == "inserted"
                    and binding_row("mutzero") == (ZERO_KEY, ZERO_SIG))
finally:
    core._name_binding_verify = real_verify
    core._gossip_claim_weak = real_weak
# Restored gates: a different small-order key is dropped again.
rest = raw_binding("restident", IDENTITY_KEY)
rest_out = core.ingest_gossiped_binding(rest)
real_ok = (zero_out in dropped and ident_out in dropped
           and rest_out in dropped and binding_row("restident") is None)
record_mutant("strict checkvalid and weak_reason both skipped",
              "zero key is not inserted on an empty node",
              real_ok, mutant_fails)
# The mutant left one row. The empty-node refusals above wrote none of theirs.
check("only the mutant's row exists; the real refusals wrote nothing",
      empty_count() == 1 and binding_row("zerokey") is None
      and binding_row("identkey") is None and binding_row("restident") is None,
      empty_count())

core.DB_PATH, core_serve.DB_PATH = _saved_db

print("mutant results:")
for name, row, real_ok, mutant_fails in MUTANTS:
    print(f"  {name}: row={row!r} real_holds={real_ok} mutant_lets_it_through={mutant_fails}")

print(f"--- {PASS} passed, {FAIL} failed ---")
if FAIL:
    sys.exit(1)
