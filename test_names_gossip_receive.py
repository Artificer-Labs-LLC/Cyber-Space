#!/usr/bin/env python3
"""Belt for the restored POST /fed/names/gossip receive route.

Scratch DB (CYBERNET_DB_DIR set before import). Covers the documented
contract, the operator allowlist, the per-source sybil cap, weak-key
admission, two mutants (sender-envelope verification and per-binding
claimant re-verification), and an in-process two-node rehearsal:
A claims, B adopts over the real route, B serves, a one-byte tamper
is refused.
"""
import os
import secrets
import sqlite3
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone

os.environ["CYBERNET_DB_DIR"] = tempfile.mkdtemp(prefix="names-gossip-recv-")
os.environ.pop("CYBERNET_PEER_ALLOWLIST", None)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient  # noqa: E402

import core  # noqa: E402
import core_serve  # noqa: E402
core.init_db()

# pin-rotation v2 (ART-42): name introduction is belted in
# test_pin_rotation_v2.py. This belt exercises the gossip gates, so any
# named sender may introduce a name here, and direct in-process calls
# carry a fixed test sender (a gossiped binding always has one).
import name_fork  # noqa: E402
name_fork.sender_may_introduce = lambda s: s is not None
_real_ingest_gossiped_binding = core.ingest_gossiped_binding


def _ingest_with_sender(binding, *a, **k):
    k.setdefault("sender_pub", "ee" * 32)
    return _real_ingest_gossiped_binding(binding, *a, **k)


core.ingest_gossiped_binding = _ingest_with_sender
import app as appmod  # noqa: E402
import federation  # noqa: E402
import window_open as wo  # noqa: E402
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
STALE_ISSUED = iso(NOW - timedelta(hours=25))
T2 = (0, _ed._Q - 1)


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


def allow_peer(pub):
    """The allowlist is mandatory. A peer the belt announces is listed."""
    cur = os.environ.get("CYBERNET_PEER_ALLOWLIST", "")
    parts = [p.strip() for p in cur.replace("\n", ",").split(",") if p.strip()]
    if pub.lower() not in {p.lower() for p in parts}:
        parts.append(pub.lower())
    os.environ["CYBERNET_PEER_ALLOWLIST"] = ",".join(parts)


def add_peer(pub, retired=""):
    now = core._now()
    with core._db_lock, core._db() as conn:
        conn.execute(
            """INSERT INTO peers (node_pub, name, network, version, genesis,
                                  capabilities, announced_at, first_seen,
                                  retired_at)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (pub, "peer", "cybernet", "0.1.0", 0, "[]", now, now, retired))
    allow_peer(pub)


def binding_row(name):
    with core._db_lock, core._db() as conn:
        row = conn.execute(
            "SELECT node_pubkey, issued_at, expires_at, signature "
            "FROM name_bindings WHERE name=?", (name,)).fetchone()
        nconf = conn.execute(
            "SELECT COUNT(*) FROM name_conflicts WHERE name=?",
            (name,)).fetchone()[0]
    return (None if row is None else tuple(row)), nconf


# Each call mints a distinct ts. A same-second repeat would be one
# signature, and the replay seen-set would refuse it before the kept
# merge this belt is measuring.
_next_env_ts = int(time.time()) - 120


def gossip_env(sender_priv, sender_pub, bindings, recipient=None, from_pub=None,
               ts=None):
    global _next_env_ts
    if ts is None:
        # Same wall-clock flake fix as the hardening belt: never let a
        # minted envelope fall outside MAX_SKEW_SEC on a slow run.
        _next_env_ts = max(_next_env_ts + 1, int(time.time()) - 60)
        ts = _next_env_ts
    body = {
        "from_node_pub": sender_pub if from_pub is None else from_pub,
        "bindings": bindings,
    }
    return _fed_env.make_envelope(
        sender_priv, sender_pub,
        core._NODE_PUB if recipient is None else recipient, body, ts=ts)


def post(env):
    return client.post("/fed/names/gossip", json=env)


def detail(resp):
    try:
        return resp.json().get("detail")
    except Exception:
        return resp.text


def flip_hex(h):
    last = h[-1]
    return h[:-1] + ("0" if last != "0" else "1")


def mixed_pub(scalar):
    P = _ed._edwards(_ed._scalarmult(_ed._BPOINT, scalar), T2)
    return _ed._encodepoint(P).hex()


def forge_sig(scalar, pub_hex, msg):
    pub = bytes.fromhex(pub_hex)
    for r in range(1, 10000):
        R = _ed._encodepoint(_ed._scalarmult(_ed._BPOINT, r))
        h = int.from_bytes(_ed._H(R + pub + msg), "little")
        if h % 2 == 0:
            S = (r + h * scalar) % _ed._L
            return (R + _ed._encodeint(S)).hex()
    raise RuntimeError("no even challenge")


def record_mutant(name, row, real_ok, mutant_fails):
    MUTANTS.append((name, row, real_ok, mutant_fails))
    check(f"MUTANT {name}: real holds and the skip lets the row through",
          real_ok and mutant_fails, (real_ok, mutant_fails, row))


# ---------------------------------------------------------------- route
routes = [(getattr(r, "path", ""), getattr(r, "methods", set()))
          for r in federation.router.routes]
check("POST /fed/names/gossip is registered",
      any(p == "/fed/names/gossip" and "POST" in (m or set()) for p, m in routes),
      [p for p, _ in routes])

sender_priv, sender_pub = node_key()
add_peer(sender_pub)
reset_hits()

# ---------------------------------------------------------------- fresh / repeat
fresh = mint("freshname", secrets.token_hex(32))
r = post(gossip_env(sender_priv, sender_pub, [fresh]))
body = r.json()
check("fresh gossip -> 200 inserted",
      r.status_code == 200 and body.get("ok") is True
      and body.get("inserted") == 1 and body.get("outcomes") == ["inserted"],
      (r.status_code, body))
stored, _ = binding_row("freshname")
check("fresh binding stored",
      stored is not None and stored[0] == fresh["node_pubkey"]
      and stored[3] == fresh["signature"], stored)

r = post(gossip_env(sender_priv, sender_pub, [fresh]))
body = r.json()
check("repeat gossip -> kept",
      r.status_code == 200 and body.get("kept") == 1
      and body.get("inserted") == 0 and body.get("outcomes") == ["kept"],
      body)

# ---------------------------------------------------------------- tampered claimant signature
tampered = mint("tampername", secrets.token_hex(32))
tampered["signature"] = flip_hex(tampered["signature"])
r = post(gossip_env(sender_priv, sender_pub, [tampered]))
body = r.json()
check("tampered claimant signature -> dropped-unverifiable",
      r.status_code == 200 and body.get("dropped") == 1
      and body.get("outcomes") == ["dropped-unverifiable"]
      and binding_row("tampername")[0] is None,
      body)

# ---------------------------------------------------------------- stale
stale = mint("stalename", secrets.token_hex(32), issued=STALE_ISSUED)
r = post(gossip_env(sender_priv, sender_pub, [stale]))
body = r.json()
check("stale (>24h) -> dropped-stale and not stored",
      r.status_code == 200 and body.get("outcomes") == ["dropped-stale"]
      and binding_row("stalename")[0] is None,
      body)

# ---------------------------------------------------------------- unknown / retired
unk_priv, unk_pub = node_key()
unknown_binding = mint("unknownname", secrets.token_hex(32))
r = post(gossip_env(unk_priv, unk_pub, [unknown_binding]))
check("unknown sender -> 404 unknown peer",
      r.status_code == 404 and detail(r) == "unknown peer"
      and binding_row("unknownname")[0] is None,
      (r.status_code, detail(r)))

ret_priv, ret_pub = node_key()
add_peer(ret_pub, retired=core._now())
retired_binding = mint("retiredname", secrets.token_hex(32))
r = post(gossip_env(ret_priv, ret_pub, [retired_binding]))
check("retired sender -> 404 unknown peer",
      r.status_code == 404 and detail(r) == "unknown peer"
      and binding_row("retiredname")[0] is None,
      (r.status_code, detail(r)))

# ---------------------------------------------------------------- recipient / from_node_pub
wrong = mint("wrongrecip", secrets.token_hex(32))
r = post(gossip_env(sender_priv, sender_pub, [wrong], recipient="f" * 64))
check("wrong recipient -> 400 not addressed to this node",
      r.status_code == 400 and detail(r) == "not addressed to this node"
      and binding_row("wrongrecip")[0] is None,
      (r.status_code, detail(r)))

mismatch = mint("mismatch", secrets.token_hex(32))
r = post(gossip_env(sender_priv, sender_pub, [mismatch], from_pub=unk_pub))
check("from_node_pub mismatch -> 400 sender_pub mismatch",
      r.status_code == 400 and detail(r) == "sender_pub mismatch"
      and binding_row("mismatch")[0] is None,
      (r.status_code, detail(r)))

r = post(gossip_env(sender_priv, sender_pub, {"not": "a list"}))
check("bindings not a list -> 400",
      r.status_code == 400 and detail(r) == "bindings must be a list",
      (r.status_code, detail(r)))

# ---------------------------------------------------------------- cap 128
# Hardening: more than 128 bindings is 400 with nothing folded. Exactly
# 128 is still accepted (one insert, the rest kept).
capped = mint("capname", secrets.token_hex(32))
past = mint("capextra", secrets.token_hex(32))
r = post(gossip_env(sender_priv, sender_pub, [capped] * 128 + [past]))
check(">128 bindings -> 400, nothing folded",
      r.status_code == 400
      and detail(r) == f"bindings exceed {federation.NAMES_GOSSIP_RECV_CAP}"
      and binding_row("capname")[0] is None
      and binding_row("capextra")[0] is None,
      (r.status_code, detail(r)))
r = post(gossip_env(sender_priv, sender_pub, [capped] * 128))
body = r.json()
check("exactly 128 bindings accepted",
      r.status_code == 200 and len(body.get("outcomes", [])) == 128
      and body["outcomes"][0] == "inserted"
      and body["outcomes"][1:] == ["kept"] * 127
      and binding_row("capname")[0] is not None
      and binding_row("capextra")[0] is None,
      (r.status_code, body.get("inserted"), body.get("kept"),
       len(body.get("outcomes", []))))

# ---------------------------------------------------------------- weak key
scalar = 0x13579BD
wpub = mixed_pub(scalar)
wmsg = core._name_claim_payload("weakgossip", wpub, ISSUED, EXPIRES)
wsig = forge_sig(scalar, wpub, wmsg)
check("premise: mixed-order gossip sig passes checkvalid and is weak",
      _ed.checkvalid(bytes.fromhex(wsig), wmsg, bytes.fromhex(wpub))
      and wo.weak_reason(wpub) == "mixed-order")
weak = {"name": "weakgossip", "node_pubkey": wpub, "issued_at": ISSUED,
        "expires_at": EXPIRES, "signature": wsig}
r = post(gossip_env(sender_priv, sender_pub, [weak]))
body = r.json()
wrow, wconf = binding_row("weakgossip")
check("mixed-order binding -> dropped-weak, no row, no conflict log",
      r.status_code == 200 and body.get("outcomes") == ["dropped-weak"]
      and wrow is None and wconf == 0,
      (body, wrow, wconf))

# ---------------------------------------------------------------- allowlist
listed = mint("allowlisted", secrets.token_hex(32))
unlisted = mint("allowunlisted", secrets.token_hex(32))
saved_allow = os.environ.get("CYBERNET_PEER_ALLOWLIST", "")
try:
    os.environ["CYBERNET_PEER_ALLOWLIST"] = "ab" * 32
    r = post(gossip_env(sender_priv, sender_pub, [unlisted]))
    check("allowlist set and sender unlisted -> 403",
          r.status_code == 403 and "allowlist" in (detail(r) or "")
          and "/fed/names/gossip" in (detail(r) or "")
          and binding_row("allowunlisted")[0] is None,
          (r.status_code, detail(r)))
    # strangers stay 404: the known-peer check is before the allowlist
    r = post(gossip_env(unk_priv, unk_pub, [mint("allowstranger", secrets.token_hex(32))]))
    check("allowlist set and unknown sender still 404",
          r.status_code == 404 and detail(r) == "unknown peer"
          and binding_row("allowstranger")[0] is None,
          (r.status_code, detail(r)))
    os.environ["CYBERNET_PEER_ALLOWLIST"] = sender_pub.upper()
    r = post(gossip_env(sender_priv, sender_pub, [listed]))
    body = r.json()
    check("allowlist set and sender listed -> inserted",
          r.status_code == 200 and body.get("outcomes") == ["inserted"]
          and binding_row("allowlisted")[0] is not None,
          body)
finally:
    os.environ["CYBERNET_PEER_ALLOWLIST"] = saved_allow

# Unset admits nobody. Verify is not reached. Restore before later rows.
after = mint("allownone", secrets.token_hex(32))
os.environ.pop("CYBERNET_PEER_ALLOWLIST", None)
unset_calls = {"n": 0}
real_verify_unset = _fed_env.verify_envelope
def _count_unset(env, *a, **k):
    unset_calls["n"] += 1
    return real_verify_unset(env, *a, **k)
_fed_env.verify_envelope = _count_unset
try:
    r = post(gossip_env(sender_priv, sender_pub, [after]))
    check("allowlist unset -> 403 before verify, nothing stored",
          r.status_code == 403 and "allowlist" in (detail(r) or "")
          and binding_row("allownone")[0] is None
          and unset_calls["n"] == 0,
          (r.status_code, detail(r), unset_calls["n"]))
finally:
    _fed_env.verify_envelope = real_verify_unset
    os.environ["CYBERNET_PEER_ALLOWLIST"] = saved_allow

# ---------------------------------------------------------------- per-sender rate
reset_hits()
rate_priv, rate_pub = node_key()
add_peer(rate_pub)
rate_binding = mint("ratesend", secrets.token_hex(32))
limit = core.RATE_LIMIT
codes = []
for _ in range(limit + 1):
    codes.append(post(gossip_env(rate_priv, rate_pub, [rate_binding])).status_code)
check("per-sender bucket: first RATE_LIMIT accepted, next is 429",
      codes[:limit] == [200] * limit and codes[limit] == 429, codes[-3:])

# ---------------------------------------------------------------- per-source cap before verify
reset_hits()
saved_limit = federation.FED_SOURCE_LIMIT
federation.FED_SOURCE_LIMIT = 2
try:
    bad_codes = []
    for _ in range(2):
        # A known allowlisted sender with a bad signature passes the
        # pre-verify gate and spends a source token, then fails verify.
        bad_env = gossip_env(sender_priv, sender_pub,
                             [mint("badsrc", secrets.token_hex(32))])
        bad_env["sig"] = flip_hex(bad_env["sig"])
        bad_codes.append(post(bad_env).status_code)
    src_binding = mint("sourcecap", secrets.token_hex(32))
    src_env = gossip_env(sender_priv, sender_pub, [src_binding])
    blocked = post(src_env)
    check("per-source cap counts invalid envelopes and blocks the next call",
          bad_codes == [400, 400] and blocked.status_code == 429
          and binding_row("sourcecap")[0] is None,
          (bad_codes, blocked.status_code, detail(blocked)))
finally:
    federation.FED_SOURCE_LIMIT = saved_limit
reset_hits()
r = post(src_env)
check("same envelope inserts once the per-source bucket is clear",
      r.status_code == 200 and r.json().get("outcomes") == ["inserted"],
      r.text[:300])

# ---------------------------------------------------------------- direct call (optional Request)
reset_hits()
direct_binding = mint("directcall", secrets.token_hex(32))
direct_env = gossip_env(sender_priv, sender_pub, [direct_binding])
out = federation.fed_names_gossip(direct_env)
check("route callable with no Request (source 'direct')",
      out.get("outcomes") == ["inserted"] and binding_row("directcall")[0] is not None,
      out)

# ---------------------------------------------------------------- mutants
print("mutants:")
reset_hits()
mut_binding = mint("mutsender", secrets.token_hex(32))
mut_env = gossip_env(sender_priv, sender_pub, [mut_binding])
mut_env["sig"] = flip_hex(mut_env["sig"])
real = post(mut_env)
real_ok = (real.status_code == 400 and detail(real) == "invalid envelope"
           and binding_row("mutsender")[0] is None)
real_verify = _fed_env.verify_envelope
_fed_env.verify_envelope = lambda *a, **k: True
try:
    mutant = post(mut_env)
    mutant_body = mutant.json()
    mutant_fails = (mutant.status_code == 200
                    and mutant_body.get("outcomes") == ["inserted"]
                    and binding_row("mutsender")[0] is not None)
finally:
    _fed_env.verify_envelope = real_verify
record_mutant("sender-verification skipped",
              "tampered envelope sig",
              real_ok, mutant_fails)
restored_ok = post(gossip_env(
    sender_priv, sender_pub, [mint("mutsender2", secrets.token_hex(32))]))
restored_bad = post({"sig": "00"})
check("sender mutant restored: valid envelope accepted, garbage refused as invalid",
      restored_ok.status_code == 200
      and restored_bad.status_code == 400
      and detail(restored_bad) == "invalid envelope",
      (restored_ok.status_code, restored_bad.status_code, detail(restored_bad)))

reset_hits()
rebind = mint("mutclaim", secrets.token_hex(32))
rebind["signature"] = flip_hex(rebind["signature"])
real = post(gossip_env(sender_priv, sender_pub, [rebind]))
real_body = real.json()
real_ok = (real.status_code == 200
           and real_body.get("outcomes") == ["dropped-unverifiable"]
           and binding_row("mutclaim")[0] is None)
real_verify_binding = core._name_binding_verify
core._name_binding_verify = lambda *a, **k: True
try:
    mutant = post(gossip_env(sender_priv, sender_pub, [rebind]))
    mutant_body = mutant.json()
    stored, _ = binding_row("mutclaim")
    mutant_fails = (mutant.status_code == 200
                    and mutant_body.get("outcomes") == ["inserted"]
                    and stored is not None and stored[0] == rebind["node_pubkey"])
finally:
    core._name_binding_verify = real_verify_binding
record_mutant("per-binding re-verification skipped",
              "tampered claimant signature",
              real_ok, mutant_fails)
honest = mint("mutclaim2", secrets.token_hex(32))
honest["signature"] = flip_hex(honest["signature"])
r = post(gossip_env(sender_priv, sender_pub, [honest]))
check("claimant verify restored: tampered binding dropped again",
      r.status_code == 200 and r.json().get("outcomes") == ["dropped-unverifiable"]
      and binding_row("mutclaim2")[0] is None,
      r.text[:300])

# ---------------------------------------------------------------- two-node rehearsal
print("two-node rehearsal:")


def switch_db(path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    core.DB_PATH = path
    core_serve.DB_PATH = path
    core.init_db()
    reset_hits()


scratch = tempfile.mkdtemp(prefix="names-gossip-pair-")
db_a = os.path.join(scratch, "a", "cybernet.db")
db_b = os.path.join(scratch, "b", "cybernet.db")
a_priv, a_pub = node_key()
check("node A pubkey is not this process (node B)", a_pub != core._NODE_PUB)

switch_db(db_a)
name_priv = secrets.token_hex(32)
claimed = mint("depthtest", name_priv)
r = client.post("/api/v1/names/claim", data=claimed)
check("node A claim via POST /api/v1/names/claim -> 200",
      r.status_code == 200, (r.status_code, r.text[:300]))
a_row, _ = binding_row("depthtest")
check("node A stored the claim",
      a_row is not None and a_row[0] == claimed["node_pubkey"]
      and a_row[3] == claimed["signature"], a_row)

switch_db(db_b)
check("node B registry does not have the name before gossip",
      binding_row("depthtest")[0] is None)
add_peer(a_pub)
env = gossip_env(a_priv, a_pub, [claimed])
check("envelope recipient is node B and sender is node A",
      env["recipient"] == core._NODE_PUB and env["sender_pub"] == a_pub
      and env["body"]["from_node_pub"] == a_pub)
r = post(env)
body = r.json()
check("node B ingest over the real route -> inserted",
      r.status_code == 200 and body.get("inserted") == 1
      and body.get("outcomes") == ["inserted"],
      (r.status_code, body))
served = client.get("/api/v1/names/depthtest")
served_body = served.json()
check("node B serves the binding",
      served.status_code == 200
      and served_body.get("name") == "depthtest"
      and served_body.get("node_pubkey") == claimed["node_pubkey"]
      and served_body.get("signature") == claimed["signature"]
      and served_body.get("issued_at") == claimed["issued_at"]
      and served_body.get("expires_at") == claimed["expires_at"],
      (served.status_code, served_body))

bad = dict(claimed)
bad["signature"] = flip_hex(bad["signature"])
r = post(gossip_env(a_priv, a_pub, [bad]))
body = r.json()
served_after = client.get("/api/v1/names/depthtest").json()
# Same signed bytes as the insert above, so the sha256 dedupe keeps the
# stored row and does not call checkvalid. The served signature stays
# the honest one. A tamper of a name that was never verified is still
# dropped-unverifiable (covered above).
check("one-byte tamper of a verified payload does not replace the served signature",
      r.status_code == 200 and body.get("outcomes") == ["kept"]
      and served_after.get("signature") == claimed["signature"],
      body)

a_disk = sqlite3.connect(db_a).execute(
    "SELECT node_pubkey, signature FROM name_bindings WHERE name=?",
    ("depthtest",)).fetchone()
b_disk = sqlite3.connect(db_b).execute(
    "SELECT node_pubkey, signature FROM name_bindings WHERE name=?",
    ("depthtest",)).fetchone()
check("A and B registries are independent copies of the same binding",
      a_disk is not None and b_disk is not None
      and tuple(a_disk) == tuple(b_disk) == (claimed["node_pubkey"], claimed["signature"]),
      (a_disk, b_disk))

print("mutant results:")
for name, row, real_ok, mutant_fails in MUTANTS:
    print(f"  {name}: row={row!r} real_holds={real_ok} mutant_lets_it_through={mutant_fails}")

print(f"--- {PASS} passed, {FAIL} failed ---")
if FAIL:
    sys.exit(1)
