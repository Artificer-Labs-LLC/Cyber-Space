#!/usr/bin/env python3
# PROVENANCE (Examiner item 5): ported onto origin/villhaze/q1-name-fixes-r3
# @ 3cadf03 by cherry-pick, branch oracle/window-open-preconditions-r2.
# Source commits on oracle/window-open-preconditions (off 8e9291a):
#   0bdb386 (names/claim gate) -> r2 b858a98
#   357b71d (names/rotate gate + zero-key vectors) -> r2 c44ac8d
#   7cc71a8 (shared names-write bucket) -> r2 cf285cf
"""ART-38 / ART-29: names/rotate (routes_social_serve.names_rotate) vectors.

Cipher 2026-10-12: the rotation path verifies the NEW binding with
_name_binding_verify(name, new_pubkey, ...). Under the pre-e8fb1fc loose
checkvalid an all-zero (small-order) new_pubkey with an all-zero signature
verifies for ~1 in 4 names, so a holder-signed rotation could move a live
name to a key nobody holds.

1. Legit rotation to a real key -> 200 (positive control).
2. Rotation to all-zero new_pubkey + zero binding signature -> 400, binding
   and name_rotations unchanged (strict checkvalid).
3. Stale hole, two arms. The loose pre-strict checkvalid (0bdb386, or
   388afa2^ in this history) still admits the zero key when weak_reason
   is stubbed out. The real path — that verifier, with weak_reason left
   in place — is 400 and writes no row. Removing the weak_reason call
   on rotate makes arm (b) fail.
4. Per-IP gate on names/rotate runs first: 1..LIMIT -> 400, LIMIT+1 -> 429,
   empty body also 429; limit configurable (CYBERNET_NAME_ROTATE_RATE_LIMIT).

Scratch DB only.
"""
import importlib.util
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone

os.environ["CYBERNET_DB_DIR"] = tempfile.mkdtemp(prefix="art38-rot-")
os.environ["CYBERNET_NAME_CLAIM_RATE_LIMIT"] = "5"  # shared names-write limit
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from fastapi.testclient import TestClient  # noqa: E402
import core  # noqa: E402
core.init_db()
import core_serve  # noqa: E402
from fed import ed25519 as _ed  # noqa: E402
import app as appmod  # noqa: E402
import routes_social_serve as rss  # noqa: E402
from rotate_name import _rotate_payload  # noqa: E402

client = TestClient(appmod.app)
PASS = FAIL = 0


def check(label, cond, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok  {label}")
    else:
        FAIL += 1
        print(f"  FAIL {label} {extra}")


def reset_rate():
    with core._db_lock:
        core_serve._hits.clear()


# Fixed timestamps so the zero-key vector is deterministic: for label
# "rotz2" the loose verifier accepts (zero pk, zero sig) over this payload.
ROT_ISSUED = "2026-01-01T00:00:00+00:00"
B_ISSUED = "2026-01-01T00:00:00+00:00"
B_EXPIRES = "2099-01-01T00:00:00+00:00"
ZERO_PUB = "00" * 32
ZERO_SIG = "00" * 64


def pub_of(priv):
    return _ed.publickey(bytes.fromhex(priv)).hex()


def seed(name, priv):
    pub = pub_of(priv)
    sig = _ed.sign(core._name_claim_payload(name, pub, B_ISSUED, B_EXPIRES),
                   bytes.fromhex(priv), bytes.fromhex(pub)).hex()
    with core._db_lock, core._db() as conn:
        conn.execute("INSERT OR REPLACE INTO name_bindings (name, node_pubkey, issued_at, expires_at, signature) VALUES (?,?,?,?,?)",
                     (name, pub, B_ISSUED, B_EXPIRES, sig))


def rotation(name, old_priv, new_pub, binding_sig):
    old_pub = pub_of(old_priv)
    rsig = _ed.sign(_rotate_payload(name, old_pub, new_pub, ROT_ISSUED),
                    bytes.fromhex(old_priv), bytes.fromhex(old_pub)).hex()
    return {"name": name, "old_pubkey": old_pub, "new_pubkey": new_pub,
            "rotation_issued_at": ROT_ISSUED, "rotation_signature": rsig,
            "binding_issued_at": B_ISSUED, "binding_expires_at": B_EXPIRES,
            "binding_signature": binding_sig}


def state(name):
    with core._db_lock, core._db() as conn:
        b = conn.execute("SELECT node_pubkey, signature FROM name_bindings WHERE name=?", (name,)).fetchone()
        n = conn.execute("SELECT COUNT(*) FROM name_rotations WHERE name=?", (name,)).fetchone()[0]
    return b, n


check("shared limit configurable from CLAIM env", rss.NAME_CLAIM_RATE_LIMIT == 5 and rss.NAME_ROTATE_RATE_LIMIT == 5, rss.NAME_ROTATE_RATE_LIMIT)
check("rotate window default 60s", rss.NAME_ROTATE_RATE_WINDOW == 60.0, rss.NAME_ROTATE_RATE_WINDOW)

# 1. positive control
reset_rate()
OLD = "44" * 32
NEW = "55" * 32
seed("rotok", OLD)
new_pub = pub_of(NEW)
nsig = _ed.sign(core._name_claim_payload("rotok", new_pub, B_ISSUED, B_EXPIRES),
                bytes.fromhex(NEW), bytes.fromhex(new_pub)).hex()
r = client.post("/api/v1/names/rotate", data=rotation("rotok", OLD, new_pub, nsig))
check("legit rotation -> 200", r.status_code == 200, r.text)
check("legit rotation moved binding", state("rotok")[0][0] == new_pub, state("rotok"))

# 2. zero-key rotation target, strict verifier
reset_rate()
seed("rotz2", OLD)
before = state("rotz2")
vec = rotation("rotz2", OLD, ZERO_PUB, ZERO_SIG)
r = client.post("/api/v1/names/rotate", data=vec)
check("zero-key rotation target -> 400 (strict)", r.status_code == 400, (r.status_code, r.text))
check("binding unchanged after refused rotation", state("rotz2") == before, (before, state("rotz2")))
check("no name_rotations row for refused rotation", state("rotz2")[1] == 0, state("rotz2"))
check("strict checkvalid refuses vector directly",
      not core._name_binding_verify("rotz2", ZERO_PUB, B_ISSUED, B_EXPIRES, ZERO_SIG))

# 3. stale hole, two arms. 0bdb386 is the historical loose verifier; this
# history's copy is the parent of the strict-checkvalid commit.
def _load_old_verifier():
    for rev in ("0bdb386", "388afa2^", "b858a98"):
        try:
            src = subprocess.run(
                ["git", "-C", HERE, "show", f"{rev}:fed/ed25519.py"],
                capture_output=True, check=True, text=True).stdout
        except Exception:
            continue
        if "def checkvalid" in src and "_is_small_order" not in src:
            return rev, src
    return None, None


def restore_rotz2():
    seed("rotz2", OLD)
    with core._db_lock, core._db() as conn:
        conn.execute("DELETE FROM name_rotations WHERE name='rotz2'")


old_rev, old_src = _load_old_verifier()
check("old loose verifier is loadable", old_src is not None, old_rev)
if old_src:
    d = tempfile.mkdtemp(prefix="oldv-")
    path = os.path.join(d, "ed25519_old.py")
    open(path, "w").write(old_src)
    spec = importlib.util.spec_from_file_location("ed25519_old", path)
    old = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(old)
    strict = core._fed_ed25519
    real_weak = rss._rotate_weak_reason
    core._fed_ed25519 = old
    try:
        # (a) the hole still reproduces once weak_reason is stubbed out
        rss._rotate_weak_reason = lambda pub: None
        reset_rate()
        restore_rotz2()
        r_a = client.post("/api/v1/names/rotate", data=vec)
        after_a = state("rotz2")
        # (b) real path: same loose verifier, weak_reason left in place
        rss._rotate_weak_reason = real_weak
        reset_rate()
        restore_rotz2()
        before_b = state("rotz2")
        r_b = client.post("/api/v1/names/rotate", data=vec)
        after_b = state("rotz2")
        # Mutant: the weak_reason call on rotate is gone. Arm (b) must fail.
        rss._rotate_weak_reason = lambda pub: None
        reset_rate()
        restore_rotz2()
        r_m = client.post("/api/v1/names/rotate", data=vec)
        after_m = state("rotz2")
    finally:
        core._fed_ed25519 = strict
        rss._rotate_weak_reason = real_weak
    restore_rotz2()
    print(f"  info old verifier {old_rev}: arm (a) {r_a.status_code}, arm (b) {r_b.status_code}, mutant {r_m.status_code}")
    check("(a) old verifier with weak_reason stubbed admits the zero key",
          r_a.status_code == 200 and after_a[0][0] == ZERO_PUB and after_a[1] == 1,
          (r_a.status_code, r_a.text, after_a))
    check("(b) real path refuses the zero key: 400 and no row",
          r_b.status_code == 400 and "weak key" in r_b.text and after_b == before_b
          and before_b[1] == 0,
          (r_b.status_code, r_b.text, before_b, after_b))
    arm_b_under_mutant = (
        r_m.status_code == 400 and "weak key" in r_m.text and after_m[1] == 0
        and after_m[0][0] != ZERO_PUB)
    check("MUTANT weak_reason removed on rotate: arm (b) fails",
          r_m.status_code == 200 and after_m[0][0] == ZERO_PUB and after_m[1] == 1
          and not arm_b_under_mutant,
          (r_m.status_code, r_m.text, after_m))

# 4. per-IP gate on names/rotate
reset_rate()
LIMIT = rss.NAME_ROTATE_RATE_LIMIT
codes = [client.post("/api/v1/names/rotate", data=vec).status_code for _ in range(LIMIT + 2)]
check("rotate probes 1..LIMIT -> 400", all(c == 400 for c in codes[:LIMIT]), codes)
check("rotate probe LIMIT+1 and beyond -> 429", all(c == 429 for c in codes[LIMIT:]), codes)
check("binding still unchanged after flood", state("rotz2")[0][0] == pub_of(OLD), state("rotz2"))
reset_rate()
for _ in range(LIMIT):
    client.post("/api/v1/names/rotate", data={})
r = client.post("/api/v1/names/rotate", data={})
check("rotate gate precedes parse (empty body -> 429)", r.status_code == 429, r.status_code)
# shared bucket: a rotate flood also spends the claim budget
r = client.post("/api/v1/names/claim", data={})
check("claim shares rotate bucket (429)", r.status_code == 429, r.status_code)
# Bulwark belt: alternate claim/rotate; request LIMIT+1 gets 429
reset_rate()
alt = []
for i in range(LIMIT + 1):
    path = "/api/v1/names/claim" if i % 2 == 0 else "/api/v1/names/rotate"
    alt.append(client.post(path, data={}).status_code)
check("alternating claim/rotate: 1..LIMIT -> 400", all(c == 400 for c in alt[:LIMIT]), alt)
check("alternating claim/rotate: LIMIT+1 -> 429", alt[LIMIT] == 429, alt)

print(f"{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
