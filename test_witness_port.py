#!/usr/bin/env python3
"""ART-40 witness-port belt (Villhaze e5fc5fa2, board cd7c1a12).

Harness: FastAPI TestClient. It does not run uvicorn, so it does not rewrite
request.client.host from X-Forwarded-For. That is the same split
--no-proxy-headers enforces in deploy/cybernet-node.service: the peer the
app sees is the direct peer, and client_source is the only place a
forwarded header is trusted. This file never calls open_window.
"""
import hashlib
import json
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone

os.environ["CYBERNET_DB_DIR"] = tempfile.mkdtemp(prefix="art40-witness-")
os.environ["CYBERNET_NAME_CLAIM_RATE_LIMIT"] = "10000"
# Pin is request-time. Leave it unset until a row needs it.
os.environ.pop("CYBERNET_GENESIS_WITNESSES", None)
os.environ.pop("CYBERNET_GENESIS_LOG_ID", None)
# ART-42 node B wiring: _rules checks the pinned sizing first.
os.environ["CYBERNET_GENESIS_LEGACY_ACCOUNTS"] = "1000"
os.environ["CYBERNET_GENESIS_LIVE_BINDINGS"] = "0"

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from fastapi.testclient import TestClient  # noqa: E402

import core  # noqa: E402
core.init_db()
import app as appmod  # noqa: E402
import routes_legacy_witness as _rlw  # noqa: E402
# READ deploy: app.py mounts only the two GETs; this belt still covers the
# write routes, so it mounts write_router on its own copy of the app.
appmod.app.include_router(_rlw.write_router)
import hop_certs  # noqa: E402
import legacy_witness as lw  # noqa: E402
import ratesrc  # noqa: E402
import routes_doh  # noqa: E402
import routes_legacy_witness as rlw  # noqa: E402
import routes_social_serve as rss  # noqa: E402
import window_open as wo  # noqa: E402
from fed import ed25519 as _ed  # noqa: E402
from rotate_name import _rotate_payload  # noqa: E402

PASS = FAIL = 0
MUTANTS = []


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


def client_at(ip):
    return TestClient(appmod.app, client=(ip, 40000))


def bindings(name):
    with core._db_lock, core._db() as conn:
        row = conn.execute(
            "SELECT node_pubkey FROM name_bindings WHERE name=?", (name,)
        ).fetchone()
        nrot = conn.execute(
            "SELECT COUNT(*) FROM name_rotations WHERE name=?", (name,)
        ).fetchone()[0]
    return (None if row is None else row[0]), nrot


def imports_for(name):
    with core._db_lock, core._db() as conn:
        wo.init_schema(conn)
        return conn.execute(
            "SELECT COUNT(*) FROM legacy_imports WHERE name=?", (name,)
        ).fetchone()[0]


def observed(log_id):
    with core._db_lock, core._db() as conn:
        wo.init_schema(conn)
        return conn.execute(
            "SELECT COUNT(*) FROM legacy_observed_heads WHERE log_id=?", (log_id,)
        ).fetchone()[0]


T2 = (0, _ed._Q - 1)
NOW = datetime.now(timezone.utc)
ISSUED = (NOW - timedelta(minutes=1)).isoformat(timespec="seconds")
EXPIRES = (NOW + timedelta(days=30)).isoformat(timespec="seconds")
T0 = 1_700_000_000
DAY = 86400


def mixed_pub(scalar):
    P = _ed._edwards(_ed._scalarmult(_ed._BPOINT, scalar), T2)
    return _ed._encodepoint(P).hex()


def forge_sig(scalar, pub_hex, msg):
    """Signature that satisfies the cofactorless equation for a*B+T2.
    checkvalid accepts it when the challenge is even; weak_reason does not."""
    pub = bytes.fromhex(pub_hex)
    for r in range(1, 10000):
        R = _ed._encodepoint(_ed._scalarmult(_ed._BPOINT, r))
        h = int.from_bytes(_ed._H(R + pub + msg), "little")
        if h % 2 == 0:
            S = (r + h * scalar) % _ed._L
            return R + _ed._encodeint(S)
    raise RuntimeError("no even challenge")


def proof_get(client, xff=None):
    headers = {"X-Forwarded-For": xff} if xff else {}
    return client.get("/api/v1/legacy-log/proof", params={"name": "probe"}, headers=headers)


class Builder:
    def __init__(self, log_id):
        self.log_id, self.entries = log_id, []

    def add(self, kind, agent_id=None, name=None, migration_id=None, k0=None, detail=None, at=T0):
        back = None
        if agent_id is not None:
            prevs = [x["seq"] for x in self.entries if x["agent_id"] == agent_id]
            back = max(prevs) if prevs else None
        e = {
            "seq": len(self.entries) + 1,
            "prev_hash": lw.entry_hash(self.entries[-1], self.log_id) if self.entries else "none",
            "kind": kind, "agent_id": agent_id, "agent_prev_seq": back,
            "name_sha256": lw.name_hash(name), "name": name, "migration_id": migration_id,
            "k0_pub": k0,
            "detail": json.dumps(detail or {}, sort_keys=True, separators=(",", ":")),
            "logged_at": at,
        }
        e["body_sha256"] = lw.body_hash(e)
        self.entries.append(e)
        return e["seq"]

    def proof(self, wset, signers, full_for=7):
        es = self.entries
        kinds = [e["kind"] for e in es]
        o = kinds.index("window-open") + 1
        c = kinds.index("window-close") + 1
        h = {
            "log_id": self.log_id, "witness_set": wset.id, "seq": len(es),
            "head_hash": lw.entry_hash(es[-1], self.log_id),
            "window_open_seq": o, "window_close_seq": c, "window_state": "closed",
            **EMPTY_ROOTS,
        }
        span = [
            lw.full(e) if (e["agent_id"] == full_for or e["agent_id"] is None) else lw.skeleton(e)
            for e in es
        ]
        return {"head": lw.sign_head(h, signers), "span": span}


EMPTY_ROOTS = {"hops_root": lw.hops_root([]), "bound_root": hop_certs.bound_root([]),
               "v1_frozen_root": hop_certs.v1_frozen_root([])}


def add_closure(b):
    """ART-42: every open writes one hold-closure committing its (here, no)
    row-kind entries and hop rows; node B's verify_rows_root requires it."""
    b.add("hold-closure", detail={"rows_root": lw.rows_root([]), "rows_n": 0,
                                  "hops_root": lw.hops_root([]), "hops_n": 0})


def standard(b, k0):
    b.add("window-open")
    add_closure(b)
    b.add("hold", 7, "zed")
    b.add("hold", 8, "yan")
    b.add("migrate-pending", 7, "zed", 1, k0, at=T0 + 10)
    close = b.add("window-close", at=T0 + 30 * DAY)
    b.add("cutover", 7, "zed", 1, k0, {"window_close_seq": close}, at=T0 + 30 * DAY)
    return close


def signer_for(priv, pub):
    def sign(msg, sk=priv, pk=pub):
        return pk, _ed.sign(msg, bytes.fromhex(sk), bytes.fromhex(pk)).hex()
    return sign


# ---------------------------------------------------------------- constants
check("proof global is at least 10x the per-IP cap",
      rlw.PROOF_GLOBAL >= 10 * rlw.PROOF_PER_IP, (rlw.PROOF_GLOBAL, rlw.PROOF_PER_IP))
check("import global is at least 10x the per-source cap",
      rlw.IMPORT_GLOBAL >= 10 * rlw.IMPORT_PER_SOURCE)
check("import global is at least 10x the per-log cap",
      rlw.IMPORT_GLOBAL >= 10 * rlw.IMPORT_PER_LOG)
check("head global is at least 10x the per-IP cap",
      rlw.HEAD_GLOBAL >= 10 * rlw.HEAD_PER_IP)
check("observe global is at least 10x the per-IP cap",
      rlw.OBSERVE_GLOBAL >= 10 * rlw.OBSERVE_PER_IP)

# ---------------------------------------------------------------- head / chain
c_head = client_at("203.0.113.1")
r = c_head.get("/api/v1/legacy-log/head")
check("empty legacy log head is 404", r.status_code == 404, r.status_code)

with core._db_lock, core._db() as conn:
    wo.init_schema(conn)
    before = conn.execute("SELECT COUNT(*) FROM legacy_migration_log").fetchone()[0]
try:
    wo.record_start("before-open", "rotation")
    refused = False
except wo.StartRefused:
    refused = True
with core._db_lock, core._db() as conn:
    after = conn.execute("SELECT COUNT(*) FROM legacy_migration_log").fetchone()[0]
check("start before the anchor is 409 and appends nothing", refused and before == after == 0,
      (refused, before, after))

with core._db_lock, core._db() as conn:
    wo.append_log_entry(conn, kind="hold", account="probe-acct", name="probe", detail={"name": "probe"})
r = c_head.get("/api/v1/legacy-log/head")
check("head is 200 once the log has an entry", r.status_code == 200, r.status_code)
r = c_head.get("/api/v1/legacy-log/witnessed")
check("witnessed is 200 with no marks when unpinned",
      r.status_code == 200 and r.json().get("marks") == [], (r.status_code, r.text[:200]))

# Anchor inserted as a row. This test does not call open_window.
with core._db_lock, core._db() as conn:
    conn.execute(
        "INSERT INTO window_open_log (id, opened_at, opened_by) VALUES (1,?,?)",
        ("2026-10-12T00:00:00+00:00", "belt"))
wo.record_start("chain-a", "rotation")
wo.record_start("chain-a", "recovery")
with core._db_lock, core._db() as conn:
    log_id, entries = wo.export_log(conn)
    sigrow = conn.execute(
        "SELECT node_sig, seq FROM legacy_migration_log ORDER BY seq DESC LIMIT 1"
    ).fetchone()
ok, last = lw.verify_chain(entries, log_id)
check("record_start chain verifies on a second node", ok and last == entries[-1]["entry_hash"], last)
kinds = [e["kind"] for e in entries]
check("chain is hold then two migrate-pending entries",
      kinds == ["hold", "migrate-pending", "migrate-pending"], kinds)
details = [json.loads(e["detail"]).get("start_kind") for e in entries if e["kind"] == "migrate-pending"]
check("caller kind is in the entry detail, not the log kind",
      details == ["rotation", "recovery"], details)
check("node signature over the header verifies",
      _ed.checkvalid(bytes.fromhex(sigrow[0]), lw.header_bytes(entries[-1], log_id),
                     bytes.fromhex(core._NODE_PUB)))
check("R2 fields are present on the chained entry",
      entries[-1]["agent_prev_seq"] == entries[-2]["seq"]
      and entries[-1]["prev_hash"] == entries[-2]["entry_hash"]
      and "name_sha256" in entries[-1])

# ---------------------------------------------------------------- (b)(c) proof buckets
reset_hits()
spoof = client_at("203.0.113.30")
codes = [proof_get(spoof, "198.51.100.1").status_code for _ in range(rlw.PROOF_PER_IP)]
check("spoofed XFF from one peer: first per-IP cap of proofs are 200",
      codes == [200] * rlw.PROOF_PER_IP, set(codes))
r = proof_get(spoof, "198.51.100.2")
check("(b) a second spoofed X-Forwarded-For from the same peer is still 429",
      r.status_code == 429, r.status_code)
proof_keys = [k for k in core._hits if k.startswith("legacy-log:proof:") and ":global" not in k]
check("(b) both spoofed XFF values landed in the one peer bucket",
      proof_keys == ["legacy-log:proof:203.0.113.30"], proof_keys)

ip1 = client_at("203.0.113.10")
ip2 = client_at("203.0.113.20")
codes = [proof_get(ip1).status_code for _ in range(200)]
check("IP-1: first per-IP cap of proof requests are 200",
      codes[:rlw.PROOF_PER_IP] == [200] * rlw.PROOF_PER_IP, set(codes[:rlw.PROOF_PER_IP]))
check("IP-1: requests past the per-IP cap are 429",
      all(c == 429 for c in codes[rlw.PROOF_PER_IP:]), set(codes[rlw.PROOF_PER_IP:]))
r = proof_get(ip2)
check("(c) after IP-1 sends 200 proof requests, IP-2's first proof is 200",
      r.status_code == 200, (r.status_code, r.text[:180]))
check("(b) two real peers have two proof buckets",
      "legacy-log:proof:203.0.113.10" in core._hits and "legacy-log:proof:203.0.113.20" in core._hits)

proxy = client_at("127.0.0.1")
a = proof_get(proxy, "198.51.100.5")
b = proof_get(proxy, "198.51.100.6")
check("trusted proxy: two X-Forwarded-For values are two buckets and both 200",
      a.status_code == 200 and b.status_code == 200
      and "legacy-log:proof:198.51.100.5" in core._hits
      and "legacy-log:proof:198.51.100.6" in core._hits,
      (a.status_code, b.status_code))

# ---------------------------------------------------------------- (a) import-legacy
witness_priv = "11" * 32
witness_pub = _ed.publickey(bytes.fromhex(witness_priv)).hex()
k0_priv = "22" * 32
k0_pub = _ed.publickey(bytes.fromhex(k0_priv)).hex()
ilog = hashlib.sha256(b"art40-import-log").hexdigest()
W = lw.WitnessSet(1, [witness_pub])
built = Builder(ilog)
standard(built, k0_pub)
proof = built.proof(W, [signer_for(witness_priv, witness_pub)])
try:
    ident = lw.check_identity(proof, "zed", W, ilog)[2]
    direct_ok = ident["k0_pub"] == k0_pub and ident["late"] is False
except lw.WitnessRefused as e:
    direct_ok = False
    ident = str(e)
check("synthetic closed log passes check_identity", direct_ok, ident)

os.environ["CYBERNET_GENESIS_WITNESSES"] = witness_pub
os.environ["CYBERNET_GENESIS_LOG_ID"] = ilog
other_log = "ab" * 32
other = client_at("198.51.100.50")
filler = [other.post("/api/v1/agents/import-legacy", json={"log_id": other_log, "name": "zzz"}).status_code
          for _ in range(rlw.IMPORT_PER_LOG)]
check("other source fills the other log_id bucket with non-200s",
      filler == [400] * rlw.IMPORT_PER_LOG, set(filler))
r = other.post("/api/v1/agents/import-legacy", json={"log_id": other_log, "name": "zzz"})
check("other log_id bucket is full on the next request", r.status_code == 429, r.status_code)
for src_ip in ("198.51.100.50", "203.0.113.50"):
    for _ in range(ratesrc.SOURCE_AUTH_LIMIT):
        core._check_rate(f"src:auth:{src_ip}", limit=ratesrc.SOURCE_AUTH_LIMIT)
importer = client_at("203.0.113.50")
msg = rlw.import_message("zed", ilog, k0_pub, proof)
body = {
    "name": "zed", "public_key": k0_pub, "log_id": ilog, "proof": proof,
    "signature": _ed.sign(msg, bytes.fromhex(k0_priv), bytes.fromhex(k0_pub)).hex(),
}
r = importer.post("/api/v1/agents/import-legacy", json=body)
check("(a) import of log L is 200 after src:auth and another log_id are full",
      r.status_code == 200, (r.status_code, r.text[:300]))
check("import wrote legacy_imports and did not write name_bindings",
      imports_for("zed") == 1 and bindings("zed")[0] is None, bindings("zed"))

# unpinned answers 503 after the bucket step
saved_w = os.environ.pop("CYBERNET_GENESIS_WITNESSES")
os.environ.pop("CYBERNET_GENESIS_LOG_ID")
r = client_at("203.0.113.80").post("/api/v1/agents/import-legacy", json={"log_id": ilog, "name": "zed"})
check("unpinned import is 503 and still consumed a per-source token",
      r.status_code == 503 and "import-legacy:203.0.113.80" in core._hits, r.status_code)
os.environ["CYBERNET_GENESIS_WITNESSES"] = saved_w
os.environ["CYBERNET_GENESIS_LOG_ID"] = ilog

# ---------------------------------------------------------------- (d) weak keys
scalar_c = 0x13579BD
cpub = mixed_pub(scalar_c)
cmsg = core._name_claim_payload("weakclaim", cpub, ISSUED, EXPIRES)
csig = forge_sig(scalar_c, cpub, cmsg).hex()
check("premise: mixed-order claim signature passes checkvalid and fails weak_reason",
      _ed.checkvalid(bytes.fromhex(csig), cmsg, bytes.fromhex(cpub)) and wo.weak_reason(cpub) == "mixed-order")
claimer = client_at("203.0.113.60")
r = claimer.post("/api/v1/names/claim", data={
    "name": "weakclaim", "node_pubkey": cpub, "issued_at": ISSUED,
    "expires_at": EXPIRES, "signature": csig})
check("(d) mixed-order claim is 400", r.status_code == 400, (r.status_code, r.text[:200]))
check("(d) refused claim wrote no name_bindings row", bindings("weakclaim")[0] is None, bindings("weakclaim"))

sp = "33" * 32
spub = _ed.publickey(bytes.fromhex(sp)).hex()
ssig = _ed.sign(core._name_claim_payload("strongclaim", spub, ISSUED, EXPIRES),
                bytes.fromhex(sp), bytes.fromhex(spub)).hex()
r = claimer.post("/api/v1/names/claim", data={
    "name": "strongclaim", "node_pubkey": spub, "issued_at": ISSUED,
    "expires_at": EXPIRES, "signature": ssig})
check("(d) strong claim is still accepted", r.status_code == 200 and bindings("strongclaim")[0] == spub,
      (r.status_code, r.text[:200]))

old_priv = "44" * 32
old_pub = _ed.publickey(bytes.fromhex(old_priv)).hex()
old_sig = _ed.sign(core._name_claim_payload("weakrot", old_pub, ISSUED, EXPIRES),
                   bytes.fromhex(old_priv), bytes.fromhex(old_pub)).hex()
r = claimer.post("/api/v1/names/claim", data={
    "name": "weakrot", "node_pubkey": old_pub, "issued_at": ISSUED,
    "expires_at": EXPIRES, "signature": old_sig})
check("holder claim for the rotate belt is 200", r.status_code == 200, r.text[:200])
scalar_n = 0x2468ACE
npub = mixed_pub(scalar_n)
nmsg = core._name_claim_payload("weakrot", npub, ISSUED, EXPIRES)
nsig = forge_sig(scalar_n, npub, nmsg).hex()
rsig = _ed.sign(_rotate_payload("weakrot", old_pub, npub, ISSUED),
                bytes.fromhex(old_priv), bytes.fromhex(old_pub)).hex()
before = bindings("weakrot")
r = claimer.post("/api/v1/names/rotate", data={
    "name": "weakrot", "old_pubkey": old_pub, "new_pubkey": npub,
    "rotation_issued_at": ISSUED, "rotation_signature": rsig,
    "binding_issued_at": ISSUED, "binding_expires_at": EXPIRES,
    "binding_signature": nsig})
check("(d) mixed-order rotate is 400", r.status_code == 400, (r.status_code, r.text[:240]))
check("(d) refused rotate wrote no binding change and no rotation row",
      bindings("weakrot") == before == (old_pub, 0), bindings("weakrot"))

new_priv = "55" * 32
new_pub = _ed.publickey(bytes.fromhex(new_priv)).hex()
hold_sig = _ed.sign(core._name_claim_payload("strongrot", old_pub, ISSUED, EXPIRES),
                    bytes.fromhex(old_priv), bytes.fromhex(old_pub)).hex()
claimer.post("/api/v1/names/claim", data={
    "name": "strongrot", "node_pubkey": old_pub, "issued_at": ISSUED,
    "expires_at": EXPIRES, "signature": hold_sig})
strong_nsig = _ed.sign(core._name_claim_payload("strongrot", new_pub, ISSUED, EXPIRES),
                       bytes.fromhex(new_priv), bytes.fromhex(new_pub)).hex()
strong_rsig = _ed.sign(_rotate_payload("strongrot", old_pub, new_pub, ISSUED),
                       bytes.fromhex(old_priv), bytes.fromhex(old_pub)).hex()
r = claimer.post("/api/v1/names/rotate", data={
    "name": "strongrot", "old_pubkey": old_pub, "new_pubkey": new_pub,
    "rotation_issued_at": ISSUED, "rotation_signature": strong_rsig,
    "binding_issued_at": ISSUED, "binding_expires_at": EXPIRES,
    "binding_signature": strong_nsig})
check("(d) strong rotate is still accepted",
      r.status_code == 200 and bindings("strongrot")[0] == new_pub, (r.status_code, r.text[:200]))

# weak OLD key: checkvalid accepts the mixed-order holder, weak_reason does not.
# The rate gate runs first, so the refusal still spends a names-write token.
# Claim would 400 this key, so the binding is seeded directly.
scalar_old = 0x97531
old_weak = mixed_pub(scalar_old)
weak_new_priv = "77" * 32
weak_new_pub = _ed.publickey(bytes.fromhex(weak_new_priv)).hex()
weak_rmsg = _rotate_payload("weakold", old_weak, weak_new_pub, ISSUED)
weak_rsig = forge_sig(scalar_old, old_weak, weak_rmsg).hex()
weak_nsig = _ed.sign(core._name_claim_payload("weakold", weak_new_pub, ISSUED, EXPIRES),
                     bytes.fromhex(weak_new_priv), bytes.fromhex(weak_new_pub)).hex()
check("premise: weak old rotation passes checkvalid and fails weak_reason",
      _ed.checkvalid(bytes.fromhex(weak_rsig), weak_rmsg, bytes.fromhex(old_weak))
      and wo.weak_reason(old_weak) == "mixed-order"
      and wo.weak_reason(weak_new_pub) is None)
with core._db_lock, core._db() as conn:
    conn.execute(
        "INSERT INTO name_bindings (name, node_pubkey, issued_at, expires_at, signature) "
        "VALUES (?,?,?,?,?)",
        ("weakold", old_weak, ISSUED, EXPIRES, "ab" * 64))
reset_hits()
weak_ip = "203.0.113.61"
r = client_at(weak_ip).post("/api/v1/names/rotate", data={
    "name": "weakold", "old_pubkey": old_weak, "new_pubkey": weak_new_pub,
    "rotation_issued_at": ISSUED, "rotation_signature": weak_rsig,
    "binding_issued_at": ISSUED, "binding_expires_at": EXPIRES,
    "binding_signature": weak_nsig})
with core._db_lock:
    weak_bucket = core._hits.get(f"names-write:{weak_ip}")
real_weak_old = (r.status_code == 400 and "weak key" in r.text
                 and bindings("weakold") == (old_weak, 0)
                 and weak_bucket is not None and len(weak_bucket) == 1)
check("rotate with a weak old key is 400",
      r.status_code == 400 and "weak key" in r.text, (r.status_code, r.text[:240]))
check("weak old rotate wrote no rotation row and left the binding",
      bindings("weakold") == (old_weak, 0), bindings("weakold"))
check("weak old rotate spent a names-write token",
      weak_bucket is not None and len(weak_bucket) == 1,
      None if weak_bucket is None else len(weak_bucket))

# ---------------------------------------------------------------- (e) witness head
scalar_w = 0x111111
wpub = mixed_pub(scalar_w)
olog = hashlib.sha256(b"art40-observe-log").hexdigest()
OW = lw.WitnessSet(1, [wpub])
head = {
    "log_id": olog, "witness_set": OW.id, "seq": 1, "head_hash": "ab" * 32,
    "window_open_seq": None, "window_close_seq": None, "window_state": "unopened",
    **EMPTY_ROOTS,
}
wmsg = lw.head_bytes(head)
wsig = forge_sig(scalar_w, wpub, wmsg)
check("premise: mixed-order witness signature passes checkvalid",
      _ed.checkvalid(wsig, wmsg, bytes.fromhex(wpub)))
signed = {"head": head, "signatures": [{"witness": wpub, "sig": wsig.hex()}]}
try:
    lw.verify_head(signed, OW, olog)
    refused_head = False
except lw.WitnessRefused:
    refused_head = True
check("(e) mixed-order witness head fails verify_head", refused_head)

os.environ["CYBERNET_GENESIS_WITNESSES"] = wpub
os.environ["CYBERNET_GENESIS_LOG_ID"] = olog
observer = client_at("203.0.113.90")
r = observer.post("/api/v1/legacy-log/observe", json={"head": signed})
check("(e) observe of a mixed-order witness head is 400", r.status_code == 400, (r.status_code, r.text[:240]))
check("(e) refused head wrote no observe mark", observed(olog) == 0, observed(olog))

ident_pub = _ed._encodepoint(_ed._IDENT).hex()
IW = lw.WitnessSet(1, [ident_pub])
ihead = dict(head, witness_set=IW.id, head_hash="cd" * 32)
isig = (_ed._encodepoint(_ed._IDENT) + (0).to_bytes(32, "little")).hex()
signed_small = {"head": ihead, "signatures": [{"witness": ident_pub, "sig": isig}]}
os.environ["CYBERNET_GENESIS_WITNESSES"] = ident_pub
try:
    lw.verify_head(signed_small, IW, olog)
    small_refused = False
except lw.WitnessRefused:
    small_refused = True
r = observer.post("/api/v1/legacy-log/observe", json={"head": signed_small})
check("(e) pure small-order witness head fails on the observe route",
      small_refused and r.status_code == 400 and observed(olog) == 0,
      (small_refused, r.status_code, observed(olog)))

# item 8 still stands
r = client_at("203.0.113.91").post("/api/v1/agents/migrate", json={})
check("legacy migrate stub is still 409",
      r.status_code == 409 and r.json().get("error") == "legacy_migrate_replaced", r.text[:200])


def names_write(c, xff):
    return c.post("/api/v1/names/claim", data={}, headers={"X-Forwarded-For": xff})


def doh_probe(c, xff):
    return c.post("/dns-query", content=b"", headers={"X-Forwarded-For": xff})


def _bucket_keys(prefix):
    return sorted(k for k in list(core._hits) if k.startswith(prefix))


def two_names_write_buckets():
    """Two XFF clients behind the trusted peer, limit 1 each."""
    saved = rss.NAME_CLAIM_RATE_LIMIT
    rss.NAME_CLAIM_RATE_LIMIT = 1
    try:
        reset_hits()
        proxy = client_at("127.0.0.1")
        a = names_write(proxy, "198.51.100.71")
        b = names_write(proxy, "198.51.100.72")
        keys = _bucket_keys("names-write:")
        ok = (a.status_code == 400 and b.status_code == 400
              and keys == ["names-write:198.51.100.71", "names-write:198.51.100.72"])
        return ok, (a.status_code, b.status_code, keys)
    finally:
        rss.NAME_CLAIM_RATE_LIMIT = saved


def two_doh_buckets():
    saved = routes_doh.DOH_RATE_LIMIT
    routes_doh.DOH_RATE_LIMIT = 1
    try:
        reset_hits()
        proxy = client_at("127.0.0.1")
        a = doh_probe(proxy, "198.51.100.81")
        b = doh_probe(proxy, "198.51.100.82")
        keys = _bucket_keys("doh:")
        ok = (a.status_code == 415 and b.status_code == 415
              and keys == ["doh:198.51.100.81", "doh:198.51.100.82"])
        return ok, (a.status_code, b.status_code, keys)
    finally:
        routes_doh.DOH_RATE_LIMIT = saved


def spoofed_xff_shares_peer():
    """Untrusted peer. Two spoofed XFF values share that peer's bucket.
    An IPv6 peer folds to its /64, which a client.host key does not."""
    saved = rss.NAME_CLAIM_RATE_LIMIT
    rss.NAME_CLAIM_RATE_LIMIT = 1
    peer = "2001:db8:abcd:12::5"
    bucket = core._source_key(peer)
    try:
        reset_hits()
        c = client_at(peer)
        a = names_write(c, "198.51.100.91")
        b = names_write(c, "198.51.100.92")
        keys = _bucket_keys("names-write:")
        ok = (a.status_code == 400 and b.status_code == 429
              and keys == [f"names-write:{bucket}"])
        return ok, (a.status_code, b.status_code, keys, bucket)
    finally:
        rss.NAME_CLAIM_RATE_LIMIT = saved


names_ok, names_extra = two_names_write_buckets()
check("two XFF clients behind the trusted peer get two names-write buckets",
      names_ok, names_extra)
doh_ok, doh_extra = two_doh_buckets()
check("two XFF clients behind the trusted peer get two DoH buckets",
      doh_ok, doh_extra)
spoof_ok, spoof_extra = spoofed_xff_shares_peer()
check("spoofed XFF from an untrusted peer shares the peer's bucket",
      spoof_ok, spoof_extra)

# ---------------------------------------------------------------- mutants
print("mutants:")


def record_mutant(name, row, real_ok, mutant_fails):
    MUTANTS.append((name, row, real_ok, mutant_fails))
    check(f"MUTANT {name}: real passes and mutant fails the row", real_ok and mutant_fails,
          (real_ok, mutant_fails))


# 1. bucket keyed globally (proof global == per-IP, no per-IP bucket)
reset_hits()
real_charge = rlw.charge_proof

def global_only(src, limit=rlw.PROOF_PER_IP):
    core._check_rate("legacy-log:proof:global", limit=limit)

rlw.charge_proof = global_only
try:
    g1 = client_at("203.0.113.70")
    g2 = client_at("203.0.113.71")
    for _ in range(200):
        proof_get(g1)
    mutant_status = proof_get(g2).status_code
finally:
    rlw.charge_proof = real_charge
record_mutant("bucket keyed globally",
              "IP-2 proof after IP-1's 200",
              True, mutant_status != 200)

# 2. signature checked after the write
real_admit = wo.run_admission

def write_then(verify, write):
    result = write()
    verify()
    return result

wo.run_admission = write_then
order_pub = _ed.publickey(bytes.fromhex("66" * 32)).hex()
try:
    r = claimer.post("/api/v1/names/claim", data={
        "name": "ordermut", "node_pubkey": order_pub, "issued_at": ISSUED,
        "expires_at": EXPIRES, "signature": "00" * 64})
    mutant_wrote = bindings("ordermut")[0] == order_pub and r.status_code == 400
finally:
    wo.run_admission = real_admit
r = claimer.post("/api/v1/names/claim", data={
    "name": "orderreal", "node_pubkey": order_pub, "issued_at": ISSUED,
    "expires_at": EXPIRES, "signature": "00" * 64})
real_clean = r.status_code == 400 and bindings("orderreal")[0] is None
record_mutant("signature checked after write",
              "bad claim signature leaves no name_bindings row",
              real_clean, mutant_wrote)

# 3. weak_reason skipped on rotate
real_rot = rss._rotate_weak_reason
rss._rotate_weak_reason = lambda pub: None
try:
    r = claimer.post("/api/v1/names/rotate", data={
        "name": "weakrot", "old_pubkey": old_pub, "new_pubkey": npub,
        "rotation_issued_at": ISSUED, "rotation_signature": rsig,
        "binding_issued_at": ISSUED, "binding_expires_at": EXPIRES,
        "binding_signature": nsig})
    mutant_rot = r.status_code == 200 and bindings("weakrot") == (npub, 1)
finally:
    rss._rotate_weak_reason = real_rot
record_mutant("weak_reason skipped on rotate",
              "mixed-order rotate is 400 and writes nothing",
              True, mutant_rot)

# 3b. weak_reason on old_pubkey only, turned into a no-op.
# The new key stays checked, so this is not the whole-function mutant above.
real_rot_old = rss._rotate_weak_reason


def skip_old_only(pub, _real=real_rot_old, _old=old_weak):
    if pub == _old:
        return None
    return _real(pub)


rss._rotate_weak_reason = skip_old_only
try:
    r = client_at("203.0.113.63").post("/api/v1/names/rotate", data={
        "name": "weakold", "old_pubkey": old_weak, "new_pubkey": weak_new_pub,
        "rotation_issued_at": ISSUED, "rotation_signature": weak_rsig,
        "binding_issued_at": ISSUED, "binding_expires_at": EXPIRES,
        "binding_signature": weak_nsig})
    mutant_old = r.status_code == 200 and bindings("weakold") == (weak_new_pub, 1)
finally:
    rss._rotate_weak_reason = real_rot_old
record_mutant("weak_reason on old_pubkey is a no-op",
              "weak old_pubkey on rotate is 400 and writes nothing",
              real_weak_old, mutant_old)

# 4. proxy headers trusted from an untrusted peer
reset_hits()
core._trust_forwarded_always = True
try:
    liar = client_at("203.0.113.40")
    for _ in range(rlw.PROOF_PER_IP):
        proof_get(liar, "198.51.100.8")
    mutant_xff = proof_get(liar, "198.51.100.9").status_code
finally:
    core._trust_forwarded_always = False
record_mutant("proxy headers trusted",
              "second spoofed XFF from one untrusted peer is 429",
              True, mutant_xff == 200)

# 5. head verified with checkvalid only (mixed-order witness admitted)
os.environ["CYBERNET_GENESIS_WITNESSES"] = wpub
os.environ["CYBERNET_GENESIS_LOG_ID"] = olog
real_admit_key = lw.witness_key_admitted
lw.witness_key_admitted = lambda pub: None
try:
    try:
        lw.verify_head(signed, OW, olog)
        mutant_verify = True
    except lw.WitnessRefused:
        mutant_verify = False
    r = observer.post("/api/v1/legacy-log/observe", json={"head": signed})
    mutant_route = r.status_code == 200 and observed(olog) == 1
finally:
    lw.witness_key_admitted = real_admit_key
record_mutant("checkvalid only (no small-order component check)",
              "mixed-order witness head is refused",
              True, mutant_verify and mutant_route)

# 6-8. limiters keyed on the direct peer address
def client_host_source(request):
    peer = request.client
    return peer.host if peer else "unknown"

real_source = core.request_source
core.request_source = client_host_source
try:
    names_mut_ok, names_mut_extra = two_names_write_buckets()
    doh_mut_ok, doh_mut_extra = two_doh_buckets()
    spoof_mut_ok, spoof_mut_extra = spoofed_xff_shares_peer()
finally:
    core.request_source = real_source
record_mutant("names-write keyed on client.host",
              "two XFF clients behind the trusted peer get two names-write buckets",
              names_ok, not names_mut_ok)
record_mutant("doh keyed on client.host",
              "two XFF clients behind the trusted peer get two DoH buckets",
              doh_ok, not doh_mut_ok)
record_mutant("names-write keyed on client.host (untrusted peer)",
              "spoofed XFF from an untrusted peer shares the peer's bucket",
              spoof_ok, not spoof_mut_ok)
if not names_mut_ok:
    print(f"  info names-write client.host mutant: {names_mut_extra}")
if not doh_mut_ok:
    print(f"  info doh client.host mutant: {doh_mut_extra}")
if not spoof_mut_ok:
    print(f"  info spoof client.host mutant: {spoof_mut_extra}")

# 6. presented key is not the witnessed inception key
os.environ["CYBERNET_GENESIS_WITNESSES"] = witness_pub
os.environ["CYBERNET_GENESIS_LOG_ID"] = ilog
k1_priv = "99" * 32
k1_pub = _ed.publickey(bytes.fromhex(k1_priv)).hex()
k1_msg = rlw.import_message("zed", ilog, k1_pub, proof)
k1_sig = _ed.sign(k1_msg, bytes.fromhex(k1_priv), bytes.fromhex(k1_pub))
check("premise: fresh K1 signature verifies over the honest zed proof",
      _ed.checkvalid(k1_sig, k1_msg, bytes.fromhex(k1_pub)) and k1_pub != k0_pub)
before_k1 = imports_for("zed")
k1_body = {
    "name": "zed", "public_key": k1_pub, "log_id": ilog, "proof": proof,
    "signature": k1_sig.hex(),
}
r = client_at("203.0.113.110").post("/api/v1/agents/import-legacy", json=k1_body)
real_inception = (r.status_code == 400 and "not the witnessed inception key" in r.text
                  and imports_for("zed") == before_k1)
check("(a) fresh K1 over an honest zed proof is 400 and writes no import",
      real_inception, (r.status_code, r.text[:240], before_k1, imports_for("zed")))
real_inception_ok = rlw.witnessed_inception_ok
rlw.witnessed_inception_ok = lambda ident, pub: True
try:
    r = client_at("203.0.113.112").post("/api/v1/agents/import-legacy", json=k1_body)
    mutant_inception = r.status_code == 200 and imports_for("zed") == before_k1 + 1
finally:
    rlw.witnessed_inception_ok = real_inception_ok
record_mutant("inception key check deleted",
              "fresh K1 over honest zed proof is 400 and writes no import",
              real_inception, mutant_inception)

# 7. cutover k0_pub differs from the migrate-pending entry
cut_priv = "ab" * 32
cut_pub = _ed.publickey(bytes.fromhex(cut_priv)).hex()
mismatch = Builder(ilog)
mismatch.add("window-open")
add_closure(mismatch)
mismatch.add("hold", 7, "zed")
mismatch.add("migrate-pending", 7, "zed", 1, k0_pub, at=T0 + 10)
close = mismatch.add("window-close", at=T0 + 30 * DAY)
mismatch.add("cutover", 7, "zed", 1, cut_pub, {"window_close_seq": close}, at=T0 + 30 * DAY)
proof_mis = mismatch.proof(W, [signer_for(witness_priv, witness_pub)])
try:
    lw.check_identity(proof_mis, "zed", W, ilog)
    mismatch_why = ""
except lw.WitnessRefused as e:
    mismatch_why = str(e)
mis_msg = rlw.import_message("zed", ilog, cut_pub, proof_mis)
mis_sig = _ed.sign(mis_msg, bytes.fromhex(cut_priv), bytes.fromhex(cut_pub))
check("premise: presented key is the cutover key and its signature verifies",
      cut_pub != k0_pub and _ed.checkvalid(mis_sig, mis_msg, bytes.fromhex(cut_pub)))
before_mis = imports_for("zed")
mis_body = {
    "name": "zed", "public_key": cut_pub, "log_id": ilog, "proof": proof_mis,
    "signature": mis_sig.hex(),
}
r = client_at("203.0.113.111").post("/api/v1/agents/import-legacy", json=mis_body)
real_cut = ("cutover does not match the migration it activates" in mismatch_why
            and r.status_code == 400
            and "cutover does not match the migration it activates" in r.text
            and "not the witnessed inception key" not in r.text
            and imports_for("zed") == before_mis)
check("(b) cutover k0 differing from migrate-pending is 400 from check_identity",
      real_cut, (mismatch_why, r.status_code, r.text[:240], before_mis, imports_for("zed")))
real_match = lw.migration_matches_cutover
lw.migration_matches_cutover = lambda *args: True
try:
    try:
        ident_mis = lw.check_identity(proof_mis, "zed", W, ilog)[2]
        ident_ok = ident_mis["k0_pub"] == cut_pub
    except lw.WitnessRefused as e:
        ident_ok = False
        ident_mis = str(e)
    r = client_at("203.0.113.113").post("/api/v1/agents/import-legacy", json=mis_body)
    mutant_cut = ident_ok and r.status_code == 200 and imports_for("zed") == before_mis + 1
finally:
    lw.migration_matches_cutover = real_match
record_mutant("cutover k0 match deleted",
              "cutover k0 differing from migrate-pending is 400",
              real_cut, mutant_cut)

print("mutant table:")
print(f"  {'mutant':<52} {'row':<56} real mutant-fails")
for name, row, real_ok, mutant_fails in MUTANTS:
    print(f"  {name:<52} {row:<56} {str(real_ok):<5} {mutant_fails}")

print(f"{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
