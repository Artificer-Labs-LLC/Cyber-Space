#!/usr/bin/env python3
"""Pin-rotation v2 belt, items12 (split from test_pin_rotation_v2.py)."""
from pinrot_common import *  # noqa: F401,F403
from pinrot_common import _round_k, _flat_nf, _flat_doc, _ed, _fed_env  # noqa: F401

# ================================================================ item 1
print("item 1: weak-key and strict checks in _norm_cert", flush=True)
params = list(inspect.signature(nf.ingest_rotation_round).parameters)
check("signature is ingest_rotation_round(conn, certs, sender_pub, ...)",
      params[:3] == ["conn", "certs", "sender_pub"], params)
check("ORDER8 premise: canonical and order 8",
      nf._strict_point_ok(bytes.fromhex(ORDER8))
      and _ed._is_small_order(_ed._decodepoint_strict(bytes.fromhex(ORDER8))))


def row_weak_new(target, label):
    def run():
        nm = f"w{secrets.token_hex(4)}"
        k1 = seed()
        claim_gate_pin(nm, k1)
        c = cert_next(nm, k1, target)
        r = ingest([c], now=next_round())
        return r["accepted"] == {} and head(nm)[0] == pub(k1)
    real = run()
    check(f"{label} new key refused; pin unmoved", real)
    with patched(nf, "_keys_ok", lambda rec: True), \
            patched(nf, "_weak", lambda p: None):
        mut = run()
    mutant(f"weak/strict key checks dropped from _norm_cert ({label})",
           f"{label} refused", real, mut)


row_weak_new(ZERO, "zero-key seed")
row_weak_new(ORDER8, "order-8 torsion")
row_weak_new(mixed_pub(seed()), "mixed-order")

# small-order OLD key with a forged signature is refused before verify
nm = "wold"
v0 = nf._verify_calls
forged = {"v": 2, "kind": "name-rotate", "tag": nf.TAG.decode(), "name": nm,
          "old_pubkey": ORDER8, "new_pubkey": pub(seed()), "issued_at": ISSUED,
          "seq": 1, "prev_hash": "11" * 32, "signature": "00" * 64}
check("order-8 OLD key refused before verify (0 verifies)",
      nf._norm_cert(forged) is None and nf._verify_calls == v0)

# non-OOB relay of an unpinned name: binding refused, rotation never pins
sender = pub(seed())
b = binding("relayname", seed())


def run_relay():
    out = core.ingest_gossiped_binding(dict(b), sender_pub=sender)
    pinned = head("relayname") is not None
    return out == "dropped-unpinned" and not pinned


real = run_relay()
check("non-OOB relay of an unpinned name is refused and not pinned", real)
with patched(nf, "sender_may_introduce", lambda s: True):
    mut = run_relay()
mutant("introducer check dropped (any sender introduces)",
       "non-OOB relay refused", real, mut)
os.environ["CYBERNET_OOB_NODE_PINS"] = sender
b2 = binding("oobname", seed())
check("OOB-allowlisted relay inserts and pins with oob_allowlist provenance",
      core.ingest_gossiped_binding(dict(b2), sender_pub=sender) == "inserted"
      and db("SELECT source FROM name_pin_log WHERE name='oobname'")[0][0]
      == "oob_allowlist")
os.environ.pop("CYBERNET_OOB_NODE_PINS")

# ================================================================ item 2
print("item 2: a cert never introduces a name; E1", flush=True)


def run_unknown():
    nm = f"ghost{secrets.token_hex(3)}"
    k1 = seed()
    c = nf.mint_cert(nm, k1, pub(seed()), 1, "22" * 32, issued_at=ISSUED)
    e0 = nf.evidence_count(sqlite3.connect(":memory:")) if False else \
        db("SELECT COUNT(*) FROM name_cert_evidence")[0][0]
    r = ingest([c], sender=pub(seed()), now=next_round())
    e1 = db("SELECT COUNT(*) FROM name_cert_evidence")[0][0]
    return head(nm) is None and r["accepted"] == {} and e1 == e0 + 1


real = run_unknown()
check("unknown-name cert refused as a pin and kept as evidence", real)


def introduce(conn, rec, sender, now=None):
    rec = dict(rec)
    conn.execute(
        "INSERT INTO name_pin_log (name, pubkey, seq, prev_pubkey,"
        " cert_signature, recorded_at, kind, source, head_hash, cert)"
        " VALUES (?,?,?,?,?,?,'rotate','rotation',?,?)",
        (rec["name"], rec["new_pubkey"], rec["seq"], rec["old_pubkey"],
         rec["signature"], nf._now(), rec["cert_hash"],
         json.dumps(nf._wire(rec))))
    return "evidence"


with patched(nf, "_keep_evidence", introduce):
    mut = run_unknown()
mutant("cert introduces the name", "unknown-name cert refused", real, mut)


def run_e1():
    nm = f"e1n{secrets.token_hex(3)}"
    k1 = seed()
    prev = secrets.token_hex(32)
    pair = [nf.mint_cert(nm, k1, pub(seed()), 1, prev, issued_at=ISSUED),
            nf.mint_cert(nm, k1, pub(seed()), 1, prev, issued_at=ISSUED)]
    ingest(pair, sender=pub(seed()), now=next_round())
    unc = not contested(nm)
    reset_rates()
    hb = binding(nm, seed(), issued=iso(datetime.now(timezone.utc)
                                         - timedelta(seconds=5)))
    r = client.post("/api/v1/names/claim", data=hb)
    return unc and r.status_code == 200


real = run_e1()
check("E1: two self-made certs leave an unknown name uncontested; honest claim 200",
      real)
with patched(nf, "birth_contest_allowed", lambda *a: True), \
        patched(nf, "birth_contest_needs_origin", lambda: False):
    mut = run_e1()
mutant("E1 current branch (contested from birth on any two certs)",
       "E1 self-made certs leave name uncontested", real, mut)

# E1 positive: the node HOLDS a binding for the certs' old key
nm = "e1held"
k1 = seed()
hb = binding(nm, k1)
with core._db_lock, core._db() as c:
    c.execute("INSERT INTO name_bindings (name, node_pubkey, issued_at,"
              " expires_at, signature) VALUES (?,?,?,?,?)",
              (nm, hb["node_pubkey"], hb["issued_at"], hb["expires_at"],
               hb["signature"]))
# KINDS anchor: a chain that starts in v2 anchors on claim_anchor(name, key).
oh = nf.claim_anchor(nm, hb["node_pubkey"])
pair = [nf.mint_cert(nm, k1, pub(seed()), 1, oh, issued_at=ISSUED),
        nf.mint_cert(nm, k1, pub(seed()), 1, oh, issued_at=ISSUED)]
ingest(pair, now=next_round())
check("E1: held binding for the old key + two certs on its claim anchor -> contested, no pin",
      contested(nm) and head(nm) is None)


finish()
