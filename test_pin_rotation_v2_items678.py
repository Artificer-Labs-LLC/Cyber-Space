#!/usr/bin/env python3
"""Pin-rotation v2 belt, items678 (split from test_pin_rotation_v2.py)."""
from pinrot_common import *  # noqa: F401,F403
from pinrot_common import _round_k, _flat_nf, _flat_doc, _ed, _fed_env  # noqa: F401

# ================================================================ item 6
print("item 6: pre-verify charge per cert, before _norm_cert, outside the lock", flush=True)
add_peer(pk6)
n6 = "budget"
k6 = seed()
claim_gate_pin(n6, k6)
flood = [nf.mint_cert(n6, k6, pub(seed()), head(n6)[1] + 1, head(n6)[2],
                      issued_at=ISSUED) for _ in range(128)]


def run_budget():
    reset_rates()
    v0 = nf._verify_calls
    r = post(flood)
    return r.status_code == 200 and (nf._verify_calls - v0) <= \
        core.NAMES_GOSSIP_VERIFY_PER_CALL, nf._verify_calls - v0


real, vr = run_budget()
check(f"128 rotation certs in one POST cost <= NAMES_GOSSIP_VERIFY_PER_CALL verifies ({vr})",
      real)


def norm_then_charge(certs, sender_pub, verify_box):
    for raw in certs:
        nf._norm_cert(raw)
    adm = []
    for raw in certs:
        if not core._charge_one_rotation(sender_pub, verify_box):
            return adm, True
        adm.append(raw)
    return adm, False


with patched(core, "charge_rotation_certs", norm_then_charge):
    mut, vm = run_budget()
mutant("charge after _norm_cert", "128 certs cost <= per-call verifies", real, mut)


def run_namefork_first():
    reset_rates()
    with core._db_lock:
        core._hits[f"namefork:{pk6}"] = [time.time()] * 32
    v0 = nf._verify_calls
    r = post(flood[:1])
    return r.status_code == 429 and nf._verify_calls == v0


real = run_namefork_first()
check("flooding sender is charged and stopped before the first verify (429, 0 verifies)",
      real)
with patched(core, "charge_rotation_certs", norm_then_charge):
    mut = run_namefork_first()
mutant("namefork charged after the first verify", "flooding sender 0 verifies",
       real, mut)
src = inspect.getsource(federation.fed_names_gossip)
check("rotation pre-pass is called outside the DB lock in the route",
      "ingest_rotation_certs(" in src and "_db_lock" not in src.split(
          "ingest_rotation_certs(")[0].split("verify_box = [0]")[-1])

# ================================================================ item 7
print("item 7: persisted per-name round limit (FORK GATE)", flush=True)


def run_rate():
    n7 = f"rate{secrets.token_hex(3)}"
    k1, k2 = seed(), seed()
    claim_gate_pin(n7, k1)
    t = next_round()
    a = cert_next(n7, k1, pub(k2))
    ingest([a], now=t)
    b = cert_next(n7, k2, pub(seed()))
    r = ingest([b], now=t + 1)          # second POST, same round
    return head(n7)[0] == pub(k2) and head(n7)[1] == 1 and \
        r["outcomes"] == ["rate-held"]


real = run_rate()
check("two POSTs in one round cannot move a pin A->B->C (persisted in DB)", real)
with patched(nf, "rotations_per_round", lambda: 2):
    mut = run_rate()
mutant("per-POST rounds (fork gate not persisted)", "two POSTs move one hop",
       real, mut)
check("round pause labelled FORK GATE (not just a rate bound) in code and docs",
      "FORK GATE" in _flat_nf and "not just a rate bound" in _flat_nf
      and "FORK GATE" in _flat_doc and "not just a rate bound" in _flat_doc
      and "RATE BOUND" not in _flat_nf and "RATE BOUND" not in _flat_doc
      and "not a fork gate" not in _flat_nf and "not a fork gate" not in _flat_doc)

# ================================================================ item 8
print("item 8: kind binding", flush=True)
n8 = "kind"
k8 = seed()
claim_gate_pin(n8, k8)
base = cert_next(n8, k8, pub(seed()))
relabel_kind = dict(base, kind="name-claim")
other_tag = b"cyberspace-name-claim/v2"
st8 = head(n8)
p8 = pub(seed())
payload = nf.cert_payload(n8, pub(k8), p8, ISSUED, st8[1] + 1, st8[2], tag=other_tag)
osig = _ed.sign(payload, k8, bytes.fromhex(pub(k8))).hex()
relabel_tag = dict(base, new_pubkey=p8, signature=osig, tag=other_tag.decode())


def run_kind():
    return nf._norm_cert(relabel_kind) is None and nf._norm_cert(relabel_tag) is None


real = run_kind()
check("cert relabelled with another kind or tag is rejected", real)
with patched(nf, "_tag_ok", lambda raw: True), \
        patched(nf, "_signing_tag", lambda raw: str(raw.get("tag")).encode()):
    mut = run_kind()
mutant("kind binding dropped", "relabelled cert rejected", real, mut)
check("run_tests.sh runs the fed/envelope.py self-test",
      re.search(r"fed/envelope\.py", open(os.path.join(HERE, "run_tests.sh")).read())
      is not None)


finish()
