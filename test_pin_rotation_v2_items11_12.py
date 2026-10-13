#!/usr/bin/env python3
"""Pin-rotation v2 belt, items11_12 (split from test_pin_rotation_v2.py)."""
from pinrot_common import *  # noqa: F401,F403
from pinrot_common import _round_k, _flat_nf, _flat_doc, _ed, _fed_env  # noqa: F401

# Fixture from item 4: a claim-gate pin named "abac" (gossip-out and the
# provenance rows read it).
nm = "abac"
kA = seed()
claim_gate_pin(nm, kA)
origin = head(nm)[2]
add_peer(pk6)

# ================================================================ item 11
print("item 11: pin provenance and the startup guard", flush=True)
with core._db_lock, core._db() as c:
    out = nf.pin_initial(c, "rotseed", pub(seed()), source="rotation",
                         binding=binding("rotseed", seed()))
check("a rotation can never create a pin (pin_initial refuses source=rotation)",
      out == "refused-source" and head("rotseed") is None)
first = db("SELECT source, origin_hash FROM name_pin_log WHERE name='abac'"
           " ORDER BY id LIMIT 1")[0]
check("first pin-log entry records source + hash of the binding",
      first[0] == "claim_gate" and first[1] == db("SELECT origin_hash FROM"
      " name_pin_origins WHERE name='abac' ORDER BY rowid LIMIT 1")[0][0])
with core._db_lock, core._db() as c:
    cnt = nf._pin_count(c)
with patched(nf, "pin_cap", lambda: cnt):
    with core._db_lock, core._db() as c:
        capped = nf.pin_initial(c, "overcap", pub(seed()), source="claim_gate",
                                binding=binding("overcap", seed()))
check("pin cap holds (same cap as name_bindings)", capped in ("refused-cap",)
      or capped == "refused-source", capped)
bcap = binding("overcap2", seed())
with patched(nf, "pin_cap", lambda: cnt):
    with core._db_lock, core._db() as c:
        capped2 = nf.pin_initial(c, "overcap2", bcap["node_pubkey"],
                                 source="claim_gate", binding=bcap)
check("pin cap refuses a new pin at the cap", capped2 == "refused-cap", capped2)


def plant(name, pubkey, source, ohash, origin_row=None):
    with core._db_lock, core._db() as c:
        if origin_row:
            c.execute("INSERT OR REPLACE INTO name_pin_origins (origin_hash,"
                      " source, name, pubkey, issued_at, expires_at, signature,"
                      " recorded_at) VALUES (?,?,?,?,?,?,?,?)",
                      (ohash, source, *origin_row, nf._now()))
        c.execute("INSERT INTO name_pin_log (name, pubkey, seq, prev_pubkey,"
                  " cert_signature, recorded_at, kind, source, origin_hash,"
                  " head_hash) VALUES (?,?,0,'','',?,'pin',?,?,?)",
                  (name, pubkey, nf._now(), source, ohash, ohash))


def guard():
    with core._db_lock, core._db() as c:
        return dict(nf.startup_guard(c))


def planted_cases():
    tag = secrets.token_hex(2)
    cases = {}
    # no provenance
    plant(f"np{tag}", pub(seed()), "", "")
    cases["no provenance"] = f"np{tag}"
    # source=rotation pointing at a REAL binding (only the source check stops it)
    kr = seed()
    br = binding(f"rs{tag}", kr)
    ohr = nf.origin_hash(br["name"], br["node_pubkey"], br["issued_at"],
                         br["expires_at"], br["signature"])
    plant(br["name"], br["node_pubkey"], "rotation", ohr,
          (br["name"], br["node_pubkey"], br["issued_at"], br["expires_at"],
           br["signature"]))
    cases["source=rotation"] = br["name"]
    # fake label: claim_gate, hash points at no stored binding
    plant(f"fl{tag}", pub(seed()), "claim_gate", secrets.token_hex(32))
    cases["fake label"] = f"fl{tag}"
    # hash points at a binding for a different key
    kw, kp = seed(), seed()
    bw = binding(f"wk{tag}", kw)
    ohw = nf.origin_hash(bw["name"], bw["node_pubkey"], bw["issued_at"],
                         bw["expires_at"], bw["signature"])
    plant(bw["name"], pub(kp), "claim_gate", ohw,
          (bw["name"], bw["node_pubkey"], bw["issued_at"], bw["expires_at"],
           bw["signature"]))
    cases["wrong binding"] = bw["name"]
    # valid key, junk signature (hash computed over the junk, so it matches)
    kj = seed()
    junk = "ab" * 64
    ohj = nf.origin_hash(f"js{tag}", pub(kj), ISSUED, EXPIRES, junk)
    plant(f"js{tag}", pub(kj), "claim_gate", ohj,
          (f"js{tag}", pub(kj), ISSUED, EXPIRES, junk))
    cases["junk signature"] = f"js{tag}"
    # control: an honest claim_gate pin survives
    good = f"ok{tag}"
    claim_gate_pin(good, seed())
    cases["control"] = good
    return cases


def run_guard(which):
    cases = planted_cases()
    refused = guard()
    ok_ctl = cases["control"] not in refused and head(cases["control"]) is not None
    hit = cases[which] in refused and head(cases[which]) is None
    return ok_ctl and hit


for which in ("no provenance", "source=rotation", "fake label",
              "wrong binding", "junk signature"):
    check(f"startup guard refuses a planted pin: {which}", run_guard(which))

real_src = run_guard("source=rotation")
with patched(nf, "guard_check", lambda conn, name: nf.guard_resolve(
        conn, name, nf._latest(conn, name)[2], nf._latest(conn, name)[6])):
    mut_src = run_guard("source=rotation")
mutant("guard has no source check", "source=rotation pin refused", real_src, mut_src)
real_fl = run_guard("fake label") and run_guard("wrong binding")
with patched(nf, "guard_resolve", lambda *a: None):
    mut_fl = run_guard("fake label") and run_guard("wrong binding")
mutant("guard checks the label, not the hash", "fake label / wrong binding refused",
       real_fl, mut_fl)
real_js = run_guard("junk signature")
with patched(nf, "guard_sig_ok", lambda *a: True):
    mut_js = run_guard("junk signature")
mutant("guard runs checkvalid on the key but skips the signature verify",
       "junk signature refused", real_js, mut_js)


def run_unpin_reclaim():
    tag = secrets.token_hex(2)
    nm = f"rc{tag}"
    plant(nm, pub(seed()), "claim_gate", secrets.token_hex(32))
    guard()
    rows = db("SELECT kind FROM name_pin_log WHERE name=? ORDER BY id", (nm,))
    kinds = [r[0] for r in rows]
    reset_rates()
    hb = binding(nm, seed(), issued=iso(datetime.now(timezone.utc)
                                         - timedelta(seconds=5)))
    r = client.post("/api/v1/names/claim", data=hb)
    return (kinds == ["pin", "unpin"] and r.status_code == 200
            and head(nm)[0] == hb["node_pubkey"]), (kinds, r.status_code)


real, ui = run_unpin_reclaim()
check(f"refused pin -> UNPINNED by an appended entry; original kept; re-claim works {ui}",
      real)


def delete_unpin(conn, name, reason):
    conn.execute("DROP TRIGGER IF EXISTS name_pin_log_no_delete")
    conn.execute("DELETE FROM name_pin_log WHERE name=?", (name,))
    nf._sync_cache(conn, name)


with patched(nf, "unpin", delete_unpin):
    mut, um = run_unpin_reclaim()
with core._db_lock, core._db() as c:
    nf.ensure_schema(c)
mutant("trigger dropped; refused pin deleted", "log keeps original + refusal",
       real, mut)
trig_ok = False
with core._db_lock, core._db() as c:
    try:
        c.execute("DELETE FROM name_pin_log WHERE name='abac'")
    except sqlite3.DatabaseError:
        trig_ok = True
check("name_pin_log DELETE aborts (insert-only trigger)", trig_ok)

# ================================================================ item 12
print("item 12: binding path, /reach, gossip-out, RESOLVER.md", flush=True)
sb = pub(seed())


def run_binding_gate():
    nm = f"bg{secrets.token_hex(3)}"
    b = binding(nm, seed())
    v0 = core._gossip_binding_verifies
    out = core.ingest_gossiped_binding(dict(b), sender_pub=sb)
    reset_rates()
    v1 = core._gossip_binding_verifies
    nm2 = f"bg{secrets.token_hex(3)}"
    r = post([], bindings=[binding(nm2, seed())])
    v2 = core._gossip_binding_verifies
    return (out == "dropped-unpinned" and v1 == v0 and r.status_code == 200
            and r.json()["outcomes"] == ["dropped-unpinned"] and v2 == v1)


real = run_binding_gate()
check("unpinned name from a non-OOB sender: 0 verifies on both gossip paths", real)
with patched(core, "_binding_pin_gate", lambda *a: None):
    mut = run_binding_gate()
mutant("pin gate after verify on the binding path", "0 verifies for unpinned", real, mut)
check("sender_pub=None is refused",
      core.ingest_gossiped_binding(binding("nosender", seed())) == "dropped-no-sender")

ncon = "contested-reach"
kq = seed()
claim_gate_pin(ncon, kq)
with core._db_lock, core._db() as c:
    nf._mark_contested(c, ncon, "belt")


def run_reach():
    return client.get(f"/api/v1/names/{ncon}/reach").status_code == 409


real = run_reach()
check("/names/{name}/reach returns 409 for a contested name", real)
import routes_social_serve as rss  # noqa: E402
with patched(nf, "is_contested", lambda conn, name: False):
    mut = run_reach()
mutant("reach ignores contested", "/reach 409", real, mut)

sent = []


def run_gossip_out():
    sent.clear()
    with patched(core, "_post_to_peer_path", lambda url, path, env: sent.append(env)):
        core._names_gossip_out()
        time.sleep(0.5)
    names = set()
    for env in sent:
        for b in env["body"].get("bindings", []):
            names.add(b["name"])
    return bool(sent) and ncon not in names and "abac" in names


real = run_gossip_out()
check("gossip-out skips contested names' bindings", real)
with patched(nf, "is_contested", lambda conn, name: False):
    mut = run_gossip_out()
mutant("gossip-out includes contested names", "contested skipped", real, mut)
check("RESOLVER.md states contested behaviour honestly (no recovery path in this build)",
      "no recovery path" in " ".join(doc.split()) and "CONTESTED" in doc)


finish()
