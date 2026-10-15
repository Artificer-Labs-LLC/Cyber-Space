#!/usr/bin/env python3
"""nexus rehearsal belt: the whole supervised sequence, chained.

Each Nexus tool is proven alone; this belt proves they compose in
the chase-packet order, offline, on a throwaway key (never the real
~/.cyberspace): status NOT READY -> keygen -> status/preflight
READY -> dry-run sends nothing -> claim posts to a fake origin
mirror -> a byte-identical gossip copy (JSON round-trip, not the
same object) feeds a fake independent node -> host_check ELIGIBLE
for that seat -> depth_check PASSes from the independent node
against the out-of-band pin, and FAILs before the gossip leg runs.
"""
import copy
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nexus_claim as nc  # noqa: E402
import nexus_depth_check as nd  # noqa: E402
import nexus_host_check as nh  # noqa: E402
import nexus_keygen as nk  # noqa: E402
import nexus_preflight as np  # noqa: E402
import nexus_status as ns  # noqa: E402

fails = 0


def _check(cond, why):
    global fails
    if not cond:
        print(f"FAIL: {why}")
        fails += 1


ROOT = Path(os.path.dirname(os.path.abspath(__file__)))
ORIGIN, INDEP = "http://10.0.0.1:8471", "http://10.0.0.9:8471"

with tempfile.TemporaryDirectory() as td:
    td = Path(td)
    key, bak = td / "nexus-name.key", td / "nexus-name.key.bak"
    env_dir = td / "hostd"

    code, lines = ns.status(key, bak, ROOT)
    _check(code == 1 and any("step 1" in ln for ln in lines),
           "empty seat: status must be NOT READY, NEXT=keygen")

    pub, problems = nk.generate(key, bak)
    _check(problems == [] and pub, f"keygen must verify: {problems}")

    code, lines = ns.status(key, bak, ROOT)
    _check(code == 0 and pub in "\n".join(lines),
           "kept key: status must be READY and print the pin pub")
    ready, p2, blockers = np.preflight("nexus", key, bak, ROOT)
    _check(ready and p2 == pub and not blockers,
           f"preflight must be READY after keygen: {blockers}")

    origin_store, indep_store = {}, {}

    def post(url, fields):
        origin_store.update(json.loads(json.dumps(fields)))
        return 200, '{"status": "claimed"}'

    def get_origin(url):
        return {"node_pubkey": origin_store.get("node_pubkey")}

    def get_indep(url):
        return indep_store or None

    code, binding, _ = nc.claim(key, bak, ORIGIN, env_dir,
                                dry_run=True, post=post, get=get_origin)
    _check(code == 0 and not origin_store and not env_dir.exists(),
           "dry-run must leave both mirrors and env untouched")

    code, binding, _ = nc.claim(key, bak, ORIGIN, env_dir,
                                post=post, get=get_origin)
    _check(code == 0 and origin_store.get("name") == "nexus",
           "claim must post the nexus binding to the origin mirror")

    code, _ = nd.depth_check(INDEP, pub, ORIGIN, get=get_indep)
    _check(code == 1, "depth must FAIL before the gossip leg runs")

    # Gossip leg: byte-identical copy via JSON round-trip only.
    indep_store.update(json.loads(json.dumps(origin_store)))
    _check(indep_store == origin_store
           and indep_store is not origin_store,
           "gossip copy must be byte-identical, not the same object")

    ok, blockers = nh.evaluate({
        "candidate_machine_id": "m-indep", "origin_machine_id": "m-origin",
        "evidence_source": "machine-itself",
        "candidate_operator": "op-b", "origin_operator": "op-a",
        "candidate_is_hq": False, "origin_is_hq": False,
        "feed": "gossip", "claim_key_present": False,
        "pin_source": "out-of-band"})
    _check(ok and not blockers, f"rehearsal seat must be ELIGIBLE: {blockers}")

    # Independent node serves the claimed binding (resolve shape).
    served = nc.build_binding(bytes.fromhex(key.read_text().strip()), 30)
    code, _ = nd.depth_check(INDEP, pub, ORIGIN, get=lambda u: served)
    _check(code == 0, "depth must PASS from independent node + pin")
    _check(copy.deepcopy(served)["node_pubkey"] == pub,
           "served binding must carry the kept key's pub")

if fails:
    print(f"test_nexus_rehearsal: {fails} FAIL")
    sys.exit(1)
print("test_nexus_rehearsal: PASS")
