"""Reach-descriptor serve + dial belt test: the resolution dial step.

Drives the REAL pieces end to end:

Part A (serve): the REAL /api/v1/names/{name}/reach route via
TestClient on a throwaway DB, with a binding + descriptor seeded
through the REAL ingest_reach_descriptor merge half:
  live binding + valid descriptor -> 200, payload self-verifies
  unknown label -> 404
  expired binding (live descriptor row) -> 404
  expired descriptor (live binding row) -> 404
  key mismatch (binding key != descriptor key) -> 404

Part B (dial): the REAL core.resolve_cyberspace with a fake-mirror
transport (monkeypatched _resolve_get_json, signatures REAL):
  valid descriptor -> the descriptor's address wins over the
                      directory scan (directory never consulted)
  tampered descriptor signature -> falls back to the directory entry
  descriptor absent -> directory fallback still resolves

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/reach-serve-dial-test.py
"""
import json
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone

tmp = tempfile.mkdtemp()
os.environ["CYBERNET_DB_DIR"] = tmp
sys.path.insert(0, os.path.expanduser("~/workspace/cybernet"))

import core  # noqa: E402
import app as cyber  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from fed import ed25519 as _ed  # noqa: E402
from fed import envelope as _env  # noqa: E402

CASES = {"passed": 0, "failed": 0}


def check(name, cond, extra=""):
    if cond:
        CASES["passed"] += 1
        print(f"  ok  {name}")
    else:
        CASES["failed"] += 1
        print(f"  FAIL {name} {extra}")


def _iso(dt):
    return dt.isoformat(timespec="seconds")


now = datetime.now(timezone.utc)
ISSUED = _iso(now - timedelta(days=1))
LIVE = _iso(now + timedelta(days=6))
DEAD = _iso(now - timedelta(hours=2))

_name_seed = os.urandom(32)
_name_pub = _ed.publickey(_name_seed).hex()
_node_seed = os.urandom(32)
_node_pub = _ed.publickey(_node_seed).hex()

LABEL = "reachbelt"
DEAD_LABEL = "reachbeltdead"
EXP_LABEL = "reachbeltexp"  # live binding, expired descriptor
MM_LABEL = "reachbeltmm"  # key mismatch


def _binding_sig(label, key_hex, issued, expires):
    return _ed.sign(core._name_claim_payload(label, key_hex, issued, expires),
                    _name_seed, bytes.fromhex(key_hex)).hex()


def seed_db():
    core.init_db()
    with core._db_lock, core._db() as conn:
        for label, issued, expires, pub in (
                (LABEL, ISSUED, LIVE, _name_pub),
                (DEAD_LABEL, ISSUED, DEAD, _name_pub),
                (EXP_LABEL, ISSUED, LIVE, _name_pub),
                (MM_LABEL, ISSUED, LIVE, _name_pub)):
            conn.execute(
                "INSERT INTO name_bindings (name, node_pubkey, issued_at,"
                " expires_at, signature) VALUES (?,?,?,?,?)",
                (label, pub, issued, expires,
                 _binding_sig(label, pub, issued, expires)))
    desc = core._reach_mint(_name_seed.hex(), _name_pub, LABEL,
                            [{"kind": "direct", "url": "http://93.184.216.36:18799/"}],
                            ISSUED, LIVE)
    assert core.ingest_reach_descriptor(desc) == "inserted", "merge half"
    # dead binding: descriptor still merges? no — ingest refuses unbound
    # or expired bindings, so seed the row directly for the 404 case.
    # Same for the expired-descriptor row: ingest's fail-closed verify
    # drops it, so it is seeded directly for the 404 case.
    dead_desc = core._reach_mint(_name_seed.hex(), _name_pub, DEAD_LABEL,
                                 [{"kind": "direct", "url": "http://93.184.216.36:18799/"}],
                                 ISSUED, DEAD)
    exp_desc = core._reach_mint(_name_seed.hex(), _name_pub, EXP_LABEL,
                                [{"kind": "direct", "url": "http://93.184.216.36:18799/"}],
                                ISSUED, DEAD)
    other_seed = os.urandom(32)
    other_pub = _ed.publickey(other_seed).hex()
    mm_desc = core._reach_mint(other_seed.hex(), other_pub, MM_LABEL,
                               [{"kind": "direct", "url": "http://93.184.216.36:18799/"}],
                               ISSUED, LIVE)
    with core._db_lock, core._db() as conn:
        for d in (dead_desc, exp_desc, mm_desc):
            conn.execute(
                "INSERT INTO reach_descriptors (name, node_pubkey, reach,"
                " issued_at, expires_at, signature) VALUES (?,?,?,?,?,?)",
                (d["name"], d["node_pubkey"],
                 json.dumps(d["reach"], sort_keys=True, separators=(",", ":")),
                 d["issued_at"], d["expires_at"], d["signature"]))


def part_a():
    print("serve route:")
    seed_db()
    with TestClient(cyber.app) as c:
        r = c.get("/api/v1/names/" + LABEL + "/reach")
        check("live binding + descriptor -> 200", r.status_code == 200, r.status_code)
        if r.status_code == 200:
            payload = r.json()
            check("descriptor self-verifies (mirror never trusted)",
                  core._reach_descriptor_verify(payload))
            check("keys are the binding key",
                  payload.get("node_pubkey") == _name_pub)
        r = c.get("/api/v1/names/no-such-name-here/reach")
        check("unknown label -> 404", r.status_code == 404, r.status_code)
        r = c.get("/api/v1/names/" + DEAD_LABEL + "/reach")
        check("expired binding -> 404", r.status_code == 404, r.status_code)
        r = c.get("/api/v1/names/" + EXP_LABEL + "/reach")
        check("expired descriptor -> 404", r.status_code == 404, r.status_code)
        r = c.get("/api/v1/names/" + MM_LABEL + "/reach")
        check("key mismatch -> 404", r.status_code == 404, r.status_code)
        r = c.get("/api/v1/names/" + LABEL + "/reach/")
        check("trailing-slash form redirects to the same descriptor (parity "
              "with names_resolve redirect_slashes)", r.status_code == 200 and
              r.json().get("node_pubkey") == _name_pub, r.status_code)


MIRROR = "http://mirror.invalid"
NODE = "http://93.184.216.34:18799"
NODE_URL = NODE + "/"
DESC_NODE = "http://93.184.216.36:18799"
DESC_URL = DESC_NODE + "/"
RLABEL = "dialbelt"


def _rbinding(corrupt=False):
    sig = _ed.sign(core._name_claim_payload(RLABEL, _name_pub, ISSUED, LIVE),
                   _name_seed, bytes.fromhex(_name_pub)).hex()
    if corrupt:
        sig = ("0" if sig[0] != "0" else "1") + sig[1:]
    return {"name": RLABEL, "node_pubkey": _name_pub, "issued_at": ISSUED,
            "expires_at": LIVE, "signature": sig}


def _rdesc(tamper=False):
    d = core._reach_mint(_name_seed.hex(), _name_pub, RLABEL,
                         [{"kind": "direct", "url": DESC_URL}],
                         ISSUED, LIVE)
    if tamper:
        d = dict(d)
        d["signature"] = ("0" if d["signature"][0] != "0" else "1") + d["signature"][1:]
    return d


def _fake_factory(mode):
    ping = _env.make_envelope(_node_seed.hex(), _node_pub, "tester", {"pong": True})
    hits = {"directory": 0, "reach": 0}
    binding = _rbinding()
    desc = {"descriptor": _rdesc(), "bad-sig": _rdesc(tamper=True),
            "absent": None}[mode]

    def fake(url: str):
        if url == MIRROR + "/api/v1/names/" + RLABEL:
            return dict(binding)
        if url == MIRROR + "/api/v1/names/" + RLABEL + "/reach":
            hits["reach"] += 1
            return dict(desc) if desc is not None else None
        if url == MIRROR + "/api/v1/directory?limit=200":
            hits["directory"] += 1
            return {"entries": [{"node_pub": _name_pub, "node_url": NODE_URL}]}
        if url in (NODE + "/fed/ping", DESC_NODE + "/fed/ping"):
            return ping
        if url in (NODE + "/api/v1/names/" + RLABEL, DESC_NODE + "/api/v1/names/" + RLABEL):
            return dict(_rbinding())
        return None
    return fake, hits


def part_b():
    print("dial step:")
    real, real_peer = core._resolve_get_json, core._resolve_peer_get_json
    try:
        for mode, expect_url, expect_dir_hits in (
                ("descriptor", DESC_NODE, 0),
                ("bad-sig", NODE, 1),
                ("absent", NODE, 1)):
            fake, hits = _fake_factory(mode)
            core._resolve_get_json = fake
            core._resolve_peer_get_json = fake
            core._resolve_memo.clear()
            got = core.resolve_cyberspace(RLABEL + ".cyberspace", MIRROR)
            check(f"{mode}: resolves to {expect_url}",
                  got is not None and got.get("node_url") == expect_url,
                  got)
            check(f"{mode}: directory consulted {expect_dir_hits}x",
                  hits["directory"] == expect_dir_hits, hits)
    finally:
        core._resolve_get_json = real
        core._resolve_peer_get_json = real_peer


part_a()
part_b()
print(f"\n{CASES['passed']} passed, {CASES['failed']} failed")
sys.exit(1 if CASES["failed"] else 0)
