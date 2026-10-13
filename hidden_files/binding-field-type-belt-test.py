#!/usr/bin/env python3
"""Belt: core's binding seats (step 2, ingest, step-6 live, and the
step-5 directory pick) refuse a NON-STRING binding field instead of
str()-aliasing it (primitives 1 naming + 2 resolution).

resolve_cyberspace step 2 and ingest_gossiped_binding both read the five
binding fields through str(): a mirror/gossip-carried JSON true served
as the name coerced to the label "true", verified against a signature
genuinely signed for "true", and was read as live (resolve fetched the
reach descriptor) / INSERTED (ingest). A digit-only pubkey served as a
number likewise stringified to its own hex. Twin of dial.plan's step-3
gate and the canonical payload builders' gate in core.

Covers: bool name, int pubkey, int issued_at at both seats refused;
valid all-string binding at both seats exact (control).

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/binding-field-type-belt-test.py
"""
import os
import secrets
import sys
import tempfile
from datetime import datetime, timedelta, timezone

TMP = tempfile.mkdtemp(prefix="binding-field-type-belt-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core  # noqa: E402

core.init_db()

CASES = {"passed": 0, "failed": 0}


def check(name, cond, extra=""):
    if cond:
        CASES["passed"] += 1
        print(f"  ok  {name}")
    else:
        CASES["failed"] += 1
        print(f"  FAIL {name} {extra}")


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S+00:00")


def _signed(label):
    now = datetime.now(timezone.utc)
    issued, expires = _iso(now - timedelta(hours=1)), _iso(now + timedelta(days=364))
    priv = secrets.token_hex(32)
    pub = core._fed_ed25519.publickey(bytes.fromhex(priv)).hex()
    sig = core._fed_ed25519.sign(
        core._name_claim_payload(label, pub, issued, expires),
        bytes.fromhex(priv), bytes.fromhex(pub)).hex()
    return {"name": label, "node_pubkey": pub, "issued_at": issued,
            "expires_at": expires, "signature": sig}


def _resolve_reach_fetched(binding, label):
    calls = []
    saved = core._resolve_get_json

    def fake(url):
        calls.append(url)
        return binding if url.endswith("/names/" + label) else None

    core._resolve_get_json = fake
    try:
        core.resolve_cyberspace(label + ".cyberspace", "http://127.0.0.1:8471")
    finally:
        core._resolve_get_json = saved
    return any(u.endswith("/reach") for u in calls)


print("ingest seat:")
b = _signed("true")
b["name"] = True
check("bool name dropped-malformed", core.ingest_gossiped_binding(b) == "dropped-malformed")
b = _signed("typebelt")
b["node_pubkey"] = int(b["node_pubkey"], 16)
check("int pubkey dropped-malformed", core.ingest_gossiped_binding(b) == "dropped-malformed")
b = _signed("typebelt")
b["issued_at"] = 123
check("int issued_at dropped-malformed", core.ingest_gossiped_binding(b) == "dropped-malformed")
check("valid string binding inserted", core.ingest_gossiped_binding(_signed("typebelt")) == "inserted")

print("resolve seat:")
b = _signed("true")
b["name"] = True
check("bool name never reaches verify/reach", _resolve_reach_fetched(b, "true") is False)
check("valid string binding reaches reach", _resolve_reach_fetched(_signed("typebelt2"), "typebelt2") is True)

print("resolve live seat:")


def _resolve_live_result(mirror_binding, live_binding, label):
    pub = mirror_binding["node_pubkey"]
    directory = {"entries": [{"node_pub": pub,
                              "node_url": "http://8.8.8.8:8471"}]}
    saved_get = core._resolve_get_json
    saved_peer = core._resolve_peer_get_json
    saved_verify = core._fed_env.verify_envelope

    def fake_get(url):
        if url.endswith("/names/" + label):
            return mirror_binding
        if url.endswith("/directory?limit=200"):
            return directory
        return None

    def fake_peer(url):
        if url.endswith("/fed/ping"):
            return {"ok": True}
        if url.endswith("/names/" + label):
            return live_binding
        return None

    core._resolve_get_json = fake_get
    core._resolve_peer_get_json = fake_peer
    core._fed_env.verify_envelope = lambda env: True
    try:
        return core.resolve_cyberspace(label + ".cyberspace",
                                       "http://127.0.0.1:8471")
    finally:
        core._resolve_get_json = saved_get
        core._resolve_peer_get_json = saved_peer
        core._fed_env.verify_envelope = saved_verify


mb = _signed("true")
lb = dict(mb)
lb["name"] = True
check("live bool name refused", _resolve_live_result(mb, lb, "true") is None)
mb = _signed("123456")
lb = dict(mb)
lb["name"] = 123456
check("live int name refused", _resolve_live_result(mb, lb, "123456") is None)
mb = _signed("livetype")
res = _resolve_live_result(mb, dict(mb), "livetype")
check("live valid string binding resolves",
      isinstance(res, dict) and res.get("node_url") == "http://8.8.8.8:8471")

print("resolve directory seat:")


def _resolve_directory_result(mirror_binding, directory, label):
    saved_get = core._resolve_get_json
    saved_peer = core._resolve_peer_get_json
    saved_verify = core._fed_env.verify_envelope
    saved_bv = core._name_binding_verify

    def fake_get(url):
        if url.endswith("/names/" + label):
            return mirror_binding
        if url.endswith("/directory?limit=200"):
            return directory
        return None

    def fake_peer(url):
        if url.endswith("/fed/ping"):
            return {"ok": True}
        if url.endswith("/names/" + label):
            return mirror_binding
        return None

    core._resolve_get_json = fake_get
    core._resolve_peer_get_json = fake_peer
    core._fed_env.verify_envelope = lambda env: True
    core._name_binding_verify = lambda *a, **k: True
    try:
        return core.resolve_cyberspace(label + ".cyberspace",
                                       "http://127.0.0.1:8471")
    finally:
        core._resolve_get_json = saved_get
        core._resolve_peer_get_json = saved_peer
        core._fed_env.verify_envelope = saved_verify
        core._name_binding_verify = saved_bv


_digit_pub = "1234567890" * 6 + "1234"  # 64 digit chars: int str() == itself
_db = _signed("digdir")
_db["node_pubkey"] = _digit_pub
check("directory int node_pub refused",
      _resolve_directory_result(
          _db, {"entries": [{"node_pub": int(_digit_pub),
                             "node_url": "http://8.8.8.8:8471"}]},
          "digdir") is None)
check("directory non-list entries reads as none",
      _resolve_directory_result(_db, {"entries": 123}, "digdir") is None)
check("directory int node_url on matched entry refused",
      _resolve_directory_result(
          _db, {"entries": [{"node_pub": _digit_pub, "node_url": 12345}]},
          "digdir") is None)
_dres = _resolve_directory_result(
    _db, {"entries": [{"node_pub": _digit_pub,
                       "node_url": "http://8.8.8.8:8471"}]}, "digdir")
check("directory valid string entry resolves",
      isinstance(_dres, dict)
      and _dres.get("node_url") == "http://8.8.8.8:8471")

print(f"{CASES['passed']} passed, {CASES['failed']} failed")
sys.exit(1 if CASES["failed"] else 0)
