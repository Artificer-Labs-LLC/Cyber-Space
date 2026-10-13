#!/usr/bin/env python3
"""Belt: resolve_cyberspace step 6 (live re-check) refuses a live
binding whose signature STRING length is not 128 even when its decode
is the right byte count (primitives 1 naming + 2 resolution).

Step 2 gates the mirror-served binding (len(signature) != 128) and
dial.plan gates its binding the same way, but the step-6 live seat
passed the peer-served signature straight to _name_binding_verify
with no length gate -- and bytes.fromhex ignores embedded spaces, so
a 129-char signature with an inserted space (or an outer-padded
spelling) decoded to the TRUE 64 bytes and VERIFIED: resolve returned
the address for a live row every other binding seat refuses on sight.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/resolve-live-sig-stringlen-belt-test.py
"""
import os
import secrets
import sys
import tempfile
from datetime import datetime, timedelta, timezone

TMP = tempfile.mkdtemp(prefix="resolve-live-sig-strlen-belt-")
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


def _resolve_live(mirror_binding, live_binding, label):
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


def spaced(sig):
    return sig[:64] + " " + sig[64:]  # 129 chars, true 64-byte decode


# Spaced variants are tried BEFORE the valid control for each label
# family, so a false accept is visible (it resolves and memoizes).
mb = _signed("livespace")
lb = dict(mb); lb["signature"] = spaced(mb["signature"])
check("live inserted-space 129-char sig refused",
      _resolve_live(mb, lb, "livespace") is None)

mb = _signed("livepad")
lb = dict(mb); lb["signature"] = " " + mb["signature"] + " "
check("live outer-padded sig refused",
      _resolve_live(mb, lb, "livepad") is None)

mb = _signed("livetamp")
lb = dict(mb)
lb["signature"] = ("0" if mb["signature"][0] != "0" else "1") + mb["signature"][1:]
check("live tampered clean sig refused (control)",
      _resolve_live(mb, lb, "livetamp") is None)

mb = _signed("liveok")
res = _resolve_live(mb, dict(mb), "liveok")
check("live valid string sig resolves (control)",
      isinstance(res, dict) and res.get("node_url") == "http://8.8.8.8:8471")

mb = _signed("liveupper")
lb = dict(mb); lb["signature"] = mb["signature"].upper()
res = _resolve_live(mb, lb, "liveupper")
check("live uppercase sig resolves (control)",
      isinstance(res, dict) and res.get("node_url") == "http://8.8.8.8:8471")

print(f"\n{CASES['passed']} passed, {CASES['failed']} failed")
sys.exit(1 if CASES["failed"] else 0)
