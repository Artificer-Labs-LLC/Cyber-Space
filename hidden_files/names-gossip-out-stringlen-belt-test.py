#!/usr/bin/env python3
"""Belt: _names_gossip_out refuses a stored binding whose sig/pubkey
STRING length is not 128/64 even when its decode is the right byte
count (primitives 1 naming + 5 discovery).

_names_gossip_out (core.py) sweeps name_bindings and forwards every
unexpired row VERBATIM to every peer via /fed/names/gossip, with no
string-length gate and no re-verify: a legacy/pre-gate row with a
129-char inserted-space sig (or outer-padded spelling, or a 65-char
spaced pubkey) decoded to the TRUE bytes but was gossiped in that
non-canonical spelling -- a spelling every receiver/binding seat now
refuses on sight (_name_binding_verify b5f5943 gates len 128/64).
The sender is the seat that puts it on the wire; only exact 128/64
spellings are gossiped. Case is left alone (uppercase forwarded).

Covers: valid forwarded exact; uppercase sig forwarded; inserted-
space sig NOT forwarded; outer-padded sig NOT forwarded; inserted-
space pubkey NOT forwarded; outer-padded pubkey NOT forwarded.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/names-gossip-out-stringlen-belt-test.py
"""
import os
import secrets
import sys
import tempfile
from datetime import datetime, timedelta, timezone

TMP = tempfile.mkdtemp(prefix="names-gossip-out-strlen-belt-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core  # noqa: E402
from core import _db, _db_lock  # noqa: E402

core.init_db()
CASES = {"passed": 0, "failed": 0}


def check(name, cond, extra=""):
    if cond:
        CASES["passed"] += 1
        print(f"  ok  {name}")
    else:
        CASES["failed"] += 1
        print(f"  FAIL {name} {extra}")


SENT = []


class FakeThread:
    def __init__(self, target=None, args=(), daemon=None):
        self.args = args

    def start(self):
        SENT.append(self.args[2])


core.threading.Thread = FakeThread


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S+00:00")


def plant(label, sig_wire=None, pub_wire=None):
    now = datetime.now(timezone.utc)
    issued, expires = _iso(now - timedelta(hours=1)), _iso(now + timedelta(days=30))
    priv = secrets.token_bytes(32)
    pub = core._fed_ed25519.publickey(priv).hex()
    payload_pub = pub_wire(pub) if pub_wire else pub
    sig = core._fed_ed25519.sign(
        core._name_claim_payload(label, payload_pub, issued, expires),
        priv, bytes.fromhex(pub)).hex()
    with _db_lock, _db() as conn:
        conn.execute(
            "INSERT INTO name_bindings (name, node_pubkey, issued_at, expires_at, signature)"
            " VALUES (?,?,?,?,?)",
            (label, payload_pub, issued, expires,
             sig if sig_wire is None else sig_wire(sig)))
    return label


def spaced(s):
    return s[:32] + " " + s[32:]


plant("ngvalid")
plant("ngupper", sig_wire=lambda s: s.upper())
plant("ngsigspace", sig_wire=spaced)
plant("ngsigpad", sig_wire=lambda s: " " + s + " ")
plant("ngpubspace", pub_wire=spaced)
plant("ngpubpad", pub_wire=lambda p: " " + p + " ")

with _db_lock, _db() as conn:
    conn.execute(
        "INSERT INTO peers (node_pub, name, network, version, genesis,"
        " capabilities, node_url, announced_at, first_seen, retired_at)"
        " VALUES (?, 'peer', 'cybernet', '0.1.0', 0, '[]',"
        " 'http://93.184.216.34/', '2026-01-01', '', '')",
        ("aa" * 32,))

n = core._names_gossip_out()
check("gossip returns recipient count", n == 1, f"n={n}")
names = set()
for env in SENT:
    for b in env["body"]["bindings"]:
        names.add(b["name"])
check("valid binding gossiped", "ngvalid" in names, f"{names}")
check("uppercase sig gossiped (control)", "ngupper" in names, f"{names}")
check("inserted-space 129-char sig NOT gossiped", "ngsigspace" not in names, f"{names}")
check("outer-padded sig NOT gossiped", "ngsigpad" not in names, f"{names}")
check("inserted-space 65-char pubkey NOT gossiped", "ngpubspace" not in names, f"{names}")
check("outer-padded pubkey NOT gossiped", "ngpubpad" not in names, f"{names}")

print(f"\n{CASES['passed']} passed, {CASES['failed']} failed")
sys.exit(1 if CASES["failed"] else 0)
