#!/usr/bin/env python3
"""Belt: _provable_deltas refuses a stored delta sig whose STRING
length is not 128 even when its decode is the right byte count
(primitives 4 identity + 5 discovery).

_provable_deltas (core.py) is the gossip-path batch builder for
_delta_out: it re-verifies each stored peers.delta_sig and forwards
the survivors VERBATIM as this node's own deltas. It carried no
string-length gate before checkvalid, and bytes.fromhex ignores
embedded spaces -- so a stored 129-char sig with an inserted space
(or an outer-padded spelling) decoded to the TRUE 64 bytes, VERIFIED,
and was forwarded verbatim: a non-canonical spelling every receiver
seat now refuses on sight (fed_directory_delta 0bcca64 and
_recv_attestation 136c464 both gate len(sig) != 128), gossiped out by
the one seat that was supposed to forward only what it can prove in
canonical form. Legacy/pre-gate rows are exactly what a re-verify
seat exists to filter. Twin of fed_directory_delta 0bcca64.

Covers: valid delta forwarded, sig exact (control); uppercase sig
forwarded (control); clean retire tombstone forwarded (control);
inserted-space 129-char sig NOT forwarded; outer-padded sig NOT
forwarded; inserted-space retire sig NOT forwarded; spaced 128-char
sig (63-byte decode) NOT forwarded (control); tampered clean sig NOT
forwarded (control).

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/provable-deltas-sig-stringlen-belt-test.py
"""
import os
import secrets
import sys
import tempfile

TMP = tempfile.mkdtemp(prefix="provable-deltas-strlen-belt-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core  # noqa: E402
from core import _db, _now, _delta_payload, _provable_deltas  # noqa: E402
from fed import ed25519  # noqa: E402

core.init_db()

CASES = {"passed": 0, "failed": 0}


def check(name, cond, extra=""):
    if cond:
        CASES["passed"] += 1
        print(f"  ok  {name}")
    else:
        CASES["failed"] += 1
        print(f"  FAIL {name} {extra}")


URL = "https://8.8.8.8:443/cybernet"


def plant(name, retire=False, sig_wire=None):
    """Insert a peer row whose delta_sig is a genuine owner signature
    (or sig_wire spelling of it); return (pub, clean_sig)."""
    sk = secrets.token_bytes(32)
    pk = ed25519.publickey(sk).hex()
    row = {"node_pub": pk, "name": name, "node_url": URL,
           "capabilities": [], "network": "cybernet",
           "version": "0.1.0", "genesis": False}
    sig = ed25519.sign(_delta_payload(row, 1, retire),
                       sk, bytes.fromhex(pk)).hex()
    with _db() as conn:
        conn.execute(
            "INSERT INTO peers (node_pub, name, network, version,"
            " genesis, capabilities, node_url, announced_at,"
            " first_seen, retired_at, dir_seq, delta_sig)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (pk, name, "cybernet", "0.1.0", 0, "[]", URL, _now(),
             _now(), _now() if retire else "", 1,
             sig if sig_wire is None else sig_wire(sig)))
    return pk, sig


def forwarded(pub):
    return [d for d in _provable_deltas() if d["row"]["node_pub"] == pub]


# 1. valid control: forwarded, sig exact.
pk, sig = plant("validone")
f = forwarded(pk)
check("valid delta forwarded", len(f) == 1, f"{f}")
check("valid sig forwarded exact", bool(f) and f[0]["sig"] == sig)

# 2. uppercase control: forwarded (case left alone, as at twin seats).
pk, sig = plant("upperone", sig_wire=lambda s: s.upper())
f = forwarded(pk)
check("uppercase sig forwarded", len(f) == 1, f"{f}")

# 3. clean retire control: forwarded as a tombstone.
pk, sig = plant("retireok", retire=True)
f = forwarded(pk)
check("clean retire forwarded", len(f) == 1 and f[0]["retire"] is True,
      f"{f}")

# 4. inserted-space 129-char sig: decodes to true bytes, must NOT forward.
pk, sig = plant("spacedone", sig_wire=lambda s: s[:64] + " " + s[64:])
check("inserted-space 129-char sig not forwarded",
      forwarded(pk) == [], f"{forwarded(pk)}")

# 5. outer-padded sig: must NOT forward.
pk, sig = plant("paddedone", sig_wire=lambda s: " " + s + " ")
check("outer-padded sig not forwarded", forwarded(pk) == [])

# 6. inserted-space retire sig: must NOT forward a tombstone.
pk, sig = plant("retirespaced", retire=True,
                sig_wire=lambda s: s[:64] + " " + s[64:])
check("inserted-space retire sig not forwarded", forwarded(pk) == [])

# 7. spaced 128-char sig (63-byte decode): not forwarded (control).
pk, sig = plant("shortone", sig_wire=lambda s: s[:10] + " " + s[11:])
check("spaced 128-char sig (63-byte decode) not forwarded",
      forwarded(pk) == [])

# 8. tampered clean sig: not forwarded (control).
pk, sig = plant("tamperone",
                sig_wire=lambda s: ("0" if s[0] != "0" else "1") + s[1:])
check("tampered clean sig not forwarded", forwarded(pk) == [])

print(f"{CASES['passed']} passed, {CASES['failed']} failed")
sys.exit(1 if CASES["failed"] else 0)
