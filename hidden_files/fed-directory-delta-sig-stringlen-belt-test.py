#!/usr/bin/env python3
"""Belt: fed_directory_delta refuses a delta sig whose STRING length is
not 128 even when its decode is the right byte count (primitives 4
identity + 5 discovery).

fed_directory_delta (federation.py) is the gossip-received directory
delta seat: it gated the sig's TYPE (str) but never its string length
before checkvalid, and bytes.fromhex ignores embedded spaces -- so a
129-char signature with an inserted space (or an outer-padded
spelling) decoded to the TRUE 64 bytes and VERIFIED, and the seat
stored sig_hex verbatim into peers.delta_sig, which _delta_out later
forwards as this node's own delta -- a non-canonical spelling every
binding seat refuses on sight (len(signature) != 128) propagating
through the directory. Twin of _recv_attestation 136c464 /
verify_envelope 2574fc2.

Covers: valid delta applied, delta_sig stored exact (control);
uppercase sig applied (control); inserted-space 129-char sig
rejected, no row; outer-padded sig rejected, no row; spaced
128-char sig (63-byte decode) rejected (control); tampered clean
sig rejected (control); inserted-space retire sig rejected, no
tombstone.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/fed-directory-delta-sig-stringlen-belt-test.py
"""
import os
import secrets
import sys
import tempfile
import time

TMP = tempfile.mkdtemp(prefix="fed-delta-strlen-belt-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core  # noqa: E402
from core import _db, _now, _delta_payload, _NODE_PUB  # noqa: E402
import federation  # noqa: E402
from fed import envelope as fenv, ed25519  # noqa: E402
from fastapi import HTTPException  # noqa: E402

core.init_db()

CASES = {"passed": 0, "failed": 0}


def check(name, cond, extra=""):
    if cond:
        CASES["passed"] += 1
        print(f"  ok  {name}")
    else:
        CASES["failed"] += 1
        print(f"  FAIL {name} {extra}")


SK = secrets.token_bytes(32)
PK = ed25519.publickey(SK).hex()
TS0 = int(time.time())
URL = "https://8.8.8.8:443/cybernet"

with _db() as conn:
    conn.execute(
        "INSERT INTO peers (node_pub, name, network, version, genesis,"
        " capabilities, announced_at, first_seen, retired_at)"
        " VALUES (?, 'sender', 'cybernet', '0.1.0', 0, '[]', ?, ?, '')",
        (PK, _now(), _now()))


def base_row(opk, name):
    return {"node_pub": opk, "name": name, "node_url": URL,
            "capabilities": [], "network": "cybernet", "version": "0.1.0",
            "genesis": False}


def mint(osk, opk, row, seq, retire, sig_wire=None):
    sig = ed25519.sign(_delta_payload(row, seq, retire),
                       osk, bytes.fromhex(opk)).hex()
    return {"row": row, "seq": seq,
            "sig": sig if sig_wire is None else sig_wire,
            "retire": retire}, sig


def deliver(deltas, ts):
    env = fenv.make_envelope(SK.hex(), PK, _NODE_PUB,
                             {"from_node_pub": PK, "deltas": deltas}, ts=ts)
    try:
        return federation.fed_directory_delta(env)
    except HTTPException as e:
        return {"error": e.status_code, "detail": e.detail}


def row_for(pub):
    with _db() as conn:
        return conn.execute(
            "SELECT node_pub, name, retired_at, delta_sig FROM peers"
            " WHERE node_pub=?", (pub,)).fetchone()


def fresh(name):
    osk = secrets.token_bytes(32)
    return osk, ed25519.publickey(osk).hex(), name


# 1. valid control: applied, delta_sig stored exact.
osk, opk, nm = fresh("validone")
d, sig = mint(osk, opk, base_row(opk, nm), 1, False)
r = deliver([d], TS0 + 3)
check("valid delta applied", r.get("applied") == 1, f"{r}")
row = row_for(opk)
check("valid delta_sig stored exact",
      row is not None and row["delta_sig"] == sig, f"{row['delta_sig'] if row else None}")

# 2. uppercase control: applied (case left alone, as at twin seats).
osk, opk, nm = fresh("upperone")
d, sig = mint(osk, opk, base_row(opk, nm), 1, False, sig_wire=None)
d["sig"] = sig.upper()
r = deliver([d], TS0 + 6)
check("uppercase sig applied", r.get("applied") == 1, f"{r}")

# 3. inserted-space 129-char sig: decoded to true bytes, must reject.
osk, opk, nm = fresh("spacedone")
d, sig = mint(osk, opk, base_row(opk, nm), 1, False)
d["sig"] = sig[:64] + " " + sig[64:]
r = deliver([d], TS0 + 9)
check("inserted-space 129-char sig rejected",
      r.get("rejected") == 1 and r.get("applied", 0) == 0, f"{r}")
check("inserted-space sig stores no row", row_for(opk) is None)

# 4. outer-padded sig: must reject.
osk, opk, nm = fresh("paddedone")
d, sig = mint(osk, opk, base_row(opk, nm), 1, False)
d["sig"] = " " + sig + " "
r = deliver([d], TS0 + 12)
check("outer-padded sig rejected",
      r.get("rejected") == 1 and r.get("applied", 0) == 0, f"{r}")
check("outer-padded sig stores no row", row_for(opk) is None)

# 5. spaced 128-char sig (63-byte decode): rejected (control).
osk, opk, nm = fresh("shortone")
d, sig = mint(osk, opk, base_row(opk, nm), 1, False)
d["sig"] = sig[:10] + " " + sig[11:]
r = deliver([d], TS0 + 15)
check("spaced 128-char sig (63-byte decode) rejected",
      r.get("rejected") == 1 and r.get("applied", 0) == 0, f"{r}")
check("spaced 128-char sig stores no row", row_for(opk) is None)

# 6. tampered clean sig: rejected (control).
osk, opk, nm = fresh("tamperone")
d, sig = mint(osk, opk, base_row(opk, nm), 1, False)
d["sig"] = ("0" if sig[0] != "0" else "1") + sig[1:]
r = deliver([d], TS0 + 18)
check("tampered clean sig rejected",
      r.get("rejected") == 1 and r.get("applied", 0) == 0, f"{r}")

# 7. inserted-space retire sig: must reject, no tombstone.
osk, opk, nm = fresh("retireone")
d, sig = mint(osk, opk, base_row(opk, nm), 1, True)
d["sig"] = sig[:64] + " " + sig[64:]
r = deliver([d], TS0 + 21)
check("inserted-space retire sig rejected",
      r.get("rejected") == 1 and r.get("retired", 0) == 0, f"{r}")
check("inserted-space retire stores no tombstone", row_for(opk) is None)

print(f"{CASES['passed']} passed, {CASES['failed']} failed")
sys.exit(1 if CASES["failed"] else 0)
