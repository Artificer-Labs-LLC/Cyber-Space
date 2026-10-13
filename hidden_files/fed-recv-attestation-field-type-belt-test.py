#!/usr/bin/env python3
"""Belt: _recv_attestation refuses a NON-STRING row field instead of
str()-aliasing it (primitives 1 naming + 5 discovery).

_recv_attestation (federation.py) read row.node_pub through str() and
passed the row to _delta_payload, which str()-coerces name/node_url/
network/version the same way: a delta-carried numeric name (12345)
stringified to the valid label "12345" -- the payload the owner
genuinely signed for that string -- and the attestation was ACCEPTED
(sig, seq returned, stored by /fed/announce and /fed/retire as the
row's delta_sig/dir_seq), the same alias fed_directory_delta's row
seat refuses on sight. Twin of that gate: only real strings are
attestation row fields; absent fields keep payload defaults.

Covers: int name rejected (live signature); int network rejected
(live signature); int node_pub rejected (checkvalid stubbed to
isolate the seat, twin of the descriptor-seat belts -- a digit-only
sender key cannot be minted on demand); non-string sig rejected;
valid string attestation accepted exact (control).

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/fed-recv-attestation-field-type-belt-test.py
"""
import os
import secrets
import sys
import tempfile

TMP = tempfile.mkdtemp(prefix="fed-recv-att-belt-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core  # noqa: E402
from core import _delta_payload  # noqa: E402
import federation  # noqa: E402
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


SK = secrets.token_bytes(32)
PK = ed25519.publickey(SK).hex()
URL = "https://8.8.8.8:443/cybernet"


def base_row(name="validnode", network="cybernet", node_pub=None):
    return {"node_pub": node_pub if node_pub is not None else PK,
            "name": name, "node_url": URL, "capabilities": [],
            "network": network, "version": "0.1.0", "genesis": False}


def mint(row, seq=1):
    sig = ed25519.sign(_delta_payload(row, seq, False),
                       SK, bytes.fromhex(PK)).hex()
    return {"row": row, "seq": seq, "sig": sig}


# 1. int name: signed for the str() alias, must be refused.
d = mint(base_row(name=12345))
sig, seq = federation._recv_attestation(d, PK, False)
check("int name refused", sig is None and seq is None, f"{sig} {seq}")

# 2. int network: signed for the str() alias, must be refused.
d = mint(base_row(network=12345))
sig, seq = federation._recv_attestation(d, PK, False)
check("int network refused", sig is None and seq is None, f"{sig} {seq}")

# 3. int node_pub (digit-only sender): stub checkvalid to isolate seat.
digit_pub = "1" * 64
row = base_row(node_pub=int(digit_pub))
orig = federation._fed_ed25519.checkvalid
federation._fed_ed25519.checkvalid = lambda s, m, pk: True
try:
    sig, seq = federation._recv_attestation(
        {"row": row, "seq": 1, "sig": "ab" * 64}, digit_pub, False)
finally:
    federation._fed_ed25519.checkvalid = orig
check("int node_pub refused", sig is None and seq is None, f"{sig} {seq}")

# 4. non-string sig: an int sig stringified to digit-hex must be refused.
d = mint(base_row())
d2 = {"row": d["row"], "seq": 1, "sig": 12345}
sig, seq = federation._recv_attestation(d2, PK, False)
check("int sig refused", sig is None and seq is None, f"{sig} {seq}")

# 5. valid string control: accepted, sig/seq exact.
d = mint(base_row())
sig, seq = federation._recv_attestation(d, PK, False)
check("valid string attestation accepted",
      sig == d["sig"] and seq == 1, f"{sig} {seq}")

print(f"{CASES['passed']} passed, {CASES['failed']} failed")
sys.exit(1 if CASES["failed"] else 0)
