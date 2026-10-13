#!/usr/bin/env python3
"""Belt: _recv_attestation refuses a delta sig whose STRING length is
not 128 even when its decode is the right byte count (primitives 4
identity + 5 discovery).

_recv_attestation (federation.py) is the ingress seat for a directory
self-attestation carried on /fed/announce or /fed/retire: it gated the
sig's TYPE (str) but never its string length before checkvalid, and
bytes.fromhex ignores embedded spaces -- so a 129-char signature with
an inserted space (or an outer-padded spelling) decoded to the TRUE
64 bytes and the attestation VERIFIED. The returned sig_hex is stored
verbatim by the callers into peers.delta_sig and later forwarded by
_delta_out as this node's own delta -- a non-canonical spelling every
binding seat refuses on sight (len(signature) != 128) propagating
through the directory. Twin of verify_envelope 2574fc2 /
verify_rotation 3fbb38b.

Covers: valid attestation accepted exact (control); uppercase sig
accepted (control); retire attestation accepted (control);
inserted-space 129-char sig refused; outer-padded sig refused;
spaced 128-char sig (63-byte decode) refused (control); tampered
clean sig refused (control).

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/recv-attestation-sig-stringlen-belt-test.py
"""
import os
import secrets
import sys
import tempfile

TMP = tempfile.mkdtemp(prefix="recv-att-strlen-belt-")
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
ROW = {"node_pub": PK, "name": "validnode", "node_url": URL,
       "capabilities": [], "network": "cybernet", "version": "0.1.0",
       "genesis": False}


def mint(seq=1, retire=False):
    sig = ed25519.sign(_delta_payload(ROW, seq, retire),
                       SK, bytes.fromhex(PK)).hex()
    return {"row": dict(ROW), "seq": seq, "sig": sig}


D = mint()
SIG = D["sig"]
SPACED_SIG = SIG[:64] + " " + SIG[64:]           # 129 chars, true 64-byte decode
PADDED_SIG = " " + SIG + " "                     # 130 chars, true decode
SPACED_SAME_LEN = SIG[:10] + " " + SIG[11:]      # 128 chars, 63-byte decode
TAMPERED = ("0" if SIG[0] != "0" else "1") + SIG[1:]


def variant(sig, retire=False):
    d = mint(retire=retire)
    d["sig"] = sig
    return d


# 1. valid control: accepted, sig/seq exact.
sig, seq = federation._recv_attestation(mint(), PK, False)
check("valid attestation accepted", sig == SIG and seq == 1, f"{sig} {seq}")

# 2. uppercase control: accepted (case left alone, as at twin seats).
sig, seq = federation._recv_attestation(variant(SIG.upper()), PK, False)
check("uppercase sig accepted", sig == SIG.upper() and seq == 1, f"{sig} {seq}")

# 3. retire control: accepted under the retire payload.
d = mint(retire=True)
sig, seq = federation._recv_attestation(d, PK, True)
check("valid retire attestation accepted", sig == d["sig"] and seq == 1,
      f"{sig} {seq}")

# 4. inserted-space 129-char sig: decoded to the true bytes, must refuse.
sig, seq = federation._recv_attestation(variant(SPACED_SIG), PK, False)
check("inserted-space 129-char sig refused", sig is None and seq is None,
      f"{sig} {seq}")

# 5. outer-padded sig: must refuse.
sig, seq = federation._recv_attestation(variant(PADDED_SIG), PK, False)
check("outer-padded sig refused", sig is None and seq is None, f"{sig} {seq}")

# 6. spaced 128-char sig (63-byte decode): refused (control).
sig, seq = federation._recv_attestation(variant(SPACED_SAME_LEN), PK, False)
check("spaced 128-char sig (63-byte decode) refused",
      sig is None and seq is None, f"{sig} {seq}")

# 7. tampered clean sig: refused (control).
sig, seq = federation._recv_attestation(variant(TAMPERED), PK, False)
check("tampered clean sig refused", sig is None and seq is None,
      f"{sig} {seq}")

print(f"{CASES['passed']} passed, {CASES['failed']} failed")
sys.exit(1 if CASES["failed"] else 0)
