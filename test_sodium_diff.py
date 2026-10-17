#!/usr/bin/env python3
"""SODIUM-DIFF (Cipher, ART-42): verifier differential over a golden file.

sodium_vectors.json holds 91 vectors: the 72 of Cipher's sodium-diff run
(r6b weak-key classes, malleated S, mixed-order A' = A + T8 with h%8==0 and
h%8!=0), 4 mixed-order-signed announce envelopes / dir-sync deltas, 3
torsion-R vectors under a PRIME-ORDER A, and the 12 Chalkias et al.
ed25519-speccheck cases (novifinancial/ed25519-speccheck @ 6551933, cases.json).

Backends: checkvalid as shipped (fed/ed25519.py:138); checkvalid's steps with
h mod L (test-only shadow); hop_certs.verify_sig via PyNaCl; verify_sig with
hop_certs.sodium() stubbed to None (must raise SodiumMissing).
Shared precheck on A: window_open.weak_reason(pk) is None and libsodium
is_valid_point(pk).

Rows:
  D1 golden: every backend matches the recorded verdict on every vector.
  D2 stub: every vector raises SodiumMissing with libsodium stubbed out.
  D3 gated: after the precheck, all three backends agree on every vector.
  D4 raw: without the precheck, checkvalid vs libsodium differ on exactly the
     mixed-order-A vectors (the two bare A' rows among them), and every one
     of them is refused by the precheck.
  D5 reduced: checkvalid with h mod L agrees with libsodium on all vectors.
  D6 prod precheck: hop_certs.verify_path and legacy_witness._sig_ok refuse
     every mixed-order-A vector.
Mutants (each must make its row fail):
  M-NOPRECHECK-hop  hop_certs.PRECHECK = False               -> D6
  M-NOPRECHECK-lw   legacy_witness.witness_key_admitted no-op -> D6
  M-NOPRECHECK-gate D3 evaluated with the precheck removed    -> D3
Scratch DB dir only.
"""
import json
import os
import sys
import tempfile

os.environ["CYBERNET_DB_DIR"] = tempfile.mkdtemp(prefix="sodium-diff-")
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import nacl.bindings as nb  # noqa: E402
from fed import ed25519 as E  # noqa: E402
import hop_certs  # noqa: E402
import legacy_witness as lw  # noqa: E402
import window_open  # noqa: E402

PASS = FAIL = 0


def check(label, cond, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok  {label}")
    else:
        FAIL += 1
        print(f"  FAIL {label} {extra}")


G = json.load(open(os.path.join(HERE, "sodium_vectors.json")))["vectors"]
VEC = [(v, bytes.fromhex(v["sig"]), bytes.fromhex(v["msg"]), bytes.fromhex(v["pk"])) for v in G]


def cv(s, m, p):
    return bool(E.checkvalid(s, m, p))


def cvred(s, m, p):
    try:
        if len(s) != 64 or len(p) != 32:
            return False
        R = E._decodepoint_strict(s[:32]); A = E._decodepoint_strict(p)
        S = int.from_bytes(s[32:], "little")
        if S >= E._L or E._is_small_order(A) or E._is_small_order(R):
            return False
        h = int.from_bytes(E._H(E._encodepoint(R) + p + m), "little") % E._L
        return E._scalarmult(E._BPOINT, S) == E._edwards(R, E._scalarmult(A, h))
    except Exception:
        return False


def sod(s, m, p):
    return bool(hop_certs.verify_sig(p.hex(), m, s.hex()))


def precheck(p):
    try:
        return window_open.weak_reason(p.hex()) is None and bool(nb.crypto_core_ed25519_is_valid_point(p))
    except Exception:
        return False


V = {}
for v, s, m, p in VEC:
    V[v["name"]] = {"cv": cv(s, m, p), "cvred": cvred(s, m, p), "nacl": sod(s, m, p), "pre": precheck(p)}

print("D1 golden verdicts:")
bad = [v["name"] for v, *_r in VEC
       if {k: V[v["name"]][k] for k in ("cv", "cvred", "nacl")} != v["expect"]
       or V[v["name"]]["pre"] != v["precheck_pass"]]
check(f"all {len(VEC)} vectors match the golden file", not bad, bad)

print("D2 stubbed libsodium:")
orig = hop_certs.sodium
hop_certs.sodium = lambda: None
raised = 0
try:
    for v, s, m, p in VEC:
        try:
            hop_certs.verify_sig(p.hex(), m, s.hex())
        except hop_certs.SodiumMissing:
            raised += 1
finally:
    hop_certs.sodium = orig
check("every vector raises SodiumMissing (no fallback verdict)", raised == len(VEC), raised)


def gated_disagreements(use_precheck=True):
    out = []
    for n, r in V.items():
        g = {k: (r[k] if (r["pre"] or not use_precheck) else False) for k in ("cv", "cvred", "nacl")}
        if len(set(g.values())) != 1:
            out.append(n)
    return out


print("D3 gated (precheck, then verify):")
check("all backends agree on every vector after the precheck", not gated_disagreements(), gated_disagreements())

print("D4 raw (no precheck):")
raw = sorted(n for n, r in V.items() if r["cv"] != r["nacl"])
mixedA = sorted(v["name"] for v in G if not v["precheck_pass"] and window_open.weak_reason(v["pk"]) == "mixed-order"
                and V[v["name"]]["cv"] != V[v["name"]]["nacl"])
check("the two bare mixed-order rows differ", {"mixed-order A, h%8==0", "mixed-order A, h%8!=0"} <= set(raw), raw)
check("every raw difference has a mixed-order A", raw == mixedA, (raw, mixedA))
check("every raw difference is refused by the precheck", all(not V[n]["pre"] for n in raw))
check("announce envelope + dir-sync delta by A' are among them",
      sum(1 for n in raw if n.startswith(("announce envelope", "dir-sync delta"))) == 4, raw)

print("D5 h mod L:")
check("checkvalid with h mod L == libsodium on every vector", all(r["cvred"] == r["nacl"] for r in V.values()))

print("D6 production precheck seats:")
MIXED = [(v, s, m, p) for v, s, m, p in VEC if window_open.weak_reason(v["pk"]) == "mixed-order"]


def d6():
    hop = [v["name"] for v, s, m, p in MIXED if hop_certs.verify_path(p.hex(), m, s.hex(), sender="d6")]
    lws = [v["name"] for v, s, m, p in MIXED if lw._sig_ok(p.hex(), m, s.hex())]
    return hop, lws


hop, lws = d6()
check(f"hop_certs.verify_path refuses all {len(MIXED)} mixed-order-A vectors", not hop, hop)
check(f"legacy_witness._sig_ok refuses all {len(MIXED)} mixed-order-A vectors", not lws, lws)

print("mutants:")
hop_certs.PRECHECK = False
hop_certs._KEY_OK.clear()
try:
    h_m, _ = d6()
finally:
    hop_certs.PRECHECK = True
check("M-NOPRECHECK-hop killed (verify_path accepts a mixed-order vector)", bool(h_m), h_m)
orig_wka = lw.witness_key_admitted
lw.witness_key_admitted = lambda pub: None
try:
    _, l_m = d6()
finally:
    lw.witness_key_admitted = orig_wka
check("M-NOPRECHECK-lw killed (_sig_ok accepts a mixed-order vector)", bool(l_m), l_m)
check("M-NOPRECHECK-gate killed (D3 without precheck disagrees)", bool(gated_disagreements(False)))

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
