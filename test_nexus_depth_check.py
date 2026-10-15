#!/usr/bin/env python3
"""nexus_depth_check belt: a PASS must be independent and pinned.

Proves, with a throwaway keygen'd key and fake node functions (no
network): a good binding from an independent node passes against
the out-of-band pin; the same node as the claim origin refuses;
a wrong pin, a tampered binding, and a missing binding each fail;
a malformed pin is a usage refusal (exit 2), never a verdict.
"""
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nexus_claim as nc  # noqa: E402
import nexus_depth_check as nd  # noqa: E402
import nexus_keygen as nk  # noqa: E402
from fed.ed25519 import publickey  # noqa: E402

fails = 0


def _check(cond, why):
    global fails
    if not cond:
        print(f"FAIL: {why}")
        fails += 1


with tempfile.TemporaryDirectory() as td:
    td = Path(td)
    key, bak = td / "nexus-name.key", td / "nexus-name.key.bak"
    _pub, _problems = nk.generate(key, bak)
    _check(not _problems, f"temp keygen failed: {_problems}")
    priv = bytes.fromhex(key.read_text().strip())
    pub = publickey(priv).hex().lower()
    binding = nc.build_binding(priv, 30)
    other = nc.build_binding(bytes.fromhex("11" * 32), 30)

    def serve(b):
        return lambda url: b

    node = "http://10.0.0.9:8471"
    origin = "http://10.0.0.1:8471"

    code, _ = nd.depth_check(node, pub, origin, get=serve(binding))
    _check(code == 0, f"independent + pinned good binding must PASS, got {code}")

    code, _ = nd.depth_check(node, pub, node, get=serve(binding))
    _check(code == 1, "same node as origin must refuse (not depth)")

    code, _ = nd.depth_check(node, "00" * 32, origin, get=serve(binding))
    _check(code == 1, "wrong pin must fail")

    tampered = dict(binding, node_pubkey=other["node_pubkey"])
    code, _ = nd.depth_check(node, pub, origin, get=serve(tampered))
    _check(code == 1, "tampered pub must fail the pin")

    bad_sig = dict(binding, signature="00" * 64)
    code, _ = nd.depth_check(node, pub, origin, get=serve(bad_sig))
    _check(code == 1, "bad signature must fail")

    code, _ = nd.depth_check(node, pub, origin, get=serve(None))
    _check(code == 1, "no binding served must fail, not pass")

    code, _ = nd.depth_check(node, "not-hex", origin, get=serve(binding))
    _check(code == 2, "malformed pin is usage (exit 2), not a verdict")

    code, _ = nd.depth_check("ftp://x", pub, origin, get=serve(binding))
    _check(code == 2, "non-http node URL is usage (exit 2)")

if fails:
    print(f"test_nexus_depth_check: {fails} FAIL")
    sys.exit(1)
print("test_nexus_depth_check: PASS")
