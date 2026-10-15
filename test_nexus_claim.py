#!/usr/bin/env python3
"""nexus_claim belt: the root claim must be preflight-gated.

Proves, with a throwaway keygen'd key in a temp dir and fake mirror
functions (no network, never the real ~/.cyberspace): a NOT READY
seat sends nothing; a dry-run signs a verifiable binding and sends
nothing; a READY seat claims, verifies the resolve-back pub, and
writes the hostd env born-0600; 409 and resolve-mismatch each
refuse with no env written.
"""
import json
import os
import stat
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nexus_claim as nc  # noqa: E402
import nexus_keygen as nk  # noqa: E402
from fed.ed25519 import checkvalid  # noqa: E402

fails = 0


def _check(cond, why):
    global fails
    if not cond:
        print(f"FAIL: {why}")
        fails += 1


with tempfile.TemporaryDirectory() as td:
    td = Path(td)
    key, bak = td / "nexus-name.key", td / "nexus-name.key.bak"
    env_dir = td / "hostd"
    calls = []

    def post_spy(url, fields):
        calls.append(("post", url))
        return 200, '{"status": "claimed"}'

    def get_spy(url):
        calls.append(("get", url))
        return {"node_pubkey": pub}

    # Missing key: preflight gate refuses before any network.
    code, binding, notes = nc.claim(key, bak, "http://127.0.0.1:9",
                                    env_dir, post=post_spy, get=get_spy)
    _check(code == 1 and binding is None and calls == [],
           "NOT READY seat must refuse with nothing sent")

    pub, problems = nk.generate(key, bak)
    _check(problems == [] and pub, "temp keygen must verify")

    # Dry-run: signed, verifiable, still nothing sent, no env.
    code, binding, notes = nc.claim(key, bak, "http://127.0.0.1:9",
                                    env_dir, dry_run=True,
                                    post=post_spy, get=get_spy)
    _check(code == 0 and calls == [] and not env_dir.exists(),
           "dry-run must send nothing and write no env")
    payload = (b"name-claim|nexus|" + pub.encode() + b"|"
               + binding["issued_at"].encode() + b"|"
               + binding["expires_at"].encode())
    _check(binding["node_pubkey"] == pub
           and checkvalid(bytes.fromhex(binding["signature"]),
                          payload, bytes.fromhex(pub)),
           "dry-run binding signature must verify against the kept key")

    # Real claim against the fake mirror: claimed, verified, env 0600.
    code, binding, notes = nc.claim(key, bak, "http://127.0.0.1:9",
                                    env_dir, post=post_spy, get=get_spy)
    env = env_dir / "nexus.env"
    _check(code == 0 and [c[0] for c in calls] == ["post", "get"],
           f"READY claim must post then verify, got {calls}")
    _check(env.exists()
           and stat.S_IMODE(env.stat().st_mode) == 0o600
           and "CYBERNET_HOSTED_NAME=nexus" in env.read_text(),
           "hostd env must be born 0600 and name nexus")

    # 409: taken is a refusal, no env.
    calls.clear()
    env2 = td / "hostd2"
    code, _, _ = nc.claim(key, bak, "http://127.0.0.1:9", env2,
                          post=lambda u, f: (409, "taken"),
                          get=get_spy)
    _check(code == 1 and not (env2 / "nexus.env").exists(),
           "409 must refuse with no env written")

    # Resolve-back mismatch: refusal, no env.
    env3 = td / "hostd3"
    code, _, _ = nc.claim(key, bak, "http://127.0.0.1:9", env3,
                          post=post_spy,
                          get=lambda u: {"node_pubkey": "00" * 32})
    _check(code == 1 and not (env3 / "nexus.env").exists(),
           "resolve mismatch must refuse with no env written")

    # Bad mirror / bad expiry: usage refusals, nothing sent.
    calls.clear()
    code, _, _ = nc.claim(key, bak, "not-a-url", env_dir,
                          post=post_spy, get=get_spy)
    _check(code == 2 and calls == [], "bad mirror must be exit 2, unsent")
    code, _, _ = nc.claim(key, bak, "http://127.0.0.1:9", env_dir,
                          expiry_days=366, post=post_spy, get=get_spy)
    _check(code == 2 and calls == [], "over-cap expiry must be exit 2")

if fails:
    print(f"{fails} FAILURES")
    sys.exit(1)
print("PASS: test_nexus_claim")
