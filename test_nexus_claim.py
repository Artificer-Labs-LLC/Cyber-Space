#!/usr/bin/env python3
"""nexus_claim belt: the root claim must be preflight-gated.

Proves, with a throwaway keygen'd key in a temp dir and fake mirror
functions (no network, never the real ~/.cyberspace): a NOT READY
seat sends nothing; a dry-run signs a verifiable binding and sends
nothing; a READY seat claims, verifies the resolve-back binding in
full (verify_name.verify: name, pinned kept pub, signature, live
window), and writes the hostd env born-0600; 409, resolve-mismatch,
a pub-only resolve-back, a forged-signature resolve-back and a
properly signed but expired resolve-back each refuse with no env
written.
"""
import contextlib
import io
import json
import os
import stat
import sys
import tempfile
from datetime import datetime, timedelta, timezone
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

    posted = {}

    def post_spy(url, fields):
        calls.append(("post", url))
        posted.update(fields)
        return 200, '{"status": "claimed"}'

    def get_spy(url):
        calls.append(("get", url))
        return dict(posted)

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
    # The env holds the private key: a dir the claim itself creates
    # to hold it must be born 0700 (plain mkdir left it group/other-
    # listable -- the leak the keygen parent-dir fix closed), nested
    # created ancestors included; a pre-existing dir is left as found.
    _check(stat.S_IMODE(env_dir.stat().st_mode) == 0o700,
           "claim-created env dir must be born 0700")
    env_deep = td / "deep" / "hostd"
    code, _, _ = nc.claim(key, bak, "http://127.0.0.1:9", env_deep,
                          post=post_spy, get=get_spy)
    _check(code == 0
           and stat.S_IMODE((td / "deep").stat().st_mode) == 0o700
           and stat.S_IMODE(env_deep.stat().st_mode) == 0o700,
           "claim-created nested env dirs must each be born 0700")
    env_pre = td / "hostd-pre"
    env_pre.mkdir()
    os.chmod(env_pre, 0o755)
    code, _, _ = nc.claim(key, bak, "http://127.0.0.1:9", env_pre,
                          post=post_spy, get=get_spy)
    _check(code == 0
           and stat.S_IMODE(env_pre.stat().st_mode) == 0o755,
           "pre-existing env dir mode must be left unchanged")

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

    # Pub-only resolve-back: the RIGHT pub with no signature, name
    # or window vouches for nothing — refusal, no env. (Pub equality
    # alone accepted exactly this before the full-verify fix.)
    env4 = td / "hostd4"
    code, _, _ = nc.claim(key, bak, "http://127.0.0.1:9", env4,
                          post=post_spy,
                          get=lambda u: {"node_pubkey": pub})
    _check(code == 1 and not (env4 / "nexus.env").exists(),
           "pub-only resolve-back must refuse with no env written")

    # Forged resolve-back: right pub, complete shape, bad signature.
    forged = dict(posted)
    forged["signature"] = ("0" if forged["signature"][0] != "0"
                           else "1") + forged["signature"][1:]
    env5 = td / "hostd5"
    code, _, _ = nc.claim(key, bak, "http://127.0.0.1:9", env5,
                          post=post_spy, get=lambda u: dict(forged))
    _check(code == 1 and not (env5 / "nexus.env").exists(),
           "forged-signature resolve-back must refuse, no env")

    # Expired resolve-back: properly signed by the kept key, but
    # its live window closed before this claim.
    priv = bytes.fromhex(key.read_text().strip())
    stale = nc.build_binding(
        priv, 30, now=datetime.now(timezone.utc) - timedelta(days=60))
    env6 = td / "hostd6"
    code, _, _ = nc.claim(key, bak, "http://127.0.0.1:9", env6,
                          post=post_spy, get=lambda u: dict(stale))
    _check(code == 1 and not (env6 / "nexus.env").exists(),
           "expired resolve-back must refuse with no env written")

    # Bad mirror / bad expiry: usage refusals, nothing sent.
    calls.clear()
    code, _, _ = nc.claim(key, bak, "not-a-url", env_dir,
                          post=post_spy, get=get_spy)
    _check(code == 2 and calls == [], "bad mirror must be exit 2, unsent")
    code, _, _ = nc.claim(key, bak, "http://127.0.0.1:9", env_dir,
                          expiry_days=366, post=post_spy, get=get_spy)
    _check(code == 2 and calls == [], "over-cap expiry must be exit 2")

    # The equals spelling (--key=PATH etc.) is accepted by main,
    # twin of nexus_status's both-spellings parser; an empty equals
    # value and a non-integer equals expiry are usage refusals.
    env_eq = td / "hostd-eq"
    _check(nc.main(["http://127.0.0.1:9", f"--key={key}",
                    f"--backup={bak}", f"--env-dir={env_eq}",
                    "--expiry-days=30", "--dry-run"]) == 0
           and not env_eq.exists(),
           "equals spelling must reach a dry-run and write no env")
    _check(nc.main([f"--key=", f"--backup={bak}"]) == 2,
           "empty equals value must be a usage refusal")
    _check(nc.main([f"--key={key}", "--expiry-days=abc"]) == 2,
           "non-integer equals expiry must be a usage refusal")

    # A following -- flag is not a space-form value: --key --backup
    # swallowed the backup flag as the key path and then blamed the
    # mirror, instead of naming --key -- twin of nexus_status's,
    # nexus_preflight's and nexus_keygen's space-form gates.
    for _argv, _flag in ((["--key", "--backup", str(bak)], "--key"),
                         (["--backup", "--key", str(key)], "--backup"),
                         (["--env-dir", "--dry-run"], "--env-dir"),
                         (["--expiry-days", "--dry-run"], "--expiry-days")):
        _err = io.StringIO()
        with contextlib.redirect_stderr(_err):
            _code = nc.main(_argv)
        _check(_code == 2 and f"{_flag} needs a value" in _err.getvalue(),
               f"following flag must refuse as {_flag} needs a value")

if fails:
    print(f"{fails} FAILURES")
    sys.exit(1)
print("PASS: test_nexus_claim")
