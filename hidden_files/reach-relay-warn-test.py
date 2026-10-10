#!/usr/bin/env python3
"""reach-relay-warn-test.py — harness belt for resolver/host.py _relay_warnings.

The relay triple (CYBERNET_RELAY_URL / CYBERNET_RELAY_PUBKEY /
CYBERNET_RELAY_TOKEN) is all-or-nothing. Nothing set = direct dial, silent
by choice. Anything set but unusable = an operator mistake the daemon must
shout about at startup instead of silently hosting direct-dial.

Drives _relay_warnings() through env permutations (real module, no mocks),
restoring the environment after every case. 12/12 expected.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from resolver import host  # noqa: E402

GOOD_URL = "http://185.143.228.228:8471"  # public-IP shape only; never dialed
GOOD_PUB = "ab" * 32
GOOD_TOK = "routing-token"

_CASES = [
    # (title, env dict, expect warnings? / cfg presence, warning substrings)
    ("none set -> silent, direct dial",
     {}, False, None, []),
    ("full valid triple -> silent, cfg present",
     {"CYBERNET_RELAY_URL": GOOD_URL,
      "CYBERNET_RELAY_PUBKEY": GOOD_PUB,
      "CYBERNET_RELAY_TOKEN": GOOD_TOK}, False, True, []),
    ("only URL -> warns on PUBKEY + TOKEN unset",
     {"CYBERNET_RELAY_URL": GOOD_URL}, True, None,
     ["CYBERNET_RELAY_PUBKEY unset", "CYBERNET_RELAY_TOKEN unset"]),
    ("URL + token, no pubkey -> warns PUBKEY unset only",
     {"CYBERNET_RELAY_URL": GOOD_URL,
      "CYBERNET_RELAY_TOKEN": GOOD_TOK}, True, None,
     ["CYBERNET_RELAY_PUBKEY unset"]),
    ("URL + non-64 pubkey -> warns pubkey shape",
     {"CYBERNET_RELAY_URL": GOOD_URL,
      "CYBERNET_RELAY_PUBKEY": "abc",
      "CYBERNET_RELAY_TOKEN": GOOD_TOK}, True, None,
     ["CYBERNET_RELAY_PUBKEY must be 64 hex chars"]),
    ("URL + 64-char non-hex pubkey -> warns not hex",
     {"CYBERNET_RELAY_URL": GOOD_URL,
      "CYBERNET_RELAY_PUBKEY": "zz" * 32,
      "CYBERNET_RELAY_TOKEN": GOOD_TOK}, True, None,
     ["CYBERNET_RELAY_PUBKEY not hex"]),
    ("oversize token -> warns too long, no secret leaked",
     {"CYBERNET_RELAY_URL": GOOD_URL,
      "CYBERNET_RELAY_PUBKEY": GOOD_PUB,
      "CYBERNET_RELAY_TOKEN": "t" * 4097}, True, None,
     ["CYBERNET_RELAY_TOKEN too long"]),
    ("malformed URL -> warns URL malformed",
     {"CYBERNET_RELAY_URL": "not a url at all!!!",
      "CYBERNET_RELAY_PUBKEY": GOOD_PUB,
      "CYBERNET_RELAY_TOKEN": GOOD_TOK}, True, None,
     ["CYBERNET_RELAY_URL malformed"]),
    ("all three empty strings -> silent, same as unset",
     {"CYBERNET_RELAY_URL": "   ",
      "CYBERNET_RELAY_PUBKEY": " ",
      "CYBERNET_RELAY_TOKEN": ""}, False, None, []),
    ("full triple -> warnings never leak the token value",
     {"CYBERNET_RELAY_URL": GOOD_URL,
      "CYBERNET_RELAY_PUBKEY": GOOD_PUB,
      "CYBERNET_RELAY_TOKEN": "t" * 4097}, True, None, []),
    ("uppercase pubkey accepted (lowered) -> cfg present, silent",
     {"CYBERNET_RELAY_URL": GOOD_URL,
      "CYBERNET_RELAY_PUBKEY": GOOD_PUB.upper(),
      "CYBERNET_RELAY_TOKEN": GOOD_TOK}, False, True, []),
    ("url-only whitespace-trimmed still counts as unset",
     {"CYBERNET_RELAY_URL": GOOD_URL,
      "CYBERNET_RELAY_PUBKEY": "  ",
      "CYBERNET_RELAY_TOKEN": GOOD_TOK}, True, None,
     ["CYBERNET_RELAY_PUBKEY unset"]),
]

_ENV_KEYS = ("CYBERNET_RELAY_URL", "CYBERNET_RELAY_PUBKEY", "CYBERNET_RELAY_TOKEN")


def _run_case(env, expect_warnings, expect_cfg, substrings):
    saved = {k: os.environ.get(k) for k in _ENV_KEYS}
    for k in _ENV_KEYS:
        os.environ.pop(k, None)
    for k, v in env.items():
        os.environ[k] = v
    try:
        warns = host._relay_warnings()
        cfg = host._relay_cfg()
    finally:
        for k in _ENV_KEYS:
            os.environ.pop(k, None)
        for k, v in saved.items():
            if v is not None:
                os.environ[k] = v
    if expect_warnings:
        assert warns, "expected warnings, got none"
    else:
        assert not warns, f"expected silence, got {warns!r}"
    if expect_cfg is True:
        assert cfg is not None, "expected a relay cfg, got None"
    elif expect_cfg is None:
        assert cfg is None, f"expected no cfg, got {cfg!r}"
    for sub in substrings:
        assert any(sub in w for w in warns), f"{sub!r} not in {warns!r}"
    # never leak secret values into warnings
    joined = " ".join(warns)
    for k in _ENV_KEYS:
        val = (env.get(k) or "").strip()
        if len(val) > 12:
            assert val not in joined, f"secret value leaked: {k}"


def main():
    for title, env, exp_warn, exp_cfg, subs in _CASES:
        _run_case(env, exp_warn, exp_cfg, subs)
        print(f"ok: {title}")
    print(f"{len(_CASES)}/{len(_CASES)} reach-relay-warn belt green")


if __name__ == "__main__":
    main()
