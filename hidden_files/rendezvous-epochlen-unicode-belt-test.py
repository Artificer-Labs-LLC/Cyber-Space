#!/usr/bin/env python3
"""Belt: CYBERNET_RENDEZVOUS_EPOCH_LEN refuses integer spellings int()
aliases -- Unicode decimal digits and underscore separators -- at all
three seats (primitive 3 hosting).

core._reach_build (the advertised seat), hold_open._rendezvous_epoch_len
(the held seat) and host._rendezvous_warnings (the warning twin) all
parsed the value with bare int(): int() parses Unicode decimal digits
(Arabic-Indic/fullwidth 600 -> 600) and accepts underscore separators
(6_00 -> 600), so a non-ASCII or underscored spelling set an epoch_len
the operator never wrote in ASCII -- advertised in the signed
descriptor, held at the relay, and blessed in silence by hostd -- where
every _env_int / reach-TTL seat (1212c00..615c80b) refuses those
spellings. Fix: ASCII-digits gate (one optional leading sign, the
60..86400 bounds check unchanged) at all three seats; valid ASCII
spellings byte-exact, aliasing spellings fall back to the frozen
default 3600 at build/hold and warn not-an-integer at hostd.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/rendezvous-epochlen-unicode-belt-test.py
"""
import os
import sys
import tempfile

TMP = tempfile.mkdtemp(prefix="rz-epochlen-unicode-")
os.environ["CYBERNET_DB_DIR"] = TMP
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "resolver"))

import core  # noqa: E402
import hold_open  # noqa: E402
import host as host_mod  # noqa: E402

CASES = {"passed": 0, "failed": 0}


def check(name, cond, extra=""):
    if cond:
        CASES["passed"] += 1
        print(f"  ok  {name}")
    else:
        CASES["failed"] += 1
        print(f"  FAIL {name} {extra}")


_real_gate = core._reject_nonpublic_node_url


def _test_gate(url):
    if url.startswith("http://127.0.0.1:"):
        return "127.0.0.1"
    return _real_gate(url)


core._reject_nonpublic_node_url = _test_gate
os.environ["CYBERNET_PUBLIC_URL"] = "http://127.0.0.1:9999"
os.environ["CYBERNET_RELAY_URL"] = "http://127.0.0.1:9998"
os.environ["CYBERNET_RELAY_PUBKEY"] = "ef" * 32
os.environ["CYBERNET_RELAY_TOKEN"] = "tok123"
os.environ["CYBERNET_RENDEZVOUS"] = "1"

PRIV = "ab" * 32
VAR = "CYBERNET_RENDEZVOUS_EPOCH_LEN"


def _set(raw):
    if raw is None:
        os.environ.pop(VAR, None)
    else:
        os.environ[VAR] = raw


def advertised(raw):
    _set(raw)
    built = core._reach_build("rzprobe", PRIV)
    if not built:
        return None
    rz = [s for s in built[0]["reach"] if s.get("kind") == "rendezvous"]
    return rz[0]["epoch_len"] if rz else None


def held(raw):
    _set(raw)
    return hold_open._rendezvous_epoch_len()


def warns(raw):
    # hostd seat: rendezvous on + a usable relay triple (its own vars).
    _set(raw)
    old = {k: os.environ.get(k) for k in
           ("CYBERNET_RELAY_URL", "CYBERNET_RELAY_PUBKEY",
            "CYBERNET_RELAY_TOKEN")}
    os.environ["CYBERNET_RELAY_URL"] = "https://8.8.8.8:8471"
    os.environ["CYBERNET_RELAY_PUBKEY"] = "cd" * 32
    os.environ["CYBERNET_RELAY_TOKEN"] = "tok"
    try:
        return host_mod._rendezvous_warnings()
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


ARABIC_600 = "٦٠٠"        # Arabic-Indic 600
FULLWIDTH_600 = "６００"  # fullwidth 600
assert int(ARABIC_600) == 600 and int(FULLWIDTH_600) == 600
assert int("6_00") == 600

# Controls: ASCII semantics unchanged at all three seats.
for raw, want in (("600", 600), ("60", 60), ("86400", 86400),
                  ("+600", 600), ("30", 3600), ("86401", 3600),
                  ("banana", 3600), ("", 3600), (None, 3600)):
    check(f"advertised ascii {raw!r} -> {want}", advertised(raw) == want,
          f"got {advertised(raw)}")
    check(f"held ascii {raw!r} -> {want}", held(raw) == want,
          f"got {held(raw)}")
check("warnings ascii valid silent", warns("600") == [])
check("warnings ascii out-of-bounds warns",
      any("not an integer in" in w for w in warns("30")))
check("warnings ascii non-integer warns",
      any("not an integer in" in w for w in warns("banana")))

# Aliasing spellings: build/hold fall back to 3600, warnings fire.
for raw in (ARABIC_600, FULLWIDTH_600, "6_00"):
    check(f"advertised alias {raw!r} -> 3600", advertised(raw) == 3600,
          f"got {advertised(raw)}")
    check(f"held alias {raw!r} -> 3600", held(raw) == 3600,
          f"got {held(raw)}")
    check(f"warnings alias {raw!r}",
          any("not an integer in" in w for w in warns(raw)),
          f"got {warns(raw)}")

print(f"\n{CASES['passed']} passed, {CASES['failed']} failed")
sys.exit(1 if CASES["failed"] else 0)
