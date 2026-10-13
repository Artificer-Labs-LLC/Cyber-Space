#!/usr/bin/env python3
"""Belt: _seed_bootstrap refuses a NON-STRING roster field instead of
str()-aliasing it (primitives 2 resolution + 5 discovery).

_seed_bootstrap (core.py) stores a seed's /fed/ping identity card as a
discovery-only roster entry, and it read name/network/version through
str() with no gate — its twin seat, the /fed/announce roster gate in
federation.py, refuses exactly this: a numeric name stringified to the
valid label "12345" and was stored as that peer name, and int
network/version were stored as their digit strings. isinstance gate
at the seat (twin of federation.py): absent fields keep their
defaults, a present non-string refuses the seed (skip — the seat is
best-effort and never raises), and a valid string card is stored
byte-exact. The network is mocked at core._peer_urlopen; envelopes are
minted by the REAL fed envelope machinery and verify for real.

Covers: valid string card -> stored exact (control); int name ->
refused, no row; int network -> refused; int version -> refused;
absent network/version -> defaults stored; bad seed + good seed ->
good seed still stored (skip, not poison).

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/seed-bootstrap-field-type-belt-test.py
"""
import json
import os
import secrets
import sys
import tempfile

TMP = tempfile.mkdtemp(prefix="seed-bootstrap-belt-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core  # noqa: E402

CASES = {"passed": 0, "failed": 0}


def check(name, cond, extra=""):
    if cond:
        CASES["passed"] += 1
        print(f"  ok  {name}")
    else:
        CASES["failed"] += 1
        print(f"  FAIL {name} {extra}")


core.init_db()

SEED_A = "https://93.184.216.34"
SEED_B = "https://93.184.216.35"


def _card(**over):
    priv = secrets.token_hex(32)
    pub = core._fed_ed25519.publickey(bytes.fromhex(priv)).hex()
    body = {"name": "seednode", "network": "cybernet", "version": "0.1.0",
            "node_pub": pub, "genesis": False}
    body.update(over)
    env = core._fed_env.make_envelope(priv, pub, "federation", body)
    return pub, json.dumps(env).encode()


class _Resp:
    def __init__(self, payload):
        self._payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self, n=-1):
        return self._payload


def _run(cards):
    """cards: {seed_url: payload}. Returns (reached, [peer rows])."""
    with core._db_lock, core._db() as conn:
        conn.execute("DELETE FROM peers")
    os.environ["CYBERNET_SEED_URL"] = ",".join(cards)
    os.environ.pop("CYBERNET_PUBLIC_URL", None)
    saved = core._peer_urlopen
    core._peer_urlopen = lambda url, timeout=8: _Resp(
        cards[url.rsplit("/fed/ping", 1)[0]])
    try:
        reached = core._seed_bootstrap()
    finally:
        core._peer_urlopen = saved
    with core._db() as conn:
        rows = [dict(r) for r in conn.execute(
            "SELECT node_pub, name, network, version FROM peers")]
    return reached, rows


# Control: a valid string card is stored byte-exact.
pub, payload = _card()
reached, rows = _run({SEED_A: payload})
check("valid string card -> stored exact (control)",
      reached == 1 and rows == [{"node_pub": pub, "name": "seednode",
                                  "network": "cybernet", "version": "0.1.0"}],
      f"reached={reached} rows={rows!r}")

# The alias: an int name stringified to the valid label "12345".
_, payload = _card(name=12345)
reached, rows = _run({SEED_A: payload})
check("int name 12345 -> refused, no row (alias)",
      reached == 0 and rows == [], f"reached={reached} rows={rows!r}")

_, payload = _card(network=7)
reached, rows = _run({SEED_A: payload})
check("int network -> refused, no row",
      reached == 0 and rows == [], f"reached={reached} rows={rows!r}")

_, payload = _card(version=2)
reached, rows = _run({SEED_A: payload})
check("int version -> refused, no row",
      reached == 0 and rows == [], f"reached={reached} rows={rows!r}")

for bad in (["seednode"], True, None):
    _, payload = _card(name=bad)
    reached, rows = _run({SEED_A: payload})
    check(f"non-string name {bad!r} -> refused, no row",
          reached == 0 and rows == [], f"reached={reached} rows={rows!r}")

# Absent network/version keep their defaults.
pub, payload = _card()
body = json.loads(payload)
del body["body"]["network"], body["body"]["version"]
# Re-sign after mutation: mint a card whose body omits the fields.
priv = secrets.token_hex(32)
pub = core._fed_ed25519.publickey(bytes.fromhex(priv)).hex()
env = core._fed_env.make_envelope(
    priv, pub, "federation",
    {"name": "bare", "node_pub": pub, "genesis": False})
reached, rows = _run({SEED_A: json.dumps(env).encode()})
check("absent network/version -> defaults stored",
      reached == 1 and rows == [{"node_pub": pub, "name": "bare",
                                  "network": "cybernet", "version": "0.1.0"}],
      f"reached={reached} rows={rows!r}")

# Skip, not poison: a bad seed first, a good seed second.
_, bad_payload = _card(name=12345)
good_pub, good_payload = _card(name="goodseed")
reached, rows = _run({SEED_A: bad_payload, SEED_B: good_payload})
check("bad seed + good seed -> good seed stored (skip, not poison)",
      reached == 1 and len(rows) == 1 and rows[0]["node_pub"] == good_pub
      and rows[0]["name"] == "goodseed",
      f"reached={reached} rows={rows!r}")

print(f"\n{CASES['passed']} passed, {CASES['failed']} failed")
sys.exit(1 if CASES["failed"] else 0)
