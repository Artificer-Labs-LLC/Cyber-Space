"""Reach/host daemon wiring (resolver/host.py, depth primitive 3/6):
the per-agent hosting daemon — name-key holder + hold-open thread +
reach-announce minting — test-driven. Drives the REAL resolver.host
module, the REAL relay app on a socket, and the REAL core dial half.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/reach-hostd-test.py
"""

import asyncio
import json
import os
import secrets
import sys
import tempfile
import threading
import time
import urllib.request

TMP = tempfile.mkdtemp(prefix="reach-hostd-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

MIRROR_PORT = 18351
MIRROR = f"http://127.0.0.1:{MIRROR_PORT}"
RELAY = MIRROR  # the same app serves the relay routes too

import core  # noqa: E402
import hold_open  # noqa: E402
import uvicorn  # noqa: E402
from app import app  # noqa: E402
from fed import ed25519 as _fed_ed25519  # noqa: E402
from resolver import host as hostd  # noqa: E402

CASES = {"passed": 0, "failed": 0}


def check(name, cond, extra=""):
    if cond:
        CASES["passed"] += 1
        print(f"  ok  {name}")
    else:
        CASES["failed"] += 1
        print(f"  FAIL {name} {extra}")


# --- the test-only SSRF allowance: the two 127.0.0.1 test URLs only ----
_real_gate = core._reject_nonpublic_node_url


def _test_gate(url):
    if url.startswith(MIRROR) or url.startswith(RELAY):
        return "127.0.0.1"
    return _real_gate(url)


core._reject_nonpublic_node_url = _test_gate
# verify the rest of the gate still stands through the wrapper
try:
    core._valid_node_url("http://169.254.169.254/latest/meta-data")
    check("gate: metadata still refused", False)
except Exception:
    check("gate: metadata still refused", True)
try:
    core._valid_node_url("http://127.0.0.1:9999/")
    check("gate: unlisted loopback still refused", False)
except Exception:
    check("gate: unlisted loopback still refused", True)

# --- serve the real app (mirror + relay) on a real socket ----------------
config = uvicorn.Config(app, host="127.0.0.1", port=MIRROR_PORT, log_level="error")
server = uvicorn.Server(config)
threading.Thread(target=server.run, daemon=True).start()
for _ in range(100):
    try:
        urllib.request.urlopen(MIRROR + "/fed/ping", timeout=1)
        break
    except Exception:
        time.sleep(0.1)
else:
    check("mirror up", False)
    sys.exit(1)
check("mirror up", True)


def _keypair():
    seed = secrets.token_hex(32)
    return seed, _fed_ed25519.publickey(bytes.fromhex(seed)).hex()


def _get(path):
    with urllib.request.urlopen(MIRROR + path, timeout=8) as r:
        return r.status, json.loads(r.read())


SK, PK = _keypair()
TOKEN = "hostd-test-token-" + secrets.token_hex(8)
NOW = __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
NOWS = NOW.isoformat()
LATER = (NOW + __import__("datetime").timedelta(days=30)).isoformat()

# claim the test name with the test key (never genesis — this key is fresh)
sig = _fed_ed25519.sign(
    core._name_claim_payload("hostdtest", PK, NOWS, LATER),
    bytes.fromhex(SK), bytes.fromhex(PK)).hex()
check("binding claimed", core.ingest_gossiped_binding(
    {"name": "hostdtest", "node_pubkey": PK, "issued_at": NOWS,
     "expires_at": LATER, "signature": sig}) == "inserted")

os.environ["CYBERNET_HOSTED_NAME"] = "hostdtest"
os.environ["CYBERNET_NAME_PRIVKEY"] = SK
os.environ["CYBERNET_MIRROR_URL"] = MIRROR
os.environ["CYBERNET_PUBLIC_URL"] = MIRROR
os.environ["CYBERNET_RELAY_URL"] = RELAY
os.environ["CYBERNET_RELAY_PUBKEY"] = secrets.token_hex(32)
os.environ["CYBERNET_RELAY_TOKEN"] = TOKEN

# 1: direct+relay announce through the REAL hostd module.
check("announce_once accepted", hostd.announce_once(MIRROR, "hostdtest", SK) is True)
st, desc = _get("/api/v1/names/hostdtest/reach")
check("serve half 200", st == 200)
check("descriptor verifies", core._reach_descriptor_verify(desc) is True)
kinds = [s["kind"] for s in desc["reach"]]
check("direct first, relay second", kinds == ["direct", "relay"], repr(kinds))
check("name-key speaking", desc["node_pubkey"] == PK)
check("idempotent re-announce", hostd.announce_once(MIRROR, "hostdtest", SK) is True)

# 2: the hold-open half holds — the REAL dial half verifies live.
stop = threading.Event()
t = threading.Thread(
    target=hold_open.hold_open_cycle,
    args=(RELAY, TOKEN, SK, stop), daemon=True)
t.start()
time.sleep(1.0)  # give the daemon a beat to register
check("relay session opens through the live daemon",
      core._relay_open_session(RELAY, "hostdtest", PK, TOKEN) is True)
check("wrong binding key fail-closes",
      core._relay_open_session(RELAY, "hostdtest", "ab" * 32, TOKEN) is False)
check("bogus token ignored on the rendezvous path (point routes, "
      "name-key auth holds)",
      core._relay_open_session(RELAY, "hostdtest", PK, "wrong-token") is True)
stop.set()

# 3: no honest reach -> announce_once refuses, nothing published.
SK2, PK2 = _keypair()
sig2 = _fed_ed25519.sign(
    core._name_claim_payload("hostdsilent", PK2, NOWS, LATER),
    bytes.fromhex(SK2), bytes.fromhex(PK2)).hex()
check("second binding claimed", core.ingest_gossiped_binding(
    {"name": "hostdsilent", "node_pubkey": PK2, "issued_at": NOWS,
     "expires_at": LATER, "signature": sig2}) == "inserted")
os.environ["CYBERNET_PUBLIC_URL"] = ""
for k in ("CYBERNET_RELAY_URL", "CYBERNET_RELAY_PUBKEY", "CYBERNET_RELAY_TOKEN"):
    os.environ.pop(k, None)
check("no honest reach -> False", hostd.announce_once(MIRROR, "hostdsilent", SK2) is False)
try:
    _get("/api/v1/names/hostdsilent/reach")
    check("nothing served for the silent name", False)
except Exception as e:
    check("nothing served for the silent name", "404" in str(e), str(e))

# 4: _config fail-closes (a hosting daemon without a name is nothing).
os.environ.pop("CYBERNET_HOSTED_NAME", None)
check("no name -> not runnable", hostd._config()[4] is False)
os.environ["CYBERNET_HOSTED_NAME"] = "hostdtest"
os.environ["CYBERNET_NAME_PRIVKEY"] = "not-hex"
check("bad key -> not runnable", hostd._config()[4] is False)
os.environ["CYBERNET_NAME_PRIVKEY"] = SK
os.environ["CYBERNET_MIRROR_URL"] = "http://127.0.0.1:1/x"
check("unlisted mirror -> not runnable", hostd._config()[4] is False)
os.environ["CYBERNET_MIRROR_URL"] = MIRROR
check("valid config runnable", hostd._config()[4] is True)

# restore reach envs the silence case cleared (test 3 tore them down)
os.environ["CYBERNET_HOSTED_NAME"] = "hostdtest"
os.environ["CYBERNET_NAME_PRIVKEY"] = SK
os.environ["CYBERNET_MIRROR_URL"] = MIRROR
os.environ["CYBERNET_PUBLIC_URL"] = MIRROR
os.environ["CYBERNET_RELAY_URL"] = RELAY
os.environ["CYBERNET_RELAY_PUBKEY"] = secrets.token_hex(32)
os.environ["CYBERNET_RELAY_TOKEN"] = TOKEN

# 5: wrong-key envelope accepted at HTTP but the merge drops it —
# the binding does the identity half.
SKE, PKE = _keypair()
check("wrong-key announce posted",
      hostd.announce_once(MIRROR, "hostdtest", SKE) is True)
st, desc = _get("/api/v1/names/hostdtest/reach")
check("binding key still served (no hijack)", desc["node_pubkey"] == PK)

print(f"\n{CASES['passed']} passed, {CASES['failed']} failed")
sys.exit(1 if CASES["failed"] else 0)
