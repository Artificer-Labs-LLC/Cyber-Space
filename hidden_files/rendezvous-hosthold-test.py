"""Hoster dual-point rendezvous hold (hold_open.py, docs/RENDEZVOUS.md
frozen spec, primitive 3): the hold-open daemon indexes its hold-open
token under the derived (E, E-1) points at the same relay, re-registers
on epoch roll, and hands the hold-open thread the ROUTING token (not
the relay pubkey — regression pin).

Drives the REAL relay app on a socket plus the REAL hold_open helpers.
Cycle wiring is tested with a patched transport (fast), the actual
point POSTs go to the real relay.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/rendezvous-hosthold-test.py
"""

import json
import os
import sys
import tempfile
import threading
import time
import urllib.request
import urllib.error

TMP = tempfile.mkdtemp(prefix="rv-hosthold-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

PORT = 18353
BASE = f"http://127.0.0.1:{PORT}"

import rendezvous  # noqa: E402
import uvicorn  # noqa: E402
from app import app  # noqa: E402
import hold_open  # noqa: E402
from fed import ed25519 as _ed  # noqa: E402
from resolver import host as hostd  # noqa: E402

CASES = {"passed": 0, "failed": 0}


def check(name, cond, extra=""):
    if cond:
        CASES["passed"] += 1
        print(f"  ok  {name}")
    else:
        CASES["failed"] += 1
        print(f"  FAIL {name} {extra}")


def get(path):
    try:
        with urllib.request.urlopen(BASE + path, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, {}


srv = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=PORT,
                                    log_level="error"))
t = threading.Thread(target=srv.run, daemon=True)
t.start()
for _ in range(100):
    try:
        urllib.request.urlopen(BASE + "/api/v1/node", timeout=2).close()
        break
    except Exception:
        time.sleep(0.1)
else:
    print("  FAIL app did not boot")
    sys.exit(1)

# Real name keypair — the KDF needs real ed25519 material.
SEED = os.urandom(32).hex()
PUB = _ed.publickey(bytes.fromhex(SEED)).hex()
OTHER_PUB = _ed.publickey(os.urandom(32)).hex()
TOKEN = "hosthold-tok-1"

# 1. _name_pub_from_priv matches the descriptor derivation, fails closed
check("pub derived from seed", hold_open._name_pub_from_priv(SEED) == PUB)
check("pub from garbage -> None", hold_open._name_pub_from_priv("zz") is None)

# 2. dual-point register against the REAL relay: both points held
n = hold_open._rendezvous_points_register(BASE, TOKEN, PUB)
check("dual-point register accepted 2", n == 2, f"got {n}")
cur, prev = rendezvous.derive_points(time.time(), PUB)
s, b = get("/relay/hold_query?point_id=" + cur)
check("point E held", s == 200 and b == {"held": True}, f"got {b}")
s, b = get("/relay/hold_query?point_id=" + prev)
check("point E-1 held", s == 200 and b == {"held": True}, f"got {b}")
s, b = get("/relay/hold_query?point_id=" +
           rendezvous.derive_points(time.time(), OTHER_PUB)[0])
check("stranger point held false", s == 200 and b == {"held": False})

# 3. malformed pub -> 0, no crash, no index pollution
n = hold_open._rendezvous_points_register(BASE, "bad-pub-tok", "zz")
check("bad pub -> 0 accepted, no crash", n == 0, f"got {n}")

# 4. _rendezvous_hold_maybe: no name key -> passthrough
check("no name key -> epoch passthrough",
      hold_open._rendezvous_hold_maybe(BASE, TOKEN, None, 1234) == 1234)

# 5. same epoch -> no re-register; rolled epoch -> re-register + new epoch
epoch = rendezvous.epoch_for(time.time())
check("same epoch -> unchanged, no call",
      hold_open._rendezvous_hold_maybe(BASE, TOKEN, PUB, epoch) == epoch)
real_epoch_for = rendezvous.epoch_for
rendezvous.epoch_for = lambda now, epoch_len=3600: real_epoch_for(now, epoch_len) + 5
try:
    got = hold_open._rendezvous_hold_maybe(BASE, "roll-tok", PUB, epoch)
finally:
    rendezvous.epoch_for = real_epoch_for
check("rolled epoch -> re-registered, new epoch returned", got == epoch + 5,
      f"got {got}")
s, b = get("/relay/hold_query?point_id=" + cur)
check("current pair still held after roll re-register",
      s == 200 and b == {"held": True}, f"got {b}")

# 6. cycle wiring: the daemon registers the points with the ROUTING
#    token and the name key's pub (patched transport, real logic)
calls = []
real_points_register = hold_open._rendezvous_points_register
real_post = hold_open._post
real_cycle_once = hold_open.hold_open_cycle_once
hold_open._rendezvous_points_register = lambda u, tok, pub: calls.append(
    (u, tok, pub)) or 2
hold_open._post = lambda u, p, payload, timeout: {"ok": True}
hold_open.hold_open_cycle_once = lambda u, tok, priv: (True, 0)
stop = threading.Event()
ct = threading.Thread(target=hold_open.hold_open_cycle,
                      args=(BASE, "cycle-tok-9", SEED, stop),
                      kwargs={"keepalive_every": 0.2}, daemon=True)
try:
    ct.start()
    time.sleep(0.8)
finally:
    stop.set()
    hold_open._rendezvous_points_register = real_points_register
    hold_open._post = real_post
    hold_open.hold_open_cycle_once = real_cycle_once
ct.join(timeout=5)
check("cycle indexed points at least once", len(calls) >= 1,
      f"calls={calls}")
check("cycle used the routing token, not a pubkey",
      all(c[1] == "cycle-tok-9" for c in calls), f"calls={calls}")
check("cycle derived the name pub from the seed",
      all(c[2] == PUB for c in calls), f"calls={calls}")
check("no re-register inside one epoch (single index)",
      len(calls) == 1, f"calls={len(calls)}")

# 7. token-swap regression pin: _relay_cfg returns
#    (url, relay_pub, routing_token) — the order run() unpacks. The
#    sandbox DNS resolves every hostname to the egress proxy IP, so the
#    SSRF gate rejects all URLs here; bypass validation — this pins the
#    tuple ORDER, not the validator.
import core as _core  # noqa: E402
_real_vnu = _core._valid_node_url
_core._valid_node_url = lambda u: u
os.environ["CYBERNET_RELAY_URL"] = "https://relay.example.com/"
os.environ["CYBERNET_RELAY_PUBKEY"] = "ee" * 32
os.environ["CYBERNET_RELAY_TOKEN"] = "the-routing-token"
try:
    cfg = hostd._relay_cfg()
finally:
    _core._valid_node_url = _real_vnu
check("_relay_cfg order (url, pub, token)",
      cfg == ("https://relay.example.com/", "ee" * 32, "the-routing-token"),
      f"got {cfg}")

srv.should_exit = True
t.join(timeout=5)
print(f"done: {CASES['passed']} passed, {CASES['failed']} failed")
sys.exit(1 if CASES["failed"] else 0)
