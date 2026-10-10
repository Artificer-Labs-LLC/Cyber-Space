"""Rendezvous dialer probe against the REAL depth stack
(docs/RENDEZVOUS.md, primitive 3).

Drives the REAL public dial entry core.resolve_cyberspace — not a
planner, not _relay_open_session called by hand — through the live
relay+rendezvous leg of step 6: binding fetch + re-verify, descriptor
fetch + re-verify, the derived-point willingness probe running under
the HOSTER'S epoch math (a custom 900s epoch_len, never the frozen 3600
default), session opened BY THE POINT, and the name key signing a fresh
challenge through the relay's hold-open.

The stack is real end to end: the real app (mirror+relay in one) on a
loopback socket, the claim through the real /api/v1/names/claim route,
the real hostd announce_once (NAT-hidden, relay-only reach, rendezvous
kind advertised), and the real hold_open_cycle daemon holding the
derived (E, E-1) points. A spy belt on core._relay_hold_probe freezes
the coupling the depth chain depends on: the probe derives with the
epoch_len the descriptor advertised, which the daemon held under.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/rendezvous-depth-probe-test.py
"""
import datetime
import json
import os
import secrets
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request

TMP = tempfile.mkdtemp(prefix="rv-depthprobe-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import core  # noqa: E402
import hold_open  # noqa: E402
import rendezvous  # noqa: E402
import uvicorn  # noqa: E402
from app import app  # noqa: E402
from fed import ed25519 as _fed_ed25519  # noqa: E402
from resolver import host as hostd  # noqa: E402

MIRROR_PORT = 18473
MIRROR = f"http://127.0.0.1:{MIRROR_PORT}"
RELAY = MIRROR  # the real app serves both the mirror and relay routes

CASES = {"passed": 0, "failed": 0}


def check(name, cond, extra=""):
    if cond:
        CASES["passed"] += 1
        print(f"  ok  {name}")
    else:
        CASES["failed"] += 1
        print(f"  FAIL {name} {extra}")


# --- the test-only SSRF allowance: the 127.0.0.1 test URL only -------------
_real_gate = core._reject_nonpublic_node_url


def _test_gate(url):
    if url.startswith(MIRROR):
        return "127.0.0.1"
    return _real_gate(url)


core._reject_nonpublic_node_url = _test_gate

# --- serve the real app (mirror + relay) on a real socket ------------------
config = uvicorn.Config(app, host="127.0.0.1", port=MIRROR_PORT,
                        log_level="error")
server = uvicorn.Server(config)
threading.Thread(target=server.run, daemon=True).start()
for _ in range(100):
    try:
        urllib.request.urlopen(MIRROR + "/fed/ping", timeout=1)
        break
    except Exception:
        time.sleep(0.1)
else:
    check("mirror+relay app up", False)
    sys.exit(1)
check("mirror+relay app up", True)


def _keypair():
    seed = secrets.token_hex(32)
    return seed, _fed_ed25519.publickey(bytes.fromhex(seed)).hex()


def _post_claim(name, pub, issued, expires, sig):
    body = urllib.parse.urlencode(
        {"name": name, "node_pubkey": pub, "issued_at": issued,
         "expires_at": expires, "signature": sig}).encode()
    req = urllib.request.Request(MIRROR + "/api/v1/names/claim", data=body,
                                 method="POST")
    with urllib.request.urlopen(req, timeout=8) as r:
        return r.status, json.loads(r.read())


SK, PK = _keypair()            # the name key — self-authenticating name
_, RELAYPUB = _keypair()       # the relay's identity (the app, in this wire)
TOK = secrets.token_hex(16)    # the hoster's routing token at the relay
NOW = datetime.datetime.now(datetime.timezone.utc)
NOWS = NOW.isoformat()
LATER = (NOW + datetime.timedelta(days=30)).isoformat()
LABEL = "rvprobe"

# 1: naming — the claim goes through the real HTTP route, signed by the
# real name key.
sig = _fed_ed25519.sign(
    core._name_claim_payload(LABEL, PK, NOWS, LATER),
    bytes.fromhex(SK), bytes.fromhex(PK)).hex()
try:
    st, claimed = _post_claim(LABEL, PK, NOWS, LATER, sig)
    ok_claim = (st == 200 and claimed.get("status") == "claimed"
                and claimed.get("node_pubkey") == PK)
except Exception as e:
    ok_claim = False
    e_claim = str(e)
check("binding claimed via real route", ok_claim,
      repr(claimed) if ok_claim else e_claim)

# 2: hosting — the real daemon module announces NAT-hidden reach: relay
# only (no public URL — hosting from anywhere), with the rendezvous kind
# advertising the hoster's CUSTOM epoch_len (900, not the frozen 3600).
os.environ["CYBERNET_HOSTED_NAME"] = LABEL
os.environ["CYBERNET_NAME_PRIVKEY"] = SK
os.environ["CYBERNET_RELAY_URL"] = RELAY
os.environ["CYBERNET_RELAY_PUBKEY"] = RELAYPUB
os.environ["CYBERNET_RELAY_TOKEN"] = TOK
os.environ["CYBERNET_RENDEZVOUS"] = "1"
os.environ["CYBERNET_RENDEZVOUS_EPOCH_LEN"] = "900"
os.environ.pop("CYBERNET_PUBLIC_URL", None)
check("announce_once accepted (relay-only, rendezvous advertised)",
      hostd.announce_once(MIRROR, LABEL, SK) is True)

with urllib.request.urlopen(
        MIRROR + f"/api/v1/names/{LABEL}/reach", timeout=8) as r:
    reach_doc = json.loads(r.read())
kinds = [s.get("kind") for s in (reach_doc.get("reach") or [])]
rz = next((s for s in (reach_doc.get("reach") or [])
           if s.get("kind") == "rendezvous"), {})
check("descriptor advertises relay + rendezvous(900), no direct",
      "relay" in kinds and rz.get("epoch_len") == 900
      and "direct" not in kinds, repr(kinds))

# 3: the NAT-hidden hoster's hold-open daemon — registers the routing
# token under the derived (E, E-1) points at the same relay (900-math).
stop = threading.Event()
daemon = threading.Thread(
    target=hold_open.hold_open_cycle,
    args=(RELAY, TOK, SK, stop), kwargs={"keepalive_every": 60.0},
    daemon=True)
daemon.start()
time.sleep(0.5)  # let the daemon register and enter /relay/wait

# 4: the spy belt — record the epoch_len the REAL probe derives under.
probe_seen = {}
_real_probe = core._relay_hold_probe


def _spy_probe(relay_url, node_pubkey, epoch_len=rendezvous.EPOCH_LEN_DEFAULT,
               hold_query=core._RENDEZVOUS_HOLD_QUERY):
    probe_seen["epoch_len"] = epoch_len
    return _real_probe(relay_url, node_pubkey, epoch_len, hold_query)


core._relay_hold_probe = _spy_probe
try:
    # 5: the dial — the REAL public entry through the REAL stack.
    t0 = time.time()
    result = core.resolve_cyberspace(LABEL + ".cyberspace", MIRROR)
    elapsed = time.time() - t0
finally:
    core._relay_hold_probe = _real_probe

check("resolve_cyberspace dials the rendezvous path through the real stack",
      isinstance(result, dict) and result.get("name") == LABEL
      and result.get("node_pubkey") == PK and result.get("node_url") == RELAY
      and isinstance(result.get("via_relay"), dict)
      and result["via_relay"].get("token") == TOK,
      repr(result)[:200] if not isinstance(result, dict) else "")
check("dial bridged inside the triangle budget", elapsed < 20.0,
      f"{elapsed:.1f}s")
check("probe ran under the hoster's epoch math (900, not 3600)",
      probe_seen.get("epoch_len") == 900,
      f"epoch_len={probe_seen.get('epoch_len')}")
core._resolve_memo.clear()

# 6: fail-closed — silence, never a guess.
check("unclaimed name -> None",
      core.resolve_cyberspace("nobodyclaimedit.cyberspace", MIRROR) is None)
stop.set()
# The daemon exits only when its 40s /relay/wait long-poll returns and
# the cycle sees the stop flag — join(5) would time out and leave the
# daemon alive to answer the "dead" dial (a false pass). Wait for the
# real exit; the relay's hold-open registration (300s TTL) still answers
# held:true, so the dial must wait out the relay's answer window with
# no hoster answering — the silence path, not an error.
daemon.join(50)
check("dead hoster: daemon actually exited", not daemon.is_alive())
time.sleep(0.4)  # let the wait loop settle before the silence dial
t0 = time.time()
dead = core.resolve_cyberspace(LABEL + ".cyberspace", MIRROR)
elapsed = time.time() - t0
check("dead hoster -> None (relay's point index still held:true on TTL; "
      "answer window expires unanswered -> silence)", dead is None)
check("dead hoster stayed inside the dial budget", elapsed < 15.0,
      f"{elapsed:.1f}s")

print(f"\n{CASES['passed']} passed, {CASES['failed']} failed")
sys.exit(1 if CASES["failed"] else 0)
