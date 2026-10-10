"""Custom epoch_len rendezvous dial triangle: the FULL seam under non-frozen
math — the REAL hold_open_cycle daemon holds derived points under
CYBERNET_RENDEZVOUS_EPOCH_LEN=600, the REAL relay app indexes them, and
the REAL dialer (_rendezvous_strategy extraction -> _relay_open_session)
bridges BY THE POINT under the advertised 600-math. Nothing in the belt
history ever closed this seam: the 17:02 epochlen belt drove the relay
app with per-layer probes, and the 16:53 dial triangle ran the REAL daemon
but only under the frozen 3600 math. Checks:
  * core._reach_build with CYBERNET_RENDEZVOUS=1 + EPOCH_LEN=600 mints
    {"kind": "rendezvous", "epoch_len": 600, "hold_query": ...}
  * the daemon's points register under 600-math (relay verifies
    epoch_len acceptance)
  * _rendezvous_strategy extracts the advertised epoch_len + hold_query
    from the descriptor
  * _relay_open_session with epoch_len=600 -> True (bridged by point,
    descriptor token never sent)
  * the SAME session with epoch_len=3600 (wrong math) reads held:false
    -> False: the mirror pairs by point under the advertised math only,
    silence is loud and fail-closed
  * a wrong name pubkey fail-closes -> False
The harness patches core._reject_nonpublic_node_url to allow the
127.0.0.1 test relay only (the SSRF gate stays intact everywhere else —
the patched wrapper delegates every non-loopback target to the real
gate).

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/rendezvous-epochlen-e2e-test.py
"""
import os
import secrets
import sys
import tempfile
import threading
import time

TMP = tempfile.mkdtemp(prefix="rz-epochlen-e2e-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import routes_relay as rr  # noqa: E402
from fed import ed25519 as _fed_ed25519  # noqa: E402
import rendezvous  # noqa: E402
import hold_open  # noqa: E402
import core  # noqa: E402
import uvicorn  # noqa: E402
from app import app  # noqa: E402

rr._RELAY_ANSWER_WAIT = 5.0
rr._RELAY_HOLD_WAIT = 0.5

EPOCH_LEN = 600
assert rendezvous._epoch_len_ok(EPOCH_LEN)

passed = failed = 0


def check(name, cond, extra=""):
    global passed, failed
    if cond:
        passed += 1
        print(f"  ok  {name}")
    else:
        failed += 1
        print(f"  FAIL {name} {extra}")


name_priv = secrets.token_hex(32)
name_pub = _fed_ed25519.publickey(bytes.fromhex(name_priv)).hex()
identity_priv = secrets.token_hex(32)
identity_pub = _fed_ed25519.publickey(bytes.fromhex(identity_priv)).hex()
RELAY_PUB = secrets.token_hex(32)
TOK = "tok-" + secrets.token_hex(8)

# --- serve the real relay app on a real socket ---------------------------
config = uvicorn.Config(app, host="127.0.0.1", port=18361, log_level="error")
server = uvicorn.Server(config)
srv_thread = threading.Thread(target=server.run, daemon=True)
srv_thread.start()
deadline = time.time() + 10
while not getattr(server, "started", False) and time.time() < deadline:
    time.sleep(0.05)
RELAY = "http://127.0.0.1:18361"

# --- the test-only SSRF allowance: 127.0.0.1 test relay only -------------
_real_gate = core._reject_nonpublic_node_url


def _test_gate(url):
    if url.startswith(RELAY):
        return "127.0.0.1"
    return _real_gate(url)


core._reject_nonpublic_node_url = _test_gate
try:
    _real_gate("http://127.0.0.1:9999/x")
    check("real gate still refuses loopback", False)
except Exception:
    check("real gate still refuses loopback", True)

# --- hoster env: custom epoch_len, rendezvous on ----------------------------
os.environ["CYBERNET_RELAY_URL"] = RELAY
os.environ["CYBERNET_RELAY_PUBKEY"] = RELAY_PUB
os.environ["CYBERNET_RELAY_TOKEN"] = TOK
os.environ["CYBERNET_RENDEZVOUS"] = "1"
os.environ["CYBERNET_RENDEZVOUS_EPOCH_LEN"] = str(EPOCH_LEN)

# the REAL descriptor-mint carries the custom math into the wire format
built = core._reach_build("epochhost", name_priv)
desc = built[0] if built else None
strategies = (desc or {}).get("reach", []) if desc else []
rz = [s for s in strategies if s.get("kind") == "rendezvous"]
check("descriptor mints a rendezvous strategy", len(rz) == 1, repr(strategies))
check("descriptor carries epoch_len=600",
      bool(rz) and rz[0].get("epoch_len") == EPOCH_LEN, repr(rz))
check("descriptor carries the wired hold_query",
      bool(rz) and rz[0].get("hold_query") == "/relay/hold_query", repr(rz))

# --- the REAL daemon holds under the custom math --------------------------
stop = threading.Event()
daemon = threading.Thread(
    target=hold_open.hold_open_cycle,
    args=(RELAY, TOK, name_priv, stop), kwargs={"keepalive_every": 60.0},
    daemon=True)
daemon.start()
time.sleep(0.6)  # let the daemon register and enter /relay/wait

# --- dialer extraction from the caller-verified descriptor ----------------
strat = core._rendezvous_strategy(desc)
check("extraction reads the advertised strategy",
      strat == {"epoch_len": EPOCH_LEN, "hold_query": "/relay/hold_query"},
      repr(strat))

# --- the triangle: probe + open by point under 600-math -------------------
t0 = time.time()
ok = core._relay_open_session(RELAY, "epochhost", name_pub, TOK,
                              epoch_len=strat["epoch_len"],
                              hold_query=strat["hold_query"])
elapsed = time.time() - t0
check("session bridges by point under the advertised 600-math",
      ok is True)
check("bridged inside the dial budget", elapsed < 8.0, f"{elapsed:.1f}s")

# --- the same session under the WRONG math is silence, not a pair ---------
check("wrong math (3600) reads held:false -> silence",
      core._relay_open_session(RELAY, "epochhost", name_pub, TOK,
                               epoch_len=3600,
                               hold_query=strat["hold_query"]) is False)

# --- wrong key still fail-closes -------------------------------------------
check("wrong name pubkey fail-closes",
      core._relay_open_session(RELAY, "epochhost", identity_pub, TOK,
                               epoch_len=EPOCH_LEN,
                               hold_query=strat["hold_query"]) is False)

stop.set()
daemon.join(5)
for k in ("CYBERNET_RELAY_URL", "CYBERNET_RELAY_PUBKEY",
          "CYBERNET_RELAY_TOKEN", "CYBERNET_RENDEZVOUS",
          "CYBERNET_RENDEZVOUS_EPOCH_LEN"):
    os.environ.pop(k, None)
server.should_exit = True
srv_thread.join(5)
print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
