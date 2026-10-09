"""Relay dial half end-to-end: core.py's REAL _relay_open_session (not a
re-implemented verify) against a daemon-held hold-open — closing the loop
on core.py's dial path. The REAL relay app serves on a socket, the REAL
hold_open_cycle runs as a NAT-hidden hoster in a thread, and the REAL
core._relay_open_session is the dialer: /relay/open -> {challenge,
name_key_sig} -> fail-closed name-key verify inside core. Checks:
  * _relay_route extracts the hoster's advertised relay strategy from a
    verified-shape descriptor (route -> session loop closed)
  * session opens through the live daemon (True)
  * a wrong name pubkey fail-closes (False) — same check, untrusted key
  * a bogus routing token is IGNORED on the rendezvous path (the held
    point, not the descriptor token, routes the session; the name-key
    signature is the auth, so the session still bridges — True)
  * a hoster whose daemon died gets silence (False)
  * _relay_open_session never raises, even on a dead relay
The harness patches core._reject_nonpublic_node_url to allow the
127.0.0.1 test relay only (the SSRF gate stays intact everywhere else —
the patched wrapper delegates every non-loopback target to the real
gate).

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/reach-relay-dial-e2e-test.py
"""
import json
import os
import secrets
import sys
import tempfile
import threading
import time

TMP = tempfile.mkdtemp(prefix="reach-relay-dial-e2e-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import routes_relay as rr  # noqa: E402
from fed import ed25519 as _fed_ed25519  # noqa: E402
import hold_open  # noqa: E402
import core  # noqa: E402
import uvicorn  # noqa: E402
from app import app  # noqa: E402

# keep the wait windows fast for the suite; shapes unchanged
rr._RELAY_ANSWER_WAIT = 5.0
rr._RELAY_HOLD_WAIT = 0.5

passed = failed = 0


def check(name, cond, extra=""):
    global passed, failed
    if cond:
        passed += 1
        print(f"  ok  {name}")
    else:
        failed += 1
        print(f"  FAIL {name} {extra}")


# the name key stands in for a real .cyberspace name key; the master
# identity key is a DIFFERENT key core's dial half must never trust
name_priv = secrets.token_hex(32)
name_pub = _fed_ed25519.publickey(bytes.fromhex(name_priv)).hex()
identity_priv = secrets.token_hex(32)
identity_pub = _fed_ed25519.publickey(bytes.fromhex(identity_priv)).hex()
TOK = "tok-" + secrets.token_hex(8)

# --- serve the real relay app on a real socket ---------------------------
config = uvicorn.Config(app, host="127.0.0.1", port=18342, log_level="error")
server = uvicorn.Server(config)
srv_thread = threading.Thread(target=server.run, daemon=True)
srv_thread.start()
deadline = time.time() + 10
while not getattr(server, "started", False) and time.time() < deadline:
    time.sleep(0.05)
RELAY = "http://127.0.0.1:18342"

# --- the test-only SSRF allowance: 127.0.0.1 test relay only -------------
_real_gate = core._reject_nonpublic_node_url


def _test_gate(url):
    if url.startswith(RELAY):
        return "127.0.0.1"
    return _real_gate(url)


core._reject_nonpublic_node_url = _test_gate
# verify the rest of the gate still stands through the wrapper
try:
    _real_gate("http://127.0.0.1:9999/x")
    check("real gate still refuses loopback", False)
except Exception:
    check("real gate still refuses loopback", True)
check("test wrapper allows the test relay",
      core._reject_nonpublic_node_url(RELAY + "/relay/open") == "127.0.0.1")

# --- route extraction from a verified-shape descriptor --------------------
desc = {"reach": [
    {"kind": "direct", "url": "http://198.51.100.7:8443"},  # not dialed here
    {"kind": "relay", "relay": name_pub, "url": RELAY, "token": TOK},
]}
route = core._relay_route(desc)
check("route extracted", isinstance(route, dict)
      and route.get("url") == RELAY and route.get("token") == TOK
      and route.get("relay_pub") == name_pub)
check("route skips direct-first ordering",
      route is not None and route.get("kind") is None)
check("route None on garbage",
      core._relay_route({"reach": [{"kind": "relay"}]}) is None)
check("route None on no reach", core._relay_route({}) is None)

# --- the full triangle: real daemon, real core dial half -----------------
stop = threading.Event()
daemon = threading.Thread(
    target=hold_open.hold_open_cycle,
    args=(RELAY, TOK, name_priv, stop), kwargs={"keepalive_every": 60.0},
    daemon=True)
daemon.start()
time.sleep(0.4)  # let the daemon register and enter /relay/wait

t0 = time.time()
ok = core._relay_open_session(RELAY, "somewhere", name_pub, TOK)
elapsed = time.time() - t0
check("core dial half opens through live daemon", ok is True)
check("triangle bridged inside dial budget", elapsed < 8.0,
      f"{elapsed:.1f}s")

# --- fail-closed paths -----------------------------------------------------
check("wrong name pubkey fail-closes",
      core._relay_open_session(RELAY, "somewhere", identity_pub, TOK)
      is False)
# The probe found the point held, so the session opened BY THE POINT —
# the descriptor's routing token is never sent on the rendezvous path
# (the dialer never learns the token it didn't need). The name-key
# signature over the relay's challenge is the auth, and it verifies,
# so the session bridges even with a bogus token.
check("bogus token ignored on the rendezvous path (point routes)",
      core._relay_open_session(RELAY, "somewhere", name_pub, "nope") is True)

# --- a hoster whose daemon died is unreachable, not an error -------------
stop.set()
daemon.join(5)
time.sleep(0.4)  # hold-open TTL expiry is 300s; stop the wait loop first
# drain: open must now wait out the answer window with no hoster answering
t0 = time.time()
dead = core._relay_open_session(RELAY, "somewhere", name_pub, TOK)
elapsed = time.time() - t0
check("dead hoster -> False (silence)", dead is False)
check("dead hoster stayed inside the dial budget", elapsed < 9.0,
      f"{elapsed:.1f}s")

# --- never raises ----------------------------------------------------------
check("never raises on a dead relay",
      core._relay_open_session("http://127.0.0.1:1", "somewhere",
                               name_pub, TOK) is False)

server.should_exit = True
srv_thread.join(5)
print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
