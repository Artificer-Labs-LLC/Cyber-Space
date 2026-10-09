"""Rendezvous kind end-to-end (core.py + hold_open.py + routes_relay.py,
docs/RENDEZVOUS.md frozen spec, primitive 3): the descriptor's
`kind: "rendezvous"` is now REAL, not reserved — the advertised
epoch_len drives the meeting math on all four sides.

Drives the REAL relay app on a socket plus the REAL mint/verify/
extract/probe functions: mint with CYBERNET_RENDEZVOUS=1 and a
non-default epoch_len (600, proving it is not the frozen default
3600), signature-verify the descriptor, extract the strategy, register
a derived point under the custom math, and confirm the relay answers
willing ONLY under that math — while the default-3600 point for the
same name reads held:false. Fail-closed checks: bad epoch_len at
register is a 400, malformed descriptor members are skipped, missing
opt-in mints nothing, bad env falls back to 3600.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/rendezvous-epochlen-test.py
"""

import json
import os
import secrets
import sys
import tempfile
import threading
import time
import urllib.request
import urllib.error

TMP = tempfile.mkdtemp(prefix="rv-epochlen-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

PORT = 18361
BASE = f"http://127.0.0.1:{PORT}"

import rendezvous  # noqa: E402
import uvicorn  # noqa: E402
from app import app  # noqa: E402
import core  # noqa: E402
import routes_relay  # noqa: E402
from fed import ed25519 as _fed_ed25519  # noqa: E402
from fastapi import HTTPException  # noqa: E402

CASES = {"passed": 0, "failed": 0}


def check(name, cond, extra=""):
    if cond:
        CASES["passed"] += 1
        print(f"  ok  {name}")
    else:
        CASES["failed"] += 1
        print(f"  FAIL {name} {extra}")


def post(path, payload):
    body = json.dumps(payload).encode()
    req = urllib.request.Request(BASE + path, data=body,
                                 headers={"Content-Type": "application/json"},
                                 method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, {}


def get(path):
    try:
        with urllib.request.urlopen(BASE + path, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, {}


# --- keys -----------------------------------------------------------------
name_priv = secrets.token_hex(32)
name_pub = _fed_ed25519.publickey(bytes.fromhex(name_priv)).hex()
relay_priv = secrets.token_hex(32)
relay_pub = _fed_ed25519.publickey(bytes.fromhex(relay_priv)).hex()
TOK = "tok-" + secrets.token_hex(8)

# --- serve the real relay app on a real socket ----------------------------
config = uvicorn.Config(app, host="127.0.0.1", port=PORT, log_level="error")
server = uvicorn.Server(config)
srv_thread = threading.Thread(target=server.run, daemon=True)
srv_thread.start()
deadline = time.time() + 10
while not getattr(server, "started", False) and time.time() < deadline:
    time.sleep(0.05)

# --- test-only SSRF allowance: 127.0.0.1 test relay only -----------------
_real_gate = core._reject_nonpublic_node_url


def _test_gate(url):
    if url.startswith(BASE):
        return "127.0.0.1"
    return _real_gate(url)


core._reject_nonpublic_node_url = _test_gate

os.environ["CYBERNET_RELAY_URL"] = BASE
os.environ["CYBERNET_RELAY_PUBKEY"] = relay_pub
os.environ["CYBERNET_RELAY_TOKEN"] = TOK
os.environ["CYBERNET_RENDEZVOUS"] = "1"
os.environ["CYBERNET_RENDEZVOUS_EPOCH_LEN"] = "600"

# --- 1: mint advertises the rendezvous kind --------------------------------
built = core._reach_build("harnessname", name_priv)
check("mint returns descriptor with opt-in", built is not None)
desc, pub = built
check("descriptor verifies fail-closed", core._reach_descriptor_verify(desc))
rz = [s for s in desc["reach"] if s.get("kind") == "rendezvous"]
check("rendezvous kind minted", len(rz) == 1,
      f"reach={json.dumps(desc['reach'])[:200]}")
rz = rz[0]
check("advertised epoch_len is 600 (not default)",
      rz.get("epoch_len") == 600, f"got {rz.get('epoch_len')}")
check("advertised hold_query is the wired path",
      rz.get("hold_query") == "/relay/hold_query")

# --- 2: dialer extracts it ------------------------------------------------
strat = core._rendezvous_strategy(desc)
check("extractor returns the strategy", strat == {
      "epoch_len": 600, "hold_query": "/relay/hold_query"}, f"got {strat}")

# --- 3: no opt-in -> no entry ----------------------------------------------
os.environ["CYBERNET_RENDEZVOUS"] = "0"
desc2 = core._reach_build("harnessname", name_priv)[0]
kinds = [s.get("kind") for s in desc2["reach"]]
check("opt-out mints no rendezvous kind", "rendezvous" not in kinds,
      f"kinds={kinds}")
# rendezvous without a relay strategy is not advertised (no meeting surface)
del os.environ["CYBERNET_RELAY_URL"]
os.environ["CYBERNET_RENDEZVOUS"] = "1"
desc3 = core._reach_build("harnessname", name_priv)
check("no strategies at all without relay -> silence (None)",
      desc3 is None, f"got {desc3!r}")
os.environ["CYBERNET_RELAY_URL"] = BASE

# --- 4: bad env epoch_len falls back to 3600 -------------------------------
os.environ["CYBERNET_RENDEZVOUS_EPOCH_LEN"] = "30"  # below 60: invalid
desc4 = core._reach_build("harnessname", name_priv)[0]
rz4 = [s for s in desc4["reach"] if s.get("kind") == "rendezvous"][0]
check("invalid env epoch_len -> frozen default 3600",
      rz4.get("epoch_len") == 3600, f"got {rz4.get('epoch_len')}")
os.environ["CYBERNET_RENDEZVOUS_EPOCH_LEN"] = "600"

# --- 5: malformed members skipped, never fatal -----------------------------
bad = {"reach": [{"kind": "rendezvous", "epoch_len": 30,
                  "hold_query": "/relay/hold_query"},
                 {"kind": "rendezvous", "epoch_len": 600,
                  "hold_query": "not-a-path"},
                 {"kind": "rendezvous", "epoch_len": 600,
                  "hold_query": "/ok?q=1"}]}
check("malformed rendezvous members skipped",
      core._rendezvous_strategy(bad) is None)
check("absent rendezvous kind -> None",
      core._rendezvous_strategy({"reach": [{"kind": "direct"}]}) is None)

# --- 6: relay honors the advertised math ------------------------------------
pair600 = rendezvous.derive_points(time.time(), name_pub, 600)
pair3600 = rendezvous.derive_points(time.time(), name_pub, 3600)
check("600 and 3600 derive different points",
      pair600 is not None and pair3600 is not None
      and set(pair600).isdisjoint(set(pair3600)))
st, _ = post("/relay/register", {"token": TOK,
                                 "rendezvous_point": pair600[0],
                                 "name_pub": name_pub, "epoch_len": 600})
check("register accepts 600-math point", st == 200, f"status={st}")
st, body = get("/relay/hold_query?point_id=" + pair600[0])
check("hold_query answers willing under advertised math",
      st == 200 and body.get("held") is True, f"{st} {body}")
st, body = get("/relay/hold_query?point_id=" + pair3600[0])
check("default-math point for same name reads held:false",
      st == 200 and body.get("held") is False, f"{st} {body}")

# --- 7: dialer probe runs the advertised math -------------------------------
held = core._relay_hold_probe(BASE, name_pub, 600, "/relay/hold_query")
check("dialer probe (600) finds the held point", held == pair600[0],
      f"got {held!r}")
held_def = core._relay_hold_probe(BASE, name_pub, 3600, "/relay/hold_query")
check("dialer probe (3600) reads silence (False)", held_def is False,
      f"got {held_def!r}")

# --- 8: register refuses bad epoch_len --------------------------------------
try:
    routes_relay._valid_rendezvous(pair600[0], name_pub, "junk")
    check("junk epoch_len refused at register", False, "no raise")
except HTTPException as e:
    check("junk epoch_len refused at register (400)", e.status_code == 400)
try:
    routes_relay._valid_rendezvous(pair600[0], name_pub, 30)
    check("out-of-bounds epoch_len refused", False, "no raise")
except HTTPException as e:
    check("out-of-bounds epoch_len refused (400)", e.status_code == 400)

print(f"\n{CASES['passed']} passed, {CASES['failed']} failed")
sys.exit(1 if CASES["failed"] else 0)
