"""Depth chain end-to-end (the six primitives, one wire):

mint a fresh name key -> claim the binding through the REAL /api/v1/names/claim
route -> announce reach through the REAL resolver.host module -> plan the dial
through the REAL dial.py against the REAL node app on a loopback socket.

Naming (mint/claim), hosting (hostd), resolution (resolver fetch + binding
re-verify), and the client dial plan all prove themselves in one shot. The
genesis name is never touched; every key here is fresh and dies with the run.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/depth-chain-e2e-test.py
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

TMP = tempfile.mkdtemp(prefix="depth-chain-e2e-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

MIRROR_PORT = 18352
MIRROR = f"http://127.0.0.1:{MIRROR_PORT}"

import core  # noqa: E402
import uvicorn  # noqa: E402
from app import app  # noqa: E402
from fed import ed25519 as _fed_ed25519  # noqa: E402
from resolver import host as hostd  # noqa: E402
import dial  # noqa: E402

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

# --- serve the real app (mirror) on a real socket --------------------------
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


def _post_claim(name, pub, issued, expires, sig):
    body = urllib.parse.urlencode(
        {"name": name, "node_pubkey": pub, "issued_at": issued,
         "expires_at": expires, "signature": sig}).encode()
    req = urllib.request.Request(MIRROR + "/api/v1/names/claim", data=body,
                                 method="POST")
    with urllib.request.urlopen(req, timeout=8) as r:
        return r.status, json.loads(r.read())


SK, PK = _keypair()
NOW = datetime.datetime.now(datetime.timezone.utc)
NOWS = NOW.isoformat()
LATER = (NOW + datetime.timedelta(days=30)).isoformat()
LABEL = "deepe2e"

# 1: naming — the claim goes through the real HTTP route, signed by the
# real name key. The signature IS the auth; the node believes only the key.
sig = _fed_ed25519.sign(
    core._name_claim_payload(LABEL, PK, NOWS, LATER),
    bytes.fromhex(SK), bytes.fromhex(PK)).hex()
try:
    st, claimed = _post_claim(LABEL, PK, NOWS, LATER, sig)
except Exception as e:
    check("binding claimed via real route", False, str(e))
    sys.exit(1)
check("binding claimed via real route",
      st == 200 and claimed.get("status") == "claimed" and
      claimed.get("node_pubkey") == PK, repr(claimed))

# a wrong key signing the same name is refused by the route, not the test.
SKX, PKX = _keypair()
sigx = _fed_ed25519.sign(
    core._name_claim_payload(LABEL, PKX, NOWS, LATER),
    bytes.fromhex(SK), bytes.fromhex(PK)).hex()  # signed by SK, not SKX
try:
    _post_claim(LABEL, PKX, NOWS, LATER, sigx)
    check("wrong-key claim refused", False)
except Exception as e:
    check("wrong-key claim refused", "400" in str(e), str(e))

# 2: hosting — the real daemon module announces honest reach (direct, at
# the mirror itself on this loopback wire).
os.environ["CYBERNET_PUBLIC_URL"] = MIRROR
check("announce_once accepted", hostd.announce_once(MIRROR, LABEL, SK) is True)

# 3+4: resolution + dial plan — the real planner against the real mirror:
# liveness, binding fetch, binding re-verify, descriptor re-verify,
# strategy extraction. A claimed, live, reach-publishing name plans.
code, lines = dial.plan(LABEL + ".cyberspace", MIRROR)
check("plan exits 0", code == 0, f"exit={code} lines={lines}")
joined = "\n".join(lines)
check("plan names the direct reach", "plan: direct" in joined, joined)
check("plan cites the signed descriptor",
      "via: name-key-signed reach descriptor" in joined, joined)
check("plan never prints the secret", PK in joined and SK not in joined, joined)

# 5: the negative wire — an unclaimed name plans to nothing, never a guess.
code2, lines2 = dial.plan("nobodyclaimedit.cyberspace", MIRROR)
check("unclaimed name -> exit 1", code2 == 1, f"exit={code2} lines={lines2}")

# 6: a claimed-but-silent name — binding live, host publishes no reach.
SK2, PK2 = _keypair()
sig2 = _fed_ed25519.sign(
    core._name_claim_payload("deepe2esilent", PK2, NOWS, LATER),
    bytes.fromhex(SK2), bytes.fromhex(PK2)).hex()
st2, _ = _post_claim("deepe2esilent", PK2, NOWS, LATER, sig2)
code3, lines3 = dial.plan("deepe2esilent.cyberspace", MIRROR)
check("silent host -> exit 3, never a guess", code3 == 3, f"exit={code3} lines={lines3}")

print(f"\ndepth-chain-e2e: {CASES['passed']} passed, {CASES['failed']} failed")
sys.exit(1 if CASES["failed"] else 0)
