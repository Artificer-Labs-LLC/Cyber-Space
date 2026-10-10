"""mint_name.py (agent onboarding, depth primitive 6 front door) end-to-end:
the REAL claim endpoint on a real socket, the REAL resolver check, the
REAL hostd _config() runnable check against the written env file.

Covers: fresh mint (key 0600 + claim + resolve + env 0600), renewal with
the same key, 409 when another key holds the name, invalid label refused
locally (no network), bad --expiry-days refused, env contents parseable
by hostd as runnable.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/mint-name-test.py
"""
import json
import os
import stat
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request

TMP = tempfile.mkdtemp(prefix="mint-name-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import uvicorn  # noqa: E402
from app import app  # noqa: E402
from fed import ed25519 as _fed_ed25519  # noqa: E402
from resolver import host as hostd  # noqa: E402
import core  # noqa: E402
import mint_name  # noqa: E402

# --- the test-only SSRF allowance: the 127.0.0.1 test URL only --------
_real_gate = core._reject_nonpublic_node_url


def _test_gate(url):
    if url.startswith(MIRROR):
        return "127.0.0.1"
    return _real_gate(url)


core._reject_nonpublic_node_url = _test_gate

PORT = 18377
MIRROR = f"http://127.0.0.1:{PORT}"
HOME = tempfile.mkdtemp(prefix="mint-name-home-")
os.environ["HOME"] = HOME  # mint_name writes under ~/.cyberspace

config = uvicorn.Config(app, host="127.0.0.1", port=PORT, log_level="error")
server = uvicorn.Server(config)
t = threading.Thread(target=server.run, daemon=True)
t.start()
for _ in range(100):
    try:
        urllib.request.urlopen(MIRROR + "/api/v1/node", timeout=1)
        break
    except Exception:
        time.sleep(0.1)

passed = failed = 0


def check(name, cond, extra=""):
    global passed, failed
    if cond:
        passed += 1
        print(f"  ok  {name}")
    else:
        failed += 1
        print(f"  FAIL {name} {extra}")


def mode600(path):
    return stat.S_IMODE(os.stat(path).st_mode) == 0o600


# --- fresh mint -------------------------------------------------------
rc = mint_name.main(["willowmint", MIRROR])
check("fresh mint exits 0", rc == 0, f"rc={rc}")
kp = os.path.join(HOME, ".cyberspace", "willowmint-name.key")
check("key file exists", os.path.exists(kp))
check("key file 0600", mode600(kp))
seed = bytes.fromhex(open(kp).read().strip())
check("seed is 32 bytes", len(seed) == 32)
pub = _fed_ed25519.publickey(seed).hex()

resp = urllib.request.urlopen(MIRROR + "/api/v1/names/willowmint", timeout=10)
got = json.loads(resp.read().decode())
check("name resolves to the name key", got.get("node_pubkey", "").lower() == pub)

envp = os.path.join(HOME, ".cyberspace", "hostd", "willowmint.env")
check("hostd env written", os.path.exists(envp))
check("hostd env 0600", mode600(envp))
env = open(envp).read()
check("env names the label", "CYBERNET_HOSTED_NAME=willowmint" in env)
check("env carries the name seed", f"CYBERNET_NAME_PRIVKEY={seed.hex()}" in env)
check("env templates all three relay fields",
      all(f"# CYBERNET_RELAY_{f}=" in env for f in ("URL", "PUBKEY", "TOKEN")))

# hostd's own config check reads this env as runnable
saved = dict(os.environ)
for line in env.splitlines():
    if line.startswith("CYBERNET_") and "=" in line:
        k, v = line.split("=", 1)
        os.environ[k] = v
os.environ["CYBERNET_MIRROR_URL"] = MIRROR
name, priv_hex, mirror_url, refresh, runnable = hostd._config()
check("hostd _config() runnable on the minted env", runnable is True and name == "willowmint",
      f"runnable={runnable} name={name}")
os.environ.clear()
os.environ.update(saved)

# --- renewal with the same key ----------------------------------------
# binding timestamps have 1s granularity and renewal needs strictly-later
# issued_at, so the re-mint must fall in a later second than the first.
time.sleep(1.2)
rc = mint_name.main(["willowmint", MIRROR])
check("re-mint same key renews (exit 0, no conflict)", rc == 0, f"rc={rc}")

# --- 409: another key holds the name ----------------------------------
# pre-claim issued 120s earlier: different keys -> earlier issued_at wins
# deterministically (no same-second pubkey-tiebreak flake).
other_priv = os.urandom(32)
other_pub = _fed_ed25519.publickey(other_priv).hex()
from datetime import datetime, timezone, timedelta
now = datetime.now(timezone.utc) - timedelta(seconds=120)
issued = now.strftime("%Y-%m-%dT%H:%M:%S+00:00")
exp = (now + timedelta(days=730)).strftime("%Y-%m-%dT%H:%M:%S+00:00")
payload = (b"name-claim|takenbyother|" + other_pub.encode() + b"|"
           + issued.encode() + b"|" + exp.encode())
sig = _fed_ed25519.sign(payload, other_priv, bytes.fromhex(other_pub)).hex()
fields = {"name": "takenbyother", "node_pubkey": other_pub, "issued_at": issued,
          "expires_at": exp, "signature": sig}
req = urllib.request.Request(
    MIRROR + "/api/v1/names/claim",
    data=urllib.parse.urlencode(fields).encode(),
    headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST")
with urllib.request.urlopen(req, timeout=10) as r:
    check("pre-claim by other key accepted", r.status == 200)
rc = mint_name.main(["takenbyother", MIRROR])
check("mint on a taken name exits 1", rc == 1, f"rc={rc}")
check("taken name still resolves to the OTHER key",
      json.loads(urllib.request.urlopen(
          MIRROR + "/api/v1/names/takenbyother", timeout=10).read().decode())
      .get("node_pubkey", "").lower() == other_pub)

# --- invalid label refused locally ------------------------------------
rc = mint_name.main(["Bad Label!", MIRROR])
check("invalid label exits 2", rc == 2, f"rc={rc}")
check("invalid label wrote no key",
      not os.path.exists(os.path.join(HOME, ".cyberspace", "bad label!-name.key")))
rc = mint_name.main(["willowmint", MIRROR, "--expiry-days=abc"])
check("bad --expiry-days exits 2", rc == 2, f"rc={rc}")

server.should_exit = True
t.join(5)
print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
