"""Belt: two-node reach-descriptor resolve e2e (primitives 1+2+3).

Extends two-node-resolve-e2e: there B's directory row was SEEDED
because the descriptor path was untested. Here nothing is seeded for
the name key -- the address half travels only through production
machinery:

  1. A claims a fresh kept-key name via the real claim route; B 404s
  2. A's real _names_gossip_out federates the binding to B
  3. B serves no /reach for the name yet; resolve via B -> None
     (binding alone never guesses an address)
  4. A's real _reach_out (env-gated send half: HOSTED_NAME +
     NAME_PRIVKEY + PUBLIC_URL) POSTs the name-key-signed descriptor
     to B's real /fed/announce reach branch; B merges it via
     ingest_reach_descriptor against the live gossiped binding
  5. B serves /api/v1/names/<label>/reach with the descriptor;
     B's directory carries NO entry under the name key
  6. core.resolve_cyberspace(label, mirror=B) returns A's address
     through step 5's DESCRIPTOR path (no via_relay), step 6
     live-verifies A
  7. an unclaimed label resolves via B -> None

Test-only allowance, helper/belt processes only:
core._reject_nonpublic_node_url is patched to admit the two loopback
node URLs (production's SSRF gate refuses loopback peer URLs, by
design; twin of two-node-resolve-e2e). The genesis name is never
touched.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/two-node-reach-resolve-e2e-belt-test.py
"""

import json
import os
import secrets
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from fed.ed25519 import publickey, sign  # noqa: E402
import core  # noqa: E402
from core import _name_claim_payload  # noqa: E402

CASES = {"passed": 0, "failed": 0}
PORT_A, PORT_B = 18795, 18796
URL_A = f"http://127.0.0.1:{PORT_A}"
URL_B = f"http://127.0.0.1:{PORT_B}"
LABEL = "twonodereach"

_real_gate = core._reject_nonpublic_node_url


def _gate(url):
    if isinstance(url, str) and url.startswith((URL_A, URL_B)):
        return None
    return _real_gate(url)


core._reject_nonpublic_node_url = _gate


def check(name, cond, extra=""):
    if cond:
        CASES["passed"] += 1
        print(f"  ok  {name}")
    else:
        CASES["failed"] += 1
        print(f"  FAIL {name} {extra}")


def ts(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S+00:00")


def get(port, path):
    try:
        with urllib.request.urlopen(
                f"http://127.0.0.1:{port}{path}", timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, {}
    except Exception:
        return 0, {}


def boot(tmp, priv, port):
    env = dict(os.environ, CYBERNET_DB_DIR=tmp,
               CYBERNET_NODE_PRIVKEY=priv)
    proc = subprocess.Popen(
        [os.path.join(REPO, "venv/bin/python"), "-m", "uvicorn",
         "app:app", "--host", "127.0.0.1", "--port", str(port)],
        cwd=REPO, env=env, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL)
    for _ in range(60):
        code, _ = get(port, "/api/v1/node")
        if code == 200:
            return proc, True
        time.sleep(0.5)
    return proc, False


def seed_peer(tmp, pub, url, name):
    conn = sqlite3.connect(os.path.join(tmp, "cybernet.db"))
    conn.execute(
        "INSERT INTO peers (node_pub, name, network, version, genesis,"
        " capabilities, announced_at, first_seen, retired_at, node_url)"
        " VALUES (?,?,?,?,?,?,?,?,?,?)",
        (pub, name, "cybernet", "0.1.0", 0, "[]",
         ts(datetime.now(timezone.utc)),
         ts(datetime.now(timezone.utc)), "", url))
    conn.commit()
    conn.close()


def run_helper(tmp_a, a_priv, extra_env, call):
    helper = (
        "import time, core\n"
        "_real = core._reject_nonpublic_node_url\n"
        "def _gate(url):\n"
        f"    return None if url.startswith(({URL_A!r}, {URL_B!r})) else _real(url)\n"
        "core._reject_nonpublic_node_url = _gate\n"
        f"n = {call}\n"
        "print('sent:', n)\n"
        "time.sleep(4)\n")
    env = dict(os.environ, CYBERNET_DB_DIR=tmp_a,
               CYBERNET_NODE_PRIVKEY=a_priv, **extra_env)
    return subprocess.run(
        [os.path.join(REPO, "venv/bin/python"), "-c", helper],
        cwd=REPO, env=env, capture_output=True, text=True, timeout=60)


def main():
    tmp_a = tempfile.mkdtemp(prefix="twonode-reach-a-")
    tmp_b = tempfile.mkdtemp(prefix="twonode-reach-b-")
    a_priv = secrets.token_hex(32)
    a_pub = publickey(bytes.fromhex(a_priv)).hex()
    b_priv = secrets.token_hex(32)
    b_pub = publickey(bytes.fromhex(b_priv)).hex()
    name_priv = bytes.fromhex(secrets.token_hex(32))
    name_pub = publickey(name_priv).hex()

    proc_a, up_a = boot(tmp_a, a_priv, PORT_A)
    proc_b, up_b = boot(tmp_b, b_priv, PORT_B)
    try:
        check("both independent nodes boot", up_a and up_b)
        if not (up_a and up_b):
            return
        seed_peer(tmp_a, b_pub, URL_B, "belt-node-b")
        seed_peer(tmp_b, a_pub, URL_A, "belt-node-a")

        now = datetime.now(timezone.utc)
        issued = ts(now - timedelta(minutes=1))
        expires = ts(now + timedelta(days=30))
        sig = sign(_name_claim_payload(LABEL, name_pub, issued, expires),
                   name_priv, bytes.fromhex(name_pub)).hex()
        body = urllib.parse.urlencode(
            {"name": LABEL, "node_pubkey": name_pub,
             "issued_at": issued, "expires_at": expires,
             "signature": sig}).encode()
        req = urllib.request.Request(
            URL_A + "/api/v1/names/claim", data=body, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                claim_code = r.status
        except urllib.error.HTTPError as e:
            claim_code = e.code
        check("A claims kept-key name via real route", claim_code == 200,
              f"got {claim_code}")
        code, _ = get(PORT_B, f"/api/v1/names/{LABEL}")
        check("B has never heard of it before gossip", code == 404,
              f"got {code}")

        out = run_helper(tmp_a, a_priv, {}, "core._names_gossip_out()")
        check("A gossip send half ran to 1 recipient",
              "sent: 1" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code = 0
        for _ in range(20):
            code, served_b = get(PORT_B, f"/api/v1/names/{LABEL}")
            if code == 200:
                break
            time.sleep(0.5)
        check("B serves the gossiped binding",
              code == 200 and served_b.get("node_pubkey") == name_pub,
              f"got {code} {served_b}")

        code, _ = get(PORT_B, f"/api/v1/names/{LABEL}/reach")
        check("B serves no reach descriptor before announce",
              code == 404, f"got {code}")
        check("resolve via B with binding only is silence",
              core.resolve_cyberspace(LABEL + ".cyberspace", URL_B) is None)

        out = run_helper(
            tmp_a, a_priv,
            {"CYBERNET_HOSTED_NAME": LABEL,
             "CYBERNET_NAME_PRIVKEY": name_priv.hex(),
             "CYBERNET_PUBLIC_URL": URL_A},
            "core._reach_out()")
        check("A reach send half ran to 1 recipient",
              "sent: 1" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, desc = 0, {}
        for _ in range(20):
            code, desc = get(PORT_B, f"/api/v1/names/{LABEL}/reach")
            if code == 200:
                break
            time.sleep(0.5)
        check("B serves the announced reach descriptor",
              code == 200 and desc.get("node_pubkey") == name_pub,
              f"got {code} {desc}")
        check("descriptor carries A's direct URL",
              any(isinstance(s, dict) and s.get("url") == URL_A
                  for s in (desc.get("reach") or [])),
              f"reach={desc.get('reach')}")

        code, directory = get(PORT_B, "/api/v1/directory?limit=200")
        entries = directory.get("entries") \
            if isinstance(directory, dict) else directory
        check("B directory carries NO entry under the name key",
              code == 200 and isinstance(entries, list) and not any(
                  isinstance(e, dict) and e.get("node_pub") == name_pub
                  for e in entries),
              f"got {code} {directory}")

        got = core.resolve_cyberspace(LABEL + ".cyberspace", URL_B)
        check("resolve via B returns the kept name key",
              isinstance(got, dict) and got.get("node_pubkey") == name_pub,
              f"got {got}")
        check("resolve via B returns A's address via descriptor",
              isinstance(got, dict) and got.get("node_url") == URL_A
              and "via_relay" not in got,
              f"got {got}")
        check("unclaimed label resolves via B to silence",
              core.resolve_cyberspace(
                  "nobodyclaimedit.cyberspace", URL_B) is None)
    finally:
        for p in (proc_a, proc_b):
            p.terminate()
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()

    print(f"\n{CASES['passed']} passed, {CASES['failed']} failed")
    sys.exit(1 if CASES["failed"] else 0)


if __name__ == "__main__":
    main()
