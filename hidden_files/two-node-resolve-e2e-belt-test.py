"""Belt: two-node resolve e2e (primitives 1 naming + 2 resolution).

Extends two-node-names-gossip-e2e: after the kept-key binding has
gossiped from independent node A to independent node B, the REAL
client resolver core.resolve_cyberspace runs against B as the mirror
and must return A's address -- B is not trusted on its word alone:

  1. A claims a fresh kept-key name via the real claim route; B 404s
  2. resolve via B BEFORE gossip -> None (silence, never a guess)
  3. A's real _names_gossip_out federates the binding to B
  4. B's directory carries the name-key -> A entry (seeded roster row,
     the shape a name-key announce creates; the reach-descriptor
     announce half is loopback-refused by B's own SSRF gate, so the
     resolver's documented directory fallback is the path under test)
  5. resolve_cyberspace(label, mirror=B) -> {node_pubkey == kept name
     key, node_url == A}: step 2 fetches B's gossiped binding, step 3
     re-verifies its signature in the belt process, step 5 reads B's
     directory, step 6 live-verifies A (signed /fed/ping + A serving
     the same binding)
  6. an unclaimed label resolves via B -> None

Test-only allowance, belt process only: core._reject_nonpublic_node_url
is patched to admit the two loopback node URLs (production's SSRF gate
refuses loopback peer URLs, by design; twin of depth-chain-e2e).
The genesis name is never touched.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/two-node-resolve-e2e-belt-test.py
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
PORT_A, PORT_B = 18793, 18794
URL_A = f"http://127.0.0.1:{PORT_A}"
URL_B = f"http://127.0.0.1:{PORT_B}"
LABEL = "twonoderesolve"

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


def main():
    tmp_a = tempfile.mkdtemp(prefix="twonode-res-a-")
    tmp_b = tempfile.mkdtemp(prefix="twonode-res-b-")
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
        check("resolve via B before gossip is silence",
              core.resolve_cyberspace(LABEL + ".cyberspace", URL_B) is None)

        helper = (
            "import time, core\n"
            "_real = core._reject_nonpublic_node_url\n"
            "def _gate(url):\n"
            f"    return None if url.startswith({URL_B!r}) else _real(url)\n"
            "core._reject_nonpublic_node_url = _gate\n"
            "n = core._names_gossip_out()\n"
            "print('recipients:', n)\n"
            "time.sleep(4)\n")
        env = dict(os.environ, CYBERNET_DB_DIR=tmp_a,
                   CYBERNET_NODE_PRIVKEY=a_priv)
        out = subprocess.run(
            [os.path.join(REPO, "venv/bin/python"), "-c", helper],
            cwd=REPO, env=env, capture_output=True, text=True, timeout=60)
        check("A gossip send half ran to 1 recipient",
              "recipients: 1" in out.stdout,
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

        # B's directory learns name-key -> A (seeded roster row, the
        # shape a name-key announce creates; see module docstring).
        seed_peer(tmp_b, name_pub, URL_A, LABEL)

        got = core.resolve_cyberspace(LABEL + ".cyberspace", URL_B)
        check("resolve via B returns the kept name key",
              isinstance(got, dict) and got.get("node_pubkey") == name_pub,
              f"got {got}")
        check("resolve via B returns A's live address",
              isinstance(got, dict) and got.get("node_url") == URL_A,
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
