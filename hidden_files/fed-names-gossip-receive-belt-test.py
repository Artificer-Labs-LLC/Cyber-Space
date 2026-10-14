"""Belt: POST /fed/names/gossip receive half (federation.py).

The send half (core._names_gossip_out) has POSTed signed binding batches
to /fed/names/gossip since Phase 1 item 6, but no receive route existed —
every batch landed on a 404 and name bindings never federated. This belt
boots a real node (throwaway CYBERNET_DB_DIR, CYBERNET_NODE_PRIVKEY set
so the belt knows the recipient pubkey) and proves:

  1. a known unretired peer's signed batch merges: a fresh, validly
     signed binding is "inserted" and then served by GET /api/v1/names/<label>
  2. the same envelope replayed is refused 400 (replay dedupe)
  3. an unknown peer's batch is refused 404 (no merge work for strangers)
  4. a binding with a forged signature tallies "dropped-unverifiable"
     and is never served
  5. a non-list bindings body is refused 400

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/fed-names-gossip-receive-belt-test.py
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
import urllib.request
from datetime import datetime, timedelta, timezone

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from fed.ed25519 import publickey, sign  # noqa: E402
from fed.envelope import make_envelope  # noqa: E402
from core import _name_claim_payload  # noqa: E402

CASES = {"passed": 0, "failed": 0}


def check(name, cond, extra=""):
    if cond:
        CASES["passed"] += 1
        print(f"  ok  {name}")
    else:
        CASES["failed"] += 1
        print(f"  FAIL {name} {extra}")


def ts(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S+00:00")


def post(port, path, payload):
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def get(port, path):
    try:
        with urllib.request.urlopen(
                f"http://127.0.0.1:{port}{path}", timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, {}


def main():
    tmp = tempfile.mkdtemp(prefix="names-gossip-belt-")
    server_priv = secrets.token_hex(32)
    server_pub = publickey(bytes.fromhex(server_priv)).hex()
    sender_priv = secrets.token_hex(32)
    sender_pub = publickey(bytes.fromhex(sender_priv)).hex()
    stranger_priv = secrets.token_hex(32)
    stranger_pub = publickey(bytes.fromhex(stranger_priv)).hex()
    name_priv = bytes.fromhex(secrets.token_hex(32))
    name_pub = publickey(name_priv).hex()

    port = 18777
    env = dict(os.environ, CYBERNET_DB_DIR=tmp,
               CYBERNET_NODE_PRIVKEY=server_priv)
    proc = subprocess.Popen(
        [os.path.join(REPO, "venv/bin/python"), "-m", "uvicorn",
         "app:app", "--host", "127.0.0.1", "--port", str(port)],
        cwd=REPO, env=env, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL)
    try:
        up = False
        for _ in range(60):
            try:
                code, _ = get(port, "/api/v1/node")
                if code == 200:
                    up = True
                    break
            except Exception:
                pass
            time.sleep(0.5)
        check("node boots", up)
        if not up:
            return

        # Seed the sender as a known, unretired peer (direct DB write —
        # the belt stands in for a completed /fed/announce).
        conn = sqlite3.connect(os.path.join(tmp, "cybernet.db"))
        conn.execute(
            "INSERT INTO peers (node_pub, name, network, version, genesis,"
            " capabilities, announced_at, first_seen, retired_at)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            (sender_pub, "belt-peer", "cybernet", "0.1.0", 0, "[]",
             ts(datetime.now(timezone.utc)),
             ts(datetime.now(timezone.utc)), ""))
        conn.commit()
        conn.close()

        now = datetime.now(timezone.utc)
        issued = ts(now - timedelta(minutes=1))
        expires = ts(now + timedelta(days=30))

        def binding(label, priv, pub):
            sig = sign(_name_claim_payload(
                label, pub, issued, expires),
                priv, bytes.fromhex(pub)).hex()
            return {"name": label, "node_pubkey": pub,
                    "issued_at": issued, "expires_at": expires,
                    "signature": sig}

        good = binding("beltname", name_priv, name_pub)
        env1 = make_envelope(sender_priv, sender_pub, server_pub,
                             {"from_node_pub": sender_pub,
                              "bindings": [good]})
        code, resp = post(port, "/fed/names/gossip", env1)
        check("known peer batch accepted", code == 200, f"got {code} {resp}")
        check("binding inserted",
              resp.get("results", {}).get("inserted") == 1, f"got {resp}")
        code, resp = get(port, "/api/v1/names/beltname")
        check("merged binding served by GET names",
              code == 200 and resp.get("node_pubkey") == name_pub,
              f"got {code} {resp}")

        code, _ = post(port, "/fed/names/gossip", env1)
        check("replayed envelope refused 400", code == 400, f"got {code}")

        env2 = make_envelope(stranger_priv, stranger_pub, server_pub,
                             {"from_node_pub": stranger_pub,
                              "bindings": [good]})
        code, _ = post(port, "/fed/names/gossip", env2)
        check("unknown peer refused 404", code == 404, f"got {code}")

        forged = dict(good, name="beltforged", signature="00" * 64)
        env3 = make_envelope(sender_priv, sender_pub, server_pub,
                             {"from_node_pub": sender_pub,
                              "bindings": [forged]})
        code, resp = post(port, "/fed/names/gossip", env3)
        check("forged binding tallied dropped-unverifiable",
              code == 200
              and resp.get("results", {}).get("dropped-unverifiable") == 1,
              f"got {code} {resp}")
        code, _ = get(port, "/api/v1/names/beltforged")
        check("forged binding never served", code == 404, f"got {code}")

        env4 = make_envelope(sender_priv, sender_pub, server_pub,
                             {"from_node_pub": sender_pub,
                              "bindings": {"not": "a list"}})
        code, _ = post(port, "/fed/names/gossip", env4)
        check("non-list bindings refused 400", code == 400, f"got {code}")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()

    print(f"\n{CASES['passed']} passed, {CASES['failed']} failed")
    sys.exit(1 if CASES["failed"] else 0)


if __name__ == "__main__":
    main()
