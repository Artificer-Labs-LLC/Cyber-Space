"""Belt: multi-hop expiry + DIRECT-strategy resolve e2e (primitives 1+2+3+4).

Multi-hop expiry panels terminated at a relay; the multi-hop direct
panel never expired. Never proven together: a SHORT-LIVED binding
carried a SECOND hop to a far resolver with a direct descriptor --
expiry at the far hop silences direct resolution even though the
hoster is still reachable, a pre-expiry challenger cannot displace
the live binding or its descriptor, and only the challenger's
post-expiry gossip succession plus its own direct re-announce
restores direct resolution at the far hop.

Four INDEPENDENT nodes (separate DBs, separate node keys):
A owner, B intermediary, D far resolver, E challenger/successor.

  1. A claims the label under K1 with a short (~110s) life; gossip
     A->B, then B->D; B and D serve it byte-identical, belt
     re-verifies it against K1 at D
  2. A announces a K1 direct-only descriptor; D serves ONLY the
     direct strategy at A's URL; resolve via D returns K1 direct
  3. Challenger E claims under K2 pre-expiry; B keeps live K1,
     drops the K2 gossip and the K2 direct announce; resolve via
     D still returns K1 direct
  4. After real expiry D serves binding 404 + descriptor 404 and
     resolve via D is silence; a stale K1 re-announce restores
     nothing
  5. E gossip replaces expired K1 on B, B gossip onward replaces
     silence with K2 on D byte-identical re-verified; E announces
     a K2 direct-only descriptor; resolve via D returns K2 with
     node_url == E and NO via_relay
  6. An unclaimed label resolves via D to silence

Test-only allowances, twin of the parent belts: helper/belt
processes patch core._reject_nonpublic_node_url to admit the
loopback node URLs only, and the belt clears core._resolve_memo
between resolves. The genesis name is never touched.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/two-node-multihop-expiry-direct-resolve-e2e-belt-test.py
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

from fed.ed25519 import checkvalid, publickey, sign  # noqa: E402
import core  # noqa: E402
from core import _name_claim_payload  # noqa: E402

CASES = {"passed": 0, "failed": 0}
PORT_A, PORT_B, PORT_D, PORT_E = 18991, 18992, 18993, 18994
URL_A = f"http://127.0.0.1:{PORT_A}"
URL_B = f"http://127.0.0.1:{PORT_B}"
URL_D = f"http://127.0.0.1:{PORT_D}"
URL_E = f"http://127.0.0.1:{PORT_E}"
URLS = (URL_A, URL_B, URL_D, URL_E)
LABEL = "mhexpdir"

_real_gate = core._reject_nonpublic_node_url


def _gate(url):
    if isinstance(url, str) and url.startswith(URLS):
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
        try:
            return e.code, json.loads(e.read())
        except Exception:
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


def unseed_peer(tmp, pub):
    conn = sqlite3.connect(os.path.join(tmp, "cybernet.db"))
    conn.execute("DELETE FROM peers WHERE node_pub=?", (pub,))
    conn.commit()
    conn.close()


def ingest_on(tmp, priv, binding):
    helper = (
        "import core\n"
        f"print(core.ingest_gossiped_binding({binding!r}))\n")
    env = dict(os.environ, CYBERNET_DB_DIR=tmp,
               CYBERNET_NODE_PRIVKEY=priv)
    return subprocess.run(
        [os.path.join(REPO, "venv/bin/python"), "-c", helper],
        cwd=REPO, env=env, capture_output=True, text=True, timeout=60)


def run_helper(tmp, priv, extra_env, call):
    urls = ", ".join(repr(u) for u in URLS)
    helper = (
        "import time, core\n"
        "_real = core._reject_nonpublic_node_url\n"
        "def _gate(url):\n"
        f"    return None if url.startswith(({urls})) else _real(url)\n"
        "core._reject_nonpublic_node_url = _gate\n"
        f"n = {call}\n"
        "print('sent:', n)\n"
        "time.sleep(4)\n")
    env = dict(os.environ, CYBERNET_DB_DIR=tmp,
               CYBERNET_NODE_PRIVKEY=priv, **extra_env)
    return subprocess.run(
        [os.path.join(REPO, "venv/bin/python"), "-c", helper],
        cwd=REPO, env=env, capture_output=True, text=True, timeout=60)


def claim(port, label, name_priv, name_pub, issued_dt, expires_dt):
    issued, expires = ts(issued_dt), ts(expires_dt)
    sig = sign(_name_claim_payload(label, name_pub, issued, expires),
               name_priv, bytes.fromhex(name_pub)).hex()
    body = urllib.parse.urlencode(
        {"name": label, "node_pubkey": name_pub,
         "issued_at": issued, "expires_at": expires,
         "signature": sig}).encode()
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/api/v1/names/claim",
        data=body, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, sig, issued, expires
    except urllib.error.HTTPError as e:
        return e.code, sig, issued, expires


def wait_served(port, label, sig):
    served, code = {}, 0
    for _ in range(20):
        code, served = get(port, f"/api/v1/names/{label}")
        if code == 200 and served.get("signature") == sig:
            return code, served
        time.sleep(0.5)
    return code, served


def wait_reach(port, label, pub):
    desc, code = {}, 0
    for _ in range(20):
        code, desc = get(port, f"/api/v1/names/{label}/reach")
        if code == 200 and desc.get("node_pubkey") == pub:
            return code, desc
        time.sleep(0.5)
    return code, desc


def verify(pub_hex, sig_hex, label, issued, expires):
    try:
        return checkvalid(
            bytes.fromhex(sig_hex),
            _name_claim_payload(label, pub_hex, issued, expires),
            bytes.fromhex(pub_hex)) is True
    except Exception:
        return False


def resolve_fresh(label, base):
    core._resolve_memo.clear()
    return core.resolve_cyberspace(label + ".cyberspace", base)


def main():
    tmp_a = tempfile.mkdtemp(prefix="mh-expiry-direct-a-")
    tmp_b = tempfile.mkdtemp(prefix="mh-expiry-direct-b-")
    tmp_d = tempfile.mkdtemp(prefix="mh-expiry-direct-d-")
    tmp_e = tempfile.mkdtemp(prefix="mh-expiry-direct-e-")
    a_priv = secrets.token_hex(32)
    a_pub = publickey(bytes.fromhex(a_priv)).hex()
    b_priv = secrets.token_hex(32)
    b_pub = publickey(bytes.fromhex(b_priv)).hex()
    d_priv = secrets.token_hex(32)
    d_pub = publickey(bytes.fromhex(d_priv)).hex()
    e_priv = secrets.token_hex(32)
    e_pub = publickey(bytes.fromhex(e_priv)).hex()
    k1_priv = bytes.fromhex(secrets.token_hex(32))
    k1_pub = publickey(k1_priv).hex()
    k2_priv = bytes.fromhex(secrets.token_hex(32))
    k2_pub = publickey(k2_priv).hex()

    proc_a, up_a = boot(tmp_a, a_priv, PORT_A)
    proc_b, up_b = boot(tmp_b, b_priv, PORT_B)
    proc_d, up_d = boot(tmp_d, d_priv, PORT_D)
    proc_e, up_e = boot(tmp_e, e_priv, PORT_E)
    try:
        check("four independent nodes boot",
              up_a and up_b and up_d and up_e)
        if not (up_a and up_b and up_d and up_e):
            return
        # Binding topology: A -> B -> D only. A never gossips to D.
        seed_peer(tmp_a, b_pub, URL_B, "belt-node-b")
        seed_peer(tmp_b, a_pub, URL_A, "belt-node-a")
        seed_peer(tmp_b, d_pub, URL_D, "belt-node-d")
        seed_peer(tmp_d, b_pub, URL_B, "belt-node-b")
        seed_peer(tmp_e, b_pub, URL_B, "belt-node-b")

        now = datetime.now(timezone.utc)
        expires1_dt = now + timedelta(seconds=110)
        code, sig1, issued1, expires1 = claim(
            PORT_A, LABEL, k1_priv, k1_pub,
            now - timedelta(seconds=10), expires1_dt)
        check("A claims kept-key name under K1 via real route (short life)",
              code == 200, f"got {code}")
        code, _ = get(PORT_D, f"/api/v1/names/{LABEL}")
        check("D has never heard of it before gossip", code == 404,
              f"got {code}")
        out = run_helper(tmp_a, a_priv, {}, "core._names_gossip_out()")
        check("A gossip K1 ran to 1 recipient", "sent: 1" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, served_b1 = wait_served(PORT_B, LABEL, sig1)
        check("B serves K1 byte-identical", code == 200
              and served_b1.get("node_pubkey") == k1_pub,
              f"got {code} {served_b1}")
        out = run_helper(tmp_b, b_priv, {}, "core._names_gossip_out()")
        check("B gossip K1 onward ran to 2 recipients",
              "sent: 2" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, served_d1 = wait_served(PORT_D, LABEL, sig1)
        check("D serves K1 byte-identical (learned via B)",
              code == 200 and served_d1.get("node_pubkey") == k1_pub
              and served_d1.get("issued_at") == issued1
              and served_d1.get("expires_at") == expires1,
              f"got {code} {served_d1}")
        check("belt re-verifies D's K1 binding against K1",
              verify(k1_pub, served_d1.get("signature", ""), LABEL,
                     issued1, expires1))

        code, _ = get(PORT_D, f"/api/v1/names/{LABEL}/reach")
        check("D serves no reach descriptor before announce",
              code == 404, f"got {code}")
        check("resolve via D with binding only is silence",
              resolve_fresh(LABEL, URL_D) is None)

        # Reach: owner announces to its peers B and D; D is seeded
        # as A's peer only now, after the binding legs ran A->B->D.
        seed_peer(tmp_a, d_pub, URL_D, "belt-node-d")
        out = run_helper(
            tmp_a, a_priv,
            {"CYBERNET_HOSTED_NAME": LABEL,
             "CYBERNET_NAME_PRIVKEY": k1_priv.hex(),
             "CYBERNET_PUBLIC_URL": URL_A},
            "core._reach_out()")
        check("A reach announce under K1 ran to 2 recipients",
              "sent: 2" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, desc = wait_reach(PORT_D, LABEL, k1_pub)
        check("D serves the K1 reach descriptor", code == 200
              and desc.get("node_pubkey") == k1_pub,
              f"got {code} {desc}")
        strats = [s for s in (desc.get("reach") or [])
                  if isinstance(s, dict)]
        check("D descriptor carries ONLY the direct strategy",
              len(strats) == 1 and strats[0].get("kind") == "direct"
              and strats[0].get("url") == URL_A,
              f"reach={desc.get('reach')}")
        got = resolve_fresh(LABEL, URL_D)
        check("resolve via far hop D returns K1 direct at A",
              isinstance(got, dict) and got.get("node_pubkey") == k1_pub
              and got.get("node_url") == URL_A
              and "via_relay" not in got
              and got.get("issued_at") == issued1
              and got.get("expires_at") == expires1,
              f"got {got}")

        # Challenger E claims under K2 pre-expiry; B keeps live K1.
        now_e = datetime.now(timezone.utc)
        code, sig2, issued2, expires2 = claim(
            PORT_E, LABEL, k2_priv, k2_pub,
            now_e - timedelta(seconds=5), now_e + timedelta(days=30))
        check("E claims same label under K2 via real route",
              code == 200, f"got {code}")
        # Seed E as B's peer only now: gossip receive requires a
        # known sender, but seeding earlier would let B's onward
        # gossip plant live K1 on E and 409 its own claim.
        seed_peer(tmp_b, e_pub, URL_E, "belt-node-e")
        out = run_helper(tmp_e, e_priv, {}, "core._names_gossip_out()")
        check("E gossip K2 (pre-expiry) ran to 1 recipient",
              "sent: 1" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        time.sleep(1)
        code, served_bx = get(PORT_B, f"/api/v1/names/{LABEL}")
        check("B keeps live K1 against K2 challenger",
              code == 200 and served_bx.get("signature") == sig1,
              f"got {code} {served_bx}")
        out = run_helper(
            tmp_e, e_priv,
            {"CYBERNET_HOSTED_NAME": LABEL,
             "CYBERNET_NAME_PRIVKEY": k2_priv.hex(),
             "CYBERNET_PUBLIC_URL": URL_E},
            "core._reach_out()")
        check("E reach announce under K2 ran to 1 recipient",
              "sent: 1" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        time.sleep(1)
        code, desc = get(PORT_B, f"/api/v1/names/{LABEL}/reach")
        check("B still serves only the K1 descriptor (K2 announce dropped)",
              code == 200 and desc.get("node_pubkey") == k1_pub,
              f"got {code} {desc}")
        got = resolve_fresh(LABEL, URL_D)
        check("resolve via far hop D still returns K1 direct (pre-expiry)",
              isinstance(got, dict) and got.get("node_pubkey") == k1_pub
              and got.get("node_url") == URL_A
              and "via_relay" not in got,
              f"got {got}")

        deadline = expires1_dt + timedelta(seconds=3)
        while datetime.now(timezone.utc) < deadline:
            time.sleep(2)
        check("K1 expiry has passed on the belt clock",
              datetime.now(timezone.utc) > expires1_dt)
        code, _ = get(PORT_D, f"/api/v1/names/{LABEL}")
        check("D serves the expired K1 binding as 404 (two hops out)",
              code == 404, f"got {code}")
        code, _ = get(PORT_D, f"/api/v1/names/{LABEL}/reach")
        check("D serves the descriptor as 404 after binding expiry",
              code == 404, f"got {code}")
        check("resolve via far hop D is silence after expiry "
              "(A itself is still reachable)",
              resolve_fresh(LABEL, URL_D) is None)

        out = run_helper(
            tmp_a, a_priv,
            {"CYBERNET_HOSTED_NAME": LABEL,
             "CYBERNET_NAME_PRIVKEY": k1_priv.hex(),
             "CYBERNET_PUBLIC_URL": URL_A},
            "core._reach_out()")
        check("stale K1 reach re-announce ran to 2 recipients",
              "sent: 2" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        time.sleep(1)
        code, _ = get(PORT_D, f"/api/v1/names/{LABEL}/reach")
        check("stale K1 re-announce restores no descriptor on D",
              code == 404, f"got {code}")
        check("resolve via D still silence after stale re-announce",
              resolve_fresh(LABEL, URL_D) is None)

        # Succession: E's K2 travels E -> B -> D through real gossip.
        out = run_helper(tmp_e, e_priv, {}, "core._names_gossip_out()")
        check("E gossip K2 (post-expiry) ran to 1 recipient",
              "sent: 1" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, served_b2 = wait_served(PORT_B, LABEL, sig2)
        check("B replaced expired K1 with K2", code == 200
              and served_b2.get("node_pubkey") == k2_pub,
              f"got {code} {served_b2}")
        out = run_helper(tmp_b, b_priv, {}, "core._names_gossip_out()")
        check("B gossip K2 onward ran to 3 recipients",
              "sent: 3" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, served_d2 = wait_served(PORT_D, LABEL, sig2)
        check("D REPLACED post-expiry silence with K2 learned onward from B",
              code == 200 and served_d2.get("node_pubkey") == k2_pub
              and served_d2.get("issued_at") == issued2
              and served_d2.get("expires_at") == expires2,
              f"got {code} {served_d2}")
        check("belt re-verifies D's K2 binding against K2",
              verify(k2_pub, served_d2.get("signature", ""), LABEL,
                     issued2, expires2))

        seed_peer(tmp_e, d_pub, URL_D, "belt-node-d")
        out = run_helper(
            tmp_e, e_priv,
            {"CYBERNET_HOSTED_NAME": LABEL,
             "CYBERNET_NAME_PRIVKEY": k2_priv.hex(),
             "CYBERNET_PUBLIC_URL": URL_E},
            "core._reach_out()")
        check("E reach announce under K2 ran to 2 recipients",
              "sent: 2" in out.stdout,
              f"stdout={out.stdout!r} stderr={out.stderr[-400:]!r}")
        code, desc = wait_reach(PORT_D, LABEL, k2_pub)
        check("D serves the K2 reach descriptor", code == 200
              and desc.get("node_pubkey") == k2_pub,
              f"got {code} {desc}")
        strats = [s for s in (desc.get("reach") or [])
                  if isinstance(s, dict)]
        check("D K2 descriptor carries ONLY the direct strategy at E",
              len(strats) == 1 and strats[0].get("kind") == "direct"
              and strats[0].get("url") == URL_E,
              f"reach={desc.get('reach')}")
        got = resolve_fresh(LABEL, URL_D)
        check("resolve via far hop D returns K2 direct at E",
              isinstance(got, dict) and got.get("node_pubkey") == k2_pub
              and got.get("node_url") == URL_E
              and "via_relay" not in got
              and got.get("issued_at") == issued2
              and got.get("expires_at") == expires2,
              f"got {got}")
        check("unclaimed label resolves via D to silence",
              resolve_fresh("nobodyclaimedit", URL_D) is None)
    finally:
        for p in (proc_a, proc_b, proc_d, proc_e):
            p.terminate()
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()

    print(f"\n{CASES['passed']} passed, {CASES['failed']} failed")
    sys.exit(1 if CASES["failed"] else 0)


if __name__ == "__main__":
    main()
