"""Rendezvous mirror wiring (routes_relay.py, docs/RENDEZVOUS.md frozen
spec, primitive 3): the mirror-side half of derived-point rendezvous.

Drives the REAL app on a socket: /relay/register indexes hold-opens
under derived points (addition-only, the hold-open protocol itself
unmodified), and GET /relay/hold_query answers willingness — current-
or-previous epoch only, everything else silent held:false.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/rendezvous-holdquery-test.py
"""

import json
import os
import sys
import tempfile
import threading
import time
import urllib.request
import urllib.error

TMP = tempfile.mkdtemp(prefix="rv-holdquery-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

PORT = 18352
BASE = f"http://127.0.0.1:{PORT}"

import rendezvous  # noqa: E402
import uvicorn  # noqa: E402
from app import app  # noqa: E402
import routes_relay  # noqa: E402

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


srv = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=PORT,
                                    log_level="error"))
t = threading.Thread(target=srv.run, daemon=True)
t.start()
for _ in range(100):
    try:
        urllib.request.urlopen(BASE + "/api/v1/node", timeout=2).close()
        break
    except Exception:
        time.sleep(0.1)
else:
    print("  FAIL app did not boot")
    sys.exit(1)

PUB = "ab" * 32  # fixed fake name pub, 64 hex — KDF needs bytes, not keys
OTHER = "cd" * 32
cur, prev = rendezvous.derive_points(time.time(), PUB)
epoch = rendezvous.epoch_for(time.time())
stale = rendezvous.derive_point_id(PUB, epoch - 2)
other_cur = rendezvous.derive_points(time.time(), OTHER)[0]

# 1. plain register (no rendezvous) still works — protocol unmodified
s, b = post("/relay/register", {"token": "plain-tok-1"})
check("plain register 200, no index pollution", s == 200 and b.get("ok"))
s, b = get("/relay/hold_query?point_id=" + cur)
check("unregistered current point -> held false", s == 200 and b == {"held": False})

# 2. register with a current point indexes it
s, b = post("/relay/register", {"token": "rv-tok-cur", "rendezvous_point": cur,
                                "name_pub": PUB})
check("register with current point 200", s == 200 and b.get("ok"))
s, b = get("/relay/hold_query?point_id=" + cur)
check("current point -> held true", s == 200 and b == {"held": True})

# 3. E-1 point held at the same mirror (epoch-tolerance half)
s, b = post("/relay/register", {"token": "rv-tok-prev", "rendezvous_point": prev,
                                "name_pub": PUB})
check("register E-1 point 200", s == 200 and b.get("ok"))
s, b = get("/relay/hold_query?point_id=" + prev)
check("E-1 point -> held true", s == 200 and b == {"held": True})

# 4. keepalive on the hold-open token refreshes the point index too
routes_relay._relay_rendezvous[cur]["seen"] = time.monotonic() - 200.0
s, b = post("/relay/keepalive", {"token": "rv-tok-cur"})
check("keepalive 200", s == 200)
s, b = get("/relay/hold_query?point_id=" + cur)
check("point still held after keepalive refresh", s == 200 and b == {"held": True},
      f"got {b}")

# 5. stale hold-open reads as absent, never a lie (lazy reap)
routes_relay._relay_rendezvous[cur]["seen"] = time.monotonic() - 400.0
routes_relay._relay_hold_opens["rv-tok-cur"]["seen"] = time.monotonic() - 400.0
s, b = get("/relay/hold_query?point_id=" + cur)
check("stale point -> held false (silent)", s == 200 and b == {"held": False})

# 6. a stale point is refused at register time (hoster miscomputed)
s, b = post("/relay/register", {"token": "rv-tok-stale", "rendezvous_point": stale,
                                "name_pub": PUB})
check("register stale point -> 400", s == 400)
s, b = get("/relay/hold_query?point_id=" + stale)
check("stale point -> held false", s == 200 and b == {"held": False})

# 7. half binding refused, whole protocol fail-closed
s, b = post("/relay/register", {"token": "rv-tok-half", "rendezvous_point": cur})
check("register point-without-pub -> 400", s == 400)
s, b = post("/relay/register", {"token": "rv-tok-half2", "rendezvous_point": "zz",
                                "name_pub": PUB})
check("register malformed point -> 400", s == 400)

# 8. malformed queries are silent held:false, never 4xx
for q in ("garbage", "ab", "zz" * 32, ""):
    s, b = get("/relay/hold_query?point_id=" + q)
    check(f"malformed query {q!r} -> silent false", s == 200 and b == {"held": False})

# 9. a stranger's current point stays false — no cross-talk
s, b = get("/relay/hold_query?point_id=" + other_cur)
check("other pub's current point -> held false", s == 200 and b == {"held": False})

# 10. point still unwilling when epoch rolled (pure willingness, now+2h)
late = rendezvous.point_is_current(prev, time.time() + 3 * 3600, PUB)
check("point not willing two epochs later", late is False)

srv.should_exit = True
t.join(timeout=5)
print(f"done: {CASES['passed']} passed, {CASES['failed']} failed")
sys.exit(1 if CASES["failed"] else 0)
