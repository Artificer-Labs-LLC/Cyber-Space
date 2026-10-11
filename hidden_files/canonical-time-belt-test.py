#!/usr/bin/env python3
"""Belt for floor fix 5 (allocation rule v0.6.3, Examiner; primitive 1 naming).

A legacy name row whose issued_at or expires_at does NOT parse as canonical
UTC (ONLY `Z` or `+00:00` since B4 — non-UTC offsets are unparseable) is
UNPARSEABLE. An unparseable row:
  1. never wins a comparison and is never live or gossiped — it reads as
     ABSENT in _name_claim_beats, the resolve path, the ingest expiry
     check, and the gossip filter;
  2. gets no hold;
  3. is refused at intake with reason expiry-cap.

Covers: unparseable issued_at, unparseable expires_at, naive datetime,
date-only string, non-UTC offset (B4), valid canonical (+00:00 / Z) as
control.

Runs the REAL claim route + REAL serve route on the REAL app (scratch DB,
loopback uvicorn), plus in-process ingest_gossiped_binding and
_name_claim_beats against the same scratch DB.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/canonical-time-belt-test.py
"""
import json
import os
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

TMP = tempfile.mkdtemp(prefix="canonical-time-belt-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import order matters: `import core` FIRST (the app.py order).
import core  # noqa: E402
core.init_db()
from fed import ed25519 as _ed  # noqa: E402
import uvicorn  # noqa: E402
from app import app  # noqa: E402

PASSED = FAILED = 0


def check(desc, cond, extra=""):
    global PASSED, FAILED
    if cond:
        PASSED += 1
        print(f"  ok  {desc}")
    else:
        FAILED += 1
        print(f"  FAIL {desc} {extra}")


def raises_ve(fn):
    try:
        fn()
    except ValueError:
        return True
    except Exception:
        return False
    return False


NOW = datetime.now(timezone.utc)
CANON = (NOW - timedelta(minutes=5)).isoformat(timespec="seconds")          # +00:00
CANON_Z = (NOW - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")        # Z
CANON_OFF = (NOW - timedelta(minutes=5)).astimezone(
    timezone(timedelta(hours=5))).isoformat(timespec="seconds")              # +05:00 (B4: NOT canonical)
CANON_EXP = (NOW + timedelta(days=30)).isoformat(timespec="seconds")
NAIVE = (NOW - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%S")           # naive
NAIVE_EXP = (NOW + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%S")
DATEONLY = (NOW + timedelta(days=30)).strftime("%Y-%m-%d")                  # date-only
GARBAGE = "not-a-time"

print("unit: _parse_claim_time strictness")
check("canonical +00:00 parses", not raises_ve(lambda: core._parse_claim_time(CANON)))
check("canonical Z parses", not raises_ve(lambda: core._parse_claim_time(CANON_Z)))
check("canonical +05:00 raises (B4: UTC-only)",
      raises_ve(lambda: core._parse_claim_time(CANON_OFF)))
check("naive datetime raises", raises_ve(lambda: core._parse_claim_time(NAIVE)))
check("date-only raises", raises_ve(lambda: core._parse_claim_time(DATEONLY)))
check("garbage raises", raises_ve(lambda: core._parse_claim_time(GARBAGE)))
check("empty raises", raises_ve(lambda: core._parse_claim_time("")))


def mint(name, priv_hex, issued_at, expires_at):
    pub = _ed.publickey(bytes.fromhex(priv_hex)).hex()
    sig = _ed.sign(
        core._name_claim_payload(name, pub, issued_at, expires_at),
        bytes.fromhex(priv_hex), bytes.fromhex(pub)).hex()
    return {"name": name, "node_pubkey": pub, "issued_at": issued_at,
            "expires_at": expires_at, "signature": sig}


print("ingest: unparseable rows are dropped-malformed (never gossiped in)")
k = os.urandom(32).hex()
check("naive issued_at dropped",
      core.ingest_gossiped_binding(mint("ct-naive-i", k, NAIVE, CANON_EXP)) == "dropped-malformed")
check("naive expires_at dropped",
      core.ingest_gossiped_binding(mint("ct-naive-e", k, CANON, NAIVE_EXP)) == "dropped-malformed")
check("date-only expires_at dropped",
      core.ingest_gossiped_binding(mint("ct-dateonly", k, CANON, DATEONLY)) == "dropped-malformed")
check("garbage issued_at dropped",
      core.ingest_gossiped_binding(mint("ct-garbage", k, GARBAGE, CANON_EXP)) == "dropped-malformed")
check("canonical control inserts",
      core.ingest_gossiped_binding(mint("ct-control", k, CANON, CANON_EXP)) == "inserted")
k2 = os.urandom(32).hex()
check("Z-form control inserts",
      core.ingest_gossiped_binding(mint("ct-zulu", k2, CANON_Z, CANON_EXP)) == "inserted")

print("_name_claim_beats: unparseable never wins")
old = {"name": "ct-beats", "node_pubkey": "aa" * 32, "issued_at": CANON}
new_bad = {"name": "ct-beats", "node_pubkey": "bb" * 32, "issued_at": NAIVE}
check("unparseable new raises (never wins)",
      raises_ve(lambda: core._name_claim_beats(new_bad, old)))
new_good = {"name": "ct-beats", "node_pubkey": "bb" * 32, "issued_at": CANON}
old_bad = {"name": "ct-beats", "node_pubkey": "aa" * 32, "issued_at": DATEONLY}
check("unparseable old raises (reads as absent, caller drops)",
      raises_ve(lambda: core._name_claim_beats(new_good, old_bad)))
# control: valid beats logic unchanged (different keys: earlier issued_at wins)
check("valid earlier issued_at wins (control)",
      core._name_claim_beats(
          {"name": "x", "node_pubkey": "bb" * 32,
           "issued_at": (NOW - timedelta(hours=2)).isoformat(timespec="seconds")},
          {"name": "x", "node_pubkey": "aa" * 32,
           "issued_at": (NOW - timedelta(hours=1)).isoformat(timespec="seconds")}) is True)


# --- live app: claim route + serve route -----------------------------------
def _free_port():
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


PORT = _free_port()
MIRROR = f"http://127.0.0.1:{PORT}"
srv = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=PORT,
                                    log_level="error"))
t = threading.Thread(target=srv.run, daemon=True)
t.start()
for _ in range(100):
    try:
        urllib.request.urlopen(MIRROR + "/api/v1/node", timeout=1).read()
        break
    except Exception:
        time.sleep(0.1)


def claim(form):
    data = urllib.parse.urlencode(form).encode()
    req = urllib.request.Request(MIRROR + "/api/v1/names/claim", data=data)
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def get_name(label):
    try:
        with urllib.request.urlopen(MIRROR + "/api/v1/names/" + label,
                                    timeout=8) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


print("claim route: unparseable refused with expiry-cap")
for desc, issued, expires in [
        ("naive issued_at", NAIVE, CANON_EXP),
        ("naive expires_at", CANON, NAIVE_EXP),
        ("date-only expires_at", CANON, DATEONLY),
        ("garbage issued_at", GARBAGE, CANON_EXP)]:
    kk = os.urandom(32).hex()
    pub = _ed.publickey(bytes.fromhex(kk)).hex()
    sig = _ed.sign(core._name_claim_payload("ct-" + desc.split()[0], pub,
                                            issued, expires),
                   bytes.fromhex(kk), bytes.fromhex(pub)).hex()
    st, body = claim({"name": "ct-" + desc.split()[0], "node_pubkey": pub,
                      "issued_at": issued, "expires_at": expires,
                      "signature": sig})
    check(f"claim refuses {desc} (400 + expiry-cap)",
          st == 400 and "expiry-cap" in body, f"st={st} body={body[:80]}")

kk = os.urandom(32).hex()
pub = _ed.publickey(bytes.fromhex(kk)).hex()
sig = _ed.sign(core._name_claim_payload("ct-ok", pub, CANON, CANON_EXP),
               bytes.fromhex(kk), bytes.fromhex(pub)).hex()
st, _ = claim({"name": "ct-ok", "node_pubkey": pub, "issued_at": CANON,
               "expires_at": CANON_EXP, "signature": sig})
check("claim accepts canonical control (200)", st == 200, f"st={st}")

print("serve route: legacy unparseable row reads as ABSENT")
# Plant a legacy row directly (bypassing the claim gate, as a pre-fix row
# would exist) and confirm the serve path 404s on it.
legacy_pub = _ed.publickey(bytes.fromhex(kk)).hex()
with core._db_lock, core._db() as conn:
    conn.execute(
        "INSERT INTO name_bindings (name, node_pubkey, issued_at, expires_at,"
        " signature) VALUES (?,?,?,?,?)",
        ("ct-legacy", legacy_pub, NAIVE, CANON_EXP, "00" * 64))
check("GET /names/ct-legacy -> 404 (absent, not live)",
      get_name("ct-legacy") == 404)
with core._db_lock, core._db() as conn:
    conn.execute("DELETE FROM name_bindings WHERE name='ct-legacy'")

srv.should_exit = True
t.join(timeout=10)

print(f"\n{__file__}: {PASSED} passed, {FAILED} failed")
sys.exit(1 if FAILED else 0)
