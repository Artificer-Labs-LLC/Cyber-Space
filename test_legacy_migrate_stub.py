#!/usr/bin/env python3
"""ART-29 item (b) belt: legacy migrate routes return 409 + fixed JSON body
(Villhaze 50876294 / 3c65ab2b). Mutant: a route returning 200 must fail."""
import os
import sys
import tempfile

os.environ["CYBERNET_DB_DIR"] = tempfile.mkdtemp(prefix="art29-stub-")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient  # noqa: E402
import core  # noqa: E402
core.init_db()
import app as appmod  # noqa: E402
import routes_legacy_migrate as rlm  # noqa: E402

PASS = FAIL = 0


def check(label, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("PASS", label)
    else:
        FAIL += 1
        print("FAIL", label)


def belt(client):
    """Return list of (label, ok) for every legacy migrate route."""
    out = []
    for m, p in rlm.LEGACY_MIGRATE_PATHS:
        r = client.request(m, p, json={})
        try:
            body = r.json()
        except Exception:
            body = None
        ok = (r.status_code == 409 and body == rlm.GONE_BODY
              and "window_open" in body.get("detail", ""))
        out.append((f"{m} {p} -> 409 + replaced-by-window_open body", ok))
    return out


client = TestClient(appmod.app)
for label, ok in belt(client):
    check(label, ok)

# Examiner a565a7b advisory 1: prove the stub touches no DB. Every sqlite
# connect and every core._db() call is counted while the 4 routes run.
import sqlite3  # noqa: E402
_hits = []
_real_connect, _real_db = sqlite3.connect, core._db
sqlite3.connect = lambda *a, **k: (_hits.append("sqlite3.connect"), _real_connect(*a, **k))[1]
core._db = lambda *a, **k: (_hits.append("core._db"), _real_db(*a, **k))[1]
try:
    nres = belt(client)
finally:
    sqlite3.connect, core._db = _real_connect, _real_db
check("stub makes no DB access (0 sqlite3.connect / core._db calls over all routes)",
      not _hits and all(ok for _, ok in nres))

# Examiner a565a7b advisory 2: the mutant patches the SHIPPED module's
# handler (the endpoint objects mounted in app.app), not a separate app.
_want = set(rlm.LEGACY_MIGRATE_PATHS)
# app.app mounts rlm.router via include_router (FastAPI keeps it as an
# _IncludedRouter reference), so patching rlm.router's routes patches the
# live shipped app.
_shipped = [r for r in rlm.router.routes
            if any((m, getattr(r, "path", None)) in _want for m in (getattr(r, "methods", None) or ()))]
_real_jr = rlm.JSONResponse
# MUTANT: patch the shipped module itself (rlm.JSONResponse, resolved by
# rlm._gone at call time) so the live app.app routes answer 200.
rlm.JSONResponse = lambda status_code, content: _real_jr(content=content, status_code=200)
try:
    mres = belt(TestClient(appmod.app))
finally:
    rlm.JSONResponse = _real_jr
check("shipped app mounts all 4 stub routes", len(_shipped) == len(rlm.LEGACY_MIGRATE_PATHS))
check("mutant (shipped routes patched to return 200) fails every belt row",
      len(mres) == len(rlm.LEGACY_MIGRATE_PATHS) and not any(ok for _, ok in mres))
check("shipped routes restored after mutant -> belt green again",
      all(ok for _, ok in belt(TestClient(appmod.app))))

print(f"{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
