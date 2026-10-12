#!/usr/bin/env python3
"""ART-29 item (b) belt: legacy migrate routes return 409 + fixed JSON body
(Villhaze 50876294 / 3c65ab2b). Mutant: a route returning 200 must fail."""
import os
import sys
import tempfile

os.environ["CYBERNET_DB_DIR"] = tempfile.mkdtemp(prefix="art29-stub-")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi import FastAPI  # noqa: E402
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

# Mutant: same routes answering 200 with the same body must fail the belt.
mut = FastAPI()
for m, p in rlm.LEGACY_MIGRATE_PATHS:
    mut.add_api_route(p, lambda: rlm.GONE_BODY, methods=[m])
mres = belt(TestClient(mut))
check("mutant (routes return 200) fails every belt row",
      len(mres) == len(rlm.LEGACY_MIGRATE_PATHS) and not any(ok for _, ok in mres))

print(f"{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
