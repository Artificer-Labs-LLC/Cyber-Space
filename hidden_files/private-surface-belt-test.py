"""Audit pin: private-surface authorization belt (spaces serve path + DM reads).

Drives the REAL routes on a throwaway DB (CYBERNET_DB_DIR), verifying:
- _serve_space rejects path escapes (../.., nested .., absolute-ish)
- space_door rejects hostile names and escapes
- read_dm for agent A about agent C only ever sees the A<->C thread:
  B<->C messages stay invisible (participant-derived channel naming)
"""
import os
import secrets
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_tmp = tempfile.mkdtemp(prefix="private-surface-")
os.environ["CYBERNET_DB_DIR"] = _tmp

import core  # noqa: E402
import routes_spaces as rs  # noqa: E402
import routes_channels as rc  # noqa: E402
from fastapi import HTTPException  # noqa: E402

PASS, FAIL = 0, 0


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name}")


def expect_404(name, fn):
    try:
        fn()
    except HTTPException as e:
        check(name, e.status_code == 404)
        return
    check(name, False)


def make_agent(conn, name):
    api_key = secrets.token_hex(24)
    salt = secrets.token_hex(16)
    cur = conn.execute(
        "INSERT INTO agents (name, description, api_key_hash, salt, key_lookup, created_at, last_seen)"
        " VALUES (?, 'd', ?, ?, ?, 't', 't')",
        (name, core._hash_key(salt, api_key), salt,
         core._key_lookup_token(api_key)))
    return cur.lastrowid, "Bearer " + api_key


def run():
    core.init_db()
    with rs._db_lock, rs._db() as conn:
        alice_id, alice_auth = make_agent(conn, "alice")
        bob_id, bob_auth = make_agent(conn, "bob")
        carol_id, carol_auth = make_agent(conn, "carol")
    os.makedirs(os.path.join(_tmp, "agents", "alice"), exist_ok=True)

    # --- spaces serve path: confinement ---
    expect_404("serve: ../../etc/passwd -> 404",
               lambda: rs._serve_space("alice", "../../etc/passwd"))
    expect_404("serve: nested .. escape -> 404",
               lambda: rs._serve_space("alice", "sub/../../../etc"))
    expect_404("door: hostile name '..' -> 404",
               lambda: rs.space_door(".."))
    expect_404("door: name with slash -> 404",
               lambda: rs.space_door("a/b"))
    expect_404("serve: unknown space -> 404",
               lambda: rs._serve_space("ghost", "x.html"))
    # own space still serves
    r = rs._serve_space("alice", "")
    check("serve: own space still serves (auto-index HTMLResponse)",
          r.status_code == 200)

    # --- DM read isolation ---
    ch = rc._dm_channel(bob_id, carol_id)
    core._post_message(ch["id"], bob_id, "secret between bob and carol")
    # alice reads "about carol": only her own thread with carol (empty)
    r = rc.read_dm("carol", limit=50, authorization=alice_auth)
    check("DM: alice's read about carol shows no bob<->carol messages",
          all(m["body"] != "secret between bob and carol"
              for m in r["messages"]))
    # bob reads his own thread with carol: sees it
    r = rc.read_dm("carol", limit=50, authorization=bob_auth)
    check("DM: bob's read about carol shows his own thread",
          any(m["body"] == "secret between bob and carol"
              for m in r["messages"]))
    # unauthenticated read is a 401
    try:
        rc.read_dm("carol", limit=50, authorization=None)
        check("DM: no-auth -> 401", False)
    except HTTPException as e:
        check("DM: no-auth -> 401", e.status_code == 401)


if __name__ == "__main__":
    run()
    print(f"done: {PASS} pass, {FAIL} fail")
    sys.exit(1 if FAIL else 0)
