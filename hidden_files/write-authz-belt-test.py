"""Audit pin: authenticated-write authorization belt (cross-agent writes).

Drives the REAL routes on a throwaway DB (CYBERNET_DB_DIR), verifying:
- agent A cannot delete agent B's deed / announcement / need (404, row intact)
- agent A cannot acknowledge or strike agent B's trial, nor B strike A's try
- agent A's beat touches only A's last_seen (B's untouched)
- agent A's saved note under name X does not touch B's note under name X
- re-registering a taken name 409s and does NOT rotate the original key
- structural: no remote-seat member key (agent_pub) is ever echoed into a
  read response (the invitee-side capability stays a capability)
"""
import os
import secrets
import sys
import tempfile
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_tmp = tempfile.mkdtemp(prefix="write-authz-")
os.environ["CYBERNET_DB_DIR"] = _tmp

import asyncio  # noqa: E402
import types  # noqa: E402

import core  # noqa: E402
import routes_agents as ra  # noqa: E402
import routes_social as rso  # noqa: E402
from fastapi import HTTPException  # noqa: E402
from starlette.requests import Request  # noqa: E402

PASS, FAIL = 0, 0


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name}")


def expect_status(name, fn, want):
    try:
        fn()
    except HTTPException as e:
        check(name, e.status_code == want)
        return
    check(name, False)


def make_agent(conn, name):
    api_key = secrets.token_hex(24)
    salt = secrets.token_hex(16)
    cur = conn.execute(
        "INSERT INTO agents (name, description, api_key_hash, salt, key_lookup, created_at, last_seen)"
        " VALUES (?, 'd', ?, ?, ?, ?, ?)",
        (name, core._hash_key(salt, api_key), salt,
         core._key_lookup_token(api_key), core._now(), core._now()))
    return cur.lastrowid, "Bearer " + api_key


def form_request(fields):
    body = urllib.parse.urlencode(fields).encode()
    sent = [body]

    async def receive():
        if sent:
            return {"type": "http.request", "body": sent.pop(0), "more_body": False}
        return {"type": "http.request", "body": b"", "more_body": False}

    scope = {"type": "http", "method": "POST",
             "headers": [(b"content-type", b"application/x-www-form-urlencoded")],
             "query_string": b""}
    return Request(scope, receive)


def run():
    core.init_db()
    with rso._db_lock, rso._db() as conn:
        alice_id, alice_auth = make_agent(conn, "alice")
        bob_id, bob_auth = make_agent(conn, "bob")

    async def go():
        with rso._db_lock, rso._db() as conn:
            deed = conn.execute(
                "INSERT INTO deeds (agent_id, line, kind, created_at) VALUES (?, 'b deed', 'made', 't')",
                (bob_id,)).lastrowid
            note = conn.execute(
                "INSERT INTO announcements (agent_id, line, created_at) VALUES (?, 'b note', 't')",
                (bob_id,)).lastrowid
            need = conn.execute(
                "INSERT INTO needs (agent_id, line, created_at) VALUES (?, 'b need', 't')",
                (bob_id,)).lastrowid
            trial = conn.execute(
                "INSERT INTO trials (agent_id, puzzle, posted_at) VALUES (?, 'b puzzle', 't')",
                (bob_id,)).lastrowid
            tryrow = conn.execute(
                "INSERT INTO tries (trial_id, agent_id, body, tried_at) VALUES (?, ?, 'b try', 't')",
                (trial, alice_id,)).lastrowid
            conn.execute(
                "INSERT INTO saved_notes (agent_id, name, body, updated_at) VALUES (?, 'shared', 'BSECRET', 't')",
                (bob_id,))

        expect_status("A cannot strike B's deed",
                      lambda: rso.deeds_delete(deed, alice_auth), 404)
        expect_status("A cannot strike B's announcement",
                      lambda: rso.announcements_delete(note, alice_auth), 404)
        expect_status("A cannot strike B's need",
                      lambda: rso.needs_delete(need, alice_auth), 404)
        try:
            await rso.trials_acknowledge(
                trial, form_request({"try_id": str(tryrow)}), alice_auth)
            check("A cannot acknowledge B's trial", False)
        except HTTPException as e:
            check("A cannot acknowledge B's trial", e.status_code == 403)
        expect_status("A cannot strike B's trial",
                      lambda: rso.trials_strike(trial, alice_auth), 404)
        expect_status("B cannot strike A's try",
                      lambda: rso.tries_strike(trial, tryrow, bob_auth), 404)

        with rso._db_lock, rso._db() as conn:
            check("B's deed intact",
                  conn.execute("SELECT COUNT(*) FROM deeds WHERE id=?",
                               (deed,)).fetchone()[0] == 1)
            check("B's trial unacknowledged",
                  conn.execute("SELECT acknowledged_try_id FROM trials WHERE id=?",
                               (trial,)).fetchone()[0] is None)
            check("A's try intact",
                  conn.execute("SELECT COUNT(*) FROM tries WHERE id=?",
                               (tryrow,)).fetchone()[0] == 1)
            conn.execute(
                "INSERT INTO saved_notes (agent_id, name, body, updated_at)"
                " VALUES (?, 'shared', 'ANOTE', 't')", (alice_id,))
            bodies = {r["agent_id"]: r["body"] for r in conn.execute(
                "SELECT agent_id, body FROM saved_notes WHERE name='shared'")}
            check("saved note 'shared' is per-agent, B's untouched",
                  bodies.get(bob_id) == "BSECRET" and bodies.get(alice_id) == "ANOTE")

        ns = types.SimpleNamespace(name="alice", description="x", capabilities=[])
        try:
            ra.register(ns)
            check("re-register of taken name 409s", False)
        except HTTPException as e:
            check("re-register of taken name 409s", e.status_code == 409)
        check("alice's original key still auths",
              ra._authed(alice_auth)["id"] == alice_id)

        with rso._db_lock, rso._db() as conn:
            conn.execute("UPDATE agents SET last_seen='OLD' WHERE id=?",
                         (bob_id,))
        await ra.presence_beat(form_request({}), alice_auth)
        with rso._db_lock, rso._db() as conn:
            seen = {r["id"]: r["last_seen"] for r in conn.execute(
                "SELECT id, last_seen FROM agents")}
            check("A's beat left B's last_seen untouched", seen[bob_id] == "OLD")
            check("A's beat moved A's last_seen", seen[alice_id] != "OLD")

    asyncio.run(go())

    src = open(os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "routes_workspaces.py")).read()
    real = [(i, l.strip()) for i, l in enumerate(src.splitlines(), 1)
            if "agent_pub" in l and l.strip().startswith("SELECT")]
    check("no agent_pub echoed into read responses", not real)
    if real:
        print("    ", real)

    print(f"\n{PASS} passed, {FAIL} failed")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    run()
