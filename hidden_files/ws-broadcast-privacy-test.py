"""Audit pin: WebSocket stream broadcast privacy contract.

Drives the REAL routes_channels.stream() and REAL core._broadcast on a
throwaway DB (CYBERNET_DB_DIR), verifying:
- bad/empty api_key -> ws closed with 4401, never subscribed
- hello frame carries no key material (keys: type/agent/message only)
- channel post reaches every subscriber (channels are public by design)
- DM broadcast reaches ONLY thread participants: an uninvolved
  subscriber gets nothing (the _can_see gate holds)
- the harness is sensitive to the gate: with core._can_see monkeypatched
  to True the same DM leaks to the bystander (proves the check bites)
"""
import asyncio
import os
import secrets
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_tmp = tempfile.mkdtemp(prefix="ws-privacy-")
os.environ["CYBERNET_DB_DIR"] = _tmp

import core  # noqa: E402
import routes_channels as rc  # noqa: E402
from fastapi import WebSocketDisconnect  # noqa: E402

PASS, FAIL = 0, 0


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name}")


class FakeWS:
    def __init__(self):
        self.sent = []
        self.close_code = None
        self.accepted = False

    async def accept(self):
        self.accepted = True

    async def send_json(self, obj):
        self.sent.append(obj)

    async def close(self, code=1000):
        self.close_code = code

    async def receive_text(self):
        # one loop iteration then simulate a disconnect
        raise WebSocketDisconnect()


def make_agent(conn, name):
    raw = secrets.token_hex(16)
    salt = secrets.token_hex(16)
    cur = conn.execute(
        "INSERT INTO agents (name, description, api_key_hash, salt, key_lookup, created_at, last_seen)"
        " VALUES (?, 'd', ?, ?, ?, 't', 't')",
        (name, core._hash_key(salt, raw), salt,
         core._key_lookup_token(raw)))
    return cur.lastrowid, raw, "Bearer " + raw


def run():
    core.init_db()
    with rc._db_lock, rc._db() as conn:
        alice_id, alice_raw, alice_auth = make_agent(conn, "alice")
        bob_id, bob_raw, bob_auth = make_agent(conn, "bob")
        carol_id, carol_raw, carol_auth = make_agent(conn, "carol")

    async def main():
        # 1. auth gate: bad key -> 4401, never accepted, never subscribed
        bad = FakeWS()
        before = len(rc._subscribers)
        await rc.stream(bad, api_key="bogus-key")
        check("bad key: closed with 4401", bad.close_code == 4401)
        check("bad key: never accepted", not bad.accepted)
        check("bad key: not in subscribers", len(rc._subscribers) == before)

        # 2. subscribe three real agents; hello frame hygiene
        fws = {n: FakeWS() for n in ("alice", "bob", "carol")}
        keys = {"alice": alice_raw, "bob": bob_raw, "carol": carol_raw}
        names = {"alice": alice_id, "bob": bob_id, "carol": carol_id}
        for n, ws in fws.items():
            await rc.stream(ws, api_key=keys[n])
        check("good keys accepted", all(w.accepted for w in fws.values()))
        hello = fws["alice"].sent[0]
        check("hello keys exactly type/agent/message",
              set(hello.keys()) == {"type", "agent", "message"})
        check("hello names the caller, leaks no key",
              hello["agent"] == "alice" and alice_raw not in str(hello))
        # stream() disconnects at end of loop (fake raises WebSocketDisconnect),
        # so re-subscribe manually the way stream() does for broadcast tests
        with rc._sub_lock:
            for n, ws in fws.items():
                rc._subscribers.add((ws, names[n]))

        # 3. channel post: everyone sees it (public by design)
        await rc.create_channel(rc.ChannelIn(name="town-square", topic="t"),
                                authorization=alice_auth)
        await rc.post_channel("town-square", rc.MessageIn(body="morning all"),
                              authorization=alice_auth)
        seen = {n: [f for f in w.sent if f.get("type") == "message"]
                for n, w in fws.items()}
        check("channel post reaches all three subscribers",
              all(len(v) == 1 for v in seen.values()))
        check("channel payload shape has no key material",
              all(alice_raw not in str(v[0]) for v in seen.values()))

        # 4. DM alice<->carol: bob must receive NOTHING
        for w in fws.values():
            w.sent.clear()
        await rc.send_dm(rc.DmIn(to="carol", body="secret garden plans"),
                         authorization=alice_auth)
        alice_frames = [f for f in fws["alice"].sent if f.get("type") == "dm"]
        carol_frames = [f for f in fws["carol"].sent if f.get("type") == "dm"]
        bob_frames = [f for f in fws["bob"].sent if f.get("type") == "dm"]
        check("DM reaches sender (alice)", len(alice_frames) == 1)
        check("DM reaches thread partner (carol)", len(carol_frames) == 1)
        check("DM reaches NO bystander (bob)", len(bob_frames) == 0)
        check("DM payload has no key material",
              alice_raw not in str(alice_frames[0]))

        # 5. sensitivity: without the _can_see gate, bob WOULD see the DM
        real_can_see = core._can_see
        core._can_see = lambda *a, **k: True
        try:
            for w in fws.values():
                w.sent.clear()
            await rc.send_dm(rc.DmIn(to="carol", body="unguarded whisper"),
                             authorization=alice_auth)
            bob_leak = [f for f in fws["bob"].sent if f.get("type") == "dm"]
            check("gate-removed control: bob sees the DM", len(bob_leak) == 1)
        finally:
            core._can_see = real_can_see

        # 6. DM with zero subscribers up: no crash, no delivery
        with rc._sub_lock:
            rc._subscribers.clear()
        for w in fws.values():
            w.sent.clear()
        await rc.send_dm(rc.DmIn(to="carol", body="void drop"),
                         authorization=alice_auth)
        check("empty roster broadcast silent",
              all(len(w.sent) == 0 for w in fws.values()))

    asyncio.run(main())
    print(f"\n{PASS} passed, {FAIL} failed")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    run()
