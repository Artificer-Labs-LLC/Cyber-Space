"""Mirror-side open-by-point (routes_relay.py): /relay/open accepts the
derived rendezvous_point the dialer computed from the name key instead
of the routing token, resolving it to the held hold-open (fresh,
registered, willing epoch only — everything else 404 silence).

Drives the REAL route functions with stubbed Requests; the relay never
verifies the signature (dialer-side fail-closed, replicated in check 2),
it only shape-checks and routes bytes.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/rendezvous-open-bypoint-test.py
"""
import asyncio
import os
import secrets
import sys
import tempfile
import time

TMP = tempfile.mkdtemp(prefix="rv-openbypoint-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import rendezvous  # noqa: E402
import routes_relay as rr  # noqa: E402
from fastapi import HTTPException  # noqa: E402
from fed import ed25519 as _fed_ed25519  # noqa: E402


class _Client:
    def __init__(self, host):
        self.host = host


class _Req:
    _n = 0

    def __init__(self, host=None):
        if host is None:
            _Req._n += 1
            host = f"10.11.{_Req._n // 256}.{_Req._n % 256}"
        self.client = _Client(host)


passed = failed = 0


def check(name, cond, extra=""):
    global passed, failed
    if cond:
        passed += 1
        print(f"  ok  {name}")
    else:
        failed += 1
        print(f"  FAIL {name} {extra}")


def run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def status_of(coro):
    try:
        run(coro)
        return None
    except HTTPException as e:
        return e.status_code


# keep the wait windows fast for the suite; shape unchanged
rr._RELAY_ANSWER_WAIT = 0.6
rr._RELAY_HOLD_WAIT = 0.5

# the name key stands in for a real .cyberspace name key
priv = secrets.token_hex(32)
pub = _fed_ed25519.publickey(bytes.fromhex(priv)).hex()
pub_b = bytes.fromhex(pub)

TOK = "tok-" + secrets.token_hex(8)

# derived (E, E-1) points for this name key
now = time.time()
E = rendezvous.epoch_for(now)
point_E, point_E1 = rendezvous.derive_points(now, pub)


def dial_side_verify(challenge, sig, key_hex):
    """Replicates core.py _relay_open_session's fail-closed verify."""
    try:
        if len(challenge) != 64 or len(sig) != 128:
            return False
        return _fed_ed25519.checkvalid(
            bytes.fromhex(sig), bytes.fromhex(challenge),
            bytes.fromhex(key_hex))
    except Exception:
        return False


# 1. register the hold-open indexed under both derived points
r = run(rr.relay_register(
    _Req(), {"token": TOK, "rendezvous_point": point_E, "name_pub": pub}))
check("register with point ok", r.get("ok") is True)
r = run(rr.relay_register(
    _Req(), {"token": TOK, "rendezvous_point": point_E1, "name_pub": pub}))
check("register with E-1 point ok", r.get("ok") is True)


# 2. full round trip by point: dial opens with rendezvous_point only,
#    hoster (holding TOK) sees the session on its token and answers
async def roundtrip_by_point(point):
    async def hoster():
        w = await rr.relay_wait(_Req(), {"token": TOK})
        assert w.get("ok") is True and w["sessions"], f"wait empty: {w}"
        sess = w["sessions"][0]
        sig = _fed_ed25519.sign(
            bytes.fromhex(sess["challenge"]),
            bytes.fromhex(priv), bytes.fromhex(pub)).hex()
        a = await rr.relay_answer(
            _Req(), {"session_id": sess["session_id"], "name_key_sig": sig})
        assert a.get("ok") is True, f"answer failed: {a}"

    async def dialer():
        return await rr.relay_open(
            _Req(), {"name": "alice", "rendezvous_point": point})

    dial_task = asyncio.ensure_future(dialer())
    await hoster()
    return await dial_task


pair = run(roundtrip_by_point(point_E))
check("open by point returns the pair",
      isinstance(pair, dict) and len(pair.get("challenge", "")) == 64
      and len(pair.get("name_key_sig", "")) == 128)
check("pair verifies against the NAME KEY (dial-side fail-closed)",
      dial_side_verify(pair["challenge"], pair["name_key_sig"], pub))
check("wrong key does NOT verify",
      not dial_side_verify(pair["challenge"], pair["name_key_sig"],
                            secrets.token_hex(32)))

pair1 = run(roundtrip_by_point(point_E1))
check("open by E-1 point round-trips too",
      dial_side_verify(pair1["challenge"], pair1["name_key_sig"], pub))

# 3. unregistered / malformed / missing point -> 404 silence
check("open unregistered point 404",
      status_of(rr.relay_open(
          _Req(), {"name": "alice", "rendezvous_point": "ab" * 32})) == 404)
check("open short point 404",
      status_of(rr.relay_open(
          _Req(), {"name": "alice", "rendezvous_point": "ab12"})) == 404)
check("open non-hex point 404",
      status_of(rr.relay_open(
          _Req(), {"name": "alice", "rendezvous_point": "zz" * 32})) == 404)
check("open with neither token nor point 404",
      status_of(rr.relay_open(_Req(), {"name": "alice"})) == 404)
check("name still required (400) even with a good point",
      status_of(rr.relay_open(
          _Req(), {"rendezvous_point": point_E})) == 400)

# 4. stale point: age the record past the hold TTL -> reaped -> 404
rr._relay_rendezvous[point_E]["seen"] -= (rr._RELAY_HOLD_TTL + 10)
check("open stale point 404 (reaped)",
      status_of(rr.relay_open(
          _Req(), {"name": "alice", "rendezvous_point": point_E})) == 404)
# re-register it for the checks below
r = run(rr.relay_register(
    _Req(), {"token": TOK, "rendezvous_point": point_E, "name_pub": pub}))
check("re-register after reap ok", r.get("ok") is True)

# 5. old-epoch point (registered but unwilling) -> 404, never 4xx.
#    injected directly: _valid_rendezvous would 400 a stale bind at
#    register time, which is the hoster's loud error, not the dialer's.
old_point = rendezvous.derive_point_id(pub, E - 5)
rr._relay_rendezvous[old_point] = {
    "token": TOK, "name_pub": pub, "seen": time.monotonic()}
check("open old-epoch point 404",
      status_of(rr.relay_open(
          _Req(), {"name": "alice", "rendezvous_point": old_point})) == 404)

# 6. token wins when both are given: TOK's hoster answers a session the
#    dialer opened with TOK + a point registered under ANOTHER token.
TOK2 = "tok-" + secrets.token_hex(8)
priv2 = secrets.token_hex(32)
pub2 = _fed_ed25519.publickey(bytes.fromhex(priv2)).hex()
point2 = rendezvous.derive_point_id(pub2, E)
run(rr.relay_register(
    _Req(), {"token": TOK2, "rendezvous_point": point2, "name_pub": pub2}))


async def roundtrip_token_wins():
    async def hoster():
        w = await rr.relay_wait(_Req(), {"token": TOK})
        assert w.get("ok") is True and w["sessions"], f"wait empty: {w}"
        sess = w["sessions"][0]
        sig = _fed_ed25519.sign(
            bytes.fromhex(sess["challenge"]),
            bytes.fromhex(priv), bytes.fromhex(pub)).hex()
        a = await rr.relay_answer(
            _Req(), {"session_id": sess["session_id"], "name_key_sig": sig})
        assert a.get("ok") is True, f"answer failed: {a}"

    async def dialer():
        return await rr.relay_open(
            _Req(), {"name": "alice", "token": TOK,
                     "rendezvous_point": point2})

    dial_task = asyncio.ensure_future(dialer())
    await hoster()
    return await dial_task


pair2 = run(roundtrip_token_wins())
check("explicit token wins over a foreign point (TOK hoster answers)",
      dial_side_verify(pair2["challenge"], pair2["name_key_sig"], pub))

print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
