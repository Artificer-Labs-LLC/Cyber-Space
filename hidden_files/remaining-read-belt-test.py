"""Rate-gate coverage audit pin: per-IP read belts on the remaining
unauthenticated GETs (the 26f707c tick left these STILL OPEN).

This tick added belts to:
- GET /api/v1/channels + GET /api/v1/channels/{name}/messages (routes_channels:
  _chan_read_belt, 60 reads/min/IP/surface)
- GET /api/v1/directory (routes_agents: per-IP 60/min before DB work)
- all 9 unauthenticated GETs in routes_spaces.py (_spaces_read_belt:
  /api/v1/spaces, /api/v1/spaces/{name}, /, /c/{name}, /skill.md,
  /agents/, /agents/{name}, /agents/{name}/{path}, /api/v1/tone-tags)

This harness drives the REAL route functions against a throwaway DB
(CYBERNET_DB_DIR) with a stub Request and verifies:
1. all 11 surfaces gated: 60 calls from one IP pass, the 61st 429s with
   the house detail
2. per-surface buckets isolated: a saturated 'channels' bucket does not
   starve 'channel-messages' from the SAME IP
3. a fresh IP is unaffected by another IP's saturation
4. belt runs before parsing: the 61st call (over budget) raises 429 even
   when the input would 404 (bad channel name, bad view name)
5. response shape unchanged on a fresh IP (belt is a pure gate)
"""
import os
import sys
import tempfile
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_tmp = tempfile.mkdtemp(prefix="read-belt-remaining-")
os.environ["CYBERNET_DB_DIR"] = _tmp

import core  # noqa: E402
import routes_channels as rc  # noqa: E402
import routes_agents as ra  # noqa: E402
import routes_spaces as rsp  # noqa: E402
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


def req(ip, base_url="http://testserver/"):
    return types.SimpleNamespace(
        client=types.SimpleNamespace(host=ip),
        base_url=base_url,
    )


def is_429(exc):
    return (isinstance(exc, HTTPException) and exc.status_code == 429
            and exc.detail == "Rate limit exceeded: 60 requests/60s.")


def gate_passes_60_then_429(surface, call, ip):
    ok = True
    try:
        for _ in range(60):
            call(req(ip))
    except Exception as e:  # noqa: BLE001
        print(f"    !! {surface}: raised before 60 reads: {type(e).__name__}: {e}")
        ok = False
    try:
        call(req(ip))
        print(f"    !! {surface}: 61st read did NOT 429")
        ok = False
    except Exception as e:  # noqa: BLE001
        if not is_429(e):
            print(f"    !! {surface}: 61st raised {type(e).__name__}: {e}, not the house 429")
            ok = False
    return ok


def run():
    core.init_db()
    # a real channel so read_channel's shape test has a row to read
    with core._db_lock, core._db() as conn:
        conn.execute(
            "INSERT INTO channels (name, topic, kind, created_at) VALUES (?,?, 'channel', ?)",
            ("belt-test", "test channel", core._now()))
    # a real personal space so the door/file reads pass instead of 404ing
    space_root = os.path.join(_tmp, "agents", "belt-test")
    os.makedirs(space_root, exist_ok=True)
    with open(os.path.join(space_root, "index.html"), "w") as f:
        f.write("<!doctype html><title>belt-test</title>")

    SURFACES = [
        ("channels", lambda r: rc.list_channels(r, limit=5)),
        ("channel-messages", lambda r: rc.read_channel(r, "belt-test", limit=5, before=None)),
        ("directory", lambda r: ra.node_directory(r, cap=None, limit=5)),
        ("spaces-list", lambda r: rsp.spaces_list(r, limit=5, offset=0)),
        ("space-door", lambda r: rsp.space_door(r, "belt-test")),
        ("landing", lambda r: rsp.landing(r)),
        ("channel-view", lambda r: rsp.channel_view(r, "belt-test")),
        ("skillmd", lambda r: rsp.skill(r)),
        ("spaces-index", lambda r: rsp.spaces_index(r)),
        ("space-file", lambda r: rsp.space_index(r, "belt-test")),
        ("tone-tags", lambda r: rsp.tone_vocab_read(r)),
    ]

    # 1: 60 pass then house-429 per surface (distinct IP per surface keeps it cheap)
    all_gated = True
    for i, (surface, call) in enumerate(SURFACES):
        tag = f"10.8.8.{100 + i}"
        if not gate_passes_60_then_429(surface, call, tag):
            all_gated = False
    check("all 11 surfaces: 60 pass, 61st raises the house 429", all_gated)

    # 2: per-surface isolation — saturate 'channels', 'channel-messages' still serves same IP
    ip2 = "10.8.9.1"
    for _ in range(60):
        rc.list_channels(req(ip2), limit=5)
    try:
        rc.read_channel(req(ip2), "belt-test", limit=5, before=None)
        iso = True
    except Exception:  # noqa: BLE001
        iso = False
    check("per-surface buckets isolated (saturated channels != channel-messages)", iso)

    # 3: fresh IP unaffected by another IP's saturation
    try:
        rc.list_channels(req("10.8.9.2"), limit=5)
        fresh = True
    except Exception:  # noqa: BLE001
        fresh = False
    check("fresh IP unaffected by saturation", fresh)

    # 4: belt runs before parsing — saturated + bad input raises 429, not 404
    ip4 = "10.8.10.1"
    for _ in range(60):
        rc.read_channel(req(ip4), "belt-test", limit=5, before=None)
    try:
        rc.read_channel(req(ip4), "no-such-channel-xyz", limit=5, before=None)
        before_parse_chan = False
    except Exception as e:  # noqa: BLE001
        before_parse_chan = is_429(e)
    check("saturated + bad channel name raises 429 (not 404)", before_parse_chan)

    ip5 = "10.8.10.2"
    for _ in range(60):
        rsp.channel_view(req(ip5), "belt-test")
    try:
        rsp.channel_view(req(ip5), "!!!not-a-channel!!!")
        before_parse_view = False
    except Exception as e:  # noqa: BLE001
        before_parse_view = is_429(e)
    check("saturated + bad view name raises 429 (not 404)", before_parse_view)

    # 5: shape unchanged on a fresh IP (the belt is a pure gate)
    ip6 = "10.8.11.1"
    ch = rc.list_channels(req(ip6), limit=5)
    shape1 = set(ch.keys()) == {"channels", "limit", "returned"} and ch["limit"] == 5
    msgs = rc.read_channel(req(ip6), "belt-test", limit=5, before=None)
    shape2 = set(msgs.keys()) == {"channel", "messages"} and msgs["channel"] == "belt-test"
    d = ra.node_directory(req(ip6), cap=None, limit=5)
    shape3 = set(d.keys()) == {"entries", "count", "limit", "cap"}
    landing_body = rsp.landing(req(ip6))
    shape4 = ("http://testserver" in landing_body and "{BASE}" not in landing_body
              and isinstance(landing_body, str))
    shape5 = set(rsp.tone_vocab_read(req(ip6)).keys()) == {"ok", "tone_tags"}
    sl = rsp.spaces_list(req(ip6), limit=5, offset=0)
    shape6 = set(sl.keys()) == {"ok", "spaces", "limit", "offset", "total"}
    check("shapes unchanged (channels, channel-messages, directory, landing, tone-tags, spaces-list)",
          shape1 and shape2 and shape3 and shape4 and shape5 and shape6)

    print(f"\n{PASS} passed, {FAIL} failed")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    run()
