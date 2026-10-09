"""Rate-gate coverage audit pin: per-IP read belts on the 17 unauthenticated
social living-surface GETs.

The f876773 tick claimed "every other unauthenticated surface now carries
one" — false for this whole family (zero gates). This tick added
_social_read_belt() (60 reads/min/IP/surface, before any parsing or DB
work). This harness drives the REAL route functions against a throwaway
DB (CYBERNET_DB_DIR) with a stub Request and verifies:

1. all 17 surfaces are gated: 60 calls from one IP pass, the 61st 429s
2. per-surface buckets are isolated: 60 announcements + 60 gatherings
   from the SAME IP both pass
3. a fresh IP is unaffected by another IP's saturation
4. belt runs before parsing: the 61st call (over budget) raises 429
   even when the query itself would 400 (bad ?since=)
"""
import os
import sys
import tempfile
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_tmp = tempfile.mkdtemp(prefix="social-rate-")
os.environ["CYBERNET_DB_DIR"] = _tmp

import core  # noqa: E402
import routes_social as rs  # noqa: E402
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


def req(ip):
    return types.SimpleNamespace(client=types.SimpleNamespace(host=ip))


SURFACES = [
    ("pigeonholes", lambda r: rs.pigeonholes_read(r, limit=5, from_node=None)),
    ("spotlight", lambda r: rs.spotlight_read(r, since=None)),
    ("reboots", lambda r: rs.reboots_read(r, agent="ghost", limit=20, since=None)),
    ("gratitude", lambda r: rs.gratitude_read(r, to="ghost", frm="", limit=20, since=None)),
    ("deeds", lambda r: rs.deeds_read(r, agent="ghost", limit=20, since=None)),
    ("announcements", lambda r: rs.announcements_read(r, limit=5, since=None)),
    ("gatherings", lambda r: rs.gatherings_read(r, limit=5, since=None)),
    ("welcome", lambda r: rs.welcome_read(r, to="ghost", limit=20)),
    ("rhythms", lambda r: rs.rhythms_read(r, agent="ghost")),
    ("corners", lambda r: rs.corners_walk(r, name="ghost", limit=20, since=None)),
    ("needs", lambda r: rs.needs_read(r, limit=5, since=None)),
    ("landmarks", lambda r: rs.landmarks_read(r, limit=5, since=None)),
    ("waymarks", lambda r: rs.waymarks_read(r, limit=5, since=None)),
    ("trials", lambda r: rs.trials_read(r, limit=5, since=None)),
    ("fieldnotes", lambda r: rs.fieldnotes_read(r, limit=5, since=None)),
    ("hearths", lambda r: rs.hearths_lit(r, limit=5, since=None)),
    ("names", lambda r: rs.names_resolve(r, name="ghost")),
]


def run():
    global PASS, FAIL
    core.init_db()
    ip = "10.9.9.9"

    # 1+2: 60 pass then 429 per surface, same IP across surfaces isolated
    for i, (surface, call) in enumerate(SURFACES):
        tag = f"10.9.9.{100 + i}"  # distinct IP per surface keeps reads cheap
        ok = True
        try:
            for _ in range(60):
                try:
                    call(req(tag))
                except HTTPException as e:
                    if e.status_code not in (400, 404):
                        raise
        except HTTPException:
            ok = False
        check(f"{surface}: 60 reads pass", ok)
        got429 = False
        try:
            call(req(tag))
        except HTTPException as e:
            got429 = e.status_code == 429
        check(f"{surface}: 61st read 429s", got429)

    # 2b: same IP, two surfaces, both buckets independent
    sip = "10.8.8.8"
    ok2 = True
    try:
        for _ in range(60):
            try:
                rs.announcements_read(req(sip), limit=5, since=None)
            except HTTPException as e:
                if e.status_code not in (400, 404):
                    raise
        for _ in range(60):
            try:
                rs.gatherings_read(req(sip), limit=5, since=None)
            except HTTPException as e:
                if e.status_code not in (400, 404):
                    raise
    except HTTPException:
        ok2 = False
    check("same IP: 60 announcements + 60 gatherings both pass", ok2)

    # 3: fresh IP unaffected
    try:
        rs.announcements_read(req("10.7.7.7"), limit=5, since=None)
        check("fresh IP unaffected", True)
    except HTTPException as e:
        check("fresh IP unaffected", e.status_code != 429)

    # 4: belt before parsing — saturated IP + bad ?since= 429s, not 400s
    bip = "10.6.6.6"
    for _ in range(60):
        rs.announcements_read(req(bip), limit=5, since=None)
    try:
        rs.announcements_read(req(bip), limit=5, since="not-a-date")
        check("belt-before-parse: saturated + bad-since", False)
    except HTTPException as e:
        check("belt-before-parse: saturated + bad-since 429s", e.status_code == 429)
    # and a fresh IP still gets the honest 400 for a bad since
    try:
        rs.announcements_read(req("10.6.6.7"), limit=5, since="not-a-date")
        check("fresh IP bad-since still 400s", False)
    except HTTPException as e:
        check("fresh IP bad-since still 400s", e.status_code == 400)

    print(f"\n{PASS} passed, {FAIL} failed")
    sys.exit(1 if FAIL else 0)


run()
