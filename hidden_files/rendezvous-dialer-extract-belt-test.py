"""Rendezvous dialer extraction belt (docs/RENDEZVOUS.md, primitive 3).

The existing dialer-hold-probe belt covers transport behavior. This belt
audits the layer beneath it, which no belt has touched: the extraction of
the rendezvous strategy from a (caller-verified) reach descriptor, and the
probe's failure semantics under hostile or degenerate inputs.

Drives the REAL core._rendezvous_strategy and core._relay_hold_probe with
a monkeypatched core._resolve_peer_get_json (no network): the validation,
derivation, and URL-join logic are all real.

Cases:
  extraction: well-formed member accepted (epoch_len + hold_query pass
    through verbatim); hostile hold_query variants (missing leading
    slash, embedded "?", embedded "#", >256 chars, non-string) each
    skipped so the member reads as absent; out-of-bound epoch_len
    (59, 86401, "600", 600.5, True) skipped; boundary 60/86400
    accepted; wrong kind / reach-not-a-list / desc-not-a-dict /
    missing reach -> None; first member malformed + second well-formed
    -> the well-formed one wins (hoster-preference order preserved).
  probe: E held:false + E-1 held:false -> False (silence: no session
    minted, the probe's whole point); E held:true -> returns the E
    point and the transport sees exactly ONE query (stops at first
    willing); E held:false + E-1 held:true -> E-1 point (boundary
    tolerance); both transport failures -> None (legacy open, never
    silent under failure); E held:false + E-1 transport failure -> None
    (a half-answer is an unanswerable query, not a nobody-holds);
    held as the string "true" -> not True -> silence (never stringly
    typed); malformed name key -> None (no raise, legacy open);
    hostile hold_query passed directly to the probe -> fail-closed to
    the wired /relay/hold_query (defense in depth; the extractor
    already refused it); URL join: relay with trailing slash and with
    a subpath both land on {relay}/relay/hold_query?point_id={64hex},
    and the point id is opaque (never the name pubkey).
  caller composition: extraction None -> the step-6 caller's
    (via_rendezvous or {}).get(...) defaults read 3600 + the wired
    path (unchanged default behavior), not garbage.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/rendezvous-dialer-extract-belt-test.py
"""
import os
import sys
import tempfile
import time

tmp = tempfile.mkdtemp()
os.environ["CYBERNET_DB_DIR"] = tmp
sys.path.insert(0, os.path.expanduser("~/workspace/cybernet"))

import core  # noqa: E402
import rendezvous  # noqa: E402
from fed import ed25519 as _ed  # noqa: E402

CASES = {"passed": 0, "failed": 0}


def check(name, cond, extra=""):
    if cond:
        CASES["passed"] += 1
        print(f"  ok  {name}")
    else:
        CASES["failed"] += 1
        print(f"  FAIL {name} {extra}")


_name_pub = _ed.publickey(os.urandom(32)).hex()
RELAY = "http://93.184.216.40:18799/"
WQ = "/relay/hold_query"


def _member(**kw):
    m = {"kind": "rendezvous", "epoch_len": 600, "hold_query": WQ}
    m.update(kw)
    return m


def _desc(*members):
    return {"reach": list(members)}


# ---- extraction ----
s = core._rendezvous_strategy(_desc(_member()))
check("extract well-formed verbatim",
      s == {"epoch_len": 600, "hold_query": WQ}, repr(s))

for i, bad in enumerate(["relay/hold_query", "/relay/hold_query?x=1",
                         "/relay/hold_query#frag", "/" + "x" * 256,
                         42, None, [WQ]]):
    s = core._rendezvous_strategy(_desc(_member(hold_query=bad)))
    check(f"extract hostile hold_query[{i}] skipped -> None", s is None,
          repr(s))

for i, bad in enumerate([59, 86401, -1, "600", 600.5, True, None, [600]]):
    s = core._rendezvous_strategy(_desc(_member(epoch_len=bad)))
    check(f"extract bad epoch_len[{i}] skipped -> None", s is None, repr(s))

for good in (60, 86400):
    s = core._rendezvous_strategy(_desc(_member(epoch_len=good)))
    check(f"extract epoch_len boundary {good} accepted",
          s == {"epoch_len": good, "hold_query": WQ}, repr(s))

check("extract wrong kind -> None",
      core._rendezvous_strategy(_desc({"kind": "relay"})) is None)
check("extract reach not list -> None",
      core._rendezvous_strategy({"reach": "nope"}) is None)
check("extract desc not dict -> None",
      core._rendezvous_strategy(["nope"]) is None)
check("extract missing reach -> None",
      core._rendezvous_strategy({}) is None)
check("extract empty reach -> None",
      core._rendezvous_strategy({"reach": []}) is None)
check("extract non-dict member tolerated, None when nothing well-formed",
      core._rendezvous_strategy({"reach": ["x", 7, None]}) is None)

s = core._rendezvous_strategy(_desc(
    _member(hold_query="/evil?x=1"), _member(epoch_len=3600)))
check("extract first-malformed second-wins (preference order)",
      s == {"epoch_len": 3600, "hold_query": WQ}, repr(s))

# caller composition with extraction None -> frozen defaults
check("extract None composes to 3600 + wired path at the caller",
      (None or {}).get("epoch_len", rendezvous.EPOCH_LEN_DEFAULT) == 3600
      and (None or {}).get("hold_query", core._RENDEZVOUS_HOLD_QUERY) == WQ)

# ---- probe: failure semantics with a fake transport ----
PAIR = rendezvous.derive_points(time.time(), _name_pub, 600)
assert PAIR and len(PAIR) == 2, "fixture derivation failed"

calls = []
_behavior = {"e": None, "prev": None, "raise": False}


def _fake(url):
    calls.append(url)
    if _behavior["raise"]:
        # _resolve_peer_get_json's real contract: any network error ->
        # None, never a raise.
        return None
    point = url.rsplit("point_id=", 1)[-1]
    if point == PAIR[0]:
        return {"held": _behavior["e"]}
    if point == PAIR[1]:
        return {"held": _behavior["prev"]}
    return {"held": False}


_real = core._resolve_peer_get_json
core._resolve_peer_get_json = _fake


def _reset(e=None, prev=None, fail=False, epoch_len=600):
    global PAIR
    # Re-derive right before each probe WITH THE SAME epoch_len the
    # probe runs under: the probe derives its own pair from
    # time.time() at call time, so the fixture must sit in the same
    # epoch of the same length (no boundary-roll mismatch between
    # fixture and probe).
    PAIR = rendezvous.derive_points(time.time(), _name_pub, epoch_len)
    assert PAIR and len(PAIR) == 2, "fixture derivation failed"
    calls.clear()
    _behavior.update({"e": e, "prev": prev, "raise": fail})


def _is_point_hex(v):
    return (isinstance(v, str) and len(v) == 64
            and all(c in "0123456789abcdef" for c in v))


_reset(e=False, prev=False)
r = core._relay_hold_probe(RELAY, _name_pub, 600)
check("probe both held:false -> False (silence, no session)",
      r is False, repr(r))
check("probe silence queried exactly E then E-1", len(calls) == 2, repr(calls))

_reset(e=True, prev=False)
r = core._relay_hold_probe(RELAY, _name_pub, 600)
check("probe E held -> returns E point id",
      r == PAIR[0] and _is_point_hex(r), repr(r))
check("probe stops at first willing (one query)", len(calls) == 1, repr(calls))

_reset(e=False, prev=True)
r = core._relay_hold_probe(RELAY, _name_pub, 600)
check("probe E-1 held -> returns E-1 point (boundary tolerance)",
      r == PAIR[1] and _is_point_hex(r), repr(r))

_reset(fail=True)
r = core._relay_hold_probe(RELAY, _name_pub, 600)
check("probe transport failure -> None (legacy open, never silent)",
      r is None, repr(r))

# half-answer: E answered held:false, E-1 transport-fails -> unknown
calls.clear()


def _fake_half(url):
    calls.append(url)
    point = url.rsplit("point_id=", 1)[-1]
    if point == PAIR[0]:
        return {"held": False}
    # transport failure on E-1: the real _resolve_peer_get_json
    # contract is None-on-error, never a raise.
    return None


core._resolve_peer_get_json = _fake_half
r = core._relay_hold_probe(RELAY, _name_pub, 600)
check("probe E false + E-1 transport fail -> None (half-answer=unknown)",
      r is None, repr(r))
core._resolve_peer_get_json = _fake

_reset(e="true", prev="nope")
r = core._relay_hold_probe(RELAY, _name_pub, 600)
check("probe stringy held values -> False (never stringly typed)",
      r is False, repr(r))

r = core._relay_hold_probe(RELAY, "not-a-key", 600)
check("probe malformed name key -> None (no raise, legacy open)",
      r is None, repr(r))

# hostile hold_query direct to the probe: fail-closed to the wired path
calls.clear()
_behavior.update({"e": False, "prev": False, "raise": False})
r = core._relay_hold_probe(RELAY, _name_pub, 600, "/evil?x=1")
check("probe hostile hold_query arg fail-closed to wired path",
      r is False and all("/relay/hold_query?point_id=" in u for u in calls)
      and not any("evil" in u for u in calls), repr(calls))

# URL join: trailing slash and subpath
for relay, want_base in (
        ("http://93.184.216.40:18799/", "http://93.184.216.40:18799"),
        ("http://93.184.216.40:18799/sub", "http://93.184.216.40:18799/sub")):
    calls.clear()
    r = core._relay_hold_probe(relay, _name_pub, 600)
    ok = (r is False and len(calls) == 2
          and all(u.startswith(want_base + WQ + "?point_id=") for u in calls))
    check(f"probe URL join under {relay!r}", ok, repr(calls))

# the point ids are opaque: never the name key, never the token
calls.clear()
_reset(e=True)
core._relay_hold_probe(RELAY, _name_pub, 600)
check("probe point ids opaque (not the name pubkey)",
      all(_name_pub not in u for u in calls) and PAIR[0] != _name_pub,
      repr(calls))

core._resolve_peer_get_json = _real

print(f"\n{CASES['passed']} passed, {CASES['failed']} failed")
sys.exit(1 if CASES["failed"] else 0)
