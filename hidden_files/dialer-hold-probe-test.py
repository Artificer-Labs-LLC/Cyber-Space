"""Dialer-side derive+hold_query belt test (docs/RENDEZVOUS.md, primitive 3).

Drives the REAL core._relay_hold_probe and core._relay_open_session with
a fake opener (no network): the request construction, point derivation,
and probe gating are all real.

Cases:
  probe queries E then E-1 (the pair the REAL rendezvous.derive_points
    computes for the name key), GET {relay}/relay/hold_query?point_id=
  held:true on E -> session opens BY THE POINT: POST to
    {relay}/relay/open with {\"name\",\"rendezvous_point\"} body (the
    dialer never sends the token on the rendezvous path), valid
    name-key sig -> True
  held:true on E-1 only -> opens by E-1 point (boundary tolerance)
  held:false on both -> False and NO /relay/open attempt (only the
    two hold_query GETs were seen; no session minted, no wait on
    silence)
  endpoint absent (404, relay predates hold_query) -> legacy session
    opens with {\"name\",\"token\"} (True with a valid sig) — new
    dialer never goes silent under an old relay
  transport failure on the query -> same legacy fallback
  bad name key (point not derivable) -> legacy fallback
  request shape: GETs are hold_query with the derived point ids;
    POST body is name+rendezvous_point on the rendezvous path,
    name+token only on the legacy path (no identity either way)

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/dialer-hold-probe-test.py
"""
import io
import json
import os
import sys
import tempfile

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


_name_seed = os.urandom(32)
_name_pub = _ed.publickey(_name_seed).hex()
RELAY_URL = "http://93.184.216.40:18799/"
RLABEL = "probbelt"

PAIR = rendezvous.derive_points(__import__("time").time(), _name_pub)
assert PAIR and len(PAIR) == 2, "fixture derivation failed"


class _FakeResp:
    def __init__(self, status, payload):
        self.status = status
        self._buf = io.BytesIO(json.dumps(payload).encode()
                               if not isinstance(payload, bytes) else payload)

    def read(self, n=-1):
        return self._buf.read(n)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _fake_factory(hold_e=None, hold_prev=None, endpoint=True,
                  query_fails=False, open_ok=True):
    """hold_e/hold_prev: what the hold_query endpoint answers per point.
    endpoint=False: the relay predates hold_query (404).
    query_fails: the transport raises on the query."""
    calls = []
    # The probe returns E first when it answers held; a held case opens
    # BY THE POINT (token never sent), a legacy case by token.
    held_point = PAIR[0] if hold_e else (PAIR[1] if hold_prev else None)

    def fake(target, timeout=8):
        method = target.get_method()
        url = target.full_url
        calls.append((method, url))
        if "/relay/hold_query" in url:
            if query_fails:
                raise ConnectionError("boom")
            if not endpoint:
                return _FakeResp(404, {})
            point = url.rsplit("point_id=", 1)[-1]
            held = None
            if point == PAIR[0]:
                held = hold_e
            elif point == PAIR[1]:
                held = hold_prev
            return _FakeResp(200, {"held": bool(held)})
        if url == RELAY_URL.rstrip("/") + "/relay/open":
            assert method == "POST"
            want = ({"name": RLABEL, "rendezvous_point": held_point}
                    if held_point
                    else {"name": RLABEL, "token": "tok-abc"})
            assert json.loads(target.data.decode()) == want, \
                "open body mismatch (no identity either way)"
            if not open_ok:
                return _FakeResp(500, {})
            chal = os.urandom(32).hex()
            sig = _ed.sign(bytes.fromhex(chal), _name_seed,
                           bytes.fromhex(_name_pub)).hex()
            return _FakeResp(200, {"challenge": chal, "name_key_sig": sig})
        raise AssertionError("unexpected url " + url)

    return fake, calls


def _run(name_key, factory):
    real = core._peer_opener.open
    fake, calls = factory
    core._peer_opener.open = fake
    try:
        got = core._relay_open_session(RELAY_URL, RLABEL, name_key, "tok-abc")
    finally:
        core._peer_opener.open = real
    return got, calls


def _opens(calls):
    return [u for (m, u) in calls if m == "POST" and "/relay/open" in u]


def main():
    print("derive + query:")
    got, calls = _run(_name_pub, _fake_factory(hold_e=True))
    queries = [u for (m, u) in calls if m == "GET"]
    check("probe queries E point first",
          len(queries) >= 1 and queries[0].endswith("point_id=" + PAIR[0]),
          queries)
    check("held:true on E -> session opens",
          got is True and len(_opens(calls)) == 1, (got, calls))

    print("silence on nobody-holds:")
    got, calls = _run(_name_pub, _fake_factory(hold_e=False, hold_prev=False))
    queries = [u for (m, u) in calls if m == "GET"]
    check("both points queried, E-1 queried after a false E",
          len(queries) == 2 and queries[1].endswith("point_id=" + PAIR[1]),
          queries)
    check("nobody holds -> False, no /relay/open minted",
          got is False and not _opens(calls), (got, calls))

    print("legacy fallbacks:")
    got, calls = _run(_name_pub, _fake_factory(hold_e=False,
                                               hold_prev=True))
    check("held:true on E-1 only -> session opens",
          got is True and len(_opens(calls)) == 1, (got, calls))

    got, calls = _run(_name_pub, _fake_factory(endpoint=False))
    check("old relay (404 on hold_query) -> legacy open",
          got is True and len(_opens(calls)) == 1, (got, calls))

    got, calls = _run(_name_pub, _fake_factory(query_fails=True))
    check("query transport failure -> legacy open",
          got is True and len(_opens(calls)) == 1, (got, calls))

    got, calls = _run("zz", _fake_factory(hold_e=False, hold_prev=False))
    queries = [u for (m, u) in calls if m == "GET"]
    check("bad name key: probe derives nothing, no query attempted, "
          "legacy open fails its own sig check -> False",
          got is False and not queries, (got, calls))

    got, calls = _run(_name_pub, _fake_factory(hold_e=True, open_ok=False))
    check("held but /relay/open 500s -> False",
          got is False, (got, calls))

    print(f"\n{CASES['passed']} passed, {CASES['failed']} failed")
    sys.exit(1 if CASES["failed"] else 0)


if __name__ == "__main__":
    main()
