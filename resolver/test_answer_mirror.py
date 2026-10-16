"""Fake-mirror unit tests for resolver/answer.py + core.resolve_cyberspace().

The mirror, the node, and the ping envelope are all faked in-process by
monkeypatching core._resolve_get_json — no network, no daemons. Signatures
are REAL Ed25519 (fed/ed25519.py, PyNaCl when present), so the six-step
verifier is exercised for real; only the transport is a fixture.

Four cases, per RESOLVER.md build order item 1:
  good binding -> A (NOERROR, one A answer, the fake node's loopback)
  bad signature -> NXDOMAIN (step 3 refuses the mirror's forgery)
  expired binding -> NXDOMAIN (step 4 reads the dead name as absent)
  silent mirror -> NXDOMAIN (step 2 hears nothing, answers nothing)

Run: cd ~/workspace/cybernet && ./venv/bin/python resolver/test_answer_mirror.py
"""

import os
import struct
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core  # noqa: E402
from fed import ed25519 as _ed  # noqa: E402
from fed import envelope as _env  # noqa: E402
from resolver import answer  # noqa: E402

LABEL = "vill"
MIRROR = "http://mirror.invalid"
NODE = "http://93.184.216.34:18799"   # global literal: the step-5 SSRF gate runs on fixtures too
NODE_URL = NODE + "/"               # the directory's form, trailing slash

CASES = {"passed": 0, "failed": 0}


def check(name, cond, extra=""):
    if cond:
        CASES["passed"] += 1
        print(f"  ok  {name}")
    else:
        CASES["failed"] += 1
        print(f"  FAIL {name} {extra}")


# --- key material: a real name keypair, a real ping envelope -------------

_name_seed = os.urandom(32)
_name_pub = _ed.publickey(_name_seed).hex()
_node_seed = os.urandom(32)
_node_pub = _ed.publickey(_node_seed).hex()


def _iso(dt):
    return dt.isoformat(timespec="seconds")


def _binding(issued_at, expires_at, key_hex=_name_pub, corrupt=False):
    sig = _ed.sign(
        core._name_claim_payload(LABEL, key_hex, issued_at, expires_at),
        _name_seed, bytes.fromhex(key_hex)).hex()
    if corrupt:
        sig = ("0" if sig[0] != "0" else "1") + sig[1:]
    return {"name": LABEL, "node_pubkey": key_hex, "issued_at": issued_at,
            "expires_at": expires_at, "signature": sig}


def _fake_get_json_factory(mode):
    """mode: 'good' | 'bad-sig' | 'expired' | 'silent'"""
    now = datetime.now(timezone.utc)
    issued = _iso(now - timedelta(days=1))
    live_exp = _iso(now + timedelta(days=6))
    dead_exp = _iso(now - timedelta(hours=2))

    if mode == "silent":
        binding = None
    elif mode == "bad-sig":
        binding = _binding(issued, live_exp, corrupt=True)
    elif mode == "expired":
        binding = _binding(issued, dead_exp)          # valid sig, dead name
    else:
        binding = _binding(issued, live_exp)

    ping = _env.make_envelope(_node_seed.hex(), _node_pub, "tester",
                              {"pong": True})

    def fake(url: str):
        if url == MIRROR + "/api/v1/names/" + LABEL:
            if binding is None:
                return None
            return dict(binding)
        if url == MIRROR + "/api/v1/directory?limit=200":
            return {"entries": [{"node_pub": _name_pub, "node_url": NODE_URL}]}
        if url == NODE + "/fed/ping":
            return ping
        if url == NODE + "/api/v1/names/" + LABEL:
            # the node answers for its name with the live binding
            return dict(_binding(issued, live_exp))
        return None
    return fake


def _query_packet(qname, qtype=1):
    """Minimal DNS query: one question, A record."""
    labels = b"".join(bytes([len(p)]) + p.encode() for p in qname.split("."))
    header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    return header + labels + b"\x00" + struct.pack(">HH", qtype, 1)


def _rcode(resp):
    return resp[3] & 0x0F


def _ancount(resp):
    return int.from_bytes(resp[6:8], "big")


def run(mode, qname, expect_rcode, expect_answers):
    real = core._resolve_get_json
    real_peer = core._resolve_peer_get_json
    fake = _fake_get_json_factory(mode)
    core._resolve_get_json = fake
    # Step 6's node fetches ride the dial-time-gated peer getter since
    # the rebind-guard tick; the same URL-keyed fake serves both.
    core._resolve_peer_get_json = fake
    # The verified-binding memo is process-global: clear it between modes
    # so each mode's fixture (same label+mirror, different binding) is
    # verified fresh. The memo's own hit/miss semantics are covered by
    # hidden_files/resolve-memo-test.py, not here.
    core._resolve_memo.clear()
    try:
        raw = _query_packet(qname)
        resp = answer.handle_query(raw, mirror_url=MIRROR,
                                   upstream=("8.8.8.8", 53))
    finally:
        core._resolve_get_json = real
        core._resolve_peer_get_json = real_peer
    check(f"{mode}: rcode == {expect_rcode}", _rcode(resp) == expect_rcode,
          f"got {_rcode(resp)}")
    check(f"{mode}: ancount == {expect_answers}",
          _ancount(resp) == expect_answers, f"got {_ancount(resp)}")
    if expect_answers:
        rdata = resp[-4:]
        check(f"{mode}: answer is the fixture 5db8d822", rdata == b"\x5d\xb8\xd8\x22",
              rdata.hex())


def run_bad_result_shapes():
    """A resolver return that is not a dict must read as NXDOMAIN,
    never raise AttributeError from handle_query's .get calls."""
    real = answer.resolve_cyberspace
    raw = _query_packet(LABEL + ".cyberspace")
    try:
        for bad in ("string-result", 123, 1.5, True, ["x"], (1, 2)):
            answer.resolve_cyberspace = lambda _n, _u, _b=bad: _b
            resp = answer.handle_query(raw, mirror_url=MIRROR,
                                       upstream=("8.8.8.8", 53))
            check(f"bad-result {type(bad).__name__}: rcode == 3",
                  _rcode(resp) == 3, f"got {_rcode(resp)}")
            check(f"bad-result {type(bad).__name__}: ancount == 0",
                  _ancount(resp) == 0, f"got {_ancount(resp)}")
        # Control: a well-formed dict with no usable node_url is the
        # ordinary NODATA path (name lives, family absent), untouched.
        answer.resolve_cyberspace = lambda _n, _u: {
            "node_url": "", "expires_at": ""}
        resp = answer.handle_query(raw, mirror_url=MIRROR,
                                   upstream=("8.8.8.8", 53))
        check("dict-result control: rcode == 0", _rcode(resp) == 0,
              f"got {_rcode(resp)}")
        check("dict-result control: ancount == 0", _ancount(resp) == 0,
              f"got {_ancount(resp)}")
    finally:
        answer.resolve_cyberspace = real


def run_redirect_refusal():
    """Real-transport seat: core._resolve_get_json must refuse a mirror
    redirect, not follow it. A local mirror 3xxs to a local foreign
    target; every code must read as None, the target must never be
    contacted, and a direct mirror 200 must still parse. Twin of the
    mint_name/rotate_name redirect belts."""
    import json as _json
    import threading as _threading
    from http.server import BaseHTTPRequestHandler as _H, HTTPServer as _S

    hits = []

    class _Target(_H):
        def do_GET(self):
            hits.append(self.path)
            body = _json.dumps({"foreign": True}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    target = _S(("127.0.0.1", 0), _Target)
    _threading.Thread(target=target.serve_forever, daemon=True).start()
    turl = f"http://127.0.0.1:{target.server_address[1]}"
    servers = [target]
    try:
        for code in (301, 302, 303, 307, 308):
            class _Mirror(_H):
                _code = code

                def do_GET(self):
                    self.send_response(self._code)
                    self.send_header("Location", turl + "/api/v1/names/x")
                    self.send_header("Content-Length", "0")
                    self.end_headers()

                def log_message(self, *a):
                    pass

            mirror = _S(("127.0.0.1", 0), _Mirror)
            servers.append(mirror)
            _threading.Thread(target=mirror.serve_forever, daemon=True).start()
            murl = f"http://127.0.0.1:{mirror.server_address[1]}"
            hits.clear()
            got = core._resolve_get_json(murl + "/api/v1/names/x")
            check(f"redirect {code}: reads as None", got is None,
                  f"got {got!r}")
            check(f"redirect {code}: target never contacted", not hits,
                  f"hits={hits!r}")
        check("direct mirror 200 still parses",
              core._resolve_get_json(turl + "/api/v1/names/x") == {"foreign": True})
        check("_NoRedirect.redirect_request is None",
              core._NoRedirect().redirect_request(
                  None, None, 302, "Found", {}, "http://127.0.0.1/") is None)
    finally:
        for srv in servers:
            srv.shutdown()


def main():
    print("fake-mirror unit tests (resolver/answer.py):")
    run_redirect_refusal()
    run_bad_result_shapes()
    run("good", LABEL + ".cyberspace", 0, 1)
    run("bad-sig", LABEL + ".cyberspace", 3, 0)
    run("expired", LABEL + ".cyberspace", 3, 0)
    run("silent", LABEL + ".cyberspace", 3, 0)
    # the lying-mirror bound: a mirror that forges nothing but lies by
    # signature can only withhold — already covered by bad-sig; a wrong
    # label is the client's own problem and stays out of our zone path.
    print(f"  {CASES['passed']} passed, {CASES['failed']} failed")
    sys.exit(1 if CASES["failed"] else 0)


if __name__ == "__main__":
    main()
