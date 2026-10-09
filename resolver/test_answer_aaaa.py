"""AAAA / NODATA unit tests for resolver/answer.py's address selection.

Covers the slice-2 harness results that were never committed as a file:

  AAAA for a v4-only node's binding  -> NOERROR, zero answers (NODATA)
  AAAA for a v6 node's binding       -> NOERROR, one 16-byte answer
  A    for a v6-only node's binding  -> NOERROR, zero answers (NODATA)
  _family_addresses dedupe           -> duplicate getaddrinfo rows collapse to one

The mirror, node, and ping envelope are faked in-process (like
test_answer_mirror.py); signatures are real Ed25519 so the six-step
verifier is exercised for real. The v6 loopback [::1] resolves via
getaddrinfo with no network — if it ever stops resolving, the test
says so instead of guessing.

Run: cd ~/workspace/cybernet && ./venv/bin/python resolver/test_answer_aaaa.py
"""

import os
import socket
import struct
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core  # noqa: E402
from fed import ed25519 as _ed  # noqa: E402
from fed import envelope as _env  # noqa: E402
from resolver import answer  # noqa: E402

LABEL = "faraday"
MIRROR = "http://mirror.invalid"
NODE_V4 = "http://93.184.216.34:18799"  # global literal: step-5 SSRF gate runs on fixtures too
NODE_V6 = "http://[2606:4700:4700::1111]:18799"  # global v6 literal, same reason

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
_node_seed = os.urandom(32)
_node_pub = _ed.publickey(_node_seed).hex()


def _iso(dt):
    return dt.isoformat(timespec="seconds")


def _binding(issued_at, expires_at):
    sig = _ed.sign(
        core._name_claim_payload(LABEL, _name_pub, issued_at, expires_at),
        _name_seed, bytes.fromhex(_name_pub)).hex()
    return {"name": LABEL, "node_pubkey": _name_pub, "issued_at": issued_at,
            "expires_at": expires_at, "signature": sig}


def _fake_get_json(node_url):
    """Fake transport for a node whose registry entry points at node_url."""
    now = datetime.now(timezone.utc)
    binding = _binding(_iso(now - timedelta(days=1)),
                       _iso(now + timedelta(days=6)))
    ping = _env.make_envelope(_node_seed.hex(), _node_pub, "tester",
                              {"pong": True})

    def fake(url: str):
        if url == MIRROR + "/api/v1/names/" + LABEL:
            return dict(binding)
        if url == MIRROR + "/api/v1/directory?limit=200":
            return {"entries": [{"node_pub": _name_pub,
                                 "node_url": node_url + "/"}]}
        if url == node_url + "/fed/ping":
            return ping
        if url == node_url + "/api/v1/names/" + LABEL:
            return dict(binding)
        return None
    return fake


def _query_packet(qname, qtype):
    labels = b"".join(bytes([len(p)]) + p.encode() for p in qname.split("."))
    header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    return header + labels + b"\x00" + struct.pack(">HH", qtype, 1)


def _rcode(resp):
    return resp[3] & 0x0F


def _ancount(resp):
    return int.from_bytes(resp[6:8], "big")


def run(node_url, qtype, expect_rcode, expect_ancount, label):
    real = core._resolve_get_json
    real_peer = core._resolve_peer_get_json
    fake = _fake_get_json(node_url)
    core._resolve_get_json = fake
    # Step 6's node fetches ride the dial-time-gated peer getter since
    # the rebind-guard tick; the same URL-keyed fake serves both.
    core._resolve_peer_get_json = fake
    # The verified-binding memo is process-global: clear it between modes
    # so each mode's fixture (same label+mirror, different node URL)
    # verifies fresh. Memo hit/miss semantics live in
    # hidden_files/resolve-memo-test.py.
    core._resolve_memo.clear()
    try:
        resp = answer.handle_query(_query_packet(LABEL + ".cyberspace", qtype),
                                   mirror_url=MIRROR, upstream=("1.1.1.1", 53))
        check(f"{label}: rcode {expect_rcode}", _rcode(resp) == expect_rcode,
              f"got {_rcode(resp)}")
        check(f"{label}: ancount {expect_ancount}",
              _ancount(resp) == expect_ancount, f"got {_ancount(resp)}")
    finally:
        core._resolve_get_json = real
        core._resolve_peer_get_json = real_peer


def rdata_len(resp):
    """Byte length of the first answer's rdata, or None if no answers."""
    if _ancount(resp) == 0:
        return None
    # Walk past the question section to the answer.
    off = 12
    while resp[off] != 0:
        off += 1 + resp[off]
    off += 1 + 4  # root label + qtype/qclass
    rdlen = int.from_bytes(resp[off + 10:off + 12], "big")
    return rdlen


def main():
    # 1. AAAA against a v4-only binding -> NODATA (name exists, family doesn't)
    run(NODE_V4, 28, 0, 0, "AAAA on v4-only node")

    # 2. AAAA against a v6 binding -> one 16-byte answer
    run(NODE_V6, 28, 0, 1, "AAAA on v6 node")

    # 3. A against a v6-only binding -> NODATA
    run(NODE_V6, 1, 0, 0, "A on v6-only node")

    # 4. A against a v4 binding still answers (regression anchor for this file)
    real = core._resolve_get_json
    real_peer = core._resolve_peer_get_json
    core._resolve_get_json = core._resolve_peer_get_json = _fake_get_json(NODE_V4)
    core._resolve_memo.clear()  # fixture isolation, see run() above
    try:
        resp = answer.handle_query(_query_packet(LABEL + ".cyberspace", 1),
                                   mirror_url=MIRROR, upstream=("1.1.1.1", 53))
        check("A on v4 node: rdata is 4 bytes", rdata_len(resp) == 4)
    finally:
        core._resolve_get_json = real
        core._resolve_peer_get_json = real_peer

    # 5. v6 answer's rdata is 16 bytes
    core._resolve_get_json = core._resolve_peer_get_json = _fake_get_json(NODE_V6)
    core._resolve_memo.clear()  # fixture isolation, see run() above
    try:
        resp = answer.handle_query(_query_packet(LABEL + ".cyberspace", 28),
                                   mirror_url=MIRROR, upstream=("1.1.1.1", 53))
        check("AAAA on v6 node: rdata is 16 bytes", rdata_len(resp) == 16)
    finally:
        core._resolve_get_json = real
        core._resolve_peer_get_json = real_peer

    # 6. _family_addresses dedupes duplicate getaddrinfo rows
    real_gai = socket.getaddrinfo

    def dup_gai(*args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "",
                 ("127.0.0.1", 0)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "",
                 ("127.0.0.1", 0)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "",
                 ("127.0.0.2", 0))]
    socket.getaddrinfo = dup_gai
    try:
        addrs = answer._family_addresses("http://127.0.0.1:18799", 1)
        check("dedupe: 3 rows -> 2 addrs", len(addrs) == 2,
              f"got {len(addrs)}")
        check("dedupe: order kept, .1 first",
              addrs[0] == socket.inet_pton(socket.AF_INET, "127.0.0.1"))
    finally:
        socket.getaddrinfo = real_gai

    # 7. _family_addresses returns [] on junk URLs (never guesses)
    check("junk url: []", answer._family_addresses("not a url", 1) == [])
    check("empty host: []",
          answer._family_addresses("http:///no-host", 28) == [])

    print(f"\n{CASES['passed']} passed, {CASES['failed']} failed")
    sys.exit(1 if CASES["failed"] else 0)


if __name__ == "__main__":
    main()
