"""DoH wire-agreement belt — the DoH bridge vs handle_query, byte for byte.

routes_doh.py is the DNS-over-HTTPS face of the same resolver the UDP/TCP
daemon serves. Its whole contract is: transport changes, bytes do not.
This belt drives the REAL POST /dns-query and GET /dns-query routes of the
REAL app (scratch DB, loopback uvicorn) and asserts, for every DNS reply
class, that the HTTP reply is BYTE-IDENTICAL to handle_query() called
directly on the same wire bytes — and that the AA bit the extension
(resolver.js) hard-requires is set on every one of them.

  1. POST wiretest.cyberspace A     -> 200 dns-message, NOERROR + A, == direct
  2. POST wiretest.cyberspace AAAA  -> NODATA (v4-only node), AA, == direct
  3. POST wiretest.cyberspace MX    -> NODATA (unhandled qtype), AA, == direct
  4. POST zz-junk.cyberspace A      -> NXDOMAIN, zero answers, AA, == direct
  5. POST garbage frame             -> SERVFAIL (txid echo), AA, == direct
  6. GET ?dns=<b64url A query>      -> same bytes as the POST (case 1)
  7. POST wrong content-type        -> 415
  8. POST empty body                -> 400
  9. POST oversize body             -> 413
 10. GET with no ?dns=              -> 400

TTL stability note: case 1's answer TTL is min(expires_at, 300); the test
binding's expiry is years out, so TTL is a flat 300 and the byte comparison
cannot flake on a second boundary.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/doh-wire-agreement-belt-test.py
"""

import base64
import os
import random
import struct
import sys
import tempfile
import threading
import time
import urllib.request
import urllib.error

HOME = tempfile.mkdtemp(prefix="doh-home-")
os.environ["HOME"] = HOME                      # mint_name writes under ~/.cyberspace
os.environ["CYBERNET_DB_DIR"] = tempfile.mkdtemp(prefix="doh-db-")

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, REPO)

import uvicorn  # noqa: E402
from app import app  # noqa: E402
import core  # noqa: E402
import mint_name  # noqa: E402
import routes_doh  # noqa: E402
from resolver import host  # noqa: E402
from resolver.answer import handle_query  # noqa: E402

PORT = 18381
MIRROR = f"http://127.0.0.1:{PORT}"
DOH = MIRROR + "/dns-query"

# the test-only SSRF allowance: the 127.0.0.1 test mirror/node only
_real_gate = core._reject_nonpublic_node_url


def _test_gate(url):
    if url.startswith(MIRROR):
        return "127.0.0.1"
    return _real_gate(url)


core._reject_nonpublic_node_url = _test_gate
routes_doh.MIRROR_URL = MIRROR  # _answer_wire reads the module global per call

server = uvicorn.Server(
    uvicorn.Config(app, host="127.0.0.1", port=PORT, log_level="error")
)
t = threading.Thread(target=server.run, daemon=True)
t.start()
for _ in range(100):
    try:
        urllib.request.urlopen(MIRROR + "/api/v1/node", timeout=1)
        break
    except Exception:
        time.sleep(0.1)
else:
    sys.exit("test node never came up")

passed = failed = 0


def check(name, cond, extra=""):
    global passed, failed
    if cond:
        passed += 1
        print(f"  ok  {name}")
    else:
        failed += 1
        print(f"  FAIL {name} {extra}")


LABEL = "wiretest"
os.environ["CYBERNET_PUBLIC_URL"] = MIRROR  # honest reach for the announce
rc = mint_name.main([LABEL, MIRROR, "--env-dir", tempfile.mkdtemp(prefix="doh-env-")])
check("mint wiretest name on the real claim endpoint", rc == 0, f"rc={rc}")
if rc != 0:
    print(f"{passed} passed, {failed} failed")
    sys.exit(1)

key_path = os.path.join(HOME, ".cyberspace", f"{LABEL}-name.key")
with open(key_path) as f:
    name_priv = f.read().strip()
announced = host.announce_once(MIRROR, LABEL, name_priv)
check("name-key reach announce accepted by the mirror", announced)


def _build_query(name, qtype):
    txid = random.getrandbits(16)
    hdr = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    qname = b"".join(
        bytes([len(p)]) + p.encode("ascii") for p in name.split(".")
    ) + b"\x00"
    return txid, hdr + qname + struct.pack(">HH", qtype, 1)


def _doh_post(pkt, ctype="application/dns-message"):
    req = urllib.request.Request(
        DOH, data=pkt,
        headers={"Content-Type": ctype},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def _doh_get(pkt=None):
    qs = "" if pkt is None else base64.urlsafe_b64encode(pkt).decode().rstrip("=")
    try:
        with urllib.request.urlopen(DOH + "?dns=" + qs, timeout=30) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def _wire(pkt):
    return handle_query(pkt, mirror_url=MIRROR, upstream=("1.1.1.1", 53),
                        ttl_cap=300)


def _decode(resp, txid):
    rtxid, flags, _qd, an, _ns, _ar = struct.unpack(">HHHHHH", resp[:12])
    return rtxid, flags & 0x000F, an, txid, bool(flags & 0x0400)


def _aa(name, is_aa, extra=""):
    check(f"{name} — AA bit set (extension contract)", is_aa, extra)


def case(name, qname, qtype, want_rcode, want_min_an=0, want_an=0):
    txid, pkt = _build_query(qname, qtype)
    status, headers, body = _doh_post(pkt)
    direct = _wire(pkt)
    ctype = next((v for k, v in headers.items() if k.lower() == "content-type"), "")
    rtxid, rcode, an, _e, aa = _decode(body, txid) if status == 200 and len(body) >= 12 else (None, None, None, None, False)
    ok = (status == 200
          and ctype == "application/dns-message"
          and rtxid == txid and rcode == want_rcode
          and (an >= want_min_an) and (want_an == 0 or an == want_an))
    check(f"{name} -> rcode {want_rcode}, txid echo, dns-message",
          ok, f"status={status} rcode={rcode} an={an}")
    check(f"{name} -> DoH bytes identical to handle_query",
          status == 200 and body == direct,
          f"len http={len(body)} len direct={len(direct)}")
    _aa(name, aa, f"rcode={rcode}")


def guarded(fn, label):
    try:
        fn()
    except Exception as exc:
        check(label, False, f"raised {exc!r}")


guarded(lambda: case("DoH POST wiretest.cyberspace A", f"{LABEL}.cyberspace", 1, 0, want_min_an=1),
        "DoH POST A")
guarded(lambda: case("DoH POST wiretest.cyberspace AAAA", f"{LABEL}.cyberspace", 28, 0, want_an=0),
        "DoH POST AAAA")
guarded(lambda: case("DoH POST wiretest.cyberspace MX", f"{LABEL}.cyberspace", 15, 0, want_an=0),
        "DoH POST MX")
junk = "zz-" + "".join(random.choice("abcdefghij") for _ in range(10))
guarded(lambda: case(f"DoH POST {junk}.cyberspace A", f"{junk}.cyberspace", 1, 3, want_an=0),
        "DoH POST NXDOMAIN")


def case_garbage():
    pkt = b"\x12\x34junk-bytes-not-dns"
    status, _h, body = _doh_post(pkt)
    rtxid, flags = struct.unpack(">HH", body[:4])
    check("DoH POST garbage frame -> SERVFAIL wire reply (not an HTTP error)",
          status == 200 and rtxid == 0x1234 and (flags & 0x000F) == 2,
          f"status={status} txid={rtxid:#x}")
    check("garbage SERVFAIL -> DoH bytes identical to handle_query",
          body == _wire(pkt), f"len http={len(body)} len direct={len(_wire(pkt))}")
    _aa("garbage-frame SERVFAIL", bool(flags & 0x0400), f"txid={rtxid:#x}")


guarded(case_garbage, "DoH POST garbage")


def case_get():
    txid, pkt = _build_query(f"{LABEL}.cyberspace", 1)  # one txid for both
    status, _h, body = _doh_get(pkt)
    status2, _h2, body2 = _doh_post(pkt)
    check("DoH GET ?dns= -> 200 with the same wire bytes as POST",
          status == 200 and body == body2,
          f"get={status} len={len(body)} post={status2} len={len(body2)}")


guarded(case_get, "DoH GET ?dns=")


def case_hygiene():
    txid, pkt = _build_query(f"{LABEL}.cyberspace", 1)
    s, _h, _b = _doh_post(pkt, ctype="text/plain")
    check("DoH POST wrong content-type -> 415", s == 415, f"status={s}")
    s, _h, _b = _doh_post(b"")
    check("DoH POST empty body -> 400", s == 400, f"status={s}")
    s, _h, _b = _doh_post(b"\x00" * 5000)
    check("DoH POST oversize body -> 413", s == 413, f"status={s}")
    s, _h, _b = _doh_get(None)
    check("DoH GET with no ?dns= -> 400", s == 400, f"status={s}")


guarded(case_hygiene, "DoH hygiene")

print(f"{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
