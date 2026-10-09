"""Unit tests for resolver/dns.py — the stdlib DNS codec.

This freezes the slice-1 codec harness (committed as prose in the
19:20 tick): every path the harness walked, now a file, so a later edit
cannot silently reopen the codec. No network, no daemons — packets are
built and parsed in-process.

The two stumbles the harness itself caught are fixtures here:
  - the pointer-precedence bug: (length & 0xC0) == 0xC0 must hold, i.e. a
    0xC0 lead byte is a POINTER, not a label; with the old buggy check
    ("&" binding tighter than "==") the pointer test below raises.
  - the wrong label-length fixture: a label whose declared length runs
    past the packet must raise ValueError — the codec refuses, never
    guesses.

Run: cd ~/workspace/cybernet && ./venv/bin/python resolver/test_dns.py
"""

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from resolver import dns  # noqa: E402

CASES = {"passed": 0, "failed": 0}


def check(name, cond, extra=""):
    if cond:
        CASES["passed"] += 1
        print(f"  ok  {name}")
    else:
        CASES["failed"] += 1
        print(f"  FAIL {name} {extra}")


def raises_valueerror(fn, *args):
    try:
        fn(*args)
    except ValueError:
        return True
    except Exception:
        return False
    return False


def _query(qname_labels, qtype=1, flags=0x0100, qdcount=1, tail=b""):
    """Build a query packet; labels is a list of raw label byte-chunks."""
    labels = b"".join(bytes([len(p)]) + p for p in qname_labels)
    header = struct.pack(">HHHHHH", 0x1234, flags, qdcount, 0, 0, 0)
    if tail:
        return header + labels + tail
    return header + labels + b"\x00" + struct.pack(">HH", qtype, 1)


# --- parse_query: the happy path ----------------------------------------

GOOD_A = _query([b"vill", b"cyberspace"])
q = dns.parse_query(GOOD_A)
check("parse: good A query id", q["id"] == 0x1234)
check("parse: good A query qname", q["qname"] == "vill.cyberspace", q["qname"])
check("parse: good A query qtype", q["qtype"] == 1)
check("parse: good A query qclass", q["qclass"] == 1)
check("parse: good A query rd echoed", q["rd"] is True)
check("parse: question bytes are the echo half",
      GOOD_A[12:12 + len(q["question"])] == q["question"])

GOOD_AAAA = _query([b"vill", b"cyberspace"], qtype=28)
check("parse: AAAA query qtype", dns.parse_query(GOOD_AAAA)["qtype"] == 28)

no_rd = dns.parse_query(_query([b"vill", b"cyberspace"], flags=0x0000))
check("parse: rd flag False when clear", no_rd["rd"] is False)

# --- parse_query: the refusals ------------------------------------------

check("parse: QR bit set is not a query",
      raises_valueerror(dns.parse_query, _query([b"vill", b"cyberspace"], flags=0x8100)))
check("parse: qdcount 0 refused",
      raises_valueerror(dns.parse_query, _query([b"vill", b"cyberspace"], qdcount=0)))
check("parse: qdcount 2 refused",
      raises_valueerror(dns.parse_query, _query([b"vill", b"cyberspace"], qdcount=2)))
check("parse: 11-byte packet refused",
      raises_valueerror(dns.parse_query, b"\x12\x34\x01\x00\x00\x01\x00"))
check("parse: truncated question tail refused",
      raises_valueerror(dns.parse_query,
                         _query([b"vill", b"cyberspace"], tail=b"\x00\x00\x01")))

# --- parse_query: label grammar ------------------------------------------

# pointer: "vill" then a 0xC0 pointer to the "cyberspace" label, which
# lives AFTER the question tail (compression points anywhere in the
# packet). Layout: 12=\x04, 13..16=vill, 17..18=0xC017 (pointer to 23),
# 19..22=qtype/qclass, 23=\x0A, 24..33=cyberspace, 34=\x00.
ptr_body = b"\x04vill" + b"\xc0\x17"
ptr_tail = struct.pack(">HH", 1, 1)
ptr_target = b"\x0Acyberspace\x00"
ptr_pkt = (struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) +
           ptr_body + ptr_tail + ptr_target)
pq = dns.parse_query(ptr_pkt)
check("parse: pointer-compressed name resolves",
      pq["qname"] == "vill.cyberspace", pq["qname"])
check("parse: pointer leaves off after the jump, not after the target",
      pq["question"] == ptr_body + ptr_tail,
      pq["question"].hex())

check("parse: pointer cycle raises (bounded loop)",
      raises_valueerror(dns.parse_query,
                        struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) +
                        b"\xc0\x0c" + struct.pack(">HH", 1, 1)))
check("parse: 0x40 label-length bits refused (not a pointer, not a label)",
      raises_valueerror(dns.parse_query,
                        struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) +
                        b"\x40zz" + b"\x00" + struct.pack(">HH", 1, 1)))
check("parse: label length past the packet refused (the cyberspace stumble)",
      raises_valueerror(dns.parse_query,
                        struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) +
                        b"\x09cy" + b"\x00" + struct.pack(">HH", 1, 1)))
check("parse: non-ascii label refused",
      raises_valueerror(dns.parse_query, _query([b"\xff\xfe", b"cyberspace"])))

# --- build_response -------------------------------------------------------

resp = dns.build_response(q, [(1, 300, b"\x7f\x00\x00\x01")])
check("build: id echoes", resp[0:2] == b"\x12\x34", resp[0:2].hex())
flags = int.from_bytes(resp[2:4], "big")
check("build: QR|AA|RD, rcode 0", flags == 0x8500, hex(flags))
check("build: ancount == 1", int.from_bytes(resp[6:8], "big") == 1)
check("build: question echoed verbatim",
      resp[12:12 + len(q["question"])] == q["question"])
ans_off = 12 + len(q["question"])
check("build: answer name is a 0xC00C pointer",
      resp[ans_off:ans_off + 2] == b"\xc0\x0c", resp[ans_off:ans_off + 2].hex())
atype, aclass, attl, ardlen = struct.unpack(">HHIH", resp[ans_off + 2:ans_off + 12])
check("build: answer type/class/ttl/rdlen", (atype, aclass, attl, ardlen) == (1, 1, 300, 4))
check("build: answer rdata is the loopback",
      resp[ans_off + 12:ans_off + 16] == b"\x7f\x00\x00\x01",
      resp[ans_off + 12:ans_off + 16].hex())

nx = dns.build_response(q, [], 3)
check("build: NXDOMAIN rcode bits", (int.from_bytes(nx[2:4], "big") & 0xF) == 3)
check("build: NXDOMAIN ancount 0", int.from_bytes(nx[6:8], "big") == 0)

no_rd_resp = dns.build_response(no_rd, [])
check("build: RD not echoed when clear",
      int.from_bytes(no_rd_resp[2:4], "big") == 0x8400,
      hex(int.from_bytes(no_rd_resp[2:4], "big")))

check("build: unknown rcode 5 raises",
      raises_valueerror(dns.build_response, q, [], 5))
check("build: negative ttl raises",
      raises_valueerror(dns.build_response, q, [(1, -1, b"\x7f\x00\x00\x01")]))

# --- error_response ---------------------------------------------------------

er = dns.error_response(b"")
check("error: empty input never raises, 12 bytes", len(er) == 12)
check("error: id 0 on unreadable header", er[0:2] == b"\x00\x00")
check("error: QR + AA + SERVFAIL", int.from_bytes(er[2:4], "big") == 0x8402,
      hex(int.from_bytes(er[2:4], "big")))

er2 = dns.error_response(b"\xab\xcdgarbage")
check("error: echoes the query id when readable", er2[0:2] == b"\xab\xcd")

er3 = dns.error_response(b"\x00\x01", 4)
check("error: AA set on non-default rcodes too",
      int.from_bytes(er3[2:4], "big") == 0x8404,
      hex(int.from_bytes(er3[2:4], "big")))

print(f"  {CASES['passed']} passed, {CASES['failed']} failed")
sys.exit(1 if CASES["failed"] else 0)
