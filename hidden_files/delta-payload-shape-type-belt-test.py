#!/usr/bin/env python3
"""Belt: _delta_payload refuses a NON-LIST capabilities, a NON-BOOL
genesis, and a NON-BOOL retire instead of coercing them into the
canonical payload (primitives 1 naming + 5 discovery).

_delta_payload (core.py) gated its five string fields and seq but
left the other three payload fields to coercion: a capabilities dict
iterated its keys into byte-identical payload to the signed list
({"messaging": 0} == ["messaging"]), a capabilities string iterated
its characters into the payload, a capabilities int escaped as
TypeError past the builder's ValueError contract, genesis "false"
and 1 bool()-coerced to the payload for a genesis row, and a retire
"false" coerced to a retire payload — aliases for claims nobody
served in that form, at the canonical seat every delta receiver
trusts. Present fields must carry their canonical shapes; absent
fields keep their defaults.

Covers: dict caps / str caps refused; int caps refused as ValueError
(not TypeError); str genesis / int genesis refused; str retire
refused; valid row byte-exact, caps list filtering, genesis/retire
bools exact (controls).

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/delta-payload-shape-type-belt-test.py
"""
import json
import os
import sys
import tempfile

TMP = tempfile.mkdtemp(prefix="delta-payload-shape-belt-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import _delta_payload  # noqa: E402

CASES = {"passed": 0, "failed": 0}


def check(name, cond, extra=""):
    if cond:
        CASES["passed"] += 1
        print(f"  ok  {name}")
    else:
        CASES["failed"] += 1
        print(f"  FAIL {name} {extra}")


def refuses(row, seq=1, retire=False):
    try:
        _delta_payload(row, seq, retire)
    except ValueError:
        return True
    except Exception:
        return False
    return False


ROW = {"node_pub": "ab" * 32, "name": "validnode",
       "node_url": "https://8.8.8.8:443/cybernet",
       "capabilities": ["messaging"], "network": "cybernet",
       "version": "0.1.0", "genesis": False}

check("dict capabilities refused",
      refuses({**ROW, "capabilities": {"messaging": 0}}))
check("str capabilities refused",
      refuses({**ROW, "capabilities": "messaging"}))
check("int capabilities refused as ValueError",
      refuses({**ROW, "capabilities": 12345}))
check("str genesis refused", refuses({**ROW, "genesis": "false"}))
check("int genesis refused", refuses({**ROW, "genesis": 1}))
check("str retire refused", refuses(ROW, retire="false"))
check("int retire refused", refuses(ROW, retire=1))

expected = json.dumps(
    {"node_pub": "ab" * 32, "name": "validnode",
     "node_url": "https://8.8.8.8:443/cybernet",
     "capabilities": ["messaging"], "network": "cybernet",
     "version": "0.1.0", "genesis": False, "seq": 1, "retire": False},
    sort_keys=True, separators=(",", ":")).encode()
check("valid row byte-exact", _delta_payload(ROW, 1, False) == expected)
check("genesis True + retire True exact",
      _delta_payload({**ROW, "genesis": True}, 2, True) == json.dumps(
          {"node_pub": "ab" * 32, "name": "validnode",
           "node_url": "https://8.8.8.8:443/cybernet",
           "capabilities": ["messaging"], "network": "cybernet",
           "version": "0.1.0", "genesis": True, "seq": 2, "retire": True},
          sort_keys=True, separators=(",", ":")).encode())
check("caps list still filters non-strings",
      _delta_payload({**ROW, "capabilities": ["messaging", 7]}, 1, False)
      == expected)
check("absent caps/genesis keep defaults",
      _delta_payload({"node_pub": "ab" * 32}, 1, False) == json.dumps(
          {"node_pub": "ab" * 32, "name": "", "node_url": "",
           "capabilities": [], "network": "cybernet", "version": "0.1.0",
           "genesis": False, "seq": 1, "retire": False},
          sort_keys=True, separators=(",", ":")).encode())

print(f"{CASES['passed']} passed, {CASES['failed']} failed")
sys.exit(1 if CASES["failed"] else 0)
