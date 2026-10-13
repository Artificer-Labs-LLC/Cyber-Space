#!/usr/bin/env python3
"""Belt: _delta_payload refuses a NON-STRING row field (and a non-int
seq) instead of str()/int()-aliasing it (primitives 1 naming + 5
discovery).

_delta_payload (core.py) is the canonical bytes builder every delta
seat verifies against, and it str()-coerced the five row fields and
int()-coerced seq: an int name (12345) built byte-identical payload
to the string "12345" (verified before the fix), seq True and seq
"1" built byte-identical payload to seq 1, and a non-dict row escaped
as AttributeError. The receiver seats (fed_directory_delta,
_recv_attestation) gate their rows before calling, but the builder
was not self-contained -- any future or direct caller inherited the
alias. Twin of the seat gates, at the source: present fields must be
strings, seq must be a real int (bool excluded); every existing
caller already treats a raise here as a failed verification.

Covers: int name / int node_pub / bool version refused (ValueError);
bool seq / str seq refused; non-dict row refused as ValueError (not
AttributeError); valid string row builds exact canonical bytes and
absent fields keep their defaults (controls).

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/delta-payload-field-type-belt-test.py
"""
import json
import os
import sys
import tempfile

TMP = tempfile.mkdtemp(prefix="delta-payload-belt-")
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


def refuses(row, seq=1):
    try:
        _delta_payload(row, seq, False)
    except ValueError:
        return True
    except Exception:
        return False
    return False


ROW = {"node_pub": "ab" * 32, "name": "validnode",
       "node_url": "https://8.8.8.8:443/cybernet", "capabilities": [],
       "network": "cybernet", "version": "0.1.0", "genesis": False}

check("int name refused", refuses({**ROW, "name": 12345}))
check("int node_pub refused", refuses({**ROW, "node_pub": 12345}))
check("bool version refused", refuses({**ROW, "version": True}))
check("bool seq refused", refuses(ROW, seq=True))
check("str seq refused", refuses(ROW, seq="1"))
check("non-dict row refused as ValueError", refuses(None))

expected = json.dumps(
    {"node_pub": "ab" * 32, "name": "validnode",
     "node_url": "https://8.8.8.8:443/cybernet", "capabilities": [],
     "network": "cybernet", "version": "0.1.0", "genesis": False,
     "seq": 1, "retire": False},
    sort_keys=True, separators=(",", ":")).encode()
check("valid string row byte-exact", _delta_payload(ROW, 1, False) == expected)
check("absent fields keep defaults",
      _delta_payload({"node_pub": "ab" * 32}, 2, True) == json.dumps(
          {"node_pub": "ab" * 32, "name": "", "node_url": "",
           "capabilities": [], "network": "cybernet", "version": "0.1.0",
           "genesis": False, "seq": 2, "retire": True},
          sort_keys=True, separators=(",", ":")).encode())

print(f"{CASES['passed']} passed, {CASES['failed']} failed")
sys.exit(1 if CASES["failed"] else 0)
