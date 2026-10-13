#!/usr/bin/env python3
"""Belt: the four workspace vouch payload builders (_invite_payload,
_countersign_payload, _leave_payload, _removed_payload) refuse a
non-int workspace_id and non-string fields as ValueError instead of
str()-aliasing them or escaping AttributeError (primitive 4 identity).

The builders are canonical signing seats, twin of _name_claim_payload
and _delta_payload — but they carried no seat gate: str(workspace_id)
built the string "1" byte-identically to int 1 (and True to a "True"
id no int row has), so a signature over the alias verified as a
signature over the typed row; .lower() on a non-string charter_hash /
key field escaped as AttributeError past the ValueError contract
every sibling parser carries. Receiver seats gate their body fields
before calling, but the builder must refuse on its own. Seat gate
(_ws_payload_gate): workspace_id a real int (never bool), every other
field a real string, else ValueError. Valid verdicts byte-exact.

Covers: valid payloads byte-exact (controls, all four builders);
string/bool/None workspace_id -> ValueError; int/None/list field on
each builder -> ValueError, never AttributeError.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/ws-payload-field-type-belt-test.py
"""
import os
import sys
import tempfile

TMP = tempfile.mkdtemp(prefix="ws-payload-type-belt-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core  # noqa: E402

CASES = {"passed": 0, "failed": 0}


def check(name, cond, extra=""):
    if cond:
        CASES["passed"] += 1
        print(f"  ok  {name}")
    else:
        CASES["failed"] += 1
        print(f"  FAIL {name} {extra}")


def refuses(fn, *args):
    """True iff fn(*args) raises ValueError (not AttributeError, not a build)."""
    try:
        fn(*args)
    except ValueError:
        return True
    except Exception:
        return False
    return False


H = "a" * 64
K = "b" * 64
P = "c" * 64

# Controls: valid payloads byte-exact.
check("invite valid exact",
      core._invite_payload(7, H, K)
      == b"workspace-invite|7|" + H.encode() + b"|" + K.encode())
check("countersign valid exact",
      core._countersign_payload(7, H, P, K)
      == b"workspace-countersign|7|" + H.encode() + b"|" + P.encode()
      + b"|" + K.encode())
check("leave valid exact",
      core._leave_payload(7, K) == b"workspace-leave|7|" + K.encode())
check("removed valid exact",
      core._removed_payload(7, K) == b"workspace-removed|7|" + K.encode())

# workspace_id aliases / wrong types refuse as ValueError.
check("invite str id refuses", refuses(core._invite_payload, "7", H, K))
check("invite bool id refuses", refuses(core._invite_payload, True, H, K))
check("countersign None id refuses",
      refuses(core._countersign_payload, None, H, P, K))
check("leave float id refuses", refuses(core._leave_payload, 7.0, K))
check("removed list id refuses", refuses(core._removed_payload, [7], K))

# Non-string fields refuse as ValueError (never AttributeError).
check("invite int charter refuses", refuses(core._invite_payload, 7, 123, K))
check("invite None key refuses", refuses(core._invite_payload, 7, H, None))
check("countersign int from_pub refuses",
      refuses(core._countersign_payload, 7, H, 123, K))
check("leave int member refuses", refuses(core._leave_payload, 7, 123))
check("removed bytes member refuses",
      refuses(core._removed_payload, 7, K.encode()))

print(f"\n{CASES['passed']} passed, {CASES['failed']} failed")
sys.exit(1 if CASES["failed"] else 0)
