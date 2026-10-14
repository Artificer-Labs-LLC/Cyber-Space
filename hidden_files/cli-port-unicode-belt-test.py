#!/usr/bin/env python3
"""Belt: resolver client --port and wiring smoke --port refuse integer
spellings bare int() aliases -- Unicode decimal digits and underscore
separators -- at their main() parse seats (primitives 2 resolution +
6 client daemon).

Both mains declared --port with argparse type=int: int() parses
Unicode decimal digits (an Arabic-Indic or fullwidth spelling of 5353
became 5353) and accepts underscore separators (5_353 became 5353), so
a non-ASCII or underscored spelling queried/smoked a port the operator
never wrote in ASCII -- where both env seats (_default_port) refuse
those spellings. Fix: the raw string reaches main and an ASCII-digits
gate (one optional leading sign, surrounding whitespace preserved)
sits exactly where type=int refused; client refusals return 2 and
smoke refusals return 1 (each seat's own bad-argument code), no query
is attempted, and valid ASCII spellings keep their exact fate.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/cli-port-unicode-belt-test.py
"""
import contextlib
import io
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "resolver"))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "resolver", "wiring"))

from resolver import client  # noqa: E402
import smoke  # noqa: E402

CASES = {"passed": 0, "failed": 0}


def check(name, cond, extra=""):
    if cond:
        CASES["passed"] += 1
        print(f"  ok  {name}")
    else:
        CASES["failed"] += 1
        print(f"  FAIL {name} {extra}")


def client_fate(value):
    seen = []

    def fake_resolve(name, qtype=None, server=None, port=None, tcp_only=False):
        seen.append(port)
        return ["192.0.2.1"]

    real = client.resolve
    client.resolve = fake_resolve
    out = io.StringIO()
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            rc = client.main(["node.cyberspace", "--port", value])
    finally:
        client.resolve = real
    text = out.getvalue()
    if "must be an integer" in text:
        return "integer", rc, seen
    if "not a dialable port" in text:
        return "range", rc, seen
    if rc == 0:
        return "passed", rc, seen
    return f"rc={rc} out={text!r}", rc, seen


def smoke_fate(value):
    calls = {"n": 0, "ports": []}

    def fake_query(name, qtype, server, port, timeout=3.0):
        calls["n"] += 1
        calls["ports"].append(port)
        return (3, 0, 0) if name.startswith("zz-") else (0, 1, 0)

    real = smoke._query
    smoke._query = fake_query
    old_argv = sys.argv
    sys.argv = ["smoke.py", "--server", "127.0.0.1", "--port", value]
    out = io.StringIO()
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            rc = smoke.main()
    finally:
        smoke._query = real
        sys.argv = old_argv
    text = out.getvalue()
    if "must be an integer" in text:
        return "integer", rc, calls
    if "not a dialable port" in text:
        return "range", rc, calls
    if rc == 0:
        return "passed", rc, calls
    return f"rc={rc} out={text!r}", rc, calls


AR5353 = "٥٣٥٣"      # Arabic-Indic 5353
FW5353 = "５３５３"      # fullwidth 5353

for label, fate_fn, good_rc in (("client", client_fate, 0), ("smoke", smoke_fate, 0)):
    fate, rc, seen = fate_fn("53599")
    check(f"{label} ASCII 53599 -> passes, port 53599", fate == "passed" and rc == good_rc and 53599 in (seen if isinstance(seen, list) else seen["ports"]), f"{fate} rc={rc} seen={seen}")
    fate, rc, seen = fate_fn("+53599")
    check(f"{label} ASCII +53599 -> passes", fate == "passed", f"{fate} rc={rc}")
    fate, rc, seen = fate_fn(" 53599 ")
    check(f"{label} ASCII ' 53599 ' -> passes", fate == "passed", f"{fate} rc={rc}")
    fate, rc, seen = fate_fn("-1")
    check(f"{label} ASCII -1 -> range refusal", fate == "range", f"{fate} rc={rc}")
    fate, rc, seen = fate_fn("65536")
    check(f"{label} ASCII 65536 -> range refusal", fate == "range", f"{fate} rc={rc}")
    for name, value in (("Arabic-Indic 5353", AR5353), ("fullwidth 5353", FW5353),
                        ("underscore 5_353", "5_353"), ("superscript", "²"),
                        ("garbage '53x'", "53x"), ("empty", "")):
        fate, rc, seen = fate_fn(value)
        n = len(seen) if isinstance(seen, list) else seen["n"]
        check(f"{label} {name} -> integer refusal, no query", fate == "integer" and n == 0, f"{fate} rc={rc} queries={n}")

# Seat-specific exit codes for the integer refusal.
_, rc, _ = client_fate(AR5353)
check("client integer refusal returns 2", rc == 2, f"rc={rc}")
_, rc, _ = smoke_fate(AR5353)
check("smoke integer refusal returns 1", rc == 1, f"rc={rc}")

print(f"\n{CASES['passed']}/{CASES['passed'] + CASES['failed']} passed")
sys.exit(1 if CASES["failed"] else 0)
