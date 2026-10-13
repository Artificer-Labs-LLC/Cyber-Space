#!/usr/bin/env python3
"""Belt test for resolver.client main()'s --port gate.

The client CLI could not be pointed at a daemon on a non-default
port at all: --server and --tcp-only existed, but the port came only
from CYBERNET_RESOLVER_PORT. main() now accepts --port as an explicit
override, twin of wiring/smoke's --port: gated to 1..65535 as a bad
argument (exit 2, no query attempted) instead of dying in transport
as a verdict on the daemon, a valid value wins over the env
derivation, and with no --port the env derivation is unchanged.
resolve() is mocked at the module seam; no wire is touched.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/client-cli-port-belt-test.py
"""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from resolver import client  # noqa: E402

PASSED = FAILED = 0


def check(name, cond, extra=""):
    global PASSED, FAILED
    if cond:
        PASSED += 1
        print(f"  ok: {name}")
    else:
        FAILED += 1
        print(f"  FAIL: {name} {extra}")


CALLS = []


def fake_resolve(name, **kw):
    CALLS.append(kw)
    return ["203.0.113.7"]


def _run(argv, env_port=None):
    CALLS.clear()
    orig_resolve = client.resolve
    orig_env = os.environ.get("CYBERNET_RESOLVER_PORT")
    client.resolve = fake_resolve
    if env_port is None:
        os.environ.pop("CYBERNET_RESOLVER_PORT", None)
    else:
        os.environ["CYBERNET_RESOLVER_PORT"] = env_port
    try:
        try:
            rc = client.main(argv)
        except SystemExit as e:  # argparse's own bad-argument exit
            rc = e.code
        return rc
    finally:
        client.resolve = orig_resolve
        if orig_env is None:
            os.environ.pop("CYBERNET_RESOLVER_PORT", None)
        else:
            os.environ["CYBERNET_RESOLVER_PORT"] = orig_env


# 1. A valid --port is honored.
rc = _run(["node.cyberspace", "--port", "5399"])
check("valid --port exits 0", rc == 0, f"rc={rc}")
check("valid --port reaches resolve",
      len(CALLS) == 1 and CALLS[0].get("port") == 5399, f"calls={CALLS}")

# 2/3. Out-of-range --port values are bad arguments: exit 2, no query.
for bad in ("0", "70000", "-5"):
    rc = _run(["node.cyberspace", "--port", bad])
    check(f"--port {bad} exits 2", rc == 2, f"rc={rc}")
    check(f"--port {bad} attempts no query", CALLS == [], f"calls={CALLS}")

# 4. A non-integer --port is argparse's bad-argument exit 2, no query.
rc = _run(["node.cyberspace", "--port", "abc"])
check("--port abc exits 2", rc == 2, f"rc={rc}")
check("--port abc attempts no query", CALLS == [], f"calls={CALLS}")

# 5. No --port: the env derivation is unchanged.
rc = _run(["node.cyberspace"], env_port="5354")
check("env port exits 0", rc == 0, f"rc={rc}")
check("env port reaches resolve",
      len(CALLS) == 1 and CALLS[0].get("port") == 5354, f"calls={CALLS}")

# 6. An explicit --port wins over the env value.
rc = _run(["node.cyberspace", "--port", "5399"], env_port="5354")
check("--port over env exits 0", rc == 0, f"rc={rc}")
check("--port wins over env",
      len(CALLS) == 1 and CALLS[0].get("port") == 5399, f"calls={CALLS}")

print(f"\n{PASSED} passed, {FAILED} failed")
sys.exit(1 if FAILED else 0)
