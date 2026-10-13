#!/usr/bin/env python3
"""Belt test for resolver.host's argv gate.

Hostd takes NO arguments — it is configured by env only, and the
systemd unit (deploy/hostd.service) passes none. Before this tick the
__main__ block checked only -h/--help and silently ignored everything
else: a mistyped flag or stray positional proceeded straight into the
config checks and, with a valid env, would have started the daemon on
a configuration the operator never asked for — exactly the
unknown-option hazard resolver.daemon and mint_name refuse. Now any
non-help argument refuses before run(), exit 2.

Checks (subprocess, so __main__ itself is exercised):
  --bogus            -> exit 2, refusal wording, argv gate (not config)
  --port 9999        -> exit 2 (an option this daemon never had)
  extra positional   -> exit 2
  -h / --help        -> exit 0 controls (help still works)

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/host-argv-gate-belt-test.py
"""

import os
import subprocess
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PASSED = FAILED = 0


def check(name, cond):
    global PASSED, FAILED
    if cond:
        PASSED += 1
        print(f"  ok: {name}")
    else:
        FAILED += 1
        print(f"  FAIL: {name}")


def run_host(*argv):
    env = {k: v for k, v in os.environ.items()
           if not k.startswith("CYBERNET_")}
    return subprocess.run(
        [sys.executable, "-m", "resolver.host", *argv],
        cwd=ROOT, capture_output=True, text=True, timeout=15, env=env)


for argv in (["--bogus"], ["--port", "9999"], ["extra"]):
    r = run_host(*argv)
    label = " ".join(argv)
    check(f"{label}: exit 2", r.returncode == 2)
    check(f"{label}: refusal names bad argument",
          "unexpected argument" in r.stderr
          and "environment only" in r.stderr)
    check(f"{label}: refused at argv gate, not config checks",
          "refusing to start" in r.stderr
          and "CYBERNET_HOSTED_NAME" not in r.stderr)

for argv in (["-h"], ["--help"]):
    r = run_host(*argv)
    check(f"{argv[0]}: exit 0 (help control)", r.returncode == 0)

print(f"\nhost-argv-gate belt: {PASSED}/{PASSED + FAILED}")
sys.exit(1 if FAILED else 0)
