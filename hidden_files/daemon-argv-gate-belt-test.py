#!/usr/bin/env python3
"""Belt test for resolver.daemon's argv gate.

The daemon takes NO arguments — it is configured by env only, and the
systemd units pass none. Before this tick the __main__ block checked
only -h/--help and silently ignored everything else: a mistyped
--port or a stray flag started the daemon on the env/default port the
operator never asked for, exactly the unknown-option hazard mint_name
refuses. Now any non-help argument refuses before run(), exit 2.

Checks (subprocess, so __main__ itself is exercised):
  --bogus            -> exit 2, refusal wording, no bind attempted
  --port 9999        -> exit 2 (the classic silently-ignored typo)
  extra positional   -> exit 2
  -h / --help        -> exit 0 controls (help still works)

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/daemon-argv-gate-belt-test.py
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


def run_daemon(*argv):
    return subprocess.run(
        [sys.executable, "-m", "resolver.daemon", *argv],
        cwd=ROOT, capture_output=True, text=True, timeout=15)


for argv in (["--bogus"], ["--port", "9999"], ["extra"]):
    r = run_daemon(*argv)
    label = " ".join(argv)
    check(f"{label}: exit 2", r.returncode == 2)
    check(f"{label}: refusal names bad argument",
          "unexpected argument" in r.stderr
          and "environment only" in r.stderr)
    check(f"{label}: daemon did not start serving",
          "refusing to start" in r.stderr)

for argv in (["-h"], ["--help"]):
    r = run_daemon(*argv)
    check(f"{argv[0]}: exit 0 (help control)", r.returncode == 0)

print(f"\ndaemon-argv-gate belt: {PASSED}/{PASSED + FAILED}")
sys.exit(1 if FAILED else 0)
