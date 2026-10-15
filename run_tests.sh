#!/bin/bash
# Full test suite entrypoint (Examiner gate 2, ART-29).
# Runs every test file in the repo, reports per-file results and a summary.
# Usage: ./run_tests.sh [venv-python]
# Defaults to ./venv/bin/python. Uses a throwaway DB dir via CYBERNET_DB_DIR.
set -u

PY="${1:-./venv/bin/python}"
export CYBERNET_DB_DIR="$(mktemp -d)"
trap 'rm -rf "$CYBERNET_DB_DIR"' EXIT

TESTS=(
  "test_dial.py"
  "test_name_claim.py"
  "test_verify_name.py"
  "test_resolve_chain.py"
  "test_rotate_name.py"
  "test_mint_name.py"
  "test_nexus_preflight.py"
  "test_nexus_keygen.py"
  "test_rendezvous.py"
  "test_hold_open.py"
  "resolver/test_answer_aaaa.py"
  "resolver/test_answer_mirror.py"
  "resolver/test_client.py"
  "resolver/test_daemon_config.py"
  "resolver/test_daemon_tcp.py"
  "resolver/test_dns.py"
  "resolver/test_forward_ttl.py"
  "resolver/test_serve_loop.py"
  "resolver/wiring/test_smoke.py"
)

pass=0
fail=0
failed_files=()

for t in "${TESTS[@]}"; do
  if "$PY" "$t" >/dev/null 2>&1; then
    echo "PASS: $t"
    pass=$((pass + 1))
  else
    echo "FAIL: $t"
    fail=$((fail + 1))
    failed_files+=("$t")
  fi
done

echo "---"
echo "SUMMARY: $pass passed, $fail failed out of ${#TESTS[@]} test files"
if [ "$fail" -gt 0 ]; then
  echo "Failed: ${failed_files[*]}"
  exit 1
fi
exit 0
