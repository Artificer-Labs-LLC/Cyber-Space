#!/bin/bash
# Full test suite entrypoint (Examiner gate 2, ART-29).
# Runs every test file in the repo, reports per-file results and a summary.
# Usage: ./run_tests.sh [venv-python]
# Defaults to ./venv/bin/python. Uses a throwaway DB dir via CYBERNET_DB_DIR.
set -u

PY="${1:-./venv/bin/python}"
export CYBERNET_DB_DIR="$(mktemp -d)"
trap 'rm -rf "$CYBERNET_DB_DIR"' EXIT

# ART-40: route limiters and ratesrc key on core.request_source.
# client.host must not appear in those files. The only allowed hit is the
# peer read inside core.request_source. Deploy keeps --no-proxy-headers.
ROOT="$(cd "$(dirname "$0")" && pwd)"
if git -C "$ROOT" grep -n 'client.host' -- 'routes_*.py' ratesrc.py; then
  echo "FAIL: client.host must not appear in route files or ratesrc.py"
  exit 1
fi
core_hits="$(git -C "$ROOT" grep -n 'client.host' -- core.py || true)"
core_n="$(printf '%s\n' "$core_hits" | grep -c 'client.host' || true)"
if [ "$core_n" -ne 1 ] || ! printf '%s\n' "$core_hits" | grep -q 'client_source(request\.client\.host'; then
  echo "FAIL: the only allowed client.host hit is core.request_source"
  printf '%s\n' "$core_hits"
  exit 1
fi
if ! grep -q -- '--no-proxy-headers' "$ROOT/deploy/cybernet-node.service"; then
  echo "FAIL: deploy/cybernet-node.service must keep --no-proxy-headers"
  exit 1
fi

# Standing rule (Villhaze 5f028f12 / Cipher): fed/envelope.py self-test
# must run in the suite. A check outside the suite is a check that does
# not exist.
if ! "$PY" -m fed.envelope; then
  echo "FAIL: fed/envelope.py self-test"
  exit 1
fi
echo "PASS: fed/envelope.py (self-test)"

TESTS=(
  "test_dial.py"
  "test_name_claim.py"
  "test_names_claim_cap.py"
  "test_ed25519_strict.py"
  "test_names_rotate_zero_key.py"
  "test_names_rotate_name_cap.py"
  "test_window_open_preconditions.py"
  # Split from test_window_open_witness_kinds.py by mutant group (41 rows
  # took ~7 min, past the suite timeout); each mutant dies in one file.
  "test_wok_kinds.py"
  "test_wok_hopcap.py"
  "test_wok_closure.py"
  "test_wok_nodeb.py"
  "test_wok_certs.py"
  "test_wok_ruling.py" "test_wok_steer.py" "test_wok_config.py" "test_wok_freeze.py" "test_wok_level.py" "test_wok_wiring.py"
  "test_legacy_migrate_stub.py"
  "test_witness_port.py"
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
