"""core._reach_build canonical minting (depth primitives 1+3):
the hosting send half mints the reach descriptor every mirror and
dialer checks with _reach_descriptor_verify — the minted stamps must
be the canonical UTC form that seat accepts.

Covers: a self-minted descriptor verifies True at its own seat; both
stamps parse via _parse_claim_time; the minted lifetime equals the
configured CYBERNET_REACH_TTL (no microsecond drift).

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/reach-build-canonical-belt-test.py
"""
import os
import secrets
import sys
import tempfile

TMP = tempfile.mkdtemp(prefix="reach-build-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import core  # noqa: E402
from fed import ed25519 as _fed_ed25519  # noqa: E402

CASES = {"passed": 0, "failed": 0}


def check(name, cond, extra=""):
    if cond:
        CASES["passed"] += 1
        print(f"  ok  {name}")
    else:
        CASES["failed"] += 1
        print(f"  FAIL {name} {extra}")


# --- the test-only SSRF allowance: the 127.0.0.1 test URL only --------
_real_gate = core._reject_nonpublic_node_url


def _test_gate(url):
    if url.startswith("http://127.0.0.1:"):
        return "127.0.0.1"
    return _real_gate(url)


core._reject_nonpublic_node_url = _test_gate

os.environ["CYBERNET_PUBLIC_URL"] = "http://127.0.0.1:9999"
os.environ.pop("CYBERNET_RELAY_URL", None)
os.environ.pop("CYBERNET_RENDEZVOUS", None)
os.environ["CYBERNET_REACH_TTL"] = "3600"

priv = secrets.token_bytes(32)
built = core._reach_build("buildprobe", priv.hex())
check("build returns a descriptor", built is not None)
desc = built[0] if built else {}

check("self-minted descriptor verifies at its own seat",
      bool(desc) and core._reach_descriptor_verify(desc) is True,
      f"issued={desc.get('issued_at')!r} expires={desc.get('expires_at')!r}")

try:
    issued_dt = core._parse_claim_time(desc["issued_at"])
    expires_dt = core._parse_claim_time(desc["expires_at"])
    parse_ok = True
except Exception:
    issued_dt = expires_dt = None
    parse_ok = False
check("both stamps are canonical UTC", parse_ok)

if parse_ok:
    check("minted lifetime equals configured TTL",
          (expires_dt - issued_dt).total_seconds() == 3600,
          f"got {(expires_dt - issued_dt).total_seconds()}")

print(f"\n{CASES['passed']} passed, {CASES['failed']} failed")
sys.exit(1 if CASES["failed"] else 0)
