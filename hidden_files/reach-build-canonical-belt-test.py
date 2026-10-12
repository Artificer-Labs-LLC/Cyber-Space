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

# Over-cap TTL: clamped to the 365-day descriptor lifetime cap, so the
# minted descriptor still verifies at its own seat instead of being
# refused everywhere as overlong.
os.environ["CYBERNET_REACH_TTL"] = str(400 * 86400)
built2 = core._reach_build("buildprobe", priv.hex())
check("over-cap TTL still builds a descriptor", built2 is not None)
desc2 = built2[0] if built2 else {}
check("over-cap descriptor verifies at its own seat",
      bool(desc2) and core._reach_descriptor_verify(desc2) is True,
      f"issued={desc2.get('issued_at')!r} expires={desc2.get('expires_at')!r}")
if desc2:
    life2 = (core._parse_claim_time(desc2["expires_at"])
             - core._parse_claim_time(desc2["issued_at"])).total_seconds()
    check("over-cap lifetime clamped to 365 days exactly",
          life2 == 365 * 86400, f"got {life2}")

# At-cap TTL passes unchanged.
os.environ["CYBERNET_REACH_TTL"] = str(365 * 86400)
built3 = core._reach_build("buildprobe", priv.hex())
desc3 = built3[0] if built3 else {}
if desc3:
    life3 = (core._parse_claim_time(desc3["expires_at"])
             - core._parse_claim_time(desc3["issued_at"])).total_seconds()
    check("at-cap lifetime passes unchanged", life3 == 365 * 86400,
          f"got {life3}")
else:
    check("at-cap lifetime passes unchanged", False, "no descriptor")

print(f"\n{CASES['passed']} passed, {CASES['failed']} failed")
sys.exit(1 if CASES["failed"] else 0)
