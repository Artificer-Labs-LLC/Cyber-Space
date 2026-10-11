#!/usr/bin/env python3
"""Verify a .cyberspace name binding offline — the self-authenticating half
of primitive 1 (naming).

A name claim is name-claim|<label>|<pub>|<issued>|<expires> signed by the
name key itself (the very key being named vouches for the binding). That
means anyone can verify a binding WITHOUT trusting the mirror: a lying
registry can withhold a name, never redirect one. This script is that
anyone: it takes a binding JSON (name, node_pubkey, issued_at, expires_at,
signature — the same shape /api/v1/names/claim accepts and stores) and
checks it end to end, no network.

Usage:
  ./venv/bin/python verify_name.py binding.json
  ./venv/bin/python verify_name.py -              # read JSON from stdin
  ./venv/bin/python verify_name.py binding.json --expect-name foo \
      --expect-pubkey <64hex>   # pin: "is this the binding I meant?"

Exit codes: 0 = binding is valid and live right now
            1 = binding is invalid, expired, or not yet issued (reason on stderr)
            2 = usage / unreadable input (no verdict)

The canonical payload must match core._name_claim_payload byte for byte:
lowercase-hex pub, exact issued/expires strings as signed.
"""

import os
import sys
import argparse
import json
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fed.ed25519 import checkvalid  # noqa: E402

_LABEL_MAX = 63


def _valid_label(label: str) -> bool:
    """Client-side mirror of core._valid_name_label (server decides)."""
    if not label or len(label) > _LABEL_MAX:
        return False
    if label != label.lower() or "." in label:
        return False
    if label.startswith("-") or label.endswith("-"):
        return False
    return all(c.isalnum() or c == "-" for c in label)


def _claim_payload(name: str, node_pubkey: str, issued_at: str,
                   expires_at: str) -> bytes:
    """Byte-for-byte twin of core._name_claim_payload."""
    return (b"name-claim|" + name.encode() + b"|"
            + node_pubkey.lower().encode() + b"|"
            + issued_at.encode() + b"|" + expires_at.encode())


def _parse_ts(s: str, field: str) -> datetime:
    # Twin of core_serve._parse_claim_time (the mirror's rule): the stamp
    # MUST be exactly `YYYY-MM-DDTHH:MM:SS` with a UTC stamp (`Z` or
    # `+00:00`). M-2 (v0.6.3 red-team): fromisoformat is NOT used
    # — on 3.11+ it accepts ~12 spellings and behaves differently across
    # versions. Strict regex + manual construction keeps the twins in
    # agreement on every Python. B1/B2: [0-9] classes (not \d) and a \Z
    # anchor (not $). B4: ONLY UTC — `-00:00` and every non-zero offset
    # are rejected. Raises ValueError on unparseable input, exactly like
    # the mirror — otherwise a mirror-refused binding would pass offline
    # verification and the "trust a name without trusting the mirror"
    # promise breaks.
    import re
    m = re.match(
        r"^([0-9]{4})-([0-9]{2})-([0-9]{2})T"
        r"([0-9]{2}):([0-9]{2}):([0-9]{2})(Z|\+00:00)\Z", s
    )
    if not m:
        raise ValueError(f"{field} is not canonical UTC timestamp: {s!r}")
    year, mon, day, hr, mi, se = (int(m.group(i)) for i in range(1, 7))
    if not (1 <= mon <= 12 and 1 <= day <= 31 and hr <= 23
            and mi <= 59 and se <= 59):
        raise ValueError(f"{field} out of range: {s!r}")
    # B4: the only surviving spellings are UTC — no offset arithmetic.
    tz = timezone.utc
    try:
        return datetime(year, mon, day, hr, mi, se, tzinfo=tz)
    except ValueError:
        raise ValueError(f"{field} invalid date: {s!r}")


def _normalize_expected(s: str) -> str:
    """Expected names/keys get the same normalize-identically-first
    treatment the mirror applies to bindings: strip, lowercase."""
    return s.strip().lower()


def verify(binding: dict, expect_name: str | None = None,
           expect_pubkey: str | None = None) -> str | None:
    """Return None if the binding verifies, else the reason it does not.

    expect_name / expect_pubkey pin the answer: "is this the binding I
    meant?" A valid binding for a DIFFERENT name or key fails with a
    naming-the-sides reason instead of verifying. Expected values are
    normalized identically to bindings (strip + lowercase) so a caller
    can pass what the mirror accepted without worrying about case.
    """
    if not isinstance(binding, dict):
        return "binding is not a JSON object"
    for k in ("name", "node_pubkey", "issued_at", "expires_at", "signature"):
        if k not in binding:
            return f"missing field: {k}"
        if not isinstance(binding[k], str):
            return f"field {k!r} is not a string"
    name = binding["name"]
    pub = binding["node_pubkey"]
    sig = binding["signature"]
    # The mirror normalizes BEFORE it validates (names_claim strips and
    # lowercases name/node_pubkey/signature, then verifies the signature
    # against the NORMALIZED values and stores the normalized form). The
    # offline verifier must vouch for exactly what the mirror stores, so
    # it normalizes identically first — a claim form the mirror accepts
    # verifies here too, never just the already-normalized stored copy.
    name = _normalize_expected(name)
    pub = _normalize_expected(pub)
    sig = _normalize_expected(sig)
    if expect_name is not None:
        exp = _normalize_expected(expect_name)
        if name != exp:
            return f"binding is for {name!r}, not the expected {exp!r}"
    if expect_pubkey is not None:
        exp = _normalize_expected(expect_pubkey)
        if pub != exp:
            return (f"binding is keyed to {pub[:16]}..., not the expected "
                    f"key {exp[:16]}...")
    if not _valid_label(name):
        return f"name {name!r} is not a valid .cyberspace label"
    if len(pub) != 64:
        return "node_pubkey is not 64 hex chars"
    try:
        pub_b = bytes.fromhex(pub)
    except ValueError:
        return "node_pubkey is not hex"
    if len(sig) != 128:
        return "signature is not 128 hex chars"
    try:
        sig_b = bytes.fromhex(sig)
    except ValueError:
        return "signature is not hex"
    try:
        issued = _parse_ts(binding["issued_at"], "issued_at")
        expires = _parse_ts(binding["expires_at"], "expires_at")
    except ValueError as e:
        return str(e)
    if not issued < expires:
        return "issued_at is not before expires_at"
    now = datetime.now(timezone.utc)
    if now < issued:
        return "binding is not yet issued"
    if now >= expires:
        return "binding has expired"
    payload = _claim_payload(name, pub, binding["issued_at"], binding["expires_at"])
    if not checkvalid(sig_b, payload, pub_b):
        return "signature does not verify: this binding is not vouched for by the named key"
    return None


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        description="verify a .cyberspace name binding offline")
    ap.add_argument("source", help="binding.json, or - for stdin")
    ap.add_argument("--expect-name",
                    help="fail unless the binding is for this label")
    ap.add_argument("--expect-pubkey",
                    help="fail unless the binding is keyed to this name key")
    args = ap.parse_args(argv)
    src = args.source
    try:
        raw = sys.stdin.read() if src == "-" else open(src, encoding="utf-8").read()
    except OSError as e:
        print(f"refused: cannot read {src}: {e}", file=sys.stderr)
        return 2
    try:
        binding = json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"refused: not JSON: {e}", file=sys.stderr)
        return 2
    reason = verify(binding, expect_name=args.expect_name,
                    expect_pubkey=args.expect_pubkey)
    if reason is not None:
        print(f"invalid: {reason}", file=sys.stderr)
        return 1
    # Print the normalized form — exactly what the mirror stores and
    # vouched for, never the raw casing a claim form happened to carry.
    nm = _normalize_expected(binding["name"])
    pk = _normalize_expected(binding["node_pubkey"])
    print(f"valid: {nm}.cyberspace -> {pk[:16]}..."
          f" (issued {binding['issued_at']}, expires {binding['expires_at']})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
