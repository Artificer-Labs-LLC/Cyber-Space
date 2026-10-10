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

Exit codes: 0 = binding is valid and live right now
            1 = binding is invalid, expired, or not yet issued (reason on stderr)
            2 = usage / unreadable input (no verdict)

The canonical payload must match core._name_claim_payload byte for byte:
lowercase-hex pub, exact issued/expires strings as signed.
"""

import os
import sys
import json
from datetime import datetime, timezone

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
    try:
        ts = datetime.fromisoformat(s)
    except (ValueError, TypeError):
        raise ValueError(f"{field} is not ISO 8601: {s!r}")
    if ts.tzinfo is None:
        raise ValueError(f"{field} must be timezone-aware: {s!r}")
    return ts


def verify(binding: dict) -> str | None:
    """Return None if the binding verifies, else the reason it does not."""
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
    if len(argv) != 1:
        print("usage: verify_name.py <binding.json | ->", file=sys.stderr)
        return 2
    src = argv[0]
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
    reason = verify(binding)
    if reason is not None:
        print(f"invalid: {reason}", file=sys.stderr)
        return 1
    print(f"valid: {binding['name']}.cyberspace -> {binding['node_pubkey'][:16]}..."
          f" (issued {binding['issued_at']}, expires {binding['expires_at']})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
