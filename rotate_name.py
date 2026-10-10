#!/usr/bin/env python3
"""Rotate a .cyberspace name key — the identity half of primitive 4 (keys).

A name binding is self-authenticating: the name key vouches for itself.
Rotation must be too. A rotation record is:

  name-rotate|<label>|<old_pub>|<new_pub>|<issued_at>

signed by the OLD key. Continuity lives in that one signature: anyone who
trusts the old binding can see "the holder of the old key designated this
new key" — no mirror, no registry, no ceremony. The new key then signs the
next claim, and the chain is unbroken.

Rotation records carry no expiry: a rotation is a point event ("at time T,
old designated new"), not a live binding — the new claim carries the
liveness window. A rotation dated in the future is not yet in force.

Usage:
  ./venv/bin/python rotate_name.py <label> [--new-key-seed HEX64]
  ./venv/bin/python rotate_name.py <label> --promote

  Mint mode loads the existing name key from ~/.cyberspace/<label>-name.key
  (the OLD key), mints and self-verifies the rotation record, writes:
    ~/.cyberspace/<label>-rotate.json     the record (publish this)
    ~/.cyberspace/<label>-name.key.next   the NEW key seed (0600)

  The old key file is NEVER overwritten by minting — promotion stays a
  deliberate operator step. Promote mode (--promote) closes the loop AFTER
  the record is seen in the wild (mirror accept, gossip, handoff):
    ~/.cyberspace/<label>-name.key        becomes the NEW key seed (0600)
    ~/.cyberspace/<label>-name.key.prev   keeps the OLD key seed (0600)
  The .next file is consumed atomically; the promotion re-verifies the
  rotation record first (signature + in-force + continuity of both keys).

Exit codes: 0 = done; 1 = refused (reason on stderr); 2 = usage / unreadable.
"""

import os
import sys
import json
import argparse
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fed.ed25519 import publickey, sign, checkvalid  # noqa: E402

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


def _normalize(s: str) -> str:
    """Expected/held values are normalized identically before any rule:
    strip, lowercase — the mirror twin."""
    return s.strip().lower()


def _rotate_payload(name: str, old_pub: str, new_pub: str,
                    issued_at: str) -> bytes:
    """The canonical bytes the OLD key signs. Distinct prefix from
    name-claim| so a claim payload can never verify as a rotation and
    vice versa (payload-prefix confusion is a signature-side attack)."""
    return (b"name-rotate|" + name.encode() + b"|" + old_pub.encode()
            + b"|" + new_pub.encode() + b"|" + issued_at.encode())


def _iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")


def mint_rotation(label: str, old_priv: bytes, new_pub_hex: str,
                  issued_at: str | None = None) -> dict:
    """Mint a rotation record dict. Raises ValueError on a refused input."""
    if len(old_priv) != 32:
        raise ValueError("old key is not a 32-byte seed")
    label = _normalize(label)
    new_pub_hex = _normalize(new_pub_hex)
    if not _valid_label(label):
        raise ValueError(f"{label!r} is not a valid .cyberspace label")
    if len(new_pub_hex) != 64:
        raise ValueError("new_pubkey is not 64 hex chars")
    try:
        bytes.fromhex(new_pub_hex)
    except ValueError:
        raise ValueError("new_pubkey is not hex")
    old_pub_hex = publickey(old_priv).hex().lower()
    if new_pub_hex == old_pub_hex:
        raise ValueError("rotation to the same key is a no-op — renew the "
                         "claim instead")
    issued_at = issued_at or _iso_now()
    payload = _rotate_payload(label, old_pub_hex, new_pub_hex, issued_at)
    sig = sign(payload, old_priv, bytes.fromhex(old_pub_hex)).hex().lower()
    return {"name": label, "old_pubkey": old_pub_hex,
            "new_pubkey": new_pub_hex, "issued_at": issued_at,
            "signature": sig}


def verify_rotation(record: dict) -> str | None:
    """Return None if the rotation verifies, else the reason it does not.

    Fail-closed on every surprise: missing/extra-shape fields, bad label,
    bad hex, bad timestamp, and — the whole point — a signature that is
    not the OLD key vouching for the NEW key.
    """
    if not isinstance(record, dict):
        return "record is not a JSON object"
    for k in ("name", "old_pubkey", "new_pubkey", "issued_at", "signature"):
        if k not in record:
            return f"missing field: {k}"
        if not isinstance(record[k], str):
            return f"field {k!r} is not a string"
    name = _normalize(record["name"])
    old_pub = _normalize(record["old_pubkey"])
    new_pub = _normalize(record["new_pubkey"])
    sig = _normalize(record["signature"])
    if not _valid_label(name):
        return f"name {name!r} is not a valid .cyberspace label"
    for field, val, want in (("old_pubkey", old_pub, 64),
                             ("new_pubkey", new_pub, 64),
                             ("signature", sig, 128)):
        try:
            raw = bytes.fromhex(val)
        except ValueError:
            return f"{field} is not hex"
        if len(raw) * 2 != want:
            return f"{field} is not {want} hex chars"
    if old_pub == new_pub:
        return "rotation to the same key is a no-op"
    try:
        issued = datetime.fromisoformat(record["issued_at"])
    except (ValueError, TypeError):
        return "issued_at is not ISO 8601"
    if issued.tzinfo is None:
        issued = issued.replace(tzinfo=timezone.utc)
    if issued > datetime.now(timezone.utc):
        return "rotation is dated in the future — not yet in force"
    payload = _rotate_payload(name, old_pub, new_pub, record["issued_at"])
    if not checkvalid(bytes.fromhex(sig), payload, bytes.fromhex(old_pub)):
        return ("signature does not verify: this rotation is not vouched "
                "for by the old name key")
    return None


def promote_rotation(label: str, home: Path) -> tuple[bool, str]:
    """Promote a minted rotation: .next becomes the name key, atomically.

    The loop-closing half of a rotation. Promotion is deliberate (an
    explicit CLI flag, never automatic), and it refuses unless EVERY link
    re-verifies — the record signature, the record in force, and both
    keys' continuity:
      - <label>-name.key.next exists (the minted new key seed)
      - <label>-rotate.json verifies AND is in force (verify_rotation)
      - the .next seed derives the record's new_pubkey
      - the CURRENT <label>-name.key still derives the record's
        old_pubkey (continuity: the operator holds the same old key
        that vouched for the record — a swapped key file refuses)

    On success: the current key seed moves to <label>-name.key.prev
    (the old key stays readable for historical verification — a verifier
    needs old keys to walk the chain), and the .next seed atomically
    replaces <label>-name.key (os.replace: never a half-written key).
    Returns (True, summary) or (False, reason). Never raises on input.
    """
    label = _normalize(label)
    if not _valid_label(label):
        return False, f"{label!r} is not a valid .cyberspace label"
    rec_path = home / f"{label}-rotate.json"
    next_path = home / f"{label}-name.key.next"
    key_path = home / f"{label}-name.key"
    prev_path = home / f"{label}-name.key.prev"
    if not next_path.exists():
        return False, (f"no pending rotation at {next_path} — "
                       f"mint one first (rotate_name.py {label})")
    if not rec_path.exists():
        return False, f"rotation record missing at {rec_path} — refuse"
    try:
        record = json.loads(rec_path.read_text())
    except (OSError, ValueError):
        return False, f"rotation record at {rec_path} is not readable JSON"
    reason = verify_rotation(record)
    if reason is not None:
        return False, f"rotation record does not verify: {reason}"
    if not key_path.exists():
        return False, (f"current name key missing at {key_path} — "
                       f"continuity broken, refuse")
    try:
        new_priv = bytes.fromhex(next_path.read_text().strip())
        old_priv = bytes.fromhex(key_path.read_text().strip())
    except (OSError, ValueError):
        return False, "key files do not hold 32-byte hex seeds"
    if len(new_priv) != 32 or len(old_priv) != 32:
        return False, "key files do not hold 32-byte seeds"
    new_pub = publickey(new_priv).hex().lower()
    old_pub = publickey(old_priv).hex().lower()
    if new_pub != _normalize(record["new_pubkey"]):
        return False, ("the .next seed does not derive the record's "
                       "new_pubkey — stale or foreign key, refuse")
    if old_pub != _normalize(record["old_pubkey"]):
        return False, ("the current name key does not derive the record's "
                       "old_pubkey — continuity broken, refuse")
    # Atomic close: old key -> .prev (kept for chain-walking history),
    # .next -> the name key. os.replace is never a half-written key.
    prev_path.write_text(old_priv.hex() + "\n")
    os.chmod(prev_path, 0o600)
    os.replace(next_path, key_path)
    os.chmod(key_path, 0o600)
    return True, (f"promoted {label}.cyberspace: "
                  f"{old_pub[:16]}... -> {new_pub[:16]}...; "
                  f"old key kept at {prev_path}")


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        description="mint a .cyberspace name-key rotation record")
    ap.add_argument("label", help="the .cyberspace label to rotate")
    ap.add_argument("--new-key-seed",
                    help="64-hex seed for the new key (else generated)")
    ap.add_argument("--promote", action="store_true",
                    help="promote <label>-name.key.next to the name key "
                         "after the record is seen in the wild")
    args = ap.parse_args(argv)
    label = _normalize(args.label)
    if not _valid_label(label):
        print(f"refused: {label!r} is not a valid .cyberspace label",
              file=sys.stderr)
        return 2
    home = Path.home() / ".cyberspace"
    if args.promote:
        ok, msg = promote_rotation(label, home)
        print(("promoted: " if ok else "refused: ") + msg,
              file=sys.stderr if not ok else sys.stdout)
        return 0 if ok else 1
    key_path = home / f"{label}-name.key"
    if not key_path.exists():
        print(f"refused: no existing name key at {key_path} — "
              f"mint the name first (mint_name.py)", file=sys.stderr)
        return 1
    try:
        old_priv = bytes.fromhex(key_path.read_text().strip())
    except (OSError, ValueError):
        print(f"refused: cannot read a 32-byte seed from {key_path}",
              file=sys.stderr)
        return 1
    if len(old_priv) != 32:
        print(f"refused: {key_path} is not a 32-byte seed", file=sys.stderr)
        return 1
    if args.new_key_seed:
        try:
            new_priv = bytes.fromhex(_normalize(args.new_key_seed))
        except ValueError:
            print("refused: --new-key-seed is not hex", file=sys.stderr)
            return 2
        if len(new_priv) != 32:
            print("refused: --new-key-seed is not a 32-byte seed",
                  file=sys.stderr)
            return 2
    else:
        new_priv = os.urandom(32)
    try:
        record = mint_rotation(label, old_priv, publickey(new_priv).hex())
    except ValueError as e:
        print(f"refused: {e}", file=sys.stderr)
        return 1
    reason = verify_rotation(record)
    if reason is not None:
        print(f"refused: self-verification failed (bug): {reason}",
              file=sys.stderr)
        return 1
    home.mkdir(parents=True, exist_ok=True)
    rec_path = home / f"{label}-rotate.json"
    rec_path.write_text(json.dumps(record, indent=2) + "\n")
    next_path = home / f"{label}-name.key.next"
    next_path.write_text(new_priv.hex())
    os.chmod(next_path, 0o600)
    print(f"valid: {label}.cyberspace rotation minted and self-verified")
    print(f"  old key {record['old_pubkey'][:16]}... -> "
          f"new key {record['new_pubkey'][:16]}...")
    print(f"  record written to {rec_path} — publish it (mirror, gossip, handoff)")
    print(f"  NEW key seed at {next_path} (0600) — promote it to "
          f"{label}-name.key only after the record is seen in the wild")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
