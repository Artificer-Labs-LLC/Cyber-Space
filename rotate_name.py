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
  ./venv/bin/python rotate_name.py <label> --submit [mirror_url]
  ./venv/bin/python rotate_name.py <label> --promote

  The rotation loop, in order: MINT -> SUBMIT -> PROMOTE.
  Mint mode loads the existing name key from ~/.cyberspace/<label>-name.key
  (the OLD key), mints and self-verifies the rotation record, writes:
    ~/.cyberspace/<label>-rotate.json     the record (publish this)
    ~/.cyberspace/<label>-name.key.next   the NEW key seed (0600)

  The old key file is NEVER overwritten by minting — promotion stays a
  deliberate operator step. Submit mode (--submit) posts the record AND
  the new binding (signed by the NEW key) to the mirror's
  /api/v1/names/rotate, then verifies the mirror moved the name:
  the live binding resolves to the new key AND the rotation hop is in
  the served chain. Promote mode (--promote) closes the loop AFTER the
  mirror accepts (submit verified it):
    ~/.cyberspace/<label>-name.key        becomes the NEW key seed (0600)
    ~/.cyberspace/<label>-name.key.prev   keeps the OLD key seed (0600)
  The .next file is consumed atomically; the promotion re-verifies the
  rotation record first (signature + in-force + continuity of both keys).
  Submit BEFORE promote: the mirror moves the binding under the OLD
  key's authority, and the operator promotes locally only once the
  record is seen in the wild.

Exit codes: 0 = done; 1 = refused (reason on stderr); 2 = usage / unreadable.
"""

import os
import sys
import json
import argparse
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime, timezone, timedelta
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fed.ed25519 import publickey, sign, checkvalid  # noqa: E402

_LABEL_MAX = 63
_DEFAULT_MIRROR = "http://127.0.0.1:8471"
_DEFAULT_EXPIRY_DAYS = 730


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


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S+00:00")


def _post_form(url: str, fields: dict, timeout: float = 30.0
               ) -> tuple[int | None, str]:
    """POST urlencoded form; returns (status, body). status None = no HTTP
    answer. Twin of mint_name's helper (server decides, client reports)."""
    data = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"


def _get_json(url: str, timeout: float = 30.0) -> dict | None:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data if isinstance(data, dict) else None
    except Exception:
        return None


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


def submit_rotation(label: str, mirror_url: str, home: Path,
                    expiry_days: int = _DEFAULT_EXPIRY_DAYS
                    ) -> tuple[bool, str]:
    """Submit a minted rotation to the mirror — the middle step of the
    loop (mint -> SUBMIT -> promote).

    Posts the rotation record AND the new binding (a fresh name-claim for
    the label, signed by the NEW key, issued now so it cannot predate the
    rotation) to the mirror's /api/v1/names/rotate. Then verifies the
    mirror actually moved the name: the live binding resolves to the new
    key AND the rotation hop is in the served chain. Fail-closed on every
    surprise — a non-200, an unparseable answer, or a resolve-back
    mismatch refuses, and nothing local is ever touched (promotion stays
    deliberate; key files are only read).

    Ordering rules, enforced client-side before anything is sent:
      - the record must verify AND be in force (verify_rotation);
      - the .next seed must derive the record's new_pubkey;
      - the current name key must still derive the record's old_pubkey —
        submit happens BEFORE promote, because the mirror only moves a
        name under the OLD key's authority. An already-promoted key file
        refuses here with the ordering spelled out.
    Returns (True, summary) or (False, reason). Never raises on input.
    """
    label = _normalize(label)
    if not _valid_label(label):
        return False, f"{label!r} is not a valid .cyberspace label"
    rec_path = home / f"{label}-rotate.json"
    next_path = home / f"{label}-name.key.next"
    key_path = home / f"{label}-name.key"
    try:
        record = json.loads(rec_path.read_text())
    except OSError:
        return False, (f"rotation record missing at {rec_path} — "
                       f"mint one first (rotate_name.py {label})")
    except ValueError:
        return False, f"rotation record at {rec_path} is not readable JSON"
    reason = verify_rotation(record)
    if reason is not None:
        return False, f"rotation record does not verify: {reason}"
    try:
        new_priv = bytes.fromhex(next_path.read_text().strip())
    except (OSError, ValueError):
        return False, (f"no pending new key at {next_path} — "
                       f"mint a rotation first (rotate_name.py {label})")
    if len(new_priv) != 32:
        return False, "new key file does not hold a 32-byte seed"
    new_pub = publickey(new_priv).hex().lower()
    if new_pub != _normalize(record["new_pubkey"]):
        return False, ("the .next seed does not derive the record's "
                       "new_pubkey — stale or foreign key, refuse")
    try:
        old_priv = bytes.fromhex(key_path.read_text().strip())
    except (OSError, ValueError):
        return False, (f"current name key missing at {key_path} — "
                       f"continuity broken, refuse")
    if len(old_priv) != 32:
        return False, "current name key does not hold a 32-byte seed"
    old_pub = publickey(old_priv).hex().lower()
    if old_pub == new_pub:
        return False, ("the name key is already the NEW key — submit BEFORE "
                       "promoting; the mirror only moves a name under the "
                       "old key's authority, nothing was sent")
    if old_pub != _normalize(record["old_pubkey"]):
        return False, ("the current name key does not derive the record's "
                       "old_pubkey — continuity broken, refuse")
    # Mint the new binding under the NEW key (the next claim). Issued now:
    # it can never predate the rotation (the record is in force, never
    # future), and the mirror demands the chain move forward in time.
    now = datetime.now(timezone.utc)
    issued_at = _iso(now)
    expires_at = _iso(now + timedelta(days=max(1, expiry_days)))
    payload = (b"name-claim|" + label.encode() + b"|" + new_pub.encode()
               + b"|" + issued_at.encode() + b"|" + expires_at.encode())
    sig = sign(payload, new_priv, bytes.fromhex(new_pub)).hex().lower()
    fields = {"name": label, "old_pubkey": old_pub, "new_pubkey": new_pub,
              "rotation_issued_at": record["issued_at"],
              "rotation_signature": record["signature"],
              "binding_issued_at": issued_at,
              "binding_expires_at": expires_at, "binding_signature": sig}
    status, body = _post_form(
        mirror_url.rstrip("/") + "/api/v1/names/rotate", fields)
    if status is None:
        return False, f"mirror did not answer: {body[:120]}"
    if status != 200:
        return False, f"mirror refused ({status}): {body.strip()[:200]}"
    try:
        result = json.loads(body)
    except ValueError:
        return False, f"unparseable rotate response: {body[:120]!r}"
    if result.get("status") != "rotated":
        return False, f"mirror did not confirm rotation: {body[:120]!r}"
    # Verify the mirror moved the name, then trust it — never before.
    resolved = _get_json(mirror_url.rstrip("/") + f"/api/v1/names/{label}")
    if not resolved or resolved.get("node_pubkey", "").lower() != new_pub:
        return False, ("mirror accepted the rotation but the name does not "
                       "resolve to the new key — investigate before "
                       "promoting")
    chain = _get_json(
        mirror_url.rstrip("/") + f"/api/v1/names/{label}/rotations")
    hop_seen = False
    if isinstance(chain, dict):
        for hop in chain.get("rotations") or []:
            if (_normalize(hop.get("old_pubkey", "")) == old_pub
                    and _normalize(hop.get("new_pubkey", "")) == new_pub
                    and _normalize(hop.get("signature", ""))
                    == _normalize(record["signature"])):
                hop_seen = True
                break
    if not hop_seen:
        return False, ("mirror accepted the rotation but the hop is not in "
                       "the served chain — investigate before promoting")
    return True, (f"submitted {label}.cyberspace rotation to {mirror_url}: "
                  f"{old_pub[:16]}... -> {new_pub[:16]}...; the name now "
                  f"resolves to the new key and the hop is in the served "
                  f"chain — promote the new key when ready "
                  f"(rotate_name.py {label} --promote)")


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        description="mint a .cyberspace name-key rotation record")
    ap.add_argument("label", help="the .cyberspace label to rotate")
    ap.add_argument("--new-key-seed",
                    help="64-hex seed for the new key (else generated)")
    ap.add_argument("--submit", nargs="?", const=_DEFAULT_MIRROR,
                    metavar="MIRROR_URL",
                    help="submit the minted rotation + new binding to the "
                         "mirror's /api/v1/names/rotate (default: "
                         f"{_DEFAULT_MIRROR}), then verify the mirror moved "
                         "the name")
    ap.add_argument("--expiry-days", type=int, default=_DEFAULT_EXPIRY_DAYS,
                    help="liveness window of the new binding on submit "
                         f"(default {_DEFAULT_EXPIRY_DAYS})")
    ap.add_argument("--promote", action="store_true",
                    help="promote <label>-name.key.next to the name key "
                         "after the record is seen in the wild")
    args = ap.parse_args(argv)
    label = _normalize(args.label)
    if not _valid_label(label):
        print(f"refused: {label!r} is not a valid .cyberspace label",
              file=sys.stderr)
        return 2
    if args.submit is not None and args.promote:
        print("refused: --submit and --promote are separate steps — "
              "submit first, promote only after the mirror accepts",
              file=sys.stderr)
        return 2
    home = Path.home() / ".cyberspace"
    if args.submit is not None:
        ok, msg = submit_rotation(label, args.submit, home, args.expiry_days)
        print(("submitted: " if ok else "refused: ") + msg,
              file=sys.stderr if not ok else sys.stdout)
        return 0 if ok else 1
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
    print(f"  record written to {rec_path} — submit it to a mirror next")
    print(f"    (rotate_name.py {label} --submit), then promote the new key")
    print(f"    only after the mirror accepts (rotate_name.py {label} --promote)")
    print(f"  NEW key seed at {next_path} (0600)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
