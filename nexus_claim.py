#!/usr/bin/env python3
"""Claim nexus.cyberspace with the KEPT key ONLY — never generates.

Third split step of the Nexus root claim, after nexus_keygen.py
(generation only) and nexus_preflight.py (readiness only):

  1. nexus_preflight must report READY for the exact key + backup
     seats given — kept key, verified byte-matching backup, tree
     carries the gossip receive route and the pin. Any blocker and
     this tool sends NOTHING (exit 1). The genesis loss (claimed
     2026-10-08, key unsaved, locked until 2027-10-08, name abandoned
     by the 2026-10-15 root-name ruling) was a fused generate+claim;
     every step of the Nexus claim is separate and fail-closed.
  2. The binding is built exactly as mint_name builds it
     (name-claim|<label>|<pub>|<issued>|<expires>, signed by the
     name key itself) and POSTed to the mirror's /api/v1/names/claim.
     409 = already claimed (exit 1). The claim is verified by
     resolving the name back at the same mirror and requiring the
     served pub to equal the kept key's pub.
  3. Only after that verification is the hostd env written
     (mint_name._hostd_env_text, born-0600, overwrite).

--dry-run builds and signs the binding, prints it, and sends
nothing: the supervised preview of exactly what a real run would
broadcast. This tool NEVER generates a key, NEVER overwrites one,
and has no label argument — the root label is fixed to "nexus".

Usage: ./venv/bin/python nexus_claim.py [mirror_url]
         [--key PATH] [--backup PATH] [--env-dir DIR]
         [--expiry-days N] [--dry-run]
Exit codes: 0 = claimed (or dry-run built), 1 = refused at a gate
or by the mirror, 2 = usage / bad argument (nothing sent).
"""

import json
import os
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mint_name as mn  # noqa: E402
import nexus_preflight as np  # noqa: E402
from fed.ed25519 import publickey, sign  # noqa: E402

_LABEL = "nexus"
_ROOT = Path(os.path.dirname(os.path.abspath(__file__)))


def build_binding(priv, expiry_days, now=None):
    """The self-certifying binding, byte-shape twin of mint_name's."""
    pub_hex = publickey(priv).hex().lower()
    now = now or datetime.now(timezone.utc)
    issued_at = mn._iso(now)
    expires_at = mn._iso(now + timedelta(days=expiry_days))
    payload = (b"name-claim|" + _LABEL.encode() + b"|" + pub_hex.encode()
               + b"|" + issued_at.encode() + b"|" + expires_at.encode())
    sig = sign(payload, priv, publickey(priv)).hex().lower()
    return {"name": _LABEL, "node_pubkey": pub_hex,
            "issued_at": issued_at, "expires_at": expires_at,
            "signature": sig}


def claim(key_path, backup_path, mirror, env_dir,
          expiry_days=mn._DEFAULT_EXPIRY_DAYS, dry_run=False,
          post=None, get=None):
    """Return (exit_code, binding | None, notes). Sends nothing
    unless preflight is READY and the mirror argument is dialable."""
    post = mn._post_form if post is None else post
    get = mn._get_json if get is None else get
    if not mn._valid_mirror(mirror):
        return 2, None, ["mirror is not a dialable http(s) URL"]
    if not (1 <= expiry_days <= mn._EXPIRY_DAYS_CAP):
        return 2, None, [f"expiry-days {expiry_days} outside "
                          f"1-{mn._EXPIRY_DAYS_CAP}"]
    ready, pub_hex, blockers = np.preflight(_LABEL, key_path,
                                             backup_path, _ROOT)
    if not ready:
        return 1, None, [f"preflight BLOCKER: {b}" for b in blockers]
    try:
        priv = mn._read_seed(Path(key_path))
    except (OSError, ValueError):
        return 2, None, [f"kept key at {key_path} does not hold a "
                         f"64-hex-char seed — nothing sent"]
    if len(priv) != 32 or publickey(priv).hex().lower() != pub_hex:
        return 1, None, ["kept key does not derive the preflight pub "
                         "— nothing sent"]
    binding = build_binding(priv, expiry_days)
    if dry_run:
        return 0, binding, ["dry-run: binding built and signed, "
                            "nothing sent, no env written"]
    status, body = post(mirror.rstrip("/") + "/api/v1/names/claim",
                        binding)
    if status == 409:
        return 1, binding, [f"taken: {_LABEL}.cyberspace is already "
                            f"claimed ({body.strip()[:120]})"]
    if status != 200:
        return 1, binding, [f"claim got {status}: {body.strip()[:200]}"]
    try:
        result = json.loads(body)
    except Exception:
        return 1, binding, [f"unparseable claim response: {body[:120]!r}"]
    if not isinstance(result, dict):
        return 1, binding, [f"unparseable claim response: {body[:120]!r}"]
    resolved = get(mirror.rstrip("/") + f"/api/v1/names/{_LABEL}")
    resolved_pub = resolved.get("node_pubkey") if resolved else None
    if (not isinstance(resolved_pub, str)
            or resolved_pub.lower() != pub_hex):
        return 1, binding, ["name does not resolve back to the kept "
                            "key — mirror accepted but did not store; "
                            "no env written"]
    env_dir = Path(env_dir)
    env_dir.mkdir(parents=True, exist_ok=True)
    env_path = env_dir / f"{_LABEL}.env"
    mn._write_secret(env_path,
                     mn._hostd_env_text(_LABEL, priv.hex(), mirror),
                     overwrite=True)
    return 0, binding, [f"claimed: {result.get('status')}",
                        f"verified: {_LABEL}.cyberspace resolves to "
                        f"the kept key",
                        f"hostd env written to {env_path} (0600)"]


def main(argv):
    key_path = Path.home() / ".cyberspace" / f"{_LABEL}-name.key"
    backup_path = Path.home() / ".cyberspace" / f"{_LABEL}-name.key.bak"
    env_dir = Path.home() / ".cyberspace" / "hostd"
    expiry_days = mn._DEFAULT_EXPIRY_DAYS
    dry_run = False
    args = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("-h", "--help"):
            print(__doc__.strip())
            return 0
        if a == "--dry-run":
            dry_run = True
        elif a in ("--key", "--backup", "--env-dir", "--expiry-days"):
            i += 1
            if i >= len(argv):
                print(f"refused: {a} needs a value", file=sys.stderr)
                return 2
            v = argv[i]
            if a == "--key":
                key_path = Path(v)
            elif a == "--backup":
                backup_path = Path(v)
            elif a == "--env-dir":
                env_dir = Path(v)
            else:
                txt = v.strip()
                digits = txt[1:] if txt[:1] in ("+", "-") else txt
                if not digits or not digits.isascii() or not digits.isdigit():
                    print("refused: --expiry-days must be an integer",
                          file=sys.stderr)
                    return 2
                expiry_days = int(txt)
        elif a.startswith("--"):
            print(f"refused: unknown argument {a!r}", file=sys.stderr)
            return 2
        else:
            args.append(a)
        i += 1
    if len(args) > 1:
        print("usage: nexus_claim.py [mirror_url] [--key PATH] "
              "[--backup PATH] [--env-dir DIR] [--expiry-days N] "
              "[--dry-run]", file=sys.stderr)
        return 2
    mirror = args[0] if args else "http://127.0.0.1:8471"
    code, binding, notes = claim(key_path, backup_path, mirror, env_dir,
                                 expiry_days, dry_run)
    if binding is not None:
        print(f"Nexus binding: {json.dumps(binding, sort_keys=True)}")
    for n in notes:
        print(n, file=sys.stderr if code else sys.stdout)
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
