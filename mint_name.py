#!/usr/bin/env python3
"""Mint a .cyberspace name for an agent: name key + claim + hostd env.

The front door of primitive 6 (the daemon every agent runs). One command
turns an agent into a hostable .cyberspace name:

  1. Generates a dedicated Ed25519 NAME KEY (never the master identity)
     at ~/.cyberspace/<label>-name.key (0600), or loads the existing one.
  2. Builds the self-certifying binding name-claim|<label>|<pub>|<issued>|<expires>,
     signed by the name key itself, and POSTs it to the mirror's
     /api/v1/names/claim. First-claim wins; 409 means the name is taken.
  3. Verifies the name resolves back to the name key at the mirror.
  4. Writes the hostd env file (CYBERNET_HOSTED_NAME + CYBERNET_NAME_PRIVKEY,
     0600) that deploy/hostd.service expects at /etc/cybernet-hostd/hostd.env.

Usage: ./venv/bin/python mint_name.py <label> [mirror_url] [--env-dir DIR]
  mirror_url defaults to http://127.0.0.1:8471 (the local node).
  --env-dir defaults to ~/.cyberspace/hostd (writes <label>.env there).
  --expiry-days defaults to 730 (2 years). The binding is renewable by
  re-signing with the same key before expiry.

The server is the authority on every rule: the label grammar here is a
client-side fast check (mirrors core._valid_name_label); the claim endpoint
re-validates and refuses anything malformed. Fail-closed throughout: any
surprise exits nonzero with the reason, never half-written state.
"""

import os
import sys
import json
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime, timezone, timedelta
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fed.ed25519 import publickey, sign  # noqa: E402

_LABEL_MAX = 63
_DEFAULT_EXPIRY_DAYS = 730


def _valid_label(label: str) -> bool:
    """Client-side fast check; mirrors core._valid_name_label (server decides)."""
    if not label or len(label) > _LABEL_MAX:
        return False
    if label != label.lower() or "." in label:
        return False
    if label.startswith("-") or label.endswith("-"):
        return False
    return all(c.isalnum() or c == "-" for c in label)


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S+00:00")


def _post_form(url: str, fields: dict, timeout: float = 30.0) -> tuple[int | None, str]:
    """POST urlencoded form; returns (status, body). status None = no HTTP answer."""
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


def main(argv: list[str]) -> int:
    args = [a for a in argv if not a.startswith("--")]
    opts = {a.split("=", 1)[0]: (a.split("=", 1)[1] if "=" in a else "")
            for a in argv if a.startswith("--")}
    if len(args) < 1:
        print("usage: mint_name.py <label> [mirror_url] [--env-dir DIR] [--expiry-days N]",
              file=sys.stderr)
        return 2
    label = args[0].strip().lower()
    mirror = args[1] if len(args) > 1 else "http://127.0.0.1:8471"
    if not _valid_label(label):
        print(f"refused: {label!r} is not a valid .cyberspace label "
              f"(lowercase alnum/hyphen, 1-{_LABEL_MAX} chars, no dots, no edge hyphens)",
              file=sys.stderr)
        return 2
    try:
        expiry_days = max(1, int(opts.get("--expiry-days", _DEFAULT_EXPIRY_DAYS)))
    except ValueError:
        print("refused: --expiry-days must be an integer", file=sys.stderr)
        return 2

    home = Path.home() / ".cyberspace"
    home.mkdir(parents=True, exist_ok=True)
    key_path = home / f"{label}-name.key"
    if key_path.exists():
        priv = bytes.fromhex(key_path.read_text().strip())
        if len(priv) != 32:
            print(f"refused: {key_path} is not a 32-byte seed", file=sys.stderr)
            return 2
        print(f"Loading existing name key from {key_path}")
    else:
        priv = os.urandom(32)
        key_path.write_text(priv.hex())
        os.chmod(key_path, 0o600)
        print(f"Generated name keypair; private key written to {key_path} (0600)")
    pub = publickey(priv)
    pub_hex = pub.hex().lower()
    print(f"Name key (pub): {pub_hex[:16]}...{pub_hex[-16:]}")

    now = datetime.now(timezone.utc)
    issued_at = _iso(now)
    expires_at = _iso(now + timedelta(days=expiry_days))
    payload = (b"name-claim|" + label.encode() + b"|" + pub_hex.encode()
               + b"|" + issued_at.encode() + b"|" + expires_at.encode())
    sig = sign(payload, priv, pub).hex().lower()
    binding = {"name": label, "node_pubkey": pub_hex, "issued_at": issued_at,
               "expires_at": expires_at, "signature": sig}

    print(f"\nClaiming {label}.cyberspace at {mirror} ...")
    status, body = _post_form(mirror.rstrip("/") + "/api/v1/names/claim", binding)
    if status == 409:
        print(f"taken: {label}.cyberspace is already claimed ({body.strip()[:120]})",
              file=sys.stderr)
        return 1
    if status != 200:
        print(f"refused: claim got {status}: {body.strip()[:200]}", file=sys.stderr)
        return 1
    try:
        result = json.loads(body)
    except Exception:
        print(f"refused: unparseable claim response: {body[:120]!r}", file=sys.stderr)
        return 1
    print(f"Claimed: {result.get('status')}")

    resolved = _get_json(mirror.rstrip("/") + f"/api/v1/names/{label}")
    if not resolved or resolved.get("node_pubkey", "").lower() != pub_hex:
        print("refused: name does not resolve back to the name key — "
              "mirror accepted but did not store; investigate before hosting",
              file=sys.stderr)
        return 1
    print(f"Verified: {label}.cyberspace resolves to the name key")

    env_dir = Path(opts.get("--env-dir", str(home / "hostd")))
    env_dir.mkdir(parents=True, exist_ok=True)
    env_path = env_dir / f"{label}.env"
    env_path.write_text(
        f"# hostd env for {label}.cyberspace — install as /etc/cybernet-hostd/hostd.env (0600)\n"
        f"# Holds the NAME KEY only. Never the master identity. Guard this file.\n"
        f"CYBERNET_HOSTED_NAME={label}\n"
        f"CYBERNET_NAME_PRIVKEY={priv.hex()}\n"
        f"# CYBERNET_MIRROR_URL={mirror.rstrip('/')}\n"
        f"# Relay hold-open (NAT-hidden hosting): uncomment ALL THREE together —\n"
        f"# a half-filled relay config is read as direct-dial only (fail-closed).\n"
        f"# CYBERNET_RELAY_URL=\n"
        f"# CYBERNET_RELAY_PUBKEY=\n"
        f"# CYBERNET_RELAY_TOKEN=\n"
        f"# CYBERNET_PUBLIC_URL=\n")
    os.chmod(env_path, 0o600)
    print(f"hostd env written to {env_path} (0600) — "
          f"run: python -m resolver.host  (see deploy/hostd.service)")
    print(f"\n{label}.cyberspace is yours. The namespace grows by one.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
