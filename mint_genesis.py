#!/usr/bin/env python3
"""Mint the genesis name-key attestation for .cyberspace.

Her Grace's word authorizes this. The script:
1. Generates a dedicated ed25519 keypair for the "genesis" name
2. Creates the self-certifying binding (signed by the name key itself)
3. Submits it to the target node's /api/v1/names/claim
4. Verifies it resolves via /api/v1/names/genesis

The private key is written to ~/.cyberspace/genesis-name.key (0600).
GUARD THIS KEY — it is the root of the .cyberspace namespace.

Usage: ./venv/bin/python mint_genesis.py [node_url]
Default node_url: http://185.143.228.228 (HQ public node)
"""

import os
import sys
import json
import urllib.request
import urllib.error
from datetime import datetime, timezone, timedelta
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fed.ed25519 import publickey, sign
import nacl.signing

NODE_URL = sys.argv[1] if len(sys.argv) > 1 else "http://185.143.228.228"
KEY_PATH = Path.home() / ".cyberspace" / "genesis-name.key"

def main():
    # 1. Generate or load the genesis name key
    KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(KEY_PATH.parent, 0o700)  # agent home holds secrets: never group/other-listable
    if KEY_PATH.exists():
        print(f"Loading existing genesis name key from {KEY_PATH}")
        privkey = bytes.fromhex(KEY_PATH.read_text().strip())
        pubkey = publickey(privkey)
    else:
        print("Generating new genesis name keypair...")
        privkey = os.urandom(32)
        pubkey = publickey(privkey)
        KEY_PATH.write_text(privkey.hex())
        os.chmod(KEY_PATH, 0o600)
        print(f"Private key written to {KEY_PATH} (0600)")

    pubkey_hex = pubkey.hex()
    print(f"Name key (pub): {pubkey_hex[:16]}...{pubkey_hex[-16:]}")

    # 2. Create the binding
    now = datetime.now(timezone.utc)
    issued_at = now.strftime("%Y-%m-%dT%H:%M:%S+00:00")
    # 10 year expiry — the namespace root should be long-lived
    expires_at = (now + timedelta(days=3650)).strftime("%Y-%m-%dT%H:%M:%S+00:00")

    payload = (b"name-claim|genesis|" + pubkey_hex.lower().encode() + b"|"
               + issued_at.encode() + b"|" + expires_at.encode())
    sig = sign(payload, privkey, pubkey)

    binding = {
        "name": "genesis",
        "node_pubkey": pubkey_hex.lower(),
        "issued_at": issued_at,
        "expires_at": expires_at,
        "signature": sig.hex().lower(),
    }

    print(f"Binding: genesis -> {pubkey_hex[:16]}...")
    print(f"  issued: {issued_at}")
    print(f"  expires: {expires_at} (10 years)")

    # 3. Submit to the node
    print(f"\nSubmitting to {NODE_URL}/api/v1/names/claim ...")
    data = urllib.parse.urlencode(binding).encode()
    req = urllib.request.Request(
        NODE_URL + "/api/v1/names/claim",
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read())
            print(f"✓ Claimed: {result.get('status')}")
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        print(f"✗ HTTP {e.code}: {body}")
        if e.code == 409:
            print("Name already claimed — the attestation exists.")
        sys.exit(1)

    # 4. Verify it resolves
    print(f"\nVerifying via {NODE_URL}/api/v1/names/genesis ...")
    with urllib.request.urlopen(NODE_URL + "/api/v1/names/genesis", timeout=30) as resp:
        resolved = json.loads(resp.read())
        if resolved.get("node_pubkey", "").lower() == pubkey_hex.lower():
            print("✓ genesis.cyberspace resolves to the name key")
            print("\nThe namespace is real. .cyberspace lives.")
        else:
            print("✗ MISMATCH: resolved key does not match!")
            sys.exit(1)

if __name__ == "__main__":
    import urllib.parse
    main()
