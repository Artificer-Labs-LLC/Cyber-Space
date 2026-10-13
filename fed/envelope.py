"""Signed-message envelope — Federation v0 (docs/FEDERATION.md).

Any inter-node message carries the sender's public key and a signature over
(timestamp, recipient, body hash). Receivers verify against the advertised
key and reject stale timestamps (>5 min skew).

Everything hangs on this module: /fed/ping, /fed/announce, DM relay, and
channel links all ride on it.
"""

import hashlib
import json
import time

from . import ed25519

VERSION = "fed/0"
MAX_SKEW_SEC = 300


def _canonical(ts: int, recipient: str, body_hash: bytes) -> bytes:
    """Build the exact bytes that get signed: length-prefixed, unambiguous."""
    r = recipient.encode()
    return b"".join(
        [
            VERSION.encode(),
            ts.to_bytes(8, "big"),
            len(r).to_bytes(2, "big"),
            r,
            body_hash,
        ]
    )


def make_envelope(privkey_hex: str, sender_pub_hex: str, recipient: str,
                  body, ts: int = None) -> dict:
    """Create a signed envelope for `body` (JSON-serializable)."""
    ts = int(ts if ts is not None else time.time())
    payload = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    body_hash = hashlib.sha256(payload).digest()
    msg = _canonical(ts, recipient, body_hash)
    priv_b = bytes.fromhex(privkey_hex)
    pub_b = bytes.fromhex(sender_pub_hex)
    # Decoded-length gates, twin of core._reach_mint: bytes.fromhex
    # ignores embedded spaces, so a spaced 64-char seed or pubkey
    # decodes to 31 bytes and sign() silently minted an envelope
    # verify_envelope itself refuses (checkvalid length-gates the
    # pubkey decode) — an envelope no seat accepts, contradicting
    # the mint contract. Only 32-byte decodes mint.
    if len(priv_b) != 32 or len(pub_b) != 32:
        raise ValueError("sender seed and pubkey must decode to 32 bytes")
    sig = ed25519.sign(msg, priv_b, pub_b)
    return {
        "v": VERSION,
        "sender_pub": sender_pub_hex,
        "ts": ts,
        "recipient": recipient,
        "body_hash": body_hash.hex(),
        "body": body,
        "sig": sig.hex(),
    }


def verify_envelope(env: dict, now: float = None) -> bool:
    """Verify a received envelope. Fail-closed: anything off -> False."""
    try:
        if not isinstance(env, dict):
            return False
        for k in ("v", "sender_pub", "ts", "recipient", "body_hash", "body", "sig"):
            if k not in env:
                return False
        if env["v"] != VERSION:
            return False
        if abs((now if now is not None else time.time()) - env["ts"]) > MAX_SKEW_SEC:
            return False
        payload = json.dumps(env["body"], sort_keys=True, separators=(",", ":")).encode()
        if hashlib.sha256(payload).hexdigest() != env["body_hash"]:
            return False
        # String-length + decoded-length gates, twin of
        # verify_rotation (3fbb38b) and _reach_descriptor_verify
        # (93c1a79): bytes.fromhex ignores embedded spaces, so a
        # 129-char sig (or 65-char sender_pub) with an inserted space
        # decoded to the TRUE bytes and VERIFIED — neither string is
        # part of the signed canonical form, yet receivers use
        # env["sender_pub"] as the identity string (rate-limit keys,
        # row-owner comparisons, writes), so a spaced spelling was a
        # second identity for the same key, in a spelling every
        # binding seat refuses on sight (len(signature) != 128).
        # Only the exact 128/64-char spellings verify; case is left
        # alone (uppercase verified before and still does).
        if not isinstance(env["sender_pub"], str) \
                or len(env["sender_pub"]) != 64 \
                or len(bytes.fromhex(env["sender_pub"])) != 32:
            return False
        if not isinstance(env["sig"], str) \
                or len(env["sig"]) != 128 \
                or len(bytes.fromhex(env["sig"])) != 64:
            return False
        msg = _canonical(env["ts"], env["recipient"],
                         bytes.fromhex(env["body_hash"]))
        return ed25519.checkvalid(bytes.fromhex(env["sig"]), msg,
                                  bytes.fromhex(env["sender_pub"]))
    except Exception:
        return False


if __name__ == "__main__":
    # RFC 8032 test vector: curve implementation sanity check.
    sk = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
    pk = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    got = ed25519.publickey(bytes.fromhex(sk)).hex()
    assert got == pk, f"publickey mismatch: {got}"
    print("RFC8032 vector: OK")

    # Envelope round-trip.
    import secrets
    seed = secrets.token_hex(32)
    pub = ed25519.publickey(bytes.fromhex(seed)).hex()
    env = make_envelope(seed, pub, "peer-node", {"ping": 1, "caps": ["messaging"]})
    assert verify_envelope(env), "valid envelope rejected"
    print("round-trip: OK")

    # Tampered body.
    bad = dict(env); bad["body"] = {"ping": 2}
    assert not verify_envelope(bad), "tampered body accepted"
    print("tamper rejection: OK")

    # Wrong key.
    seed2 = secrets.token_hex(32)
    bad = dict(env); bad["sender_pub"] = ed25519.publickey(bytes.fromhex(seed2)).hex()
    assert not verify_envelope(bad), "wrong key accepted"
    print("wrong-key rejection: OK")

    # Stale timestamp.
    bad = dict(env); bad["ts"] = env["ts"] - 3600
    assert not verify_envelope(bad), "stale ts accepted"
    print("stale rejection: OK")

    # Fresh sig over old ts should fail because we re-sign in make, but
    # replay of a stale envelope must fail (covered above). Also confirm
    # a fresh re-sign at old ts is caught by skew, not by signature.
    bad = make_envelope(seed, pub, "peer-node", env["body"], ts=env["ts"] - 3600)
    assert not verify_envelope(bad), "re-signed stale envelope accepted"
    print("replay rejection: OK")

    print("ALL ENVELOPE TESTS PASS")
