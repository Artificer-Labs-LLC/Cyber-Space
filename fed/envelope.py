"""Signed-message envelope — Federation v0 (docs/FEDERATION.md).

Any inter-node message carries the sender's public key and a signature over
(timestamp, recipient, body hash). Receivers verify against the advertised
key and reject stale timestamps (>5 min skew).

Everything hangs on this module: /fed/ping, /fed/announce, DM relay, and
channel links all ride on it.
"""

import hashlib
import json
import re
import time

from . import ed25519

VERSION = "fed/0"
MAX_SKEW_SEC = 300
# Wire v0 kind: bound into the signature so one route's envelope cannot
# verify on another route inside the skew window (Villhaze 5a602248).
_KIND_RE = re.compile(r"[a-z0-9-]{1,32}")


def _canonical(ts: int, recipient: str, body_hash: bytes,
               kind: str | None = None) -> bytes:
    """Build the exact bytes that get signed: length-prefixed, unambiguous.

    `kind` is part of the signed bytes when the envelope carries one.
    An envelope with no kind keeps the historical canonical form so a
    reader can still verify an old ping; every production route sets a
    kind and refuses a mismatch.
    """
    r = recipient.encode()
    parts = [
        VERSION.encode(),
        ts.to_bytes(8, "big"),
        len(r).to_bytes(2, "big"),
        r,
    ]
    if kind is not None:
        k = kind.encode()
        parts.append(len(k).to_bytes(2, "big"))
        parts.append(k)
    parts.append(body_hash)
    return b"".join(parts)


def make_envelope(privkey_hex: str, sender_pub_hex: str, recipient: str,
                  body, ts: int = None, kind: str | None = None) -> dict:
    """Create a signed envelope for `body` (JSON-serializable).

    Pass `kind` on every production route. The kind is covered by the
    signature. Omitting it is only for verifying a historical envelope
    that never carried one.
    """
    if kind is not None and not _KIND_RE.fullmatch(kind):
        raise ValueError("envelope kind must be 1-32 chars of [a-z0-9-]")
    ts = int(ts if ts is not None else time.time())
    payload = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    body_hash = hashlib.sha256(payload).digest()
    msg = _canonical(ts, recipient, body_hash, kind)
    sig = ed25519.sign(msg, bytes.fromhex(privkey_hex),
                       bytes.fromhex(sender_pub_hex))
    env = {
        "v": VERSION,
        "sender_pub": sender_pub_hex,
        "ts": ts,
        "recipient": recipient,
        "body_hash": body_hash.hex(),
        "body": body,
        "sig": sig.hex(),
    }
    if kind is not None:
        env["kind"] = kind
    return env


def verify_envelope(env: dict, now: float = None,
                    expect_kind: str | None = None) -> bool:
    """Verify a received envelope. Fail-closed: anything off -> False.

    `expect_kind` is the route's message type. A missing kind, or a kind
    that belongs to another route, is a refusal — the signature is over
    the kind, so a borrowed envelope cannot be replayed across routes.
    """
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
        kind = env.get("kind") if "kind" in env else None
        if expect_kind is not None:
            if kind != expect_kind:
                return False
        if kind is not None and (not isinstance(kind, str)
                                 or not _KIND_RE.fullmatch(kind)):
            return False
        payload = json.dumps(env["body"], sort_keys=True, separators=(",", ":")).encode()
        if hashlib.sha256(payload).hexdigest() != env["body_hash"]:
            return False
        msg = _canonical(env["ts"], env["recipient"],
                         bytes.fromhex(env["body_hash"]), kind)
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

    # Kind is bound. An announce envelope must not verify as gossip.
    kinded = make_envelope(seed, pub, "peer-node", {"ping": 1}, kind="announce")
    assert verify_envelope(kinded, expect_kind="announce"), "kinded envelope rejected"
    assert not verify_envelope(kinded, expect_kind="gossip"), "cross-route kind accepted"
    assert not verify_envelope(kinded, expect_kind="ping"), "missing-kind route accepted a foreign kind"
    swapped = dict(kinded)
    swapped["kind"] = "gossip"
    assert not verify_envelope(swapped, expect_kind="gossip"), "re-labeled kind accepted"
    print("kind binding: OK")

    print("ALL ENVELOPE TESTS PASS")
