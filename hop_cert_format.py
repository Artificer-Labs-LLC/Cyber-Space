"""Canonical rotation-cert serializer (v1 and v2). Pure functions only:
stdlib hashlib/json, no libsodium, no verify path, no I/O at import. The
pin-rotation track imports this module; do not change the byte format
without telling the KINDS / pin-rotation owners.

  v1  name-rotate|<name>|<old_pub>|<new_pub>|<issued_at>
  v2  name-rotate/v2|<name>|<seq>|<prev_hash>|<old_pub>|<new_pub>|<issued_at>
cert_hash covers the full cert, signature included.
"""
import hashlib
import json

CERT_DOMAIN = b"cyberspace-rotate-cert/v0\n"
CLAIM_DOMAIN = b"cyberspace-claim-anchor/v0\n"
ROW_FIELDS = ("name", "i", "old", "new", "issued_at", "sig", "v", "seq", "prev_hash")


def norm(k) -> str:
    return k.strip().lower() if isinstance(k, str) else ""


def v1_payload(name, old, new, issued_at) -> bytes:
    return (b"name-rotate|" + name.encode() + b"|" + old.encode() + b"|" + new.encode()
            + b"|" + issued_at.encode())


def v2_payload(name, seq, prev_hash, old, new, issued_at) -> bytes:
    return "|".join(["name-rotate/v2", name, str(int(seq)), prev_hash, old, new,
                     issued_at]).encode()


def claim_anchor(name: str, claim_pub: str) -> str:
    return hashlib.sha256(CLAIM_DOMAIN + f"{name}|{norm(claim_pub)}".encode()).hexdigest()


def cert_hash(row: dict) -> str:
    body = json.dumps([row["v"], row["name"], row.get("seq"), row.get("prev_hash"),
                       row["old"], row["new"], row["issued_at"], row["sig"]],
                      separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(CERT_DOMAIN + body.encode("ascii")).hexdigest()
