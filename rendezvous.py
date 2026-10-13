"""Derived-point rendezvous KDF (docs/RENDEZVOUS.md, docs/HOSTING.md, primitive 3).

Pure shared math both sides run identically, no exchange: hoster and
dialer each derive the meeting point from the name key and the epoch,
then pair at a mirror without ever telling the mirror whose name it is
pairing. The point_id is an opaque 64-hex token, never an identity —
session material is still name-key-signed end-to-end.

    epoch    = floor(now / epoch_len)           (unix-epoch aligned)
    point_id = sha256("cybernet-rendezvous-v1:" || name_pub_32B
                      || epoch_8B_BE).hex()

Epoch-boundary tolerance (frozen 2026-10-09): both sides derive E and
E-1; the dialer tries E first, then E-1; the hoster holds both at the
same mirror; mirrors answer willing for current-or-previous epoch only,
older epochs fail closed and silent.

This module never touches the network, the DB, or any key material
beyond the name pubkey bytes it is handed. Every check returns None or
False instead of raising across its boundary; callers fail closed.
"""

import hashlib
import math

RENDEZVOUS_DST = b"cybernet-rendezvous-v1:"

# epoch_len bounds from the frozen descriptor spec: seconds per epoch.
EPOCH_LEN_MIN = 60
EPOCH_LEN_MAX = 86400
EPOCH_LEN_DEFAULT = 3600

_NAME_PUB_HEX_LEN = 64  # name key is 64 hex in descriptors, 32B on the wire


def _epoch_len_ok(epoch_len) -> bool:
    return (isinstance(epoch_len, int) and not isinstance(epoch_len, bool)
            and EPOCH_LEN_MIN <= epoch_len <= EPOCH_LEN_MAX)


def _name_pub_bytes(name_pub_hex) -> bytes | None:
    """32-byte name pubkey from descriptor hex, None if malformed."""
    if not isinstance(name_pub_hex, str) or len(name_pub_hex) != _NAME_PUB_HEX_LEN:
        return None
    try:
        raw = bytes.fromhex(name_pub_hex)
    except ValueError:
        return None
    return raw


def epoch_for(now: float, epoch_len: int = EPOCH_LEN_DEFAULT) -> int | None:
    """Whole epochs since the unix epoch. None on invalid epoch_len."""
    if not _epoch_len_ok(epoch_len):
        return None
    if isinstance(now, bool):
        return None
    try:
        now_f = float(now)
    except (TypeError, ValueError, OverflowError):
        return None
    if not math.isfinite(now_f) or now_f < 0:
        return None
    return int(now_f // epoch_len)


def derive_point_id(name_pub_hex: str, epoch: int) -> str | None:
    """One 64-hex point_id, computed identically by both sides.

    None on malformed name key or epoch (callers fail closed).
    """
    raw = _name_pub_bytes(name_pub_hex)
    if raw is None:
        return None
    if (not isinstance(epoch, int) or isinstance(epoch, bool)
            or epoch < 0 or epoch > 0xFFFFFFFFFFFFFFFF):
        return None
    return hashlib.sha256(
        RENDEZVOUS_DST + raw + epoch.to_bytes(8, "big")).hexdigest()


def derive_points(now: float, name_pub_hex: str,
                  epoch_len: int = EPOCH_LEN_DEFAULT) -> tuple | None:
    """(point_E, point_Eminus1) — the pair each side holds/queries.

    The dialer tries E first, then E-1; the hoster holds both at the same
    mirror (paired from the name, not steered). None on invalid input —
    never guess a point from bad parameters.
    """
    epoch = epoch_for(now, epoch_len)
    if epoch is None:
        return None
    cur = derive_point_id(name_pub_hex, epoch)
    prev = derive_point_id(name_pub_hex, epoch - 1) if epoch > 0 else None
    if cur is None or prev is None:
        return None
    return (cur, prev)


def point_is_current(point_hex: str, now: float, name_pub_hex: str,
                     epoch_len: int = EPOCH_LEN_DEFAULT) -> bool:
    """Mirror-side willingness check: is this point in the current or
    immediately previous epoch? Older epochs are silent False (fail-closed).
    """
    pair = derive_points(now, name_pub_hex, epoch_len)
    if pair is None:
        return False
    return point_hex == pair[0] or point_hex == pair[1]
