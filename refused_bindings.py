"""Refused-bindings filter for the window-open snapshot.

Allocation rule v0.6.3, section 7.3.9 (R2 refused-bindings, as settled by
O.R.A.C.L.E. with Bulwark's and Loom's amendments).

A refused binding — refusal reasons ``grammar``, ``length``, ``expiry-cap``,
``not-in-manifest`` — gets NO ``binding-hold`` and exactly ONE leaf each in
the single ``refused-bindings`` structure. Refused bindings stay
``name_bindings`` rows until their own capped expiry; they are
gap-provisional and hint-only. Window-open must not fail because a live
binding is non-conforming.

Canonical leaf (no trailing newline, no binding_sha256):
    cyberspace-refused-binding/v1\\nname=<label>\\nnode_pubkey=<64 hex>\\nreason=<code>
Every ``grammar`` leaf uses ``name=sha256:<hex>`` — the lowercase hex
SHA-256 of the exact stored UTF-8 label bytes (71 B value) — not only
labels outside ``[a-z0-9-]``. The raw label is published in the audit
list next to the leaf so the holder can recompute the hash.

Reason codes, fixed set, never free text: ``grammar``, ``length``,
``expiry-cap``, ``not-in-manifest``.

Classification priority (each binding gets exactly one leaf):
    length -> grammar -> expiry-cap -> not-in-manifest
A binding passing all four is hold-eligible.

Note: the window-open snapshot itself (``_snapshot`` in the migration
code) does not exist in this repo yet — this module is the filter it
will call. The belt drives it directly against row dicts.
"""

import hashlib
from datetime import datetime

LEAF_PREFIX = "cyberspace-refused-binding/v1"
REASONS = ("grammar", "length", "expiry-cap", "not-in-manifest")

# Window-open label rules (§7.3.9): [a-z0-9-], byte-length based.
_LABEL_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-")


def _label_byte_len(label: str) -> int:
    return len(label.encode("utf-8"))


def _grammar_ok(label: str) -> bool:
    """Window-open binding grammar: [a-z0-9-] 1-63 bytes, no edge hyphen,
    no xn-- prefix, no -- in positions 3-4, ASCII only."""
    if not label:
        return False
    b = label.encode("utf-8")
    if len(b) > 63:
        return False
    if not all(c < 128 for c in b):
        return False
    if label.startswith("-") or label.endswith("-"):
        return False
    if label.startswith("xn--"):
        return False
    if len(label) >= 4 and label[2:4] == "--":
        return False
    return all(c in _LABEL_CHARS for c in label)


def _canonical_time_ok(s) -> bool:
    """Floor fix 5 canonical rule: explicit numeric UTC offset required.
    Naive datetimes, date-only strings, and garbage are unparseable."""
    if not isinstance(s, str) or not s:
        return False
    try:
        dt = datetime.fromisoformat(s)
    except (ValueError, TypeError):
        return False
    return dt.tzinfo is not None


def _length_refused(label: str) -> bool:
    """Spec §7.3.9: length refusal for 1-2 and 33-63 byte labels."""
    n = _label_byte_len(label)
    return 1 <= n <= 2 or 33 <= n <= 63


def refused_leaf(name: str, node_pubkey: str, reason: str) -> bytes:
    """Build the canonical refused-binding leaf bytes for one binding."""
    if reason not in REASONS:
        raise ValueError(f"unknown refused-bindings reason: {reason!r}")
    pub = str(node_pubkey).lower()
    if reason == "grammar":
        # Every grammar leaf hashes the label (spec §7.3.9 R2 sha256 form).
        name_field = "sha256:" + hashlib.sha256(
            str(name).encode("utf-8")).hexdigest()
    else:
        name_field = str(name)
    leaf = (LEAF_PREFIX + "\nname=" + name_field
            + "\nnode_pubkey=" + pub + "\nreason=" + reason)
    return leaf.encode("utf-8")


def classify_binding(row: dict, manifest_labels) -> str | None:
    """Return the refusal reason for a name_bindings row, or None if the
    row is hold-eligible. ``row`` needs name/node_pubkey/expires_at;
    ``manifest_labels`` is a set of labels present in the manifest."""
    label = str(row.get("name", ""))
    if _length_refused(label):
        return "length"
    if not _grammar_ok(label):
        return "grammar"
    if not _canonical_time_ok(row.get("expires_at")):
        return "expiry-cap"
    if label not in manifest_labels:
        return "not-in-manifest"
    return None


def snapshot_refused_bindings(rows, manifest_labels):
    """Partition name-binding rows into (holds, refused).

    ``rows``: iterable of dicts with name, node_pubkey, issued_at,
    expires_at (expires_at may be None for NULL-expiry legacy rows).
    ``manifest_labels``: labels present in the manifest.

    Returns ``(holds, refused)`` where ``holds`` is the list of rows
    eligible for a binding-hold and ``refused`` is a list of
    ``(leaf_bytes, reason)`` — exactly one leaf per refused binding,
    in input order. Deterministic: same inputs, same outputs.
    """
    manifest = set(manifest_labels)
    holds = []
    refused = []
    for row in rows:
        reason = classify_binding(row, manifest)
        if reason is None:
            holds.append(row)
        else:
            refused.append((refused_leaf(row.get("name", ""),
                                        row.get("node_pubkey", ""),
                                        reason), reason))
    return holds, refused
