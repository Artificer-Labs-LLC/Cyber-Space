#!/usr/bin/env python3
"""Verify a .cyberspace name binding offline — the self-authenticating half
of primitive 1 (naming).

A name claim is name-claim|<label>|<pub>|<issued>|<expires> signed by the
name key itself (the very key being named vouches for the binding). That
means anyone can verify a binding WITHOUT trusting the mirror: a lying
registry can withhold a name, never redirect one. This script is that
anyone: it takes a binding JSON (name, node_pubkey, issued_at, expires_at,
signature — the same shape /api/v1/names/claim accepts and stores) and
checks it end to end, no network.

Usage:
  ./venv/bin/python verify_name.py binding.json
  ./venv/bin/python verify_name.py -              # read JSON from stdin
  ./venv/bin/python verify_name.py binding.json --expect-name foo \
      --expect-pubkey <64hex>   # pin: "is this the binding I meant?"

Exit codes: 0 = binding is valid and live right now
            1 = binding is invalid, expired, or not yet issued (reason on stderr)
            2 = usage / unreadable input (no verdict)

The canonical payload must match core._name_claim_payload byte for byte:
lowercase-hex pub, exact issued/expires strings as signed.
"""

import os
import stat
import sys
import argparse
import json
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fed.ed25519 import checkvalid  # noqa: E402

_LABEL_MAX = 63

# A binding is five short fields (label, 64-hex key, two timestamps, a
# 128-hex signature) — a few hundred bytes. Cap the input read at the
# sibling tools' 64KB mirror bound (resolve_chain._FETCH_MAX /
# mint_name._MIRROR_RESP_MAX) instead of slurping a whole file/stdin
# into memory before json.loads ever runs.
_INPUT_MAX = 65536


def _valid_label(label: str) -> bool:
    """Client-side mirror of core._valid_name_label (server decides)."""
    # Twin of the mint_name gate: a non-string label escaped as
    # TypeError from len()/the "." test or AttributeError from a list
    # element's .lower — a crash, not this predicate's False (None
    # alone happened to read as empty).
    if not isinstance(label, str):
        return False
    if not label or len(label) > _LABEL_MAX:
        return False
    if label != label.lower() or "." in label:
        return False
    if label.startswith("-") or label.endswith("-"):
        return False
    return all((c.isascii() and c.isalnum()) or c == "-" for c in label)


def _claim_payload(name: str, node_pubkey: str, issued_at: str,
                   expires_at: str) -> bytes:
    """Byte-for-byte twin of core._name_claim_payload."""
    # Twin of core's gate: a non-string field escaped as AttributeError
    # from .encode()/.lower(); only real strings have a canonical form,
    # refused as ValueError (the verdict language verify() already uses).
    for _field, _value in (("name", name), ("node_pubkey", node_pubkey),
                           ("issued_at", issued_at),
                           ("expires_at", expires_at)):
        if not isinstance(_value, str):
            raise ValueError(f"{_field} must be a string: {_value!r}")
    return (b"name-claim|" + name.encode() + b"|"
            + node_pubkey.lower().encode() + b"|"
            + issued_at.encode() + b"|" + expires_at.encode())


def _parse_ts(s: str, field: str) -> datetime:
    # Twin of core_serve._parse_claim_time (the mirror's rule): the stamp
    # MUST be exactly `YYYY-MM-DDTHH:MM:SS` with a UTC stamp (`Z` or
    # `+00:00`). M-2 (v0.6.3 red-team): fromisoformat is NOT used
    # — on 3.11+ it accepts ~12 spellings and behaves differently across
    # versions. Strict regex + manual construction keeps the twins in
    # agreement on every Python. B1/B2: [0-9] classes (not \d) and a \Z
    # anchor (not $). B4: ONLY UTC — `-00:00` and every non-zero offset
    # are rejected. Raises ValueError on unparseable input, exactly like
    # the mirror — otherwise a mirror-refused binding would pass offline
    # verification and the "trust a name without trusting the mirror"
    # promise breaks.
    import re
    # A binding JSON can carry a non-string stamp straight in (123/true/a
    # list); re.match would leak TypeError past the caller's ValueError
    # verdict seat. Refuse in-contract, twin of core._parse_claim_time.
    if not isinstance(s, str):
        raise ValueError(f"{field} is not canonical UTC timestamp: {s!r}")
    m = re.match(
        r"^([0-9]{4})-([0-9]{2})-([0-9]{2})T"
        r"([0-9]{2}):([0-9]{2}):([0-9]{2})(Z|\+00:00)\Z", s
    )
    if not m:
        raise ValueError(f"{field} is not canonical UTC timestamp: {s!r}")
    year, mon, day, hr, mi, se = (int(m.group(i)) for i in range(1, 7))
    if not (1 <= mon <= 12 and 1 <= day <= 31 and hr <= 23
            and mi <= 59 and se <= 59):
        raise ValueError(f"{field} out of range: {s!r}")
    # B4: the only surviving spellings are UTC — no offset arithmetic.
    tz = timezone.utc
    try:
        return datetime(year, mon, day, hr, mi, se, tzinfo=tz)
    except ValueError:
        raise ValueError(f"{field} invalid date: {s!r}")


def _normalize_expected(s: str) -> str:
    """Expected names/keys get the same normalize-identically-first
    treatment the mirror applies to bindings: strip, lowercase."""
    # A non-string has nothing to normalize: it escaped as AttributeError
    # from .strip() (int/None/list/dict) or — worse — ALIASED through
    # bytes' own .strip()/.lower(), returning bytes where every caller
    # compares against str (a bytes pin/name then read as a garbage
    # naming-the-sides verdict instead of no value at all). The empty
    # string is this module's no-value sentinel: every downstream gate
    # refuses it (invalid label, wrong hex length, unequal pin), exactly
    # as resolve_chain._label already maps a falsy name to "".
    if not isinstance(s, str):
        return ""
    return s.strip().lower()


def verify(binding: dict, expect_name: str | None = None,
           expect_pubkey: str | None = None) -> str | None:
    """Return None if the binding verifies, else the reason it does not.

    expect_name / expect_pubkey pin the answer: "is this the binding I
    meant?" A valid binding for a DIFFERENT name or key fails with a
    naming-the-sides reason instead of verifying. Expected values are
    normalized identically to bindings (strip + lowercase) so a caller
    can pass what the mirror accepted without worrying about case.
    """
    if not isinstance(binding, dict):
        return "binding is not a JSON object"
    for k in ("name", "node_pubkey", "issued_at", "expires_at", "signature"):
        if k not in binding:
            return f"missing field: {k}"
        if not isinstance(binding[k], str):
            return f"field {k!r} is not a string"
    name = binding["name"]
    pub = binding["node_pubkey"]
    sig = binding["signature"]
    # The mirror normalizes BEFORE it validates (names_claim strips and
    # lowercases name/node_pubkey/signature, then verifies the signature
    # against the NORMALIZED values and stores the normalized form). The
    # offline verifier must vouch for exactly what the mirror stores, so
    # it normalizes identically first — a claim form the mirror accepts
    # verifies here too, never just the already-normalized stored copy.
    name = _normalize_expected(name)
    pub = _normalize_expected(pub)
    sig = _normalize_expected(sig)
    if expect_name is not None:
        if not isinstance(expect_name, str):
            return "expected name pin is not a string"
        exp = _normalize_expected(expect_name)
        if name != exp:
            return f"binding is for {name!r}, not the expected {exp!r}"
    if expect_pubkey is not None:
        if not isinstance(expect_pubkey, str):
            return "expected pubkey pin is not a string"
        exp = _normalize_expected(expect_pubkey)
        if pub != exp:
            return (f"binding is keyed to {pub[:16]}..., not the expected "
                    f"key {exp[:16]}...")
    if not _valid_label(name):
        return f"name {name!r} is not a valid .cyberspace label"
    if len(pub) != 64:
        return "node_pubkey is not 64 hex chars"
    try:
        pub_b = bytes.fromhex(pub)
    except ValueError:
        return "node_pubkey is not hex"
    # Decoded-length gate, twin of this file's --expect-pubkey pin gate
    # and verify_rotation's len(raw)*2 check: bytes.fromhex ignores
    # embedded spaces, so a 64-char string with two spaces decodes to
    # a 31-byte key — it passed both checks above and was misreported
    # as a signature failure, when the key itself is malformed. Only
    # a 32-byte decode is a 64-hex key.
    if len(pub_b) != 32:
        return "node_pubkey is not 64 hex chars"
    if len(sig) != 128:
        return "signature is not 128 hex chars"
    try:
        sig_b = bytes.fromhex(sig)
    except ValueError:
        return "signature is not hex"
    # Same gate for the signature: a spaced 128-char string decodes
    # to 63 bytes and read as a signature failure instead of the
    # malformed signature it is. Only a 64-byte decode is a
    # 128-hex signature.
    if len(sig_b) != 64:
        return "signature is not 128 hex chars"
    try:
        issued = _parse_ts(binding["issued_at"], "issued_at")
        expires = _parse_ts(binding["expires_at"], "expires_at")
    except ValueError as e:
        return str(e)
    if not issued < expires:
        return "issued_at is not before expires_at"
    # Lifetime cap, twin of core._name_binding_admission_ok
    # (NAME_EXPIRY_DAYS): admission refuses a binding signed for longer
    # than 365 days, and the cap is intrinsic to the binding itself
    # (expires - issued), so the offline seat can check it without
    # trusting any mirror — an over-cap binding verified here while
    # every admission seat read the same claim as refused.
    if (expires - issued) > timedelta(days=365):
        return "binding lifetime exceeds 365 days"
    now = datetime.now(timezone.utc)
    if now < issued:
        return "binding is not yet issued"
    if now >= expires:
        return "binding has expired"
    payload = _claim_payload(name, pub, binding["issued_at"], binding["expires_at"])
    if not checkvalid(sig_b, payload, pub_b):
        return "signature does not verify: this binding is not vouched for by the named key"
    return None


def main(argv: list[str]) -> int:
    # Duplicate gate, twin of rotate_name / the nexus_*/mint_name
    # parsers: argparse silently last-wins on a repeated value flag,
    # so --expect-name foo --expect-name bar verified against bar
    # while the operator believed the pin was foo (probed this
    # tick). Refuse a repeated value flag by name, in space, equals
    # or mixed spelling, before argparse runs — before any input
    # is read.
    _seen: set[str] = set()
    for _tok in argv:
        if _tok == "--":
            break
        if not _tok.startswith("--"):
            continue
        _name = _tok.partition("=")[0]
        if _name in ("--expect-name", "--expect-pubkey"):
            if _name in _seen:
                print(f"refused: {_name} given more than once",
                      file=sys.stderr)
                return 2
            _seen.add(_name)
    ap = argparse.ArgumentParser(
        description="verify a .cyberspace name binding offline")
    ap.add_argument("source", help="binding.json, or - for stdin")
    ap.add_argument("--expect-name",
                    help="fail unless the binding is for this label")
    ap.add_argument("--expect-pubkey",
                    help="fail unless the binding is keyed to this name key")
    args = ap.parse_args(argv)
    # The pins are arguments, not verdicts: a pin that can never match
    # any binding (an invalid label, or a key that is not 64 hex chars)
    # read as exit 1 "binding is for/keyed to X, not the expected Y" —
    # a verdict on the binding — when the pin itself was at fault.
    # Gate them before any input is read, exit 2, twin of the mirror
    # gates in mint/rotate/resolve_chain.
    if args.expect_name is not None and not _valid_label(
            _normalize_expected(args.expect_name)):
        print("refused: --expect-name is not a valid .cyberspace label "
              "— bad argument, no verdict", file=sys.stderr)
        return 2
    if args.expect_pubkey is not None:
        exp = _normalize_expected(args.expect_pubkey)
        try:
            pin_ok = len(exp) == 64 and len(bytes.fromhex(exp)) == 32
        except ValueError:
            pin_ok = False
        if not pin_ok:
            print("refused: --expect-pubkey is not a 64-hex name key "
                  "— bad argument, no verdict", file=sys.stderr)
            return 2
    src = args.source
    try:
        if src == "-":
            raw = sys.stdin.read(_INPUT_MAX + 1)
        else:
            # Only a regular file may be opened: open() on a FIFO blocks
            # until a writer appears, so a FIFO (or device) at the
            # binding seat hung this anyone-can-verify check forever
            # instead of returning its no-verdict exit 2 — the twin of
            # the nexus_preflight S_ISREG gates. os.stat follows
            # symlinks, so a symlink TO a regular file stays valid
            # while a symlink to a FIFO is refused; a missing path
            # raises OSError into the refusal below as before.
            if not stat.S_ISREG(os.stat(src).st_mode):
                print(f"refused: {src} is not a regular file "
                      "— no verdict", file=sys.stderr)
                return 2
            with open(src, encoding="utf-8") as f:
                raw = f.read(_INPUT_MAX + 1)
    except OSError as e:
        print(f"refused: cannot read {src}: {e}", file=sys.stderr)
        return 2
    if len(raw) > _INPUT_MAX:
        print(f"refused: input exceeds {_INPUT_MAX} bytes — a binding is "
              "a few hundred bytes; no verdict", file=sys.stderr)
        return 2
    try:
        binding = json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"refused: not JSON: {e}", file=sys.stderr)
        return 2
    reason = verify(binding, expect_name=args.expect_name,
                    expect_pubkey=args.expect_pubkey)
    if reason is not None:
        print(f"invalid: {reason}", file=sys.stderr)
        return 1
    # Print the normalized form — exactly what the mirror stores and
    # vouched for, never the raw casing a claim form happened to carry.
    nm = _normalize_expected(binding["name"])
    pk = _normalize_expected(binding["node_pubkey"])
    print(f"valid: {nm}.cyberspace -> {pk[:16]}..."
          f" (issued {binding['issued_at']}, expires {binding['expires_at']})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
