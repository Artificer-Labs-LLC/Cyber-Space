#!/usr/bin/env python3
"""Follow a .cyberspace name's rotation chain end to end — the chain-following
client for primitive 4 (identity).

A rotation is self-authenticating: the OLD name key designates the new one,
signed by the old key alone. So anyone who trusts an old binding can follow
the chain of designations to the CURRENT name key without trusting the
mirror at all — a lying registry can withhold a name, never rewrite its
lineage. This script is that anyone: it takes a name's rotation history
(the exact JSON GET /api/v1/names/{name}/rotations serves) and walks it,
verifying every hop offline.

Two modes:
  ./venv/bin/python resolve_chain.py <name> --mirror http://HOST:PORT
      # fetch the chain from a mirror, walk it offline
  ./venv/bin/python resolve_chain.py -             # read rotations JSON from stdin
      # fully offline: verify a saved chain from the mirror alone

Options:
  --expect-original-key HEX64   pin the chain's head: "I trusted THIS key
      before the first rotation". Without it the walk still proves
      internal continuity (every hop vouched by its predecessor) but the
      caller vouches for nothing at the head.
  --with-live                   also fetch the live binding (only with
      --mirror) and demand the chain's terminal key == the key the live
      binding names. A dead name (no live binding) is not a broken chain:
      the chain walks clean and the name reads available.

The walk is fail-closed, in order:
  1. the chain is non-empty;
  2. every rotation is for the queried name (normalized, strip+lower);
  3. every rotation verifies via rotate_name.verify_rotation — the
     signature is the OLD key vouching for the NEW key, not future-dated;
  4. linkage: hop N's old_pubkey == hop N-1's new_pubkey — a gap means the
     mirror served a broken lineage;
  5. the pinned original key matches hop 0's old_pubkey (when pinned).

issued_at regression across hops is reported as a note, never a failure:
the mirror orders by acceptance, and same-second ties are real.

Exit codes: 0 = chain walks clean (and the live binding agrees, when asked)
            1 = broken chain (reason on stderr)
            2 = usage / unreadable input (no verdict)
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rotate_name import verify_rotation  # noqa: E402
from verify_name import verify as verify_binding, _normalize_expected  # noqa: E402

_LABEL_MAX = 63


class ChainError(Exception):
    """The chain does not walk. Reason is str(self)."""


def _label(label: str) -> str:
    return _normalize_expected(label or "")


def _fetch(url: str) -> dict:
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code in (400, 404):
            raise ChainError(f"mirror says no chain here: HTTP {e.code} {url}")
        raise ChainError(f"mirror fetch failed: HTTP {e.code} {url}")
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise ChainError(f"mirror unreachable: {e}")
    except (ValueError, json.JSONDecodeError):
        raise ChainError(f"mirror returned non-JSON at {url}")


def walk(doc: dict, name: str, expect_original_key: str | None = None):
    """Walk the rotation chain. Returns (terminal_key, hops).

    hops is a list of dicts: {old_pubkey, new_pubkey, issued_at, note}.
    Raises ChainError if the chain does not walk clean.
    """
    if not isinstance(doc, dict):
        raise ChainError("rotations document is not a JSON object")
    rots = doc.get("rotations")
    if not isinstance(rots, list) or not rots:
        raise ChainError("rotations document carries no rotation rows")
    want = _label(name)
    hops = []
    prev_new = None
    prev_issued = None
    for i, row in enumerate(rots):
        if not isinstance(row, dict):
            raise ChainError(f"hop {i}: not an object")
        row = dict(row)
        # The mirror's row carries the name at the document top level;
        # verify_rotation expects it on the record — inject before checks.
        row.setdefault("name", want)
        # Name first, like verify_name's pins: a cross-label replay gets a
        # naming-the-sides reason, not a signature reason. The signature
        # would fail too (the name is inside the signed payload) — this
        # just names the problem precisely.
        if _label(row["name"]) != want:
            raise ChainError(
                f"hop {i}: for {_label(row['name'])!r}, not the queried {want!r}")
        reason = verify_rotation(row)
        if reason is not None:
            raise ChainError(f"hop {i}: {reason}")
        old = _normalize_expected(row["old_pubkey"])
        new = _normalize_expected(row["new_pubkey"])
        if i == 0 and expect_original_key is not None:
            exp = _normalize_expected(expect_original_key)
            if old != exp:
                raise ChainError(
                    f"hop 0: old key {old[:16]}... is not the pinned "
                    f"original {exp[:16]}...")
        elif i > 0 and old != prev_new:
            raise ChainError(
                f"hop {i}: old key {old[:16]}... does not continue "
                f"hop {i - 1}'s new key {prev_new[:16]}... — lineage gap")
        note = ""
        issued = row["issued_at"]
        if prev_issued is not None and issued < prev_issued:
            note = "issued time regressed vs previous hop"
        hops.append({"old_pubkey": old, "new_pubkey": new,
                     "issued_at": issued, "note": note})
        prev_new = new
        prev_issued = issued
    return prev_new, hops


def check_live(name: str, mirror: str, terminal_key: str) -> str:
    """Fetch the live binding and compare it against the chain's terminal
    key. Returns a one-line verdict. Raises ChainError if the binding
    exists but does not agree."""
    binding = _fetch(f"{mirror.rstrip('/')}/api/v1/names/{_label(name)}")
    if not isinstance(binding, dict):
        raise ChainError("live binding is not a JSON object")
    reason = verify_binding(binding)
    if reason is not None:
        raise ChainError(f"live binding fails offline verification: {reason}")
    live_key = _normalize_expected(binding["node_pubkey"])
    if live_key != terminal_key:
        raise ChainError(
            f"live binding names {live_key[:16]}..., but the chain walks "
            f"to {terminal_key[:16]}... — the answering key is not the "
            f"designated heir")
    return (f"live binding names the chain's terminal key "
            f"{terminal_key[:16]}... (issued {binding['issued_at']})")


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        description="follow a .cyberspace name's rotation chain end to end")
    ap.add_argument("source", help="<name>, or - for rotations JSON on stdin")
    ap.add_argument("--mirror", default="",
                    help="mirror base URL, e.g. http://127.0.0.1:8000")
    ap.add_argument("--expect-original-key",
                    help="pin the chain's head to this 64-hex name key")
    ap.add_argument("--with-live", action="store_true",
                    help="also fetch the live binding and demand agreement")
    args = ap.parse_args(argv)

    if args.source == "-":
        if args.with_live or args.mirror:
            print("refused: stdin mode is fully offline; drop --mirror/--with-live",
                  file=sys.stderr)
            return 2
        name = ""
        try:
            doc = json.loads(sys.stdin.read())
        except (ValueError, json.JSONDecodeError) as e:
            print(f"refused: stdin is not JSON: {e}", file=sys.stderr)
            return 2
        name = _label(doc.get("name", ""))
    else:
        name = _label(args.source)
        if not name:
            print("refused: empty name", file=sys.stderr)
            return 2
        if not args.mirror:
            print("refused: fetching a chain needs --mirror (or - for stdin)",
                  file=sys.stderr)
            return 2
        try:
            doc = _fetch(f"{args.mirror.rstrip('/')}/api/v1/names/{name}/rotations")
        except ChainError as e:
            print(f"broken: {e}", file=sys.stderr)
            return 1

    try:
        terminal, hops = walk(doc, name, args.expect_original_key)
    except ChainError as e:
        print(f"broken: {e}", file=sys.stderr)
        return 1

    live_note = ""
    if args.with_live:
        try:
            live_note = check_live(name, args.mirror, terminal)
        except ChainError as e:
            # A 404 on the binding is a dead name, not a broken chain —
            # the lineage still walks clean, the label is simply available.
            if "no chain here" not in str(e) and "HTTP 404" not in str(e):
                print(f"broken: {e}", file=sys.stderr)
                return 1
            live_note = "no live binding: name is dead, chain intact, label available"

    nm = name or _label(doc.get("name", "")) or "?"
    print(f"{nm}.cyberspace rotation chain: {len(hops)} hop(s), walks clean")
    for i, h in enumerate(hops):
        n = f" [{h['note']}]" if h["note"] else ""
        print(f"  hop {i}: {h['old_pubkey'][:16]}... -> {h['new_pubkey'][:16]}... "
              f"(issued {h['issued_at']}){n}")
    print(f"terminal key: {terminal}")
    if live_note:
        print(live_note)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
