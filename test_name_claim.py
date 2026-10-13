"""Unit tests for the names-registry primitives in core.py.

Covers the two halves of the claim gate that the resolver suites don't:
  _valid_name_label  — the first-label grammar (names/claim + names_resolve
                       + resolve_cyberspace step 1 all call it)
  _name_claim_beats  — the deterministic conflict rule: same key re-signing
                       (later issued_at supersedes), different keys (earlier
                       issued_at wins, ties by lower pubkey hex). No votes,
                       no auctions — every mirror computes the same answer.

In-process only: no network, no daemons, no DB.

Run: cd ~/workspace/cybernet && ./venv/bin/python test_name_claim.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core import _name_claim_beats, _node_url_host, _parse_claim_time, _reject_nonpublic_node_url, _valid_name_label, _valid_node_url  # noqa: E402
from fastapi import HTTPException  # noqa: E402

CASES = {"passed": 0, "failed": 0}


def check(name, cond, extra=""):
    if cond:
        CASES["passed"] += 1
        print(f"  ok  {name}")
    else:
        CASES["failed"] += 1
        print(f"  FAIL {name} {extra}")


def _b(name, pubkey, issued, expires="2099-01-01T00:00:00+00:00"):
    return {"name": name, "node_pubkey": pubkey,
            "issued_at": issued, "expires_at": expires,
            "signature": "00" * 64}


PUB_A = "aa" + "00" * 31   # 64 hex, lexicographically lower
PUB_B = "bb" + "00" * 31   # 64 hex, lexicographically higher
EARLY = "2026-10-07T20:00:00+00:00"
LATER = "2026-10-07T21:00:00+00:00"


def label_cases():
    print("label grammar:")
    check("plain lowercase label", _valid_name_label("genesis") is True)
    check("digits and hyphens", _valid_name_label("node-42") is True)
    check("single char", _valid_name_label("x") is True)
    check("63 chars", _valid_name_label("a" * 63) is True)
    check("empty", _valid_name_label("") is False)
    check("64 chars too long", _valid_name_label("a" * 64) is False)
    check("uppercase", _valid_name_label("Genesis") is False)
    check("dot splits labels", _valid_name_label("a.b") is False)
    check("leading hyphen", _valid_name_label("-gen") is False)
    check("trailing hyphen", _valid_name_label("gen-") is False)
    check("space", _valid_name_label("ge n") is False)
    check("underscore", _valid_name_label("ge_n") is False)
    # Ruled 2026-10-12 (was: frozen as observed, not blessed):
    # str.isalnum() is unicode-aware, but the resolver's DNS wire face
    # decodes labels as ASCII and refuses the rest — a unicode label was
    # claimable yet never resolvable. The grammar is ASCII-only now.
    check("unicode alnum refused (ASCII-only grammar)",
          _valid_name_label("génèrïs") is False)
    check("unicode single char refused",
          _valid_name_label("é") is False)
    # Bool predicate: a non-string must come back False, never a
    # TypeError/AttributeError (server seat of the mint/verify/rotate
    # twins; None alone happened to read as empty before the gate).
    for bad in (123, 1.5, True, b"foo", ["foo"], None):
        try:
            got = _valid_name_label(bad)
        except Exception as e:  # noqa: BLE001
            check(f"non-string {bad!r} refused without raising", False,
                  f"raised {type(e).__name__}: {e}")
            continue
        check(f"non-string {bad!r} refused", got is False,
              f"-> {got!r}")


def conflict_cases():
    print("conflict rule:")
    check("same key: later issued_at renews",
          _name_claim_beats(_b("x", PUB_A, LATER), _b("x", PUB_A, EARLY)) is True)
    check("same key: stale replay loses",
          _name_claim_beats(_b("x", PUB_A, EARLY), _b("x", PUB_A, LATER)) is False)
    check("same key+same issued_at: no replace",
          _name_claim_beats(_b("x", PUB_A, EARLY), _b("x", PUB_A, EARLY)) is False)
    check("different keys: earlier issued_at wins",
          _name_claim_beats(_b("x", PUB_B, EARLY), _b("x", PUB_A, LATER)) is True)
    check("different keys: later issued_at loses",
          _name_claim_beats(_b("x", PUB_B, LATER), _b("x", PUB_A, EARLY)) is False)
    check("tie: lower pubkey wins",
          _name_claim_beats(_b("x", PUB_A, EARLY), _b("x", PUB_B, EARLY)) is True)
    check("tie: higher pubkey loses",
          _name_claim_beats(_b("x", PUB_B, EARLY), _b("x", PUB_A, EARLY)) is False)
    check("same key differing only in case: same key",
          _name_claim_beats(_b("x", PUB_A.upper(), LATER),
                            _b("x", PUB_A, EARLY)) is True)


def node_url_cases():
    print("node_url gate:")
    # The refusal contract is HTTPException(400); every caller catches
    # exactly that. A non-string must read as 400, never leak
    # AttributeError/TypeError from .strip() (None already read as 400
    # via the empty-string path and still does).
    for bad in (123, 1.5, True, b"http://x.example", ["http://x.example"], None):
        try:
            got = _valid_node_url(bad)
        except HTTPException as e:
            check(f"non-string {bad!r} refused as 400",
                  e.status_code == 400, f"-> {e.status_code}")
            continue
        except Exception as e:  # noqa: BLE001
            check(f"non-string {bad!r} refused as 400", False,
                  f"raised {type(e).__name__}: {e}")
            continue
        check(f"non-string {bad!r} refused as 400", False, f"-> {got!r}")
    check("valid public URL passes verbatim",
          _valid_node_url("http://185.143.228.228:8471")
          == "http://185.143.228.228:8471")
    check("trailing slash normalized",
          _valid_node_url("http://185.143.228.228:8471/")
          == "http://185.143.228.228:8471")
    for bad in ("", "not a url", "http://185.143.228.228:99999"):
        try:
            got = _valid_node_url(bad)
            check(f"bad string {bad!r} refused as 400", False, f"-> {got!r}")
        except HTTPException as e:
            check(f"bad string {bad!r} refused as 400",
                  e.status_code == 400, f"-> {e.status_code}")


def node_url_host_cases():
    print("node_url host extraction:")
    # Refusal contract is HTTPException(400), same as _valid_node_url:
    # a non-string must not leak AttributeError/TypeError from .split(),
    # and a no-match string must not leak AttributeError from a None
    # match's .group(), at the peer-pin seats.
    for bad in (123, 1.5, True, b"http://x.example", ["http://x.example"], None,
                "", "not a url", "ftp://x.example", "http://"):
        try:
            got = _node_url_host(bad)
        except HTTPException as e:
            check(f"bad {bad!r} refused as 400",
                  e.status_code == 400, f"-> {e.status_code}")
            continue
        except Exception as e:  # noqa: BLE001
            check(f"bad {bad!r} refused as 400", False,
                  f"raised {type(e).__name__}: {e}")
            continue
        check(f"bad {bad!r} refused as 400", False, f"-> {got!r}")
    check("IP host exact",
          _node_url_host("http://185.143.228.228:8471") == "185.143.228.228")
    check("hostname exact",
          _node_url_host("https://node.example:8471") == "node.example")
    check("query stripped from host",
          _node_url_host("http://185.143.228.228:8471/path?x=1")
          == "185.143.228.228")
    check("IPv6 brackets stripped",
          _node_url_host("http://[2001:db8::1]:8471/") == "2001:db8::1")


def reject_nonpublic_cases():
    print("node_url SSRF gate:")
    # Refusal contract is HTTPException(400), same as _valid_node_url:
    # a non-string must not leak AttributeError/TypeError from .split(),
    # and a no-match string must not leak AttributeError from a None
    # match's .group(), at the gate itself (not only via caller wraps).
    for bad in (123, 1.5, True, b"http://x.example", ["http://x.example"], None,
                "", "not a url", "ftp://x.example", "http://"):
        try:
            got = _reject_nonpublic_node_url(bad)
        except HTTPException as e:
            check(f"bad {bad!r} refused as 400",
                  e.status_code == 400, f"-> {e.status_code}")
            continue
        except Exception as e:  # noqa: BLE001
            check(f"bad {bad!r} refused as 400", False,
                  f"raised {type(e).__name__}: {e}")
            continue
        check(f"bad {bad!r} refused as 400", False, f"-> {got!r}")
    check("public IP pins exact",
          _reject_nonpublic_node_url("http://185.143.228.228:8471")
          == "185.143.228.228")
    check("query stripped before pin",
          _reject_nonpublic_node_url(
              "http://185.143.228.228:8471/relay/hold_query?point_id=1")
          == "185.143.228.228")
    try:
        got = _reject_nonpublic_node_url("http://127.0.0.1:8471")
        check("loopback refused as 400", False, f"-> {got!r}")
    except HTTPException as e:
        check("loopback refused as 400", e.status_code == 400,
              f"-> {e.status_code}")


def claim_time_cases():
    print("claim-time parser:")
    # Refusal contract is ValueError on ANY unparseable input — every
    # caller (conflict rule, liveness, memo) guards ValueError alone.
    # A non-string stamp (a JSON/gossip field can carry one straight
    # in) escaped as TypeError from the regex .match() instead.
    for bad in (123, 1.5, True, None, b"2026-10-07T20:00:00Z",
                ["2026-10-07T20:00:00Z"], {"t": 1}):
        try:
            got = _parse_claim_time(bad)
        except ValueError:
            check(f"non-string {bad!r} refused as ValueError", True)
            continue
        except Exception as e:  # noqa: BLE001
            check(f"non-string {bad!r} refused as ValueError", False,
                  f"raised {type(e).__name__}: {e}")
            continue
        check(f"non-string {bad!r} refused as ValueError", False,
              f"-> {got!r}")
    check("canonical +00:00 parses exact",
          _parse_claim_time(EARLY).isoformat() == "2026-10-07T20:00:00+00:00")
    check("canonical Z parses exact",
          _parse_claim_time("2026-10-07T20:00:00Z").isoformat()
          == "2026-10-07T20:00:00+00:00")
    try:
        _parse_claim_time("garbage")
        check("garbage string still ValueError", False, "parsed")
    except ValueError:
        check("garbage string still ValueError", True)


def main():
    print("names-registry primitive tests (core.py):")
    label_cases()
    conflict_cases()
    node_url_cases()
    node_url_host_cases()
    reject_nonpublic_cases()
    claim_time_cases()
    print(f"  {CASES['passed']} passed, {CASES['failed']} failed")
    sys.exit(1 if CASES["failed"] else 0)


if __name__ == "__main__":
    main()
