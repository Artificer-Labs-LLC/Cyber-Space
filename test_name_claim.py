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
import stat
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core import _ensure_private_dir, _name_claim_beats, _name_claim_payload, _node_keypair, _node_url_host, _old_binding_beaten, _parse_claim_time, _reach_canonical, _reject_nonpublic_node_url, _valid_name_label, _valid_node_url  # noqa: E402
import core as _core  # noqa: E402
from unittest import mock as _mock  # noqa: E402
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


def claim_beats_pubkey_cases():
    print("conflict rule pubkey types:")
    # Refusal contract is ValueError on a malformed binding, same as
    # _parse_claim_time — _old_binding_beaten guards ValueError alone
    # (its Examiner-block fallback). A non-string pubkey escaped as
    # AttributeError from .lower() (int/None/float/bool/list) or
    # TypeError from the bytes-vs-str tiebreak instead.
    from datetime import datetime, timezone
    now_dt = datetime.now(timezone.utc)
    for bad in (123, 1.5, True, None, b"aa", ["aa"]):
        for seat in ("new", "old"):
            new_b = _b("x", bad if seat == "new" else PUB_A, EARLY)
            old_b = _b("x", bad if seat == "old" else PUB_B, EARLY)
            try:
                got = _name_claim_beats(new_b, old_b)
            except ValueError:
                check(f"non-string {seat} pubkey {bad!r} refused as ValueError", True)
                continue
            except Exception as e:  # noqa: BLE001
                check(f"non-string {seat} pubkey {bad!r} refused as ValueError",
                      False, f"raised {type(e).__name__}: {e}")
                continue
            check(f"non-string {seat} pubkey {bad!r} refused as ValueError",
                  False, f"-> {got!r}")
    # Downstream: the fallback now engages — a foreign malformed
    # challenger reads as not-beaten (bool), never a leaked crash.
    old_live = _b("x", PUB_A, EARLY, expires="2099-01-01T00:00:00+00:00")
    check("downstream fallback reads foreign malformed as not-beaten",
          _old_binding_beaten(old_live, _b("x", 123, EARLY), PUB_B, now_dt) is False)
    check("valid tie-break still exact",
          _name_claim_beats(_b("x", PUB_A, EARLY), _b("x", PUB_B, EARLY)) is True)


def old_binding_fallback_pubkey_cases():
    print("old-binding fallback pubkey types:")
    # The Examiner-block fallback promises a bool: an unparseable stored
    # row is beaten iff the claimant holds the SAME key. A non-string
    # key on either side escaped as AttributeError from .lower()
    # (int/None/list) instead of reading as not-the-same-key.
    from datetime import datetime, timezone
    now_dt = datetime.now(timezone.utc)
    old_bad = _b("x", PUB_A, "garbage", expires="garbage")
    for bad in (123, 1.5, True, None, ["aa"]):
        check(f"non-string claimant {bad!r} reads not-beaten",
              _old_binding_beaten(old_bad, _b("x", PUB_B, EARLY), bad, now_dt) is False)
        old_intkey = _b("x", bad, "garbage", expires="garbage")
        check(f"non-string stored key {bad!r} reads not-beaten",
              _old_binding_beaten(old_intkey, _b("x", PUB_B, EARLY), PUB_A, now_dt) is False)
    check("same key no longer beats unparseable row (BW-RC1B fail-closed)",
          _old_binding_beaten(old_bad, _b("x", PUB_A, EARLY), PUB_A.upper(), now_dt) is False)
    check("foreign key still refused on unparseable row",
          _old_binding_beaten(old_bad, _b("x", PUB_B, EARLY), PUB_B, now_dt) is False)


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


def claim_payload_cases():
    # The canonical payload builders are library seats: a non-string
    # field escaped as AttributeError from .encode()/.lower(), past the
    # ValueError contract their sibling parsers carry. Every field of
    # both builders refuses as ValueError; valid bytes are exact.
    good = ("foo", "AB" * 32, EARLY, LATER)
    want_claim = (b"name-claim|foo|" + b"ab" * 32 + b"|"
                  + EARLY.encode() + b"|" + LATER.encode())
    check("claim payload bytes exact", _name_claim_payload(*good) == want_claim)
    want_reach = (b"reach-descriptor|foo|" + b"ab" * 32 + b"|[]|"
                  + EARLY.encode() + b"|" + LATER.encode())
    check("reach canonical bytes exact",
          _reach_canonical("foo", "AB" * 32, [], EARLY, LATER) == want_reach)
    for i in range(4):
        for bad in (123, 1.5, True, None, b"foo", ["foo"], {"f": 1}):
            args = list(good)
            args[i] = bad
            for fn, nm in ((_name_claim_payload, "claim"),
                           (lambda *a: _reach_canonical(a[0], a[1], [], a[2], a[3]), "reach")):
                try:
                    fn(*args)
                except ValueError:
                    check(f"{nm} field{i} {bad!r} refused as ValueError", True)
                    continue
                except Exception as e:  # noqa: BLE001
                    check(f"{nm} field{i} {bad!r} refused as ValueError", False,
                          f"raised {type(e).__name__}: {e}")
                    continue
                check(f"{nm} field{i} {bad!r} refused as ValueError", False, "built")


def db_dir_cases():
    print("db dir privacy:")
    def mode(p):
        return stat.S_IMODE(os.stat(p).st_mode)
    with tempfile.TemporaryDirectory() as td:
        fresh = os.path.join(td, "a", "b")
        _ensure_private_dir(fresh)
        check("fresh nested db dir born 0700", mode(fresh) == 0o700,
              oct(mode(fresh)))
        check("fresh parent dir born 0700",
              mode(os.path.join(td, "a")) == 0o700,
              oct(mode(os.path.join(td, "a"))))
        _ensure_private_dir(fresh)  # re-run is a no-op, never re-chmods
        check("re-run keeps created dir 0700", mode(fresh) == 0o700)
        pre = os.path.join(td, "pre")
        os.mkdir(pre)
        os.chmod(pre, 0o755)
        _ensure_private_dir(pre)
        check("pre-existing dir left exactly as found", mode(pre) == 0o755,
              oct(mode(pre)))


def node_key_cases():
    print("node key first-boot race:")
    winner = "ab" * 32
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, ".node.key")
        with open(path, "w") as f:
            f.write(winner)
        real_exists = os.path.exists
        calls = {"n": 0}

        def racy(p, _path=path):
            if p == _path:
                calls["n"] += 1
                return False if calls["n"] == 1 else real_exists(p)
            return real_exists(p)

        with _mock.patch.object(_core, "_NODE_KEY_PATH", path), \
                _mock.patch.object(os.path, "exists", racy), \
                _mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("CYBERNET_NODE_PRIVKEY", None)
            try:
                priv, pub = _node_keypair()
                check("first-boot race loser adopts winner key",
                      priv == winner and len(pub) == 64)
            except FileExistsError:
                check("first-boot race loser adopts winner key", False,
                      "FileExistsError uncaught")
        fresh = os.path.join(td, "fresh.key")
        fsync_kinds = []
        real_fsync = os.fsync

        def fsync_spy(fd):
            fsync_kinds.append(
                "dir" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file")
            return real_fsync(fd)

        with _mock.patch.object(_core, "_NODE_KEY_PATH", fresh), \
                _mock.patch.object(os, "fsync", fsync_spy), \
                _mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("CYBERNET_NODE_PRIVKEY", None)
            priv, _pub = _node_keypair()
            mode = stat.S_IMODE(os.stat(fresh).st_mode)
            with open(fresh) as f:
                saved = f.read().strip()
            check("fresh node key born 0600, saved whole",
                  mode == 0o600 and saved == priv, oct(mode))
            check("fresh node key create fsyncs file and parent dir",
                  fsync_kinds == ["file", "dir"], str(fsync_kinds))
            priv2, _ = _node_keypair()
            check("second boot reads the same identity", priv2 == priv)
        # In-flight winner: the file exists (the winner won O_EXCL)
        # but its bytes have not landed yet — the settled read must
        # adopt the key once the write completes, not die on the
        # empty file the old immediate read hit at import time.
        inflight = os.path.join(td, "inflight.key")
        with open(inflight, "w"):
            pass  # created, zero bytes written yet

        def finish_write():
            time.sleep(0.3)
            with open(inflight, "w") as f:
                f.write(winner)

        with _mock.patch.object(_core, "_NODE_KEY_PATH", inflight), \
                _mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("CYBERNET_NODE_PRIVKEY", None)
            t = threading.Thread(target=finish_write)
            t.start()
            try:
                priv3, _pub3 = _node_keypair()
                check("in-flight winner adopted once its write lands",
                      priv3 == winner)
            except RuntimeError:
                check("in-flight winner adopted once its write lands",
                      False, "RuntimeError on an in-flight write")
            t.join()
        # A file that never settles (crash-truncated for good) still
        # fails closed with the same RuntimeError after the window.
        stuck = os.path.join(td, "stuck.key")
        with open(stuck, "w"):
            pass
        with _mock.patch.object(_core, "_NODE_KEY_PATH", stuck), \
                _mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("CYBERNET_NODE_PRIVKEY", None)
            try:
                _node_keypair()
                check("never-settling key file still refused", False,
                      "no RuntimeError")
            except RuntimeError:
                check("never-settling key file still refused", True)


def main():
    print("names-registry primitive tests (core.py):")
    db_dir_cases()
    node_key_cases()
    label_cases()
    conflict_cases()
    claim_beats_pubkey_cases()
    old_binding_fallback_pubkey_cases()
    node_url_cases()
    node_url_host_cases()
    reject_nonpublic_cases()
    claim_time_cases()
    claim_payload_cases()
    print(f"  {CASES['passed']} passed, {CASES['failed']} failed")
    sys.exit(1 if CASES["failed"] else 0)


if __name__ == "__main__":
    main()
