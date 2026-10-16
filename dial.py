#!/usr/bin/env python3
"""cyberspace-dial: the agent's dry-run dial planner — primitive 2/3 front door.

Naming has mint_name.py. Resolution has resolver/client.py (the UDP/TCP
wire face). Hosting has resolver/host.py (the hosting daemon). This is the
fourth seat: given a .cyberspace name, show HOW it would be dialed — direct
URL, relay hold-open, or rendezvous — from the mirror's verified binding
and the name-key-signed reach descriptor.

It is a planner, not a dialer: it runs the five provable steps
(binding fetch, binding re-verify, expiry, descriptor fetch, descriptor
re-verify + strategy extraction) and deliberately stops before step 6,
the live verification that resolve_cyberspace performs. Nothing opens a
session, nothing sends bytes to the hoster — the daemon dials only what
this plan describes.

Fail-closed semantics mirror the resolver's: the mirror is operator
trust-anchor only (CYBERNET_MIRROR_URL, or --mirror), never a
peer-supplied address. A name with a live binding but no announced reach
is a silent host: the plan reports nothing to dial, never a guess.

Exit codes: 0 plan printed | 1 name-side failure (invalid label, no
binding, bad signature, expired) | 2 mirror silent | 3 name bound but no
reach (silent host) | 4 bad arguments.
"""

import argparse
import ipaddress
import os
import sys
import urllib.parse
from datetime import datetime, timedelta, timezone

import core


def _default_mirror() -> str:
    return os.environ.get("CYBERNET_MIRROR_URL", "http://127.0.0.1:8471")


def _fail(label: str, msg: str) -> None:
    print(f"{label}: {msg}", flush=True)


def plan(address: str, mirror: str) -> tuple[int, list[str]]:
    """Return (exit_code, report_lines). Never raises on bad input."""
    out: list[str] = []

    # Step 0: label shape — an invalid label is a name-side failure, and
    # the plan never goes to the network for it. A non-string address
    # reached .strip() raw and escaped as AttributeError/TypeError,
    # breaking plan()'s never-raises contract; it is no label at all.
    if not isinstance(address, str):
        return 1, ["name-side: address is not a string"]
    addr = (address or "").strip().lower()
    if addr.endswith("."):
        addr = addr[:-1]  # a single FQDN root dot, as the resolver client accepts
    if not addr.endswith(core.CYBERSPACE_SUFFIX):
        return 1, ["name-side: address is not in .cyberspace"]
    label = addr[: -len(core.CYBERSPACE_SUFFIX)]
    if not core._valid_name_label(label):
        return 1, ["name-side: invalid label"]
    # A non-string mirror reached .strip() raw the same way — a bad
    # argument (exit 4), never a crash and never "mirror: silent".
    if not isinstance(mirror, str):
        return 4, ["args: mirror URL is not a string"]
    mirror = (mirror or "").strip().rstrip("/")
    if not mirror:
        return 4, ["args: empty mirror URL"]
    # A mirror that is not an http(s) URL with a host can never be
    # fetched (_resolve_get_json swallows the urlopen error as None),
    # so without this check it read as exit 2 "mirror: silent" — a
    # well-formed mirror that is merely down — when it is really a bad
    # argument. Shape only, mirroring resolverd's mirror warning:
    # loopback is honest here, no public-address gate. Never echo the
    # value (it is operator config, not the caller's to see repeated).
    # The port is part of the shape: urlsplit does not validate it, so
    # a mirror naming an undialable port (0, >65535, or non-numeric —
    # parts.port raises for the last two) passed this gate and read as
    # the same false "silent". A port no dial can ever attempt is a
    # bad argument, exactly as core._valid_node_url ruled for node URLs.
    # The rest of the mirror shape is mint_name._valid_mirror's: a
    # userinfo spelling dials the host AFTER the "@" while spelling
    # like the one before it, a query/fragment spelling mangles the
    # appended "/api/v1/..." fetch, and a host spelled outside the
    # stored-address host class (percent escape, backslash, non-ASCII)
    # can never be dialed as written — each passed this gate and read
    # as the same false "silent" (probed this tick). A bracketed IPv6
    # literal stays valid, judged by parsing it (zone included).
    # The raw-string gate is _valid_mirror's too, and this twin had
    # not carried it: whitespace/control characters surviving the
    # outer strip above (an interior newline/tab — urlsplit silently
    # strips \t\r\n before parsing — a space, or a \x01 in the path)
    # passed every check below and read as the same false "silent",
    # though no honest mirror contains one and the fetch can never
    # ask for the URL as written.
    ws_ok = not any(c.isspace() or ord(c) < 0x20 or ord(c) == 0x7F
                    for c in mirror)
    try:
        parts = urllib.parse.urlsplit(mirror)
        port = parts.port
        host = parts.hostname
        if not host:
            host_ok = False
        elif ":" in host:
            try:
                ipaddress.IPv6Address(host)
                host_ok = True
            except ValueError:
                host_ok = False
        else:
            host_ok = all(c.isascii() and (c.isalnum() or c in "._-")
                          for c in host)
        mirror_ok = (
            ws_ok
            and parts.scheme in ("http", "https")
            and host_ok
            and parts.username is None and parts.password is None
            and (port is None or 1 <= port <= 65535)
            and "?" not in mirror and "#" not in mirror
        )
    except ValueError:
        mirror_ok = False
    if not mirror_ok:
        return 4, ["args: malformed mirror URL (not an http(s) URL with a host)"]

    # Step 1: mirror liveness — a silent mirror is distinguishable from
    # a withheld name. The liveness answer is untrusted for everything
    # except reachability: any JSON 200 counts as alive.
    if core._resolve_get_json(mirror + "/api/v1/node") is None:
        return 2, ["mirror: silent (no answer at /api/v1/node)"]

    # Step 2: binding fetch — exact name only, fail-closed like the
    # resolver: a mirror can withhold a name but never redirect one.
    binding = core._resolve_get_json(mirror + "/api/v1/names/" + label)
    if not isinstance(binding, dict):
        return 1, ["name-side: no binding for this label"]

    # Step 3: binding re-verify — shape, signature, expiry. The mirror's
    # word alone is never enough; the signature must verify against the
    # name key the mirror claims.
    # The binding fields are mirror-carried JSON: str() aliased a
    # non-string field into the string it merely resembles — a JSON
    # true served as the name verified as the label "true" (str(True)
    # .lower()) against a signature genuinely signed for "true", and a
    # digit-only pubkey served as a number stringified to its own hex.
    # Only real strings are binding fields (twin of the canonical
    # payload builders' gate in core); anything else is malformed.
    _raw = [binding.get(k, "") for k in
            ("name", "node_pubkey", "issued_at", "expires_at", "signature")]
    if not all(isinstance(v, str) for v in _raw):
        return 1, ["name-side: malformed binding"]
    name = _raw[0].lower()
    node_pubkey = _raw[1].lower()
    issued_at = _raw[2]
    expires_at = _raw[3]
    signature = _raw[4].lower()
    if name != label or len(node_pubkey) != 64 or len(signature) != 128:
        return 1, ["name-side: malformed binding"]
    try:
        pub_b = bytes.fromhex(node_pubkey)
        sig_b = bytes.fromhex(signature)
    except ValueError:
        return 1, ["name-side: malformed binding"]
    # Decoded-length gate, twin of verify_name 69ba6b5: bytes.fromhex
    # ignores embedded spaces, so a spaced 64-char pubkey decoded to
    # 31 bytes (a spaced signature to 63), passed the shape gate above,
    # and _name_binding_verify read it as "signature does not verify"
    # when the key/sig itself was malformed — the planner's verdicts
    # must stay precise, malformed is not unverifiable.
    if len(pub_b) != 32 or len(sig_b) != 64:
        return 1, ["name-side: malformed binding"]
    if not core._name_binding_verify(name, node_pubkey, issued_at,
                                     expires_at, signature):
        return 1, ["name-side: binding signature does not verify"]
    # The daemon's step 4 parses issued_at too (its floor fix: an
    # unparseable issued_at reads as absent, never live) — a signer can
    # sign a garbage issued_at and pass step 3, so without this check
    # the plan previewed a dial (exit 0) for a binding the resolver
    # itself reads as no binding at all.
    try:
        issued_dt = core._parse_claim_time(issued_at)
    except ValueError:
        return 1, ["name-side: malformed binding"]
    # Same not-yet-issued floor as the resolver's step 4 (verify_name's
    # wording): a future-dated binding has not begun, however valid.
    if issued_dt > datetime.now(timezone.utc):
        return 1, ["name-side: binding not yet issued"]
    try:
        expires_dt = core._parse_claim_time(expires_at)
        live = expires_dt > datetime.now(timezone.utc)
    except ValueError:
        live = False
        expires_dt = None
    if not live:
        return 1, ["name-side: binding expired"]
    # Lifetime cap, twin of core._name_binding_admission_ok and of the
    # resolver's step 4: intrinsic to the binding (expires - issued),
    # so an over-cap binding the mirror serves (valid signature, live
    # expiry) is refused here just as admission refuses it.
    if (expires_dt - issued_dt) > timedelta(days=core.NAME_EXPIRY_DAYS):
        return 1, ["name-side: binding lifetime exceeds 365 days"]
    out.append(f"name: {addr}")
    out.append(f"name-key: {node_pubkey}")

    # Step 4: descriptor fetch + re-verify — the reach list rides a
    # name-key-signed envelope; node_pubkey must equal the binding's key,
    # or the descriptor is somebody else's mouth moving.
    desc = core._resolve_get_json(mirror + "/api/v1/names/" + label + "/reach")
    if isinstance(desc, dict) and core._reach_descriptor_verify(desc):
        # Only real strings are descriptor fields (twin of the step-3
        # binding gate): _reach_descriptor_verify gates name/pub today,
        # but this seat must not str()-alias on its own — a digit-only
        # pubkey served as a number stringified to its own hex and the
        # seat read the descriptor as this name's, the SAME alias the
        # binding and directory seats refuse on sight.
        _desc_pub = desc.get("node_pubkey")
        if not isinstance(_desc_pub, str) or _desc_pub.lower() != node_pubkey:
            # A descriptor that verifies but names a different key is not
            # this name's mouth moving: the daemon (resolve_cyberspace
            # step 5) skips it and falls to the directory scan, so the
            # plan previews that instead of vetoing the dial.
            out.append("note: descriptor names a different key — directory fallback")
            desc = None
        elif not isinstance(desc.get("name"), str) \
                or desc.get("name").lower() != label:
            # A descriptor that verifies under the right key but was
            # signed for a DIFFERENT name is not this name's mouth
            # moving either: the name is inside the signed canonical
            # form, so a mirror cross-serving one name's descriptor
            # under another name (same key, two claims) could otherwise
            # redirect this dial to the other name's reach. The daemon
            # (resolve_cyberspace step 5) skips it the same way, so the
            # plan previews the directory fallback instead.
            out.append("note: descriptor names a different name — directory fallback")
            desc = None
    else:
        desc = None

    # Step 5: strategy extraction, in hoster-preference order: direct,
    # then relay, then rendezvous — the same order resolve_cyberspace
    # dials. Legacy directory fallback: the mirror's directory scanned
    # for the entry whose node_pub IS the name key (see
    # resolve_cyberspace's contract). The real mirror serves
    # {"entries": [...]} — the planner reads the same shape the daemon
    # reads, and the same ?limit=200 wide slice (a mirror with >200
    # reachable peers reads as silence past the slice, fail-closed).
    if desc is not None:
        direct = None
        for strat in desc.get("reach") or []:
            if not isinstance(strat, dict):
                continue
            # Only real strings are strategy fields (twin of core's
            # step-5 direct seat and of _relay_route/_rendezvous_
            # strategy): str() here aliased a non-string kind whose
            # string form is "direct" into the direct strategy, and a
            # non-string url past _valid_node_url's own non-string gate.
            if strat.get("kind") != "direct":
                continue
            _url_raw = strat.get("url")
            if not isinstance(_url_raw, str):
                continue
            try:
                direct = core._valid_node_url(_url_raw)
            except core.HTTPException:
                continue
            break
        if direct:
            out.append(f"plan: direct {direct}")
            out.append("via: name-key-signed reach descriptor")
            return 0, out
        relay = core._relay_route(desc)
        if relay:
            tok = relay["token"]
            out.append(f"plan: relay {relay['relay_pub']} via {relay['url']}")
            out.append(f"token: {len(tok)} chars (dial credential, not printed)")
            out.append("via: name-key-signed reach descriptor")
            return 0, out
        rv = core._rendezvous_strategy(desc)
        if rv:
            out.append(f"plan: rendezvous epoch_len={rv['epoch_len']}")
            out.append(f"probe: {rv['hold_query']}?point_id=<derived>")
            out.append("via: name-key-signed reach descriptor")
            return 0, out

    directory = core._resolve_get_json(mirror + "/api/v1/directory?limit=200")
    if isinstance(directory, dict):
        # The directory is mirror-controlled: an entries value that is
        # not a list (123, true) died in a TypeError traceback on the
        # iteration instead of reading as no matching entry — plan()
        # promises never to raise on bad input. Only a list can hold
        # entries; every other shape simply has none.
        entries = directory.get("entries")
        for entry in entries if isinstance(entries, list) else []:
            if not isinstance(entry, dict):
                continue
            # Only real strings are directory fields (twin of core
            # resolve_cyberspace's step-5 directory gate): str() here
            # aliased a mirror-carried int node_pub into the digit-
            # string form of a digit-only name key — the SAME entry
            # the binding seats refuse on sight — and the plan read
            # it as this name's legacy directory entry.
            entry_pub = entry.get("node_pub")
            if not isinstance(entry_pub, str) \
                    or entry_pub.lower() != node_pubkey:
                continue
            entry_url = entry.get("node_url")
            if not isinstance(entry_url, str):
                continue
            try:
                url = core._valid_node_url(entry_url)
            except core.HTTPException:
                continue
            out.append(f"plan: direct {url}")
            out.append("via: legacy directory entry (name-key announced)")
            return 0, out

    # The name is claimed and live, the host publishes nothing: a silent
    # host reads as nothing, never as a guess.
    out.append("plan: none — name is bound but the host publishes no reach")
    return 3, out


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    # argparse silently last-wins on a repeated value flag, so
    # --mirror A --mirror B planned against B while the operator
    # believed the trust-anchor was A (probed this tick). Refuse a
    # repeated --mirror by name, in space, equals or mixed spelling,
    # before argparse runs — before any mirror is fetched. Exit 4 is
    # this planner's bad-argument code. Twin of resolve_chain's gate.
    _seen: set[str] = set()
    for _tok in argv:
        if _tok == "--":
            break
        if not _tok.startswith("--"):
            continue
        _name = _tok.partition("=")[0]
        if _name != "--mirror" and "--mirror".startswith(_name):
            # argparse accepts any unambiguous prefix as an
            # abbreviation, so --mir (even --m) silently became
            # --mirror and dodged the duplicate gate below: a
            # --mir A --mirror B pair planned against B while the
            # operator believed the anchor was A (probed this
            # tick). Refuse the abbreviated spelling itself, by
            # name, before argparse can expand it.
            print(f"refused: {_name} is an abbreviation of --mirror "
                  f"— spell it out", file=sys.stderr)
            return 4
        if _name == "--mirror":
            if _name in _seen:
                print(f"refused: {_name} given more than once",
                      file=sys.stderr)
                return 4
            _seen.add(_name)
    parser = argparse.ArgumentParser(
        description="Dry-run dial planner for .cyberspace names.",
        allow_abbrev=False,
    )
    parser.add_argument("name", help="the .cyberspace name to plan a dial to")
    parser.add_argument(
        "--mirror", default=_default_mirror(),
        help="mirror base URL (default: CYBERNET_MIRROR_URL or 127.0.0.1:8471)",
    )
    # argparse itself still raises SystemExit on the bad arguments no
    # gate above can pre-empt — an unknown flag, a dangling --mirror, a
    # missing or surplus positional — crashing any in-process caller of
    # main(); --help raises SystemExit 0 the same way. Convert the exit
    # to this CLI's return after argparse prints its usage/error text;
    # the __main__ seat re-raises the return, so shell behaviour is
    # unchanged. Twin of rotate_name.py / resolve_chain.py.
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2

    code, lines = plan(args.name, args.mirror)
    for line in lines:
        print(line, flush=True)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
