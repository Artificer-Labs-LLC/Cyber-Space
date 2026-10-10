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
import os
import sys
from datetime import datetime, timezone

import core


def _default_mirror() -> str:
    return os.environ.get("CYBERNET_MIRROR_URL", "http://127.0.0.1:8471")


def _fail(label: str, msg: str) -> None:
    print(f"{label}: {msg}", flush=True)


def plan(address: str, mirror: str) -> tuple[int, list[str]]:
    """Return (exit_code, report_lines). Never raises on bad input."""
    out: list[str] = []

    # Step 0: label shape — an invalid label is a name-side failure, and
    # the plan never goes to the network for it.
    addr = (address or "").strip().lower()
    if not addr.endswith(core.CYBERSPACE_SUFFIX):
        return 1, ["name-side: address is not in .cyberspace"]
    label = addr[: -len(core.CYBERSPACE_SUFFIX)]
    if not core._valid_name_label(label):
        return 1, ["name-side: invalid label"]
    mirror = (mirror or "").strip().rstrip("/")
    if not mirror:
        return 4, ["args: empty mirror URL"]

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
    name = str(binding.get("name", "")).lower()
    node_pubkey = str(binding.get("node_pubkey", "")).lower()
    issued_at = str(binding.get("issued_at", ""))
    expires_at = str(binding.get("expires_at", ""))
    signature = str(binding.get("signature", "")).lower()
    if name != label or len(node_pubkey) != 64 or len(signature) != 128:
        return 1, ["name-side: malformed binding"]
    try:
        bytes.fromhex(node_pubkey)
        bytes.fromhex(signature)
    except ValueError:
        return 1, ["name-side: malformed binding"]
    if not core._name_binding_verify(name, node_pubkey, issued_at,
                                     expires_at, signature):
        return 1, ["name-side: binding signature does not verify"]
    try:
        live = core._parse_claim_time(expires_at) > datetime.now(timezone.utc)
    except ValueError:
        live = False
    if not live:
        return 1, ["name-side: binding expired"]
    out.append(f"name: {addr}")
    out.append(f"name-key: {node_pubkey}")

    # Step 4: descriptor fetch + re-verify — the reach list rides a
    # name-key-signed envelope; node_pubkey must equal the binding's key,
    # or the descriptor is somebody else's mouth moving.
    desc = core._resolve_get_json(mirror + "/api/v1/names/" + label + "/reach")
    if isinstance(desc, dict) and core._reach_descriptor_verify(desc):
        if str(desc.get("node_pubkey", "")).lower() != node_pubkey:
            return 1, ["name-side: descriptor names a different key"]
    else:
        desc = None

    # Step 5: strategy extraction, in hoster-preference order: direct,
    # then relay, then rendezvous — the same order resolve_cyberspace
    # dials. Legacy directory fallback: the mirror's directory scanned
    # for the entry whose node_pub IS the name key (see
    # resolve_cyberspace's contract).
    if desc is not None:
        direct = None
        for strat in desc.get("reach") or []:
            if not isinstance(strat, dict):
                continue
            if str(strat.get("kind", "")) != "direct":
                continue
            try:
                direct = core._valid_node_url(str(strat.get("url", "")))
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

    directory = core._resolve_get_json(mirror + "/api/v1/directory")
    if isinstance(directory, dict):
        for entry in (directory.get("nodes")
                      or directory.get("agents") or []):
            if not isinstance(entry, dict):
                continue
            if str(entry.get("node_pub", "")).lower() != node_pubkey:
                continue
            try:
                url = core._valid_node_url(str(entry.get("node_url", "")))
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
    parser = argparse.ArgumentParser(
        description="Dry-run dial planner for .cyberspace names."
    )
    parser.add_argument("name", help="the .cyberspace name to plan a dial to")
    parser.add_argument(
        "--mirror", default=_default_mirror(),
        help="mirror base URL (default: CYBERNET_MIRROR_URL or 127.0.0.1:8471)",
    )
    args = parser.parse_args(argv)

    code, lines = plan(args.name, args.mirror)
    for line in lines:
        print(line, flush=True)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
