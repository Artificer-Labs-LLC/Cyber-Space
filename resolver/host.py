"""cybernet-hostd: the per-agent hosting daemon of .cyberspace.

The daemon every agent runs (six primitives: primitive 3 hosting /
primitive 6 client daemon) — a name-key holder that keeps one hosted
.cyberspace name reachable from anywhere: a direct public URL, or a
relay hold-open when the host sits behind NAT.

Two parts, one process:
  1. hold-open thread — hold_open.hold_open_cycle: registers the
     hold-open at the public relay and answers each dialer's challenge
     with the NAME KEY (never the master identity). The relay sees
     bytes, never identity. The same hold-open is indexed under the
     derived (E, E-1) rendezvous points at the same relay — a dialer
     that derived the point itself pairs it without the relay learning
     the label (docs/RENDEZVOUS.md frozen spec).
  2. reach-announce loop — mints the name-key-signed reach descriptor
     (core._reach_build: direct + relay strategies, fail-closed when
     there is no honest reach) and POSTs the signed /fed/announce to
     the mirror. The mirror merges via ingest_reach_descriptor —
     stranger-can-host, self-authenticating against a live same-key
     binding; without the announce no descriptor is served, and with no
     honest reach the daemon publishes nothing rather than a lie.

What the daemon holds: the name key's 32-byte seed (hex) and ONLY the
name key. It never touches the master identity key, the node roster,
or the registry — the binding names the key that answers, nothing else.

Config (environment, bad values degrade to silence, never to a lie):
  CYBERNET_HOSTED_NAME     .cyberspace label hosted (required to run)
  CYBERNET_NAME_PRIVKEY    64-hex name-key seed (required to run)
  CYBERNET_MIRROR_URL      public mirror base URL for the reach announce
                           (REQUIRED — there is no default. The old
                           docstring claimed http://127.0.0.1:8471, but
                           that loopback value never passes the
                           public-URL gate core._valid_node_url applies;
                           a mirror is a public node. Unset or invalid
                           -> the daemon refuses to start, loudly.)
  CYBERNET_PUBLIC_URL      direct dial URL (optional if relay is set)
  CYBERNET_RELAY_URL / CYBERNET_RELAY_PUBKEY / CYBERNET_RELAY_TOKEN
                           relay hold-open (optional if direct is set)
                           — all three together or nothing: a
                           half-filled triple disables the relay and
                           run() says so loudly on stderr at startup
                           (nothing set = direct dial, silent by choice)
  CYBERNET_REACH_TTL       descriptor lifetime seconds (default 86400)
  CYBERNET_HOSTD_REFRESH   re-announce cadence seconds (default 600)

Run from the repo root:  python -m resolver.host
"""

import json
import os
import random
import signal
import sys
import threading
import time
import urllib.error
import urllib.request

import core
import hold_open

def _env_int(name: str, default: int, floor: int = 1) -> int:
    """Bad env values fall back, never crash the daemon."""
    try:
        return max(floor, int(os.environ.get(name, "").strip()))
    except (ValueError, TypeError):
        return default


def _config() -> tuple[str, str, str | None, int, bool]:
    """(name, name_priv_hex, mirror_url, refresh, runnable). runnable is
    False when the daemon has no valid name+key (it refuses to run:
    a hosting daemon without a name is nothing — fail-closed at startup)
    or no usable mirror. The mirror is REQUIRED and must be a public URL
    (core._valid_node_url's gate): there is no loopback default, because
    the old 127.0.0.1:8471 default could never pass that gate — a mirror
    is a public node, and a host with nowhere honest to announce simply
    does not start.
    """
    name = os.environ.get("CYBERNET_HOSTED_NAME", "").strip().lower()
    name_priv = os.environ.get("CYBERNET_NAME_PRIVKEY", "").strip().lower()
    ok = bool(name) and core._valid_name_label(name) is True
    if ok:
        try:
            ok = len(bytes.fromhex(name_priv)) == 32
        except Exception:
            ok = False
    mirror_raw = os.environ.get("CYBERNET_MIRROR_URL", "").strip()
    try:
        mirror = core._valid_node_url(mirror_raw)
    except Exception:
        mirror, ok = None, False
    return name, name_priv, mirror, _env_int("CYBERNET_HOSTD_REFRESH", 600), ok


def _relay_cfg() -> tuple[str, str, str] | None:
    """The relay hold-open config, or None when the host dials direct
    only. Shape-checked here (shape-proofed again inside _reach_build —
    a relay URL that passes one gate but not the other is simply not
    advertised)."""
    relay_url = os.environ.get("CYBERNET_RELAY_URL", "").strip()
    relay_pub = os.environ.get("CYBERNET_RELAY_PUBKEY", "").strip().lower()
    relay_token = os.environ.get("CYBERNET_RELAY_TOKEN", "").strip()
    if not relay_url or not relay_pub or not relay_token:
        return None
    try:
        if len(relay_pub) != 64:
            raise ValueError("relay pubkey must be 64 hex chars")
        bytes.fromhex(relay_pub)  # same gate core._reach_build applies
        if len(relay_token) > core._RELAY_TOKEN_CAP:
            raise ValueError("relay token too long")
        return (core._valid_node_url(relay_url), relay_pub, relay_token)
    except Exception:
        return None


def _relay_warnings() -> list[str]:
    """Loud config mistakes, or []. The triple (URL, PUBKEY, TOKEN) is
    all-or-nothing: nothing set means relay simply not configured (direct
    dial — silent, a choice). Anything set but unusable is a mistake the
    daemon would otherwise hide by hosting direct-dial with no hint, so
    run() prints each of these to stderr. Mirrors the exact rules in
    core._reach_build; never prints secret VALUES, only which var and
    why."""
    url = os.environ.get("CYBERNET_RELAY_URL", "").strip()
    pub = os.environ.get("CYBERNET_RELAY_PUBKEY", "").strip().lower()
    tok = os.environ.get("CYBERNET_RELAY_TOKEN", "").strip()
    if not url and not pub and not tok:
        return []
    problems: list[str] = []
    if not url:
        problems.append("CYBERNET_RELAY_URL unset")
    else:
        try:
            core._valid_node_url(url)
        except Exception:
            problems.append("CYBERNET_RELAY_URL malformed")
    if not pub:
        problems.append("CYBERNET_RELAY_PUBKEY unset")
    elif len(pub) != 64:
        problems.append("CYBERNET_RELAY_PUBKEY must be 64 hex chars")
    else:
        try:
            bytes.fromhex(pub)
        except Exception:
            problems.append("CYBERNET_RELAY_PUBKEY not hex")
    if not tok:
        problems.append("CYBERNET_RELAY_TOKEN unset")
    elif len(tok) > core._RELAY_TOKEN_CAP:
        problems.append(
            f"CYBERNET_RELAY_TOKEN too long (> {core._RELAY_TOKEN_CAP} chars)")
    return problems


def _mirror_post(mirror_url: str, path: str, env: dict) -> bool:
    """Signed POST to the mirror. True on HTTP 200; anything else
    (4xx/5xx/timeout) is silence, never a crash. Never raises."""
    try:
        req = urllib.request.Request(
            mirror_url + path, data=json.dumps(env).encode(),
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            return resp.status == 200
    except Exception:
        return False


def announce_once(mirror_url: str, name: str, name_priv_hex: str) -> bool:
    """Mint and dispatch one reach announce to the mirror (the send half
    of docs/HOSTING.md, primitive 3). The envelope is signed by the NAME
    KEY: sender_pub == body.node_pub == the binding key, a name identity
    speaking for its own reachability. Returns True when the mirror
    accepted the announce (HTTP 200 — the merge half tallies outcomes
    server-side); False when there is no honest reach to advertise or
    the mirror is unreachable. Never raises."""
    try:
        built = core._reach_build(name, name_priv_hex)
        if built is None:
            return False
        desc, name_pub = built
        body = {
            "name": name,
            "network": "cybernet",
            "version": "0.1.0",
            "node_pub": name_pub,
            "reach_descriptor": desc,
        }
        env = core._fed_env.make_envelope(name_priv_hex, name_pub,
                                          "federation", body)
        return _mirror_post(mirror_url, "/fed/announce", env)
    except Exception:
        return False


def run() -> int:
    """Run the hosting daemon until SIGINT/SIGTERM. Returns 0 on clean
    shutdown, 2 when misconfigured (a hosting daemon without a name or
    a mirror refuses to start — fail-closed). Never raises."""
    name, name_priv, mirror_url, refresh, ok = _config()
    if not ok:
        if not os.environ.get("CYBERNET_MIRROR_URL", "").strip():
            print("hostd: CYBERNET_MIRROR_URL is required (a public mirror"
                  " URL) — refusing to start with nowhere honest to announce",
                  file=sys.stderr)
        return 2
    stop = threading.Event()

    def _stop(_signum, _frame):
        stop.set()

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    relay = _relay_cfg()
    if relay is None:
        # Half-configured relay would otherwise silently degrade to
        # direct-dial: the operator set the intent but no hold-open will
        # ever register. Shout it at startup (stderr, no secret values).
        for warn in _relay_warnings():
            print(f"hostd: relay disabled: {warn}", file=sys.stderr)
    else:
        # _relay_cfg returns (relay_url, relay_pub, relay_token): the
        # hold-open registers under the ROUTING token the reach
        # descriptor advertises (core._reach_build), not the relay's
        # identity pubkey — the dialer looks the hold-open up by that
        # token (was: pubkey passed as token, dialers 404ed).
        relay_url, _, relay_token = relay
        threading.Thread(
            target=hold_open.hold_open_cycle,
            args=(relay_url, relay_token, name_priv, stop),
            daemon=True).start()

    while not stop.is_set():
        try:
            announce_once(mirror_url, name, name_priv)
        except Exception:
            pass  # the loop degrades, never guesses
        stop.wait(refresh * random.uniform(0.8, 1.2))
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
