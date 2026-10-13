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
                           — set but not a valid public URL -> the
                           direct strategy is silently dropped by
                           _reach_build, so run() warns loudly on
                           stderr at startup (see _public_url_warnings)
                           — NEITHER a usable direct URL nor a usable
                           relay triple -> _reach_build returns None and
                           no announce can ever succeed, so run() warns
                           loudly on stderr at startup that there is no
                           reach strategy at all (see _no_reach_warnings)
  CYBERNET_RELAY_URL / CYBERNET_RELAY_PUBKEY / CYBERNET_RELAY_TOKEN
                           relay hold-open (optional if direct is set)
                           — all three together or nothing: a
                           half-filled triple disables the relay and
                           run() says so loudly on stderr at startup
                           (nothing set = direct dial, silent by choice)
  CYBERNET_RENDEZVOUS / CYBERNET_RENDEZVOUS_EPOCH_LEN
                           derived-point rendezvous (optional, only
                           exactly "1" enables it) — the descriptor
                           entry rides on the relay strategy, so with
                           no usable relay it is silently omitted by
                           _reach_build, and a bad epoch_len silently
                           falls back to the frozen default; an
                           epoch_len set while rendezvous is off is
                           held under but never advertised, so dialers
                           deriving with the default never meet the
                           points; run() warns loudly on stderr at
                           startup for all three (see
                           _rendezvous_warnings)
  CYBERNET_REACH_TTL       descriptor lifetime seconds (default 86400)
                           — set but not an integer -> _reach_build
                           silently falls back to 86400, and an integer
                           below 600 is silently clamped to 600; run()
                           warns loudly on stderr at startup for both
                           (see _reach_ttl_warnings)
  CYBERNET_HOSTD_REFRESH   re-announce cadence seconds (default 600)
                           — set but not an integer -> _env_int silently
                           falls back to 600, and an integer below 1 is
                           silently clamped to 1 (a near-continuous
                           announce loop); run() warns loudly on stderr
                           at startup for both (see
                           _hostd_refresh_warnings)

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
import rendezvous

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


def _startup_problems() -> list[str]:
    """Why run() must refuse to start, or []. run() used to speak ONLY
    when CYBERNET_MIRROR_URL was unset: a malformed mirror, a bad label,
    or a missing/short/non-hex name key (with a mirror set) exited 2 in
    total silence — systemd 'failed', zero output, the operator left
    guessing which of the three required values was wrong. Mirrors the
    exact gates _config applies; never prints secret VALUES, only
    which var and why."""
    problems: list[str] = []
    name = os.environ.get("CYBERNET_HOSTED_NAME", "").strip().lower()
    if not name:
        problems.append("CYBERNET_HOSTED_NAME unset")
    elif core._valid_name_label(name) is not True:
        problems.append("CYBERNET_HOSTED_NAME is not a valid "
                        ".cyberspace label")
    name_priv = os.environ.get("CYBERNET_NAME_PRIVKEY", "").strip()
    if not name_priv:
        problems.append("CYBERNET_NAME_PRIVKEY unset")
    else:
        try:
            if len(bytes.fromhex(name_priv)) != 32:
                problems.append("CYBERNET_NAME_PRIVKEY must be a "
                                "64-hex-char (32-byte) seed")
        except Exception:
            problems.append("CYBERNET_NAME_PRIVKEY is not hex")
    mirror_raw = os.environ.get("CYBERNET_MIRROR_URL", "").strip()
    if not mirror_raw:
        problems.append("CYBERNET_MIRROR_URL is required (a public "
                        "mirror URL) — refusing to start with nowhere "
                        "honest to announce")
    else:
        try:
            core._valid_node_url(mirror_raw)
        except Exception:
            problems.append("CYBERNET_MIRROR_URL is not a valid "
                            "public node URL")
    return problems


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
        # Decoded-length gate, same as core._reach_build: bytes.fromhex
        # ignores embedded spaces, so a spaced 64-char pubkey decodes
        # to 31 bytes and core would refuse the relay strategy this
        # cfg claims is configured.
        if len(bytes.fromhex(relay_pub)) != 32:
            raise ValueError("relay pubkey must decode to 32 bytes")
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
            # Decoded-length gate (twin of _relay_cfg / core._reach_build):
            # a spaced 64-char pubkey parses but decodes to 31 bytes and
            # core refuses it — warn instead of staying silent.
            if len(bytes.fromhex(pub)) != 32:
                problems.append("CYBERNET_RELAY_PUBKEY must be 64 hex chars")
        except Exception:
            problems.append("CYBERNET_RELAY_PUBKEY not hex")
    if not tok:
        problems.append("CYBERNET_RELAY_TOKEN unset")
    elif len(tok) > core._RELAY_TOKEN_CAP:
        problems.append(
            f"CYBERNET_RELAY_TOKEN too long (> {core._RELAY_TOKEN_CAP} chars)")
    return problems


def _public_url_warnings() -> list[str]:
    """Loud direct-dial config mistake, or []. Unset means direct dial
    simply not configured (silent, a choice — relay-only hosting is
    honest). Set but not a valid public node URL is a mistake
    core._reach_build hides: it drops the direct strategy, so the
    descriptor carries relay only (or nothing, and announce fails
    generically) while the operator believes direct hosting is on.
    Mirrors _relay_warnings; never prints the value itself."""
    url = os.environ.get("CYBERNET_PUBLIC_URL", "").strip()
    if not url:
        return []
    try:
        core._valid_node_url(url)
        return []
    except Exception:
        return ["CYBERNET_PUBLIC_URL is not a valid public node URL "
                "— direct strategy will not be advertised"]


def _relay_strategy_present() -> bool:
    """Whether core._reach_build will carry a relay strategy — the
    exact gates it applies (valid public relay URL, 64-hex relay
    pubkey, non-empty token within the cap). Never raises."""
    relay_url = os.environ.get("CYBERNET_RELAY_URL", "").strip()
    relay_pub = os.environ.get("CYBERNET_RELAY_PUBKEY", "").strip().lower()
    relay_token = os.environ.get("CYBERNET_RELAY_TOKEN", "").strip()
    try:
        core._valid_node_url(relay_url)
        if len(relay_pub) != 64:
            return False
        if len(bytes.fromhex(relay_pub)) != 32:
            return False
        return bool(relay_token) and len(relay_token) <= core._RELAY_TOKEN_CAP
    except Exception:
        return False


def _direct_strategy_present() -> bool:
    """Whether core._reach_build will carry a direct strategy — the
    exact gate it applies (valid public CYBERNET_PUBLIC_URL). Never
    raises."""
    try:
        core._valid_node_url(os.environ.get("CYBERNET_PUBLIC_URL", "").strip())
        return True
    except Exception:
        return False


def _no_reach_warnings() -> list[str]:
    """Loud no-reach config mistake, or []. Direct and relay are each
    optional IF the other is set, so a minted env (mint_name.py writes
    neither — both stay commented, unknown at mint time) installed
    as-is, or any config with an invalid public URL and an absent or
    half-filled relay triple, has NO usable strategy: _reach_build
    returns None, announce_once returns False forever, and the only
    trace was the first announce note's ambiguous 'no honest reach'
    among three possible causes. run() names the real cause at
    startup: the name will not be reachable until one strategy is
    configured. The daemon still runs and retries (a strategy can
    only arrive via a restart with fixed env, but the announce loop's
    retry contract is unchanged); never prints secret VALUES."""
    if _direct_strategy_present() or _relay_strategy_present():
        return []
    return ["no usable reach strategy — neither a valid "
            "CYBERNET_PUBLIC_URL (direct) nor a complete relay triple "
            "(CYBERNET_RELAY_URL + CYBERNET_RELAY_PUBKEY + "
            "CYBERNET_RELAY_TOKEN) is configured, so no reach "
            "descriptor can be built and the name will NOT be "
            "reachable"]


def _rendezvous_warnings() -> list[str]:
    """Loud rendezvous config mistakes, or []. Rendezvous is enabled
    only by exactly CYBERNET_RENDEZVOUS=1 (unset and "0" are silent —
    off by choice, unless an epoch_len is also set; see below). Four
    set-but-ineffective cases core._reach_build otherwise hides: a
    value other than "1" (a "true"/"yes" the operator believes
    enabled it); "1" with no usable relay strategy (the descriptor
    entry rides on the relay strategy, so it is omitted and no dialer
    ever probes the derived points); a set
    CYBERNET_RENDEZVOUS_EPOCH_LEN that is not an integer in bounds
    (descriptor and hold-open both fall back to the frozen default, so
    the operator's custom epoch silently never takes effect); and a
    set CYBERNET_RENDEZVOUS_EPOCH_LEN while rendezvous is NOT enabled
    (the hold-open derives its points under it unconditionally, but
    the descriptor never advertises it, so a dialer deriving with
    the frozen default never meets the held points). Never prints
    secret VALUES, only which var and why."""
    raw = os.environ.get("CYBERNET_RENDEZVOUS", "").strip()
    epoch_raw = os.environ.get("CYBERNET_RENDEZVOUS_EPOCH_LEN", "").strip()
    if raw != "1":
        problems: list[str] = []
        if raw and raw != "0":
            problems.append(
                "CYBERNET_RENDEZVOUS is set but is not '1' — rendezvous "
                "is NOT enabled (only exactly '1' enables it)")
        if epoch_raw:
            # The hold-open derives its points under this value
            # unconditionally (hold_open._rendezvous_epoch_len), but
            # _reach_build advertises it only when rendezvous is
            # enabled — set while off, a custom epoch is held under
            # yet never advertised, so a dialer deriving with the
            # frozen default never meets the held points.
            problems.append(
                "CYBERNET_RENDEZVOUS_EPOCH_LEN is set but rendezvous "
                "is not enabled — the hold-open will derive points "
                "under it, but it will NOT be advertised, so dialers "
                f"deriving with the frozen default "
                f"{rendezvous.EPOCH_LEN_DEFAULT} will not meet them "
                "(set CYBERNET_RENDEZVOUS=1 to advertise it)")
        return problems
    problems = []
    if not _relay_strategy_present():
        problems.append(
            "CYBERNET_RENDEZVOUS=1 but no usable relay strategy — "
            "rendezvous will not be advertised (the descriptor entry "
            "rides on the relay strategy)")
    if epoch_raw:
        try:
            epoch_ok = rendezvous._epoch_len_ok(int(epoch_raw))
        except (ValueError, TypeError):
            epoch_ok = False
        if not epoch_ok:
            problems.append(
                "CYBERNET_RENDEZVOUS_EPOCH_LEN is not an integer in "
                f"{rendezvous.EPOCH_LEN_MIN}..{rendezvous.EPOCH_LEN_MAX} "
                f"— the frozen default {rendezvous.EPOCH_LEN_DEFAULT} "
                "will be advertised and held instead")
    return problems


def _reach_ttl_warnings() -> list[str]:
    """Loud reach-TTL config mistakes, or []. Unset/empty means the
    86400 default (silent, a choice). Three set-but-ineffective cases
    core._reach_build otherwise hides: a non-integer value falls back
    to 86400, an integer below 600 is clamped to 600, and an integer
    over the 365-day descriptor lifetime cap is clamped to 31536000
    — an operator who set 60 expecting a one-minute descriptor (or
    typed a unit suffix) gets a different lifetime than configured,
    with the name staying resolvable long after they believed it
    expired. Mirrors _reach_build exactly (min(365d, max(600,
    int(...))) / ValueError -> 86400); never prints the value itself."""
    raw = os.environ.get("CYBERNET_REACH_TTL", "").strip()
    if not raw:
        return []
    try:
        ttl = int(raw)
    except (ValueError, TypeError):
        return ["CYBERNET_REACH_TTL is not an integer — the 86400 "
                "default will be advertised instead"]
    if ttl < 600:
        return ["CYBERNET_REACH_TTL is below the 600 floor — 600 "
                "will be advertised instead"]
    if ttl > 365 * 86400:
        return ["CYBERNET_REACH_TTL exceeds the 365-day descriptor "
                "lifetime cap — 31536000 will be advertised instead"]
    return []


def _hostd_refresh_warnings() -> list[str]:
    """Loud refresh-cadence config mistakes, or []. Unset/empty means
    the 600 default (silent, a choice). Two set-but-ineffective cases
    _env_int otherwise hides: a non-integer value falls back to 600,
    and an integer below the floor of 1 is clamped to 1 — an operator
    who set 0 believing re-announce was disabled instead gets a
    near-continuous announce loop against the mirror. Mirrors
    _env_int("CYBERNET_HOSTD_REFRESH", 600) exactly (max(1, int(...))
    / ValueError -> 600); never prints the value itself."""
    raw = os.environ.get("CYBERNET_HOSTD_REFRESH", "").strip()
    if not raw:
        return []
    try:
        refresh = int(raw)
    except (ValueError, TypeError):
        return ["CYBERNET_HOSTD_REFRESH is not an integer — the 600 "
                "default will be used instead"]
    if refresh < 1:
        return ["CYBERNET_HOSTD_REFRESH is below the 1 floor — 1 "
                "will be used instead (re-announce is never disabled "
                "by this value)"]
    return []


# Mirror-response read bound, twin of mint_name._MIRROR_RESP_MAX /
# rotate_name._MIRROR_RESP_MAX / core._PEER_RESP_MAX: every other depth
# POST seat reads its mirror/peer reply under this same 64KB cap and
# treats oversize as silence. This seat was the last exception — it
# judged the reply by status alone and never read the body at all, so
# an oversize 200 body (a mirror, or anything answering for it,
# streaming without end) counted as an accepted announce. A legit
# /fed/announce verdict is a few hundred bytes; an oversize body is
# never that verdict, so it reads as not-accepted, exactly like every
# other bad mirror answer at this seat.
_MIRROR_RESP_MAX = 65536


def _mirror_post(mirror_url: str, path: str, env: dict) -> bool:
    """Signed POST to the mirror. True on HTTP 200 with a body under
    the read bound; anything else (4xx/5xx/timeout/oversize) is
    silence, never a crash. Never raises."""
    try:
        req = urllib.request.Request(
            mirror_url + path, data=json.dumps(env).encode(),
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            if resp.status != 200:
                return False
            raw = resp.read(_MIRROR_RESP_MAX + 1)
            return len(raw) <= _MIRROR_RESP_MAX
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


def _announce_note(was_ok: bool | None, is_ok: bool, name: str) -> str | None:
    """Operator note for an announce-state TRANSITION, or None.

    announce_once reports only a bool and run() used to discard it: a
    hostd whose key does not control the hosted name (wrong-name env,
    stale pre-rotation installed env) announced into the void forever —
    systemd 'active', name dark, not one line of output. Silence on a
    steady state is right; silence on a transition is a lie of omission.
    First result and every change are spoken; steady states stay quiet.
    Never names a single cause: a refused announce can be no honest
    reach, an unreachable mirror, or a key/name mismatch."""
    if was_ok is None and is_ok:
        return (f"hostd: reach announce for {name}.cyberspace accepted "
                f"by the mirror — the name is reachable")
    if was_ok is None and not is_ok:
        return (f"hostd: WARNING reach announce for {name}.cyberspace NOT "
                f"accepted — the name is NOT reachable (no honest reach, "
                f"mirror unreachable, or CYBERNET_NAME_PRIVKEY does not "
                f"control this name); will keep retrying")
    if was_ok and not is_ok:
        return (f"hostd: WARNING reach announce for {name}.cyberspace "
                f"stopped being accepted — the name is going dark; "
                f"will keep retrying")
    if not was_ok and is_ok:
        return (f"hostd: reach announce for {name}.cyberspace accepted "
                f"again — the name is reachable")
    return None


def run() -> int:
    """Run the hosting daemon until SIGINT/SIGTERM (or, embedded in a
    worker thread where signal handlers cannot be installed, until the
    embedding process ends). Returns 0 on clean shutdown, 2 when
    misconfigured (a hosting daemon without a name or a mirror refuses
    to start — fail-closed). Never raises."""
    name, name_priv, mirror_url, refresh, ok = _config()
    if not ok:
        for problem in _startup_problems():
            print(f"hostd: refusing to start: {problem}",
                  file=sys.stderr)
        return 2
    stop = threading.Event()

    def _stop(_signum, _frame):
        stop.set()

    for _sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(_sig, _stop)
        except (ValueError, OSError):
            # signal.signal only works in the main thread. An embedded
            # hostd (an agent hosting its name in-process, in a worker
            # thread) must still host — the embedding process owns
            # lifetime there. Dying here would break the never-raises
            # contract for exactly that deployment (twin of resolverd).
            print(f"hostd: cannot install {_sig!s} handler "
                  f"(not the main thread?) — hosting without it; "
                  f"stop is the embedding process's to give",
                  file=sys.stderr)

    for warn in _public_url_warnings():
        print(f"hostd: direct disabled: {warn}", file=sys.stderr)

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

    for warn in _no_reach_warnings():
        print(f"hostd: reach: {warn}", file=sys.stderr)

    for warn in _rendezvous_warnings():
        print(f"hostd: rendezvous: {warn}", file=sys.stderr)

    for warn in _reach_ttl_warnings():
        print(f"hostd: reach ttl: {warn}", file=sys.stderr)

    for warn in _hostd_refresh_warnings():
        print(f"hostd: refresh: {warn}", file=sys.stderr)

    last_ok: bool | None = None
    while not stop.is_set():
        try:
            ok_now = announce_once(mirror_url, name, name_priv)
        except Exception:
            ok_now = False  # the loop degrades, never guesses
        note = _announce_note(last_ok, ok_now, name)
        if note is not None:
            print(note, file=sys.stderr, flush=True)
        last_ok = ok_now
        stop.wait(refresh * random.uniform(0.8, 1.2))
    return 0


if __name__ == "__main__":
    if "-h" in sys.argv[1:] or "--help" in sys.argv[1:]:
        print(__doc__.strip())
        raise SystemExit(0)
    if sys.argv[1:]:
        # Hostd takes NO arguments — it is configured by env only
        # (the systemd unit passes none). Any argument is a bad argument:
        # silently ignoring one (a mistyped flag, a stray positional)
        # started the daemon on the env configuration the operator never
        # asked for, exactly the unknown-option hazard resolver.daemon
        # and mint_name refuse.
        print(f"hostd: refusing to start: unexpected argument(s) "
              f"{' '.join(sys.argv[1:])!r} — this daemon is configured "
              f"by environment only, no arguments are accepted",
              file=sys.stderr)
        raise SystemExit(2)
    raise SystemExit(run())
