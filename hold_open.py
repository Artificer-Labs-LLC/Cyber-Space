"""Hoster hold-open daemon cycle (docs/HOSTING.md, primitive 3).

The hoster half of the relay bridge. A NAT-hidden hoster cannot be
dialed inbound, so NAT penetration is the HOSTER's outbound dial: the
daemon holds a hold-open at a public relay (POST /relay/register),
then cycles POST /relay/wait long-polls; each session the relay lists
carries a fresh challenge minted for a dialer's session-open — the
daemon signs it with the NAME KEY and bridges the answer
(POST /relay/answer). The dialer then receives
{challenge, name_key_sig} and verifies it fail-closed against the
binding's name key.

Derived-point rendezvous (docs/RENDEZVOUS.md frozen spec, primitive 3):
the same hold-open is ALSO indexed under the name-derived (E, E-1)
rendezvous points — the daemon registers its routing token under both
points at the same relay, so a dialer that derived the point itself
can pair it without the relay ever learning the label. The point
registrations roll with the epoch: when the epoch changes, the daemon
re-registers the fresh pair; stale points fail closed silent at the
relay (its willingness check), so a missed roll reads as absent, never
as a lie.

What the daemon holds: the name key's 32-byte seed (hex), and ONLY the
name key. It never touches the master identity key, the node roster,
or the registry — the challenge is signed by the key the binding
names, nothing else. The relay sees bytes, never identity; the daemon
sees challenges and tokens, never dialers.

The cycle degrades, never guesses: if the relay drops the hold-open
(404), the daemon re-registers; if the relay goes silent entirely, the
daemon backs off and retries — a name whose host is unreachable reads
NXDOMAIN to clients (fail-closed at resolve_cyberspace step 6), never
an unverified answer.

Never raises across its boundary: every check returns False or a
count; 429/5xx from the relay are silence, not crashes."""
import json
import math
import os
import threading
import time
import urllib.request

import rendezvous
from fed import ed25519 as _fed_ed25519

# Default long-poll budget per cycle: the daemon's /relay/wait blocks up
# to this before re-cycling (the relay's own ceiling governs, this only
# bounds a stale loop).
_HOLD_WAIT_TIMEOUT = 40.0
# Renew the hold-open well inside the relay's 300s reap window.
_KEEPALIVE_EVERY = 240.0
# Backoff when the relay is silent before retrying the register.
_BACKOFF_S = 10.0
# Relay-response read bound, twin of core._PEER_RESP_MAX and
# resolve_chain._FETCH_MAX: the relay is untrusted for every other
# shape this daemon checks, so its body gets the same 64KB cap (legit
# relay answers — register/wait/answer/keepalive — are a few hundred
# bytes). read() unbounded let a relay stream an endless body into
# memory before any shape check ran; oversize reads as silence (None),
# exactly like every other bad relay answer.
_RELAY_RESP_MAX = 65536


def _rendezvous_epoch_len() -> int:
    """The epoch_len the daemon holds derived points under — the SAME
    value core._reach_build advertises in the descriptor's rendezvous
    kind (CYBERNET_RENDEZVOUS_EPOCH_LEN), so hoster and dialer compute
    the same meeting math. Fail-closed to the frozen default when the
    env is missing or out of the 60..86400 bounds."""
    try:
        val = int(os.environ.get("CYBERNET_RENDEZVOUS_EPOCH_LEN", "") or 0)
        if rendezvous._epoch_len_ok(val):
            return val
    except (ValueError, TypeError):
        pass
    return rendezvous.EPOCH_LEN_DEFAULT


def _post(relay_url: str, path: str, payload: dict,
          timeout: float) -> dict | None:
    """One JSON POST against the relay. Returns the parsed dict on 200,
    None on anything else (non-200, timeout, unparseable). Never raises."""
    try:
        body = json.dumps(payload).encode()
        req = urllib.request.Request(
            relay_url.rstrip("/") + path, data=body,
            headers={"Content-Type": "application/json",
                     "Accept": "application/json"},
            method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status != 200:
                return None
            raw = resp.read(_RELAY_RESP_MAX + 1)
            if len(raw) > _RELAY_RESP_MAX:
                return None
            data = json.loads(raw.decode("utf-8"))
            return data if isinstance(data, dict) else None
    except Exception:
        return None


def hold_open_register(relay_url: str, token: str) -> bool:
    """Announce the hold-open: this name key is dialing out and holding
    this routing token. True when the relay accepted it."""
    if not isinstance(relay_url, str) or not relay_url.startswith(
            ("http://", "https://")):
        return False
    if not isinstance(token, str) or not token or len(token) > 4096:
        return False
    return _post(relay_url, "/relay/register", {"token": token},
                 timeout=10.0) is not None


def _rendezvous_points_register(relay_url: str, token: str,
                                name_pub_hex: str,
                                epoch_len: int = rendezvous.EPOCH_LEN_DEFAULT) -> int:
    """Index the same hold-open token under the derived (E, E-1)
    rendezvous points (docs/RENDEZVOUS.md frozen spec): the dialer
    derives the pair itself, so the relay pairs hold-opens by the point
    and never learns the label. Both points bind the SAME routing token
    the hold-open was registered with — one token, two opaque keys.
    The points are derived under epoch_len — the SAME value the reach
    descriptor advertises (core._reach_build reads the same env), and
    the relay validates willingness under the epoch_len carried in the
    register body. A 400 from the relay (a point the relay's clock finds
    unwilling — epoch-boundary clock skew) is silence, not an error:
    the plain hold-open still stands, and the next epoch roll
    re-registers the fresh pair. Never raises."""
    try:
        if not rendezvous._epoch_len_ok(epoch_len):
            epoch_len = rendezvous.EPOCH_LEN_DEFAULT
        pair = rendezvous.derive_points(time.time(), name_pub_hex,
                                       epoch_len)
    except Exception:
        return 0
    if pair is None:
        return 0
    accepted = 0
    for point in pair:
        try:
            if _post(relay_url, "/relay/register",
                     {"token": token, "rendezvous_point": point,
                      "name_pub": name_pub_hex, "epoch_len": epoch_len},
                     timeout=10.0) is not None:
                accepted += 1
        except Exception:
            pass  # silence per point; the other may still land
    return accepted


def _rendezvous_hold_maybe(relay_url: str, token: str,
                           name_pub_hex: str | None,
                           point_epoch: int | None,
                           epoch_len: int = rendezvous.EPOCH_LEN_DEFAULT) -> int | None:
    """Re-register the (E, E-1) point pair when the epoch rolled since
    point_epoch, under epoch_len (the advertised value — see
    _rendezvous_epoch_len). Returns the new epoch when (re-)registered,
    the old point_epoch when nothing needed doing, None when there is
    no name key to derive from. The relay's keepalive path refreshes the
    point index's seen timestamps, so a re-register is only needed on
    an epoch roll — the points themselves go unwilling, never stale.
    Never raises."""
    if name_pub_hex is None:
        return point_epoch
    # epoch_len is caller-supplied at this library seat (hold_open_cycle
    # passes the env-derived value, but a direct caller can pass
    # anything): epoch_for refuses a bad one (out of bounds, non-int,
    # bool) with None, so the roll check below read it as "no epoch"
    # and returned the stale point_epoch forever — the points were
    # never re-registered, went unwilling at the relay, and the name
    # went dark under rendezvous while the daemon looked healthy.
    # _rendezvous_points_register, called just below, normalizes the
    # same bad value to the frozen default; normalize here too, so
    # the epoch compared and the epoch registered under agree.
    if not rendezvous._epoch_len_ok(epoch_len):
        epoch_len = rendezvous.EPOCH_LEN_DEFAULT
    try:
        epoch = rendezvous.epoch_for(time.time(), epoch_len)
    except Exception:
        return point_epoch
    if epoch is None or epoch == point_epoch:
        return point_epoch
    _rendezvous_points_register(relay_url, token, name_pub_hex, epoch_len)
    return epoch


def _name_pub_from_priv(name_priv_hex: str) -> str | None:
    """The name pubkey (64 hex) from the 32-byte seed — the same
    derivation the reach descriptor uses (core._reach_build). None when
    the seed is unusable; the hold-open still works without rendezvous
    points (degraded, not broken)."""
    try:
        raw = bytes.fromhex(name_priv_hex)
        # Decoded-length gate, twin of rendezvous._name_pub_bytes:
        # bytes.fromhex ignores embedded spaces, so a 64-char string
        # with two spaces decoded to a 31-byte seed — and the key
        # derivation silently accepted it, yielding a pubkey that is
        # NOT the name's key. Rendezvous points registered under that
        # wrong key are points no dialer will ever derive: the hoster
        # reads as absent, silently. Only a 32-byte decode is a seed.
        if len(raw) != 32:
            return None
        return _fed_ed25519.publickey(raw).hex()
    except Exception:
        return None


def _sign_challenge(challenge_hex: str, name_priv_hex: str) -> str | None:
    """Sign the relay's minted challenge with the NAME KEY. The dial
    side verifies this exact signature fail-closed against the binding's
    node_pubkey — a valid signature proves the name's key answered live.
    None on any shape or key failure (never sign garbage)."""
    try:
        if not isinstance(challenge_hex, str) or len(challenge_hex) != 64:
            return None
        if not isinstance(name_priv_hex, str) or len(name_priv_hex) != 64:
            return None
        sk = bytes.fromhex(name_priv_hex)
        chal = bytes.fromhex(challenge_hex)
        # Decoded-length gates, twin of _name_pub_from_priv above:
        # the string-length checks above admit a 64-char string whose
        # decode is 31 bytes (embedded spaces) — signing that decode
        # signs a challenge nobody minted, under a seed that is not
        # the name key, and the dial side refuses both on sight.
        if len(sk) != 32 or len(chal) != 32:
            return None
        pk = _fed_ed25519.publickey(sk)
        sig = _fed_ed25519.sign(chal, sk, pk)
        if len(sig) != 64:
            return None
        return sig.hex()
    except Exception:
        return None


def hold_open_cycle_once(relay_url: str, token: str,
                         name_priv_hex: str) -> tuple[bool, int]:
    """One cycle of the daemon: long-poll /relay/wait, sign and answer
    every pending session with the NAME KEY.

    Returns (hold_open_alive, sessions_answered). hold_open_alive False
    means the relay answered 404 (hold-open reaped) or went silent —
    the caller re-registers. A cycle that answers nothing is still a
    healthy cycle; an answered challenge is consumed exactly once by the
    relay, so a duplicate /relay/wait listing answers 404 and is simply
    skipped."""
    data = _post(relay_url, "/relay/wait", {"token": token},
                 timeout=_HOLD_WAIT_TIMEOUT)
    if data is None:
        return (False, 0)
    # The wait answer is relay-controlled: a sessions value that is
    # not a list (123, true) died in a TypeError on the iteration
    # instead of reading as no pending sessions — this cycle promises
    # never to raise across its boundary. Only a list can hold
    # sessions; every other shape simply has none.
    sessions = data.get("sessions")
    answered = 0
    for sess in sessions if isinstance(sessions, list) else []:
        if not isinstance(sess, dict):
            continue
        session_id = sess.get("session_id")
        challenge = sess.get("challenge")
        if not isinstance(session_id, str) or not session_id:
            continue
        sig = _sign_challenge(challenge, name_priv_hex)
        if sig is None:
            continue
        if _post(relay_url, "/relay/answer",
                 {"session_id": session_id, "name_key_sig": sig},
                 timeout=10.0) is not None:
            answered += 1
    return (True, answered)


def _keepalive_every_ok(value) -> bool:
    """A usable keepalive interval: a real, finite, positive number.
    Bool is not a number here (True would alias to a 1-second spam),
    and NaN/inf compare False against every elapsed time, which
    would silently disable keepalives and let the relay reap the
    hold-open — all of those fall back to the default instead."""
    return (isinstance(value, (int, float))
            and not isinstance(value, bool)
            and math.isfinite(value) and value > 0)


def hold_open_cycle(relay_url: str, token: str, name_priv_hex: str,
                    stop: threading.Event,
                    keepalive_every: float = _KEEPALIVE_EVERY,
                    name_pub_hex: str | None = None) -> None:
    """Run the hoster hold-open until stop is set: register, then loop
    cycle -> keepalive inside the reap window -> re-register on 404.
    Backs off when the relay is silent. The hold-open token is ALSO
    indexed under the derived (E, E-1) rendezvous points — the name
    pubkey is derived from name_priv_hex unless name_pub_hex is given,
    and the point pair re-registers on every epoch roll (stale points
    fail closed silent at the relay). Never raises."""
    if not _keepalive_every_ok(keepalive_every):
        keepalive_every = _KEEPALIVE_EVERY
    if name_pub_hex is not None:
        # Decoded-length gate, twin of _name_pub_from_priv /
        # rendezvous._name_pub_bytes: the string-length check alone
        # admitted a spaced 64-char pub (bytes.fromhex ignores spaces,
        # 31-byte decode) and any non-hex 64-char string — both passed
        # here, suppressed the derivation below, then derive_points
        # refused them, so no rendezvous points were ever registered
        # and the hoster read as absent though the true pub was
        # derivable from the seed. Only a 32-byte decode is a name key.
        try:
            _pub_ok = (isinstance(name_pub_hex, str)
                       and len(name_pub_hex) == 64
                       and len(bytes.fromhex(name_pub_hex)) == 32)
        except ValueError:
            _pub_ok = False
        if not _pub_ok:
            name_pub_hex = None
    if name_pub_hex is None:
        name_pub_hex = _name_pub_from_priv(name_priv_hex)
    epoch_len = _rendezvous_epoch_len()
    point_epoch: int | None = None
    last_keepalive = 0.0
    while not stop.is_set():
        if not hold_open_register(relay_url, token):
            stop.wait(_BACKOFF_S)
            continue
        last_keepalive = time.monotonic()
        point_epoch = _rendezvous_hold_maybe(
            relay_url, token, name_pub_hex, point_epoch, epoch_len)
        while not stop.is_set():
            if time.monotonic() - last_keepalive >= keepalive_every:
                if _post(relay_url, "/relay/keepalive", {"token": token},
                         timeout=10.0) is None:
                    break  # re-register: hold-open may have been reaped
                last_keepalive = time.monotonic()
                # The keepalive refreshed the point index's seen
                # timestamps; only an epoch roll needs new points.
                point_epoch = _rendezvous_hold_maybe(
                    relay_url, token, name_pub_hex, point_epoch, epoch_len)
            alive, _ = hold_open_cycle_once(relay_url, token, name_priv_hex)
            if not alive:
                break  # hold-open lost or relay silent: re-register
        # fall through to re-register unless asked to stop
