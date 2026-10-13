#!/usr/bin/env python3
"""Rotate a .cyberspace name key — the identity half of primitive 4 (keys).

A name binding is self-authenticating: the name key vouches for itself.
Rotation must be too. A rotation record is:

  name-rotate|<label>|<old_pub>|<new_pub>|<issued_at>

signed by the OLD key. Continuity lives in that one signature: anyone who
trusts the old binding can see "the holder of the old key designated this
new key" — no mirror, no registry, no ceremony. The new key then signs the
next claim, and the chain is unbroken.

Rotation records carry no expiry: a rotation is a point event ("at time T,
old designated new"), not a live binding — the new claim carries the
liveness window. A rotation dated in the future is not yet in force.

Usage:
  ./venv/bin/python rotate_name.py <label> [--new-key-seed HEX64]
  ./venv/bin/python rotate_name.py <label> --submit [mirror_url]
  ./venv/bin/python rotate_name.py <label> --promote

  The rotation loop, in order: MINT -> SUBMIT -> PROMOTE.
  Mint mode loads the existing name key from ~/.cyberspace/<label>-name.key
  (the OLD key), mints and self-verifies the rotation record, writes:
    ~/.cyberspace/<label>-rotate.json     the record (publish this)
    ~/.cyberspace/<label>-name.key.next   the NEW key seed (0600)

  The old key file is NEVER overwritten by minting — promotion stays a
  deliberate operator step. Submit mode (--submit) posts the record AND
  the new binding (signed by the NEW key) to the mirror's
  /api/v1/names/rotate, then verifies the mirror moved the name:
  the live binding resolves to the new key AND the rotation hop is in
  the served chain. Promote mode (--promote) closes the loop AFTER the
  mirror accepts (submit verified it):
    ~/.cyberspace/<label>-name.key        becomes the NEW key seed (0600)
    ~/.cyberspace/<label>-name.key.prev   keeps the OLD key seed (0600)
  The .next file is consumed atomically; the promotion re-verifies the
  rotation record first (signature + in-force + continuity of both keys).
  Submit BEFORE promote: the mirror moves the binding under the OLD
  key's authority, and the operator promotes locally only once the
  record is seen in the wild.

Exit codes: 0 = done; 1 = refused (reason on stderr); 2 = usage / unreadable.
"""

import os
import sys
import json
import argparse
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime, timezone, timedelta
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fed.ed25519 import publickey, sign, checkvalid  # noqa: E402
from mint_name import _write_secret, _valid_mirror  # noqa: E402

_LABEL_MAX = 63
_DEFAULT_MIRROR = "http://127.0.0.1:8471"
# A day under the namespace's 365-day binding-lifetime cap
# (core.NAME_EXPIRY_DAYS): the new binding minted on submit must never
# be one every admission/verify/resolve seat refuses. Twin of mint_name.
_DEFAULT_EXPIRY_DAYS = 364
_EXPIRY_DAYS_CAP = 365


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


def _normalize(s: str) -> str:
    """Expected/held values are normalized identically before any rule:
    strip, lowercase — the mirror twin."""
    return s.strip().lower()


def _parse_canonical_ts(s: str) -> datetime:
    """Strict twin of core_serve._parse_claim_time / verify_name._parse_ts:
    exactly `YYYY-MM-DDTHH:MM:SS` with a UTC stamp (`Z` or `+00:00`), and
    nothing else. `datetime.fromisoformat` is NOT used — it accepts ~12
    spellings (space separators, naive stamps read as UTC here, fractional
    seconds, non-UTC offsets, date-only) that every mirror seat refuses:
    the rotate route re-parses rotation_issued_at with _parse_claim_time
    and the gossip helpers do the same, so a rotation signed over a
    non-canonical stamp verified here (and walked clean in
    resolve_chain) while every mirror read it as malformed. Raises
    ValueError on any non-canonical input."""
    import re
    # A stored/JSON record can carry a non-string stamp straight in
    # (123/true/a list); re.match would leak TypeError past seats that
    # guard ValueError alone. Refuse in-contract, twin of
    # core._parse_claim_time.
    if not isinstance(s, str):
        raise ValueError(f"issued_at is not canonical UTC timestamp: {s!r}")
    m = re.match(
        r"^([0-9]{4})-([0-9]{2})-([0-9]{2})T"
        r"([0-9]{2}):([0-9]{2}):([0-9]{2})(Z|\+00:00)\Z", s)
    if not m:
        raise ValueError(f"issued_at is not canonical UTC timestamp: {s!r}")
    year, mon, day, hr, mi, se = (int(m.group(i)) for i in range(1, 7))
    if not (1 <= mon <= 12 and 1 <= day <= 31 and hr <= 23
            and mi <= 59 and se <= 59):
        raise ValueError(f"issued_at out of range: {s!r}")
    try:
        return datetime(year, mon, day, hr, mi, se, tzinfo=timezone.utc)
    except ValueError:
        raise ValueError(f"issued_at invalid date: {s!r}")


def _rotate_payload(name: str, old_pub: str, new_pub: str,
                    issued_at: str) -> bytes:
    """The canonical bytes the OLD key signs. Distinct prefix from
    name-claim| so a claim payload can never verify as a rotation and
    vice versa (payload-prefix confusion is a signature-side attack)."""
    return (b"name-rotate|" + name.encode() + b"|" + old_pub.encode()
            + b"|" + new_pub.encode() + b"|" + issued_at.encode())


def _iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S+00:00")


# Mirror-response read bound, twin of mint_name._MIRROR_RESP_MAX /
# core._PEER_RESP_MAX / resolve_chain._FETCH_MAX: the mirror is
# untrusted for every other shape this client checks, so its body gets
# the same 64KB cap (legit mirror answers — a rotate verdict, a name
# resolution, a rotations chain — are far smaller). read() unbounded
# let a mirror stream an endless body into memory before any verdict
# ran; an oversize body is never a parsed document (see readers below).
_MIRROR_RESP_MAX = 65536


def _read_bounded(stream) -> bytes | None:
    """Read at most _MIRROR_RESP_MAX bytes; None when the body is larger."""
    raw = stream.read(_MIRROR_RESP_MAX + 1)
    return None if len(raw) > _MIRROR_RESP_MAX else raw


def _post_form(url: str, fields: dict, timeout: float = 30.0
               ) -> tuple[int | None, str]:
    """POST urlencoded form; returns (status, body). status None = no HTTP
    answer. Twin of mint_name's helper (server decides, client reports).

    An oversize body (success or HTTPError alike) returns as "" — the
    caller reads a 200 with an empty body as its unparseable-rotate
    refusal, and every other status refuses on the status itself."""
    data = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = _read_bounded(resp)
            return resp.status, "" if raw is None else raw.decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        raw = _read_bounded(e)
        return e.code, "" if raw is None else raw.decode("utf-8", "replace")
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"


def _get_json(url: str, timeout: float = 30.0) -> dict | None:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            raw = _read_bounded(resp)
            if raw is None:
                return None
            data = json.loads(raw.decode("utf-8"))
            return data if isinstance(data, dict) else None
    except Exception:
        return None


def mint_rotation(label: str, old_priv: bytes, new_pub_hex: str,
                  issued_at: str | None = None) -> dict:
    """Mint a rotation record dict. Raises ValueError on a refused input."""
    # Every argument is caller-supplied at this library seat (main()
    # passes validated values, but a direct caller can pass anything):
    # a non-string label/new_pubkey escaped as AttributeError from
    # _normalize's .strip(), a non-bytes seed as TypeError from len()
    # or the signer, and a non-string/non-canonical issued_at either
    # escaped as AttributeError from the payload's .encode() or —
    # worse — minted a record verify_rotation itself refuses as
    # non-canonical, a rotation no seat will ever accept. Gate the
    # types at the source, and hold an explicit issued_at to the same
    # canonical shape verify_rotation demands; only then is a minted
    # record one the verifier can vouch for. A future issued_at stays
    # mintable (verify reads it as not-yet-in-force, by design).
    if not isinstance(label, str):
        raise ValueError("label is not a string")
    if not isinstance(old_priv, (bytes, bytearray)):
        raise ValueError("old key is not a 32-byte seed")
    old_priv = bytes(old_priv)
    if not isinstance(new_pub_hex, str):
        raise ValueError("new_pubkey is not a string")
    if issued_at is not None and not isinstance(issued_at, str):
        raise ValueError("issued_at is not a string")
    if len(old_priv) != 32:
        raise ValueError("old key is not a 32-byte seed")
    label = _normalize(label)
    new_pub_hex = _normalize(new_pub_hex)
    if not _valid_label(label):
        raise ValueError(f"{label!r} is not a valid .cyberspace label")
    if len(new_pub_hex) != 64:
        raise ValueError("new_pubkey is not 64 hex chars")
    try:
        bytes.fromhex(new_pub_hex)
    except ValueError:
        raise ValueError("new_pubkey is not hex")
    old_pub_hex = publickey(old_priv).hex().lower()
    if new_pub_hex == old_pub_hex:
        raise ValueError("rotation to the same key is a no-op — renew the "
                         "claim instead")
    issued_at = issued_at or _iso_now()
    _parse_canonical_ts(issued_at)  # raises ValueError if non-canonical
    payload = _rotate_payload(label, old_pub_hex, new_pub_hex, issued_at)
    sig = sign(payload, old_priv, bytes.fromhex(old_pub_hex)).hex().lower()
    return {"name": label, "old_pubkey": old_pub_hex,
            "new_pubkey": new_pub_hex, "issued_at": issued_at,
            "signature": sig}


def verify_rotation(record: dict) -> str | None:
    """Return None if the rotation verifies, else the reason it does not.

    Fail-closed on every surprise: missing/extra-shape fields, bad label,
    bad hex, bad timestamp, and — the whole point — a signature that is
    not the OLD key vouching for the NEW key.
    """
    if not isinstance(record, dict):
        return "record is not a JSON object"
    for k in ("name", "old_pubkey", "new_pubkey", "issued_at", "signature"):
        if k not in record:
            return f"missing field: {k}"
        if not isinstance(record[k], str):
            return f"field {k!r} is not a string"
    name = _normalize(record["name"])
    old_pub = _normalize(record["old_pubkey"])
    new_pub = _normalize(record["new_pubkey"])
    sig = _normalize(record["signature"])
    if not _valid_label(name):
        return f"name {name!r} is not a valid .cyberspace label"
    for field, val, want in (("old_pubkey", old_pub, 64),
                             ("new_pubkey", new_pub, 64),
                             ("signature", sig, 128)):
        try:
            raw = bytes.fromhex(val)
        except ValueError:
            return f"{field} is not hex"
        if len(raw) * 2 != want:
            return f"{field} is not {want} hex chars"
    if old_pub == new_pub:
        return "rotation to the same key is a no-op"
    try:
        issued = _parse_canonical_ts(record["issued_at"])
    except (ValueError, TypeError):
        return "issued_at is not a canonical UTC timestamp"
    if issued > datetime.now(timezone.utc):
        return "rotation is dated in the future — not yet in force"
    payload = _rotate_payload(name, old_pub, new_pub, record["issued_at"])
    if not checkvalid(bytes.fromhex(sig), payload, bytes.fromhex(old_pub)):
        return ("signature does not verify: this rotation is not vouched "
                "for by the old name key")
    return None


def _refresh_hostd_env_text(text: str, old_hex: str, new_hex: str,
                            label: str = ""):
    """Swap CYBERNET_NAME_PRIVKEY old->new in a hostd env body.

    Returns (new_text, status): "updated" (the active privkey line held
    the OLD seed and now holds the new one — every other line preserved
    byte-for-byte), "foreign" (the line holds a different seed — text
    returned untouched; never clobber a key we cannot account for),
    "absent" (no active privkey line — text untouched), "wrong-name"
    (label given and the env's CYBERNET_HOSTED_NAME names a DIFFERENT
    name — text untouched regardless of the key: the file is another
    name's env that happens to sit at this path, and refreshing it
    would make hostd sign that name with this name's key). Pure: the
    caller decides whether to write.
    """
    if label:
        for line in text.splitlines():
            if line.startswith("CYBERNET_HOSTED_NAME="):
                hosted = line.split("=", 1)[1].strip().lower()
                if hosted != label.lower():
                    return text, "wrong-name"
                break
    out, status = [], "absent"
    for line in text.splitlines(keepends=True):
        if line.startswith("CYBERNET_NAME_PRIVKEY="):
            cur = line.split("=", 1)[1].strip().lower()
            if cur == old_hex.lower():
                out.append(f"CYBERNET_NAME_PRIVKEY={new_hex}\n")
                status = "updated"
                continue
            status = "foreign"
        out.append(line)
    return "".join(out), status


# Where deploy/install-agent.sh installs the hostd env — the copy
# hostd.service actually reads (EnvironmentFile=). The staging env under
# ~/.cyberspace/hostd is only the source it was copied FROM.
_INSTALLED_HOSTD_ENV = Path("/etc/cybernet-hostd/hostd.env")


def _installed_env_note(installed_path: Path, old_hex: str,
                        new_hex: str, label: str = "") -> str:
    """Read-only check of the INSTALLED hostd env after a promote.

    install-agent.sh copies the staging env to /etc/cybernet-hostd/
    hostd.env and hostd.service reads THAT file — refreshing the staging
    copy alone leaves a restarted hostd signing with the old key. This
    never writes there (an unprivileged CLI has no business in /etc);
    it only makes the summary tell the truth: stale -> re-install,
    current -> say so, foreign/unreadable -> warn. Absent -> "" (the
    staging note already covers the manual case).

    The installed file is a SINGLETON: it hosts exactly one name, named
    by its CYBERNET_HOSTED_NAME. If that name is not the rotated label,
    the key comparison is meaningless for this rotation — the file is
    another name's hostd env, 're-install over it' would evict that
    name, and 'restart hostd' would do nothing for this one. Say so."""
    if not installed_path.exists():
        return ""
    try:
        text = installed_path.read_text()
    except OSError:
        return (f"; WARNING: installed hostd env at {installed_path} "
                f"unreadable — check its CYBERNET_NAME_PRIVKEY manually; "
                f"hostd reads that file, not the staging env")
    cur = None
    hosted = None
    for line in text.splitlines():
        if line.startswith("CYBERNET_NAME_PRIVKEY="):
            cur = line.split("=", 1)[1].strip().lower()
        elif line.startswith("CYBERNET_HOSTED_NAME="):
            hosted = line.split("=", 1)[1].strip().lower()
    if label and hosted is not None and hosted != label.lower():
        return (f"; NOTE: installed hostd env at {installed_path} hosts "
                f"{hosted}.cyberspace, not {label.lower()}.cyberspace — "
                f"it is NOT this name's env, NOT touched; do NOT copy "
                f"this name's env over it (that would evict "
                f"{hosted}.cyberspace); this name is not hosted from "
                f"the installed env")
    if cur == new_hex.lower():
        return (f"; installed hostd env at {installed_path} already "
                f"holds the new key — restart hostd")
    if cur == old_hex.lower():
        return (f"; WARNING: installed hostd env at {installed_path} "
                f"still holds the OLD key and hostd reads THAT file — "
                f"a restart alone will NOT pick up the new key; "
                f"re-install the refreshed env (deploy/install-agent.sh "
                f"--hostd-env, or copy it over {installed_path} at 0600) "
                f"and then restart hostd")
    return (f"; WARNING: installed hostd env at {installed_path} holds "
            f"a different or no CYBERNET_NAME_PRIVKEY — NOT touched; "
            f"check it manually, hostd reads that file")


def promote_rotation(label: str, home: Path,
                     installed_env: Path = _INSTALLED_HOSTD_ENV
                     ) -> tuple[bool, str]:
    """Promote a minted rotation: .next becomes the name key, atomically.

    The loop-closing half of a rotation. Promotion is deliberate (an
    explicit CLI flag, never automatic), and it refuses unless EVERY link
    re-verifies — the record signature, the record in force, and both
    keys' continuity:
      - <label>-name.key.next exists (the minted new key seed)
      - <label>-rotate.json verifies AND is in force (verify_rotation)
      - the .next seed derives the record's new_pubkey
      - the CURRENT <label>-name.key still derives the record's
        old_pubkey (continuity: the operator holds the same old key
        that vouched for the record — a swapped key file refuses)

    On success: the current key seed moves to <label>-name.key.prev
    (the old key stays readable for historical verification — a verifier
    needs old keys to walk the chain), and the .next seed atomically
    replaces <label>-name.key (os.replace: never a half-written key).
    The hostd env mint wrote (home/hostd/<label>.env) is refreshed to the
    new seed when it still holds the old one — hostd signs from that env,
    not from the key file; a foreign/absent privkey line, or an env whose
    CYBERNET_HOSTED_NAME names a different name, is reported in
    the summary, never overwritten. The INSTALLED env (install-agent.sh's
    copy at /etc/cybernet-hostd/hostd.env, the file hostd.service reads)
    is checked read-only and reported the same way — never written.
    Returns (True, summary) or (False, reason). Never raises on input.
    """
    label = _normalize(label)
    if not _valid_label(label):
        return False, f"{label!r} is not a valid .cyberspace label"
    rec_path = home / f"{label}-rotate.json"
    next_path = home / f"{label}-name.key.next"
    key_path = home / f"{label}-name.key"
    prev_path = home / f"{label}-name.key.prev"
    if not next_path.exists():
        return False, (f"no pending rotation at {next_path} — "
                       f"mint one first (rotate_name.py {label})")
    if not rec_path.exists():
        return False, f"rotation record missing at {rec_path} — refuse"
    try:
        record = json.loads(rec_path.read_text())
    except (OSError, ValueError):
        return False, f"rotation record at {rec_path} is not readable JSON"
    reason = verify_rotation(record)
    if reason is not None:
        return False, f"rotation record does not verify: {reason}"
    if not key_path.exists():
        return False, (f"current name key missing at {key_path} — "
                       f"continuity broken, refuse")
    try:
        new_priv = bytes.fromhex(next_path.read_text().strip())
        old_priv = bytes.fromhex(key_path.read_text().strip())
    except (OSError, ValueError):
        return False, "key files do not hold 32-byte hex seeds"
    if len(new_priv) != 32 or len(old_priv) != 32:
        return False, "key files do not hold 32-byte seeds"
    new_pub = publickey(new_priv).hex().lower()
    old_pub = publickey(old_priv).hex().lower()
    if new_pub != _normalize(record["new_pubkey"]):
        return False, ("the .next seed does not derive the record's "
                       "new_pubkey — stale or foreign key, refuse")
    if old_pub != _normalize(record["old_pubkey"]):
        return False, ("the current name key does not derive the record's "
                       "old_pubkey — continuity broken, refuse")
    # Atomic close: old key -> .prev (kept for chain-walking history),
    # .next -> the name key. os.replace is never a half-written key.
    prev_path = home / f"{label}-name.key.prev"
    _write_secret(prev_path, old_priv.hex() + "\n")
    os.replace(next_path, key_path)
    os.chmod(key_path, 0o600)
    # hostd signs its reach announces with CYBERNET_NAME_PRIVKEY from the
    # env mint wrote (home/hostd/<label>.env) — NOT from the key file just
    # promoted. Left stale, hostd keeps signing with the OLD key after the
    # mirror moved to the new one and the hosted name goes dark. Refresh
    # that one line when the env still holds the old seed; a foreign seed
    # or a missing line is reported, never overwritten.
    env_note = ""
    env_path = home / "hostd" / f"{label}.env"
    if env_path.exists():
        try:
            new_text, status = _refresh_hostd_env_text(
                env_path.read_text(), old_priv.hex(), new_priv.hex(),
                label)
        except OSError:
            status, new_text = "unreadable", None
        if status == "wrong-name":
            env_note = (f"; WARNING: hostd env at {env_path} hosts a "
                        f"different name (its CYBERNET_HOSTED_NAME is "
                        f"not {label}) — NOT touched; it is not this "
                        f"name's env, check its filename/contents "
                        f"manually or hostd will sign the wrong name")
        elif status == "updated":
            _write_secret(env_path, new_text, overwrite=True)
            env_note = (f"; hostd env at {env_path} refreshed to the new "
                        f"key — restart hostd to pick it up")
        elif status == "foreign":
            env_note = (f"; WARNING: hostd env at {env_path} holds a "
                        f"different key — NOT touched; update its "
                        f"CYBERNET_NAME_PRIVKEY manually or hostd will "
                        f"sign with the wrong key")
        elif status == "unreadable":
            env_note = (f"; WARNING: hostd env at {env_path} unreadable — "
                        f"check its CYBERNET_NAME_PRIVKEY manually")
        else:
            env_note = (f"; WARNING: hostd env at {env_path} has no active "
                        f"CYBERNET_NAME_PRIVKEY line — check it manually")
    else:
        env_note = ("; no hostd env under ~/.cyberspace/hostd — if hostd "
                    "runs from an installed env elsewhere, update its "
                    "CYBERNET_NAME_PRIVKEY to the new key and restart it")
    env_note += _installed_env_note(installed_env, old_priv.hex(),
                                    new_priv.hex(), label)
    return True, (f"promoted {label}.cyberspace: "
                  f"{old_pub[:16]}... -> {new_pub[:16]}...; "
                  f"old key kept at {prev_path}{env_note}")


def submit_rotation(label: str, mirror_url: str, home: Path,
                    expiry_days: int = _DEFAULT_EXPIRY_DAYS
                    ) -> tuple[bool, str]:
    """Submit a minted rotation to the mirror — the middle step of the
    loop (mint -> SUBMIT -> promote).

    Posts the rotation record AND the new binding (a fresh name-claim for
    the label, signed by the NEW key, issued now so it cannot predate the
    rotation) to the mirror's /api/v1/names/rotate. Then verifies the
    mirror actually moved the name: the live binding resolves to the new
    key AND the rotation hop is in the served chain. Fail-closed on every
    surprise — a non-200, an unparseable answer, or a resolve-back
    mismatch refuses, and nothing local is ever touched (promotion stays
    deliberate; key files are only read).

    Ordering rules, enforced client-side before anything is sent:
      - the record must verify AND be in force (verify_rotation);
      - the .next seed must derive the record's new_pubkey;
      - the current name key must still derive the record's old_pubkey —
        submit happens BEFORE promote, because the mirror only moves a
        name under the OLD key's authority. An already-promoted key file
        refuses here with the ordering spelled out.
    Returns (True, summary) or (False, reason). Never raises on input.
    """
    label = _normalize(label)
    if not _valid_label(label):
        return False, f"{label!r} is not a valid .cyberspace label"
    if not _valid_mirror(mirror_url):
        return False, ("mirror is not a dialable http(s) URL with a host "
                       "and a port in 1-65535 — bad argument, nothing "
                       "was sent")
    if expiry_days < 1:
        # No silent clamp: the binding mint below used max(1, ...) —
        # twin of mint_name's floor — turning 0/negative into a 1-day
        # binding the operator never asked for.
        return False, (f"--expiry-days={expiry_days} is below the 1-day "
                       f"floor — a binding must live at least a day, "
                       f"so nothing was sent")
    if expiry_days > _EXPIRY_DAYS_CAP:
        return False, (f"--expiry-days={expiry_days} exceeds the namespace's "
                       f"{_EXPIRY_DAYS_CAP}-day binding-lifetime cap — the "
                       f"rotate route refuses any binding signed for longer, "
                       f"so nothing was sent")
    rec_path = home / f"{label}-rotate.json"
    next_path = home / f"{label}-name.key.next"
    key_path = home / f"{label}-name.key"
    try:
        record = json.loads(rec_path.read_text())
    except OSError:
        return False, (f"rotation record missing at {rec_path} — "
                       f"mint one first (rotate_name.py {label})")
    except ValueError:
        return False, f"rotation record at {rec_path} is not readable JSON"
    reason = verify_rotation(record)
    if reason is not None:
        return False, f"rotation record does not verify: {reason}"
    try:
        new_priv = bytes.fromhex(next_path.read_text().strip())
    except (OSError, ValueError):
        return False, (f"no pending new key at {next_path} — "
                       f"mint a rotation first (rotate_name.py {label})")
    if len(new_priv) != 32:
        return False, "new key file does not hold a 32-byte seed"
    new_pub = publickey(new_priv).hex().lower()
    if new_pub != _normalize(record["new_pubkey"]):
        return False, ("the .next seed does not derive the record's "
                       "new_pubkey — stale or foreign key, refuse")
    try:
        old_priv = bytes.fromhex(key_path.read_text().strip())
    except (OSError, ValueError):
        return False, (f"current name key missing at {key_path} — "
                       f"continuity broken, refuse")
    if len(old_priv) != 32:
        return False, "current name key does not hold a 32-byte seed"
    old_pub = publickey(old_priv).hex().lower()
    if old_pub == new_pub:
        return False, ("the name key is already the NEW key — submit BEFORE "
                       "promoting; the mirror only moves a name under the "
                       "old key's authority, nothing was sent")
    if old_pub != _normalize(record["old_pubkey"]):
        return False, ("the current name key does not derive the record's "
                       "old_pubkey — continuity broken, refuse")
    # Mint the new binding under the NEW key (the next claim). Issued now:
    # it can never predate the rotation (the record is in force, never
    # future), and the mirror demands the chain move forward in time.
    now = datetime.now(timezone.utc)
    issued_at = _iso(now)
    expires_at = _iso(now + timedelta(days=expiry_days))
    payload = (b"name-claim|" + label.encode() + b"|" + new_pub.encode()
               + b"|" + issued_at.encode() + b"|" + expires_at.encode())
    sig = sign(payload, new_priv, bytes.fromhex(new_pub)).hex().lower()
    fields = {"name": label, "old_pubkey": old_pub, "new_pubkey": new_pub,
              "rotation_issued_at": record["issued_at"],
              "rotation_signature": record["signature"],
              "binding_issued_at": issued_at,
              "binding_expires_at": expires_at, "binding_signature": sig}
    status, body = _post_form(
        mirror_url.rstrip("/") + "/api/v1/names/rotate", fields)
    if status is None:
        return False, f"mirror did not answer: {body[:120]}"
    if status != 200:
        return False, f"mirror refused ({status}): {body.strip()[:200]}"
    try:
        result = json.loads(body)
    except ValueError:
        return False, f"unparseable rotate response: {body[:120]!r}"
    # The rotate response is mirror-controlled: valid JSON that is not
    # an object ('[]', '123', '"ok"') has no status to read — result.get
    # died in an AttributeError traceback instead of the refusal every
    # other bad rotate response gets (twin of mint_name da6174b).
    if not isinstance(result, dict):
        return False, f"unparseable rotate response: {body[:120]!r}"
    if result.get("status") != "rotated":
        return False, f"mirror did not confirm rotation: {body[:120]!r}"
    # Verify the mirror moved the name, then trust it — never before.
    # Same mirror-controlled shape: a non-string node_pubkey (123, null)
    # died in .lower() with a traceback instead of reading as the
    # did-not-move refusal below — _get_json only proves dict shape.
    resolved = _get_json(mirror_url.rstrip("/") + f"/api/v1/names/{label}")
    resolved_pub = resolved.get("node_pubkey") if resolved else None
    if not isinstance(resolved_pub, str) or resolved_pub.lower() != new_pub:
        return False, ("mirror accepted the rotation but the name does not "
                       "resolve to the new key — investigate before "
                       "promoting")
    chain = _get_json(
        mirror_url.rstrip("/") + f"/api/v1/names/{label}/rotations")
    hop_seen = False
    # The served chain is mirror-controlled too: a rotations value that
    # is not a list, a hop that is not an object, or a hop field that is
    # not a string (123, null) died in .get/.strip tracebacks instead of
    # reading as the hop-not-seen refusal below. Only a well-formed hop
    # can match; every other shape simply is not the hop.
    hops = chain.get("rotations") if isinstance(chain, dict) else None
    if isinstance(hops, list):
        for hop in hops:
            if not isinstance(hop, dict):
                continue
            hop_fields = (hop.get("old_pubkey"), hop.get("new_pubkey"),
                          hop.get("signature"))
            if not all(isinstance(v, str) for v in hop_fields):
                continue
            if (_normalize(hop_fields[0]) == old_pub
                    and _normalize(hop_fields[1]) == new_pub
                    and _normalize(hop_fields[2])
                    == _normalize(record["signature"])):
                hop_seen = True
                break
    if not hop_seen:
        return False, ("mirror accepted the rotation but the hop is not in "
                       "the served chain — investigate before promoting")
    return True, (f"submitted {label}.cyberspace rotation to {mirror_url}: "
                  f"{old_pub[:16]}... -> {new_pub[:16]}...; the name now "
                  f"resolves to the new key and the hop is in the served "
                  f"chain — promote the new key when ready "
                  f"(rotate_name.py {label} --promote)")


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        description="mint a .cyberspace name-key rotation record")
    ap.add_argument("label", help="the .cyberspace label to rotate")
    ap.add_argument("--new-key-seed",
                    help="64-hex seed for the new key (else generated)")
    ap.add_argument("--submit", nargs="?", const=_DEFAULT_MIRROR,
                    metavar="MIRROR_URL",
                    help="submit the minted rotation + new binding to the "
                         "mirror's /api/v1/names/rotate (default: "
                         f"{_DEFAULT_MIRROR}), then verify the mirror moved "
                         "the name")
    ap.add_argument("--expiry-days", type=int, default=None,
                    help="liveness window of the new binding on submit "
                         f"(default {_DEFAULT_EXPIRY_DAYS}; submit only)")
    ap.add_argument("--promote", action="store_true",
                    help="promote <label>-name.key.next to the name key "
                         "after the record is seen in the wild")
    args = ap.parse_args(argv)
    label = _normalize(args.label)
    if not _valid_label(label):
        print(f"refused: {label!r} is not a valid .cyberspace label",
              file=sys.stderr)
        return 2
    if args.submit is not None and args.promote:
        print("refused: --submit and --promote are separate steps — "
              "submit first, promote only after the mirror accepts",
              file=sys.stderr)
        return 2
    # The seed is an argument, not a verdict: it used to be parsed only
    # in the offline-mint path, AFTER the existing-key read — so a
    # malformed seed (not hex, or not 32 bytes) against a missing key
    # read as exit 1 "no existing name key" (a verdict on local state)
    # when the argument itself was at fault, and a seed passed with
    # --submit/--promote was silently ignored entirely. Gate its shape
    # (and its only meaningful combination) before any file is read or
    # anything is sent, exit 2; the parsed seed is reused below.
    new_priv: bytes | None = None
    if args.new_key_seed is not None:
        if args.submit is not None or args.promote:
            print("refused: --new-key-seed only applies when minting a "
                  "rotation — drop it for --submit/--promote",
                  file=sys.stderr)
            return 2
        try:
            new_priv = bytes.fromhex(_normalize(args.new_key_seed))
        except ValueError:
            print("refused: --new-key-seed is not hex — bad argument, "
                  "nothing was minted", file=sys.stderr)
            return 2
        if len(new_priv) != 32:
            print("refused: --new-key-seed is not a 32-byte seed — bad "
                  "argument, nothing was minted", file=sys.stderr)
            return 2
    # Expiry is an argument, not a verdict — twin of the seed gate
    # above: it only applies on submit (rotation records carry no
    # expiry), yet was silently ignored on the mint/promote paths, and
    # on submit an out-of-range value came back from submit_rotation
    # as exit 1 (a state verdict) after the mirror gate. Gate its
    # combination and range here, before any file or wire use, exit 2.
    expiry_days = _DEFAULT_EXPIRY_DAYS
    if args.expiry_days is not None:
        if args.submit is None:
            print("refused: --expiry-days only applies with --submit — "
                  "bad argument, nothing was minted or promoted",
                  file=sys.stderr)
            return 2
        if args.expiry_days < 1:
            print(f"refused: --expiry-days={args.expiry_days} is below "
                  f"the 1-day floor — bad argument, nothing was sent",
                  file=sys.stderr)
            return 2
        if args.expiry_days > _EXPIRY_DAYS_CAP:
            print(f"refused: --expiry-days={args.expiry_days} exceeds "
                  f"the namespace's {_EXPIRY_DAYS_CAP}-day "
                  f"binding-lifetime cap — bad argument, nothing was sent",
                  file=sys.stderr)
            return 2
        expiry_days = args.expiry_days
    home = Path.home() / ".cyberspace"
    if args.submit is not None:
        if not _valid_mirror(args.submit):
            print("refused: mirror is not a dialable http(s) URL with a "
                  "host and a port in 1-65535 — bad argument, nothing "
                  "was sent", file=sys.stderr)
            return 2
        ok, msg = submit_rotation(label, args.submit, home, expiry_days)
        print(("submitted: " if ok else "refused: ") + msg,
              file=sys.stderr if not ok else sys.stdout)
        return 0 if ok else 1
    if args.promote:
        ok, msg = promote_rotation(label, home)
        print(("promoted: " if ok else "refused: ") + msg,
              file=sys.stderr if not ok else sys.stdout)
        return 0 if ok else 1
    key_path = home / f"{label}-name.key"
    if not key_path.exists():
        print(f"refused: no existing name key at {key_path} — "
              f"mint the name first (mint_name.py)", file=sys.stderr)
        return 1
    try:
        old_priv = bytes.fromhex(key_path.read_text().strip())
    except (OSError, ValueError):
        print(f"refused: cannot read a 32-byte seed from {key_path}",
              file=sys.stderr)
        return 1
    if len(old_priv) != 32:
        print(f"refused: {key_path} is not a 32-byte seed", file=sys.stderr)
        return 1
    if new_priv is None:
        new_priv = os.urandom(32)
    try:
        record = mint_rotation(label, old_priv, publickey(new_priv).hex())
    except ValueError as e:
        print(f"refused: {e}", file=sys.stderr)
        return 1
    reason = verify_rotation(record)
    if reason is not None:
        print(f"refused: self-verification failed (bug): {reason}",
              file=sys.stderr)
        return 1
    home.mkdir(parents=True, exist_ok=True)
    rec_path = home / f"{label}-rotate.json"
    rec_path.write_text(json.dumps(record, indent=2) + "\n")
    next_path = home / f"{label}-name.key.next"
    _write_secret(next_path, new_priv.hex())
    print(f"valid: {label}.cyberspace rotation minted and self-verified")
    print(f"  old key {record['old_pubkey'][:16]}... -> "
          f"new key {record['new_pubkey'][:16]}...")
    print(f"  record written to {rec_path} — submit it to a mirror next")
    print(f"    (rotate_name.py {label} --submit), then promote the new key")
    print(f"    only after the mirror accepts (rotate_name.py {label} --promote)")
    print(f"  NEW key seed at {next_path} (0600)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
