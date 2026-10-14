#!/usr/bin/env python3
"""Mint a .cyberspace name for an agent: name key + claim + hostd env.

The front door of primitive 6 (the daemon every agent runs). One command
turns an agent into a hostable .cyberspace name:

  1. Generates a dedicated Ed25519 NAME KEY (never the master identity)
     at ~/.cyberspace/<label>-name.key (0600), or loads the existing one.
  2. Builds the self-certifying binding name-claim|<label>|<pub>|<issued>|<expires>,
     signed by the name key itself, and POSTs it to the mirror's
     /api/v1/names/claim. First-claim wins; 409 means the name is taken.
  3. Verifies the name resolves back to the name key at the mirror.
  4. Writes the hostd env file (CYBERNET_HOSTED_NAME + CYBERNET_NAME_PRIVKEY
     + CYBERNET_MIRROR_URL, 0600) that deploy/hostd.service expects at
     /etc/cybernet-hostd/hostd.env. The mirror line is ACTIVE, not a
     comment: resolver.host refuses to start without it, so a minted
     env installed as-is must already carry the mirror it claimed at.
     (Hostd still applies its public-URL gate — a loopback mint mirror
     is written faithfully and hostd refuses it loudly, by design.)

Usage: ./venv/bin/python mint_name.py <label> [mirror_url] [--env-dir DIR]
  mirror_url defaults to http://127.0.0.1:8471 (the local node).
  --env-dir defaults to ~/.cyberspace/hostd (writes <label>.env there).
  --expiry-days defaults to 364. The namespace refuses any binding
  signed for longer than 365 days (core.NAME_EXPIRY_DAYS — admission,
  verify, resolve and dial all enforce the same intrinsic cap), so the
  default stays a day under the cap and a value above 365 is refused
  locally, before any key is written or claim sent: a 730-day default
  minted bindings the claim route itself refused, dead on arrival.
  The binding is renewable by re-signing with the same key before expiry.

The server is the authority on every rule: the label grammar here is a
client-side fast check (mirrors core._valid_name_label); the claim endpoint
re-validates and refuses anything malformed. Fail-closed throughout: any
surprise exits nonzero with the reason, never half-written state.
"""

import os
import sys
import json
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime, timezone, timedelta
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fed.ed25519 import publickey, sign  # noqa: E402

_LABEL_MAX = 63
# A day under the namespace's 365-day binding-lifetime cap
# (core.NAME_EXPIRY_DAYS): the minter must never mint what every
# admission/verify/resolve seat refuses.
_DEFAULT_EXPIRY_DAYS = 364
_EXPIRY_DAYS_CAP = 365

# Key-seed read bound, twin of rotate_name's _SEED_MAX: a seed file is
# 64 hex chars plus whitespace, yet the existing-key seat loaded it via
# read_text() unbounded before bytes.fromhex ran. The cap is generous
# (16x a real seed file) so padded/hand-copied seeds still read
# byte-exact; anything larger is never a seed.
_SEED_MAX = 1024


def _read_seed(path) -> bytes:
    """Read a hex seed file under _SEED_MAX; ValueError on oversize.

    Raises OSError/ValueError exactly as the seat's old
    bytes.fromhex(path.read_text().strip()) did, so the caller's
    existing (OSError, ValueError) refusal wording is untouched."""
    with path.open(encoding="utf-8") as f:
        raw = f.read(_SEED_MAX + 1)
    if len(raw) > _SEED_MAX:
        raise ValueError(f"seed file at {path} exceeds {_SEED_MAX} chars")
    stripped = raw.strip()
    # String-length gate, twin of resolver/host._config's seed gate:
    # bytes.fromhex ignores embedded whitespace, so a 65-char
    # inserted-space (or line-wrapped, or tabbed) seed decoded to the
    # TRUE 32 bytes and minted happily — a key file hostd refuses on
    # sight (its seed must be exactly 64 hex chars), leaving the name
    # minted but unhostable. Only the exact 64-char spelling is a seed;
    # outer padding still strips above, uppercase still reads
    # byte-exact (fromhex is case-insensitive, length unchanged).
    if len(stripped) != 64:
        raise ValueError(f"seed file at {path} is not a 64-hex-char seed")
    return bytes.fromhex(stripped)


def _write_secret(path, text, overwrite=False):
    """Write a secret file that is never world-readable, even briefly.

    write_text() + chmod() leaves a window (default umask) where the
    file sits at 0644. O_CREAT with mode 0o600 closes it: the file is
    born with no group/other bits (mode & ~umask can only narrow
    further, never widen). Without overwrite, O_EXCL refuses an existing
    path (no half-written secret over a live key). With overwrite, the
    write lands on a born-600 temp sibling + os.replace, so the live
    path is never half-written either. Content is the caller's text
    byte-for-byte.
    """
    path = Path(path)
    if overwrite and path.exists():
        tmp = Path(str(path) + ".tmp")
        _write_secret(tmp, text)
        os.replace(tmp, path)
        return
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    fd = os.open(path, flags, 0o600)
    try:
        data = text.encode("utf-8")
        written = 0
        while written < len(data):
            written += os.write(fd, data[written:])
    finally:
        os.close(fd)


def _hostd_env_text(label: str, priv_hex: str, mirror: str) -> str:
    """The hostd env file body. The three ACTIVE lines are exactly the
    required config resolver.host._config reads (name, name key, mirror);
    relay/public-URL lines stay commented — they are optional, unknown
    at mint time, and a half-filled relay triple is read as direct-dial
    only. The remaining hostd knobs (rendezvous, reach TTL, refresh
    cadence) stay commented too, with their defaults named: hostd warns
    loudly on set-but-ineffective values for all of them, but an
    operator who never sees the names cannot set them at all.
    Agreement with hostd is pinned by
    hidden_files/mint-env-hostd-agreement-belt-test.py."""
    # Twin of the canonical-payload builders' gate (_claim_payload /
    # core._reach_canonical): a non-string field has no env form — a
    # non-string mirror crashed .rstrip() with AttributeError, and a
    # None/non-string priv_hex was silently stringified INTO the
    # key-bearing file as the literal CYBERNET_NAME_PRIVKEY=None (the
    # clobber rotate_name._refresh_hostd_env_text was gated against).
    # Only real strings are written; refuse as ValueError at the source.
    for _field, _value in (("label", label), ("priv_hex", priv_hex),
                           ("mirror", mirror)):
        if not isinstance(_value, str):
            raise ValueError(f"{_field} must be a string: {_value!r}")
    return (
        f"# hostd env for {label}.cyberspace — install as /etc/cybernet-hostd/hostd.env (0600)\n"
        f"# Holds the NAME KEY only. Never the master identity. Guard this file.\n"
        f"CYBERNET_HOSTED_NAME={label}\n"
        f"CYBERNET_NAME_PRIVKEY={priv_hex}\n"
        f"CYBERNET_MIRROR_URL={mirror.rstrip('/')}\n"
        f"# Relay hold-open (NAT-hidden hosting): uncomment ALL THREE together —\n"
        f"# a half-filled relay config is read as direct-dial only (fail-closed).\n"
        f"# CYBERNET_RELAY_URL=\n"
        f"# CYBERNET_RELAY_PUBKEY=\n"
        f"# CYBERNET_RELAY_TOKEN=\n"
        f"# CYBERNET_PUBLIC_URL=\n"
        f"# Rendezvous (derived-point dial, rides on the relay strategy):\n"
        f"# only exactly 1 enables it; epoch defaults to 3600.\n"
        f"# CYBERNET_RENDEZVOUS=\n"
        f"# CYBERNET_RENDEZVOUS_EPOCH_LEN=\n"
        f"# Reach descriptor lifetime / re-announce cadence (seconds):\n"
        f"# CYBERNET_REACH_TTL=86400\n"
        f"# CYBERNET_HOSTD_REFRESH=600\n")


def _valid_mirror(mirror: str) -> bool:
    """Mirror shape check; mirrors dial.plan (server decides).

    A mirror that is not an http(s) URL with a host, or that names a
    port no dial can ever attempt (0, >65535, or non-numeric — urlsplit
    does not validate it, so parts.port must be read and raises for the
    last two), is a bad argument, not an unreachable mirror. Without
    this gate main() wrote the name key first and then read the failure
    as a claim refusal (exit 1) — or, for a scheme-less value, crashed
    raw in Request construction — leaving half-written state behind.

    Whitespace/control characters are refused on the RAW string first:
    urlsplit silently strips \\t\\r\\n before parsing, so a mirror like
    "http://host:8471/\\nCYBERNET_MIRROR_URL=http://evil" passes every
    check below — but _hostd_env_text writes the ORIGINAL string
    verbatim into the key-bearing hostd env file, where the newline
    injects whole env lines (a second MIRROR_URL, a forged NAME_PRIVKEY)
    into a 0600 file installed under /etc. A leading space / trailing
    tab passed the same way and wrote a value hostd never reads back
    as written. No honest mirror contains whitespace; refuse it."""
    # A non-string has no mirror shape at all: it escaped as TypeError
    # from the iteration below (int/None) or AttributeError from a
    # bytes element's .isspace — a crash, not this predicate's False.
    if not isinstance(mirror, str):
        return False
    if any(c.isspace() or ord(c) < 0x20 or ord(c) == 0x7F for c in mirror):
        return False
    try:
        parts = urllib.parse.urlsplit(mirror)
        port = parts.port
    except ValueError:
        return False
    return (parts.scheme in ("http", "https") and bool(parts.hostname)
            and (port is None or 1 <= port <= 65535))


def _valid_label(label: str) -> bool:
    """Client-side fast check; mirrors core._valid_name_label (server decides)."""
    # Twin of the _valid_mirror gate above: a non-string label escaped
    # as TypeError from len()/the "." test instead of this predicate's
    # False (None alone happened to read as empty).
    if not isinstance(label, str):
        return False
    if not label or len(label) > _LABEL_MAX:
        return False
    if label != label.lower() or "." in label:
        return False
    if label.startswith("-") or label.endswith("-"):
        return False
    return all((c.isascii() and c.isalnum()) or c == "-" for c in label)


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S+00:00")


# Mirror-response read bound, twin of core._PEER_RESP_MAX and
# resolve_chain._FETCH_MAX: the mirror is untrusted for every other
# shape this client checks, so its body gets the same 64KB cap (legit
# mirror answers — a claim verdict, a name resolution — are a few
# hundred bytes). read() unbounded let a mirror stream an endless
# body into memory before any verdict ran; an oversize body is never
# a parsed document (see the two readers below).
_MIRROR_RESP_MAX = 65536


def _read_bounded(stream) -> bytes | None:
    """Read at most _MIRROR_RESP_MAX bytes; None when the body is larger."""
    raw = stream.read(_MIRROR_RESP_MAX + 1)
    return None if len(raw) > _MIRROR_RESP_MAX else raw


def _post_form(url: str, fields: dict, timeout: float = 30.0) -> tuple[int | None, str]:
    """POST urlencoded form; returns (status, body). status None = no HTTP answer.

    An oversize body (success or HTTPError alike) returns as "" — the
    caller reads a 200 with an empty body as its unparseable-claim
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


def main(argv: list[str]) -> int:
    if "-h" in argv or "--help" in argv:
        print(__doc__.strip())
        return 0
    # Parse options in BOTH spellings (--opt value and --opt=value):
    # the old hand-rolled split read a space-form value as a positional
    # and the option as "", so the documented [--expiry-days N] form
    # was refused as "must be an integer", a space-form --env-dir
    # silently became Path("") (the cwd), an unknown option (a typo
    # like --expiry-day) was silently ignored and the mint proceeded
    # at the default the operator never asked for, and extra
    # positionals vanished. Unknown/malformed options and surplus
    # positionals are bad arguments, refused before any key/network.
    _KNOWN_OPTS = ("--env-dir", "--expiry-days")
    args: list[str] = []
    opts: dict[str, str] = {}
    i = 0
    while i < len(argv):
        a = argv[i]
        if a.startswith("--"):
            name, eq, val = a.partition("=")
            if name not in _KNOWN_OPTS:
                print(f"refused: unknown option {name!r} — supported: "
                      f"--env-dir DIR, --expiry-days N", file=sys.stderr)
                return 2
            if not eq:
                i += 1
                if i >= len(argv) or argv[i].startswith("--"):
                    print(f"refused: {name} needs a value", file=sys.stderr)
                    return 2
                val = argv[i]
            opts[name] = val
        else:
            args.append(a)
        i += 1
    if len(args) < 1 or len(args) > 2:
        print("usage: mint_name.py <label> [mirror_url] [--env-dir DIR] [--expiry-days N]",
              file=sys.stderr)
        return 2
    label = args[0].strip().lower()
    mirror = args[1] if len(args) > 1 else "http://127.0.0.1:8471"
    if not _valid_label(label):
        print(f"refused: {label!r} is not a valid .cyberspace label "
              f"(lowercase alnum/hyphen, 1-{_LABEL_MAX} chars, no dots, no edge hyphens)",
              file=sys.stderr)
        return 2
    try:
        expiry_days = int(opts.get("--expiry-days", _DEFAULT_EXPIRY_DAYS))
    except ValueError:
        print("refused: --expiry-days must be an integer", file=sys.stderr)
        return 2
    if expiry_days < 1:
        # No silent clamp: max(1, ...) turned 0/negative into a 1-day
        # binding the operator never asked for, wrote the key, and read
        # as a claim refusal — a set-but-ineffective value, refused as
        # a bad argument exactly like the over-cap case below.
        print(f"refused: --expiry-days={expiry_days} is below the 1-day "
              f"floor — a binding must live at least a day, so nothing "
              f"was minted", file=sys.stderr)
        return 2
    if expiry_days > _EXPIRY_DAYS_CAP:
        print(f"refused: --expiry-days={expiry_days} exceeds the namespace's "
              f"{_EXPIRY_DAYS_CAP}-day binding-lifetime cap — the claim "
              f"route refuses any binding signed for longer, so nothing "
              f"was minted", file=sys.stderr)
        return 2
    if not _valid_mirror(mirror):
        print("refused: mirror is not a dialable http(s) URL with a host "
              "and a port in 1-65535 — bad argument, nothing was minted",
              file=sys.stderr)
        return 2

    home = Path.home() / ".cyberspace"
    home.mkdir(parents=True, exist_ok=True)
    key_path = home / f"{label}-name.key"
    if key_path.exists():
        # An existing key file that does not parse as hex (corrupt,
        # truncated mid-copy, hand-edited) is an operator-side bad
        # input: bytes.fromhex raised ValueError uncaught and the
        # mint died in a traceback — a crash, not the refusal every
        # other bad input here gets, and not the verdict the len
        # check below gives a parseable-but-wrong-size seed. Refuse
        # as a bad argument, twin of rotate_name's guarded key reads.
        # The file is left untouched: never overwrite a key we
        # could not read.
        try:
            priv = _read_seed(key_path)
        except (OSError, ValueError):
            print(f"refused: {key_path} does not hold a hex seed — "
                  f"fix or remove it; nothing was minted and it was "
                  f"not overwritten", file=sys.stderr)
            return 2
        if len(priv) != 32:
            print(f"refused: {key_path} is not a 32-byte seed", file=sys.stderr)
            return 2
        print(f"Loading existing name key from {key_path}")
    else:
        priv = os.urandom(32)
        _write_secret(key_path, priv.hex())
        print(f"Generated name keypair; private key written to {key_path} (0600)")
    pub = publickey(priv)
    pub_hex = pub.hex().lower()
    print(f"Name key (pub): {pub_hex[:16]}...{pub_hex[-16:]}")

    now = datetime.now(timezone.utc)
    issued_at = _iso(now)
    expires_at = _iso(now + timedelta(days=expiry_days))
    payload = (b"name-claim|" + label.encode() + b"|" + pub_hex.encode()
               + b"|" + issued_at.encode() + b"|" + expires_at.encode())
    sig = sign(payload, priv, pub).hex().lower()
    binding = {"name": label, "node_pubkey": pub_hex, "issued_at": issued_at,
               "expires_at": expires_at, "signature": sig}

    print(f"\nClaiming {label}.cyberspace at {mirror} ...")
    status, body = _post_form(mirror.rstrip("/") + "/api/v1/names/claim", binding)
    if status == 409:
        print(f"taken: {label}.cyberspace is already claimed ({body.strip()[:120]})",
              file=sys.stderr)
        return 1
    if status != 200:
        print(f"refused: claim got {status}: {body.strip()[:200]}", file=sys.stderr)
        return 1
    try:
        result = json.loads(body)
    except Exception:
        print(f"refused: unparseable claim response: {body[:120]!r}", file=sys.stderr)
        return 1
    # The claim response is mirror-controlled: valid JSON that is not
    # an object ('[]', '123', '"ok"') has no status to read — result.get
    # died in an AttributeError traceback instead of the refused verdict
    # every other bad claim response gets.
    if not isinstance(result, dict):
        print(f"refused: unparseable claim response: {body[:120]!r}", file=sys.stderr)
        return 1
    print(f"Claimed: {result.get('status')}")

    resolved = _get_json(mirror.rstrip("/") + f"/api/v1/names/{label}")
    # Same mirror-controlled shape: a non-string node_pubkey (123, null)
    # died in .lower() with a traceback instead of reading as the
    # did-not-store refusal below — _get_json only proves dict shape.
    resolved_pub = resolved.get("node_pubkey") if resolved else None
    if not isinstance(resolved_pub, str) or resolved_pub.lower() != pub_hex:
        print("refused: name does not resolve back to the name key — "
              "mirror accepted but did not store; investigate before hosting",
              file=sys.stderr)
        return 1
    print(f"Verified: {label}.cyberspace resolves to the name key")

    env_dir = Path(opts.get("--env-dir", str(home / "hostd")))
    env_dir.mkdir(parents=True, exist_ok=True)
    env_path = env_dir / f"{label}.env"
    _write_secret(
        env_path,
        _hostd_env_text(label, priv.hex(), mirror),
        overwrite=True)
    print(f"hostd env written to {env_path} (0600) — "
          f"run: python -m resolver.host  (see deploy/hostd.service)")
    print(f"\n{label}.cyberspace is yours. The namespace grows by one.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
