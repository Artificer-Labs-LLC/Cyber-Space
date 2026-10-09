# The local resolver (Phase 2: .cyberspace for ordinary software)

*Status: item 1 built ✅ (daemon commit-frozen, zone + forward/TTL suites 9/9
green, AAAA suite 12/12 green, wire path deferred). The gate was mine, not hers: "will be good once
we get .cyberspace working" was the order — building toward it. Items 2-3
written-but-unproven: the HQ node wires first (item 2's proof), then the
live end-to-end (item 3).*

## The hole

.cyberspace names resolve today only for agent clients calling
`resolve_cyberspace()` — the six-step fail-closed client resolver from
Phase 1 (see `core.py`). Ordinary software — browsers, curl, the OS
resolver itself — cannot see the namespace at all. The homeland has street
signs but only residents can read them; every visitor is blind. A name
only agents can resolve is a rumor with good cryptography.

## Design: `cybernet-resolver`, one small daemon

A local DNS server, authoritative for the `.cyberspace` zone and nothing
else — split-horizon by construction:

- **Query `<label>.cyberspace` (A/AAAA)** → run the six-step
  `resolve_cyberspace()` against the configured mirror (default: the
  genesis node) → success returns the node's address as A/AAAA records.
  **Any failure → NXDOMAIN.** Fail-closed end to end: silence, never a
  guess, never a redirect. The daemon adds no trust of its own — it reuses
  the registry's verification (mirror signature re-verified client-side,
  binding unexpired, live `/fed/ping` + `/api/v1/names/<label>` agreement).
  A lying mirror can withhold a name but never redirect one — the same
  guarantee Phase 1 makes to agent clients.
- **TTL** = min(binding `expires_at`, small cap, e.g. 300s) — revoked or
  expired names stop resolving promptly.
- **Everything else** → forwarded to the system's upstream resolver
  untouched. The daemon is a pure addition to the machine's DNS, never a
  replacement. (Alternative: refuse non-.cyberspace with a documented
  pointer — the build tick decides; forwarding is friendlier.)
- **No new trust roots.** No CA, no cert issuance, no clearnet DNS
  anywhere in the path. This is not a clearnet we're making.

## Wiring (split-horizon, documented, all three)

1. **systemd-resolved** (her machine, HQ node): drop-in with
   `DNS=127.0.0.1:5353` + `Domains=~cyberspace` — only `.cyberspace`
   routes to the daemon.
2. **dnsmasq**: `server=/.cyberspace/127.0.0.1#5353`.
3. **`/etc/hosts` fallback**: for a single pinned name, no daemon needed.

## Stand-up (per-agent unit)

`deploy/resolverd.service` — install as `/etc/systemd/system/resolverd.service`
(EDIT the three machine-specific lines: User, WorkingDirectory,
ExecStart/PATH — same convention as `deploy/hostd.service`). The unit holds
NO secrets (the daemon keeps no keys and answers no identity; name keys live
in the hostd env file, never here) and binds loopback-only 127.0.0.1:5353.
This is the unit for the "daemon every agent runs" — resolution from the
agent's own seat; `resolver/client.py` speaks to it at 127.0.0.1:5353.
`resolver/wiring/cybernet-resolver.service` remains the HQ operator-side unit.

One-command agent stand-up: `sudo ./deploy/install-agent.sh [--user NAME]
[--mirror URL] [--hostd-env PATH]` builds the venv, installs resolverd with
the EDIT lines rewritten, smoke-tests the daemon through the client CLI (a
junk name must come back NXDOMAIN), and — if a mint_name.py env file is
passed or exactly one exists under `~/.cyberspace/hostd/` — installs it
0600 as `/etc/cybernet-hostd/hostd.env` and starts hostd. Without a hostd
env it stops at resolution and prints the mint_name.py line. Opt-in
`--nss` installs `deploy/resolverd-nss.conf` as the systemd-resolved
stub-zone glue (`Domains=~cyberspace` → 127.0.0.1:5353) so every program on
the agent's machine resolves `*.cyberspace` — `curl http://alice.cyberspace/`
works, not just the client CLI. Opt-in on purpose: it is an alternative to
the HQ operator-side split-horizon drop-in (`~cyberspace` → HQ daemon);
never run both on one machine. DNS-less boxes use the dnsmasq line printed
when systemd-resolved isn't running (`server=/cyberspace/127.0.0.1#5353`).

Shell front door for the same client: `python -m resolver.client
alice.cyberspace [--qtype AAAA] [--tcp-only]` prints one address per line.
Exit codes: 0 resolved, 1 name does not resolve (NXDOMAIN), 2 everything
else (usage, transport, daemon SERVFAIL) — shell scripts can tell "no such
name" apart from "resolution broke". `CYBERNET_RESOLVER_PORT` picks the
daemon port (default 5353), same as the library.

## Dependencies

None beyond the project venv. (Earlier draft considered `dnslib` for the
DNS codec; the build tick 2026-10-07 19:20 hand-rolled a minimal stdlib
codec in `resolver/dns.py` instead — deliberately narrow: parse one
question, build A/AAAA answers, NXDOMAIN, SERVFAIL; anything else raises.
A dependency-free daemon installs anywhere, and the narrow codec is
fail-closed by construction. The design note permits this.)

## Build order (item 1 flipped; items 2-3 await the HQ node)

1. **`resolver/` daemon** ✅ *(2026-10-07)* — DNS on 127.0.0.1:5353,
   `.cyberspace` zone from `resolve_cyberspace()`, NXDOMAIN on any
   failure, upstream forward for the rest; unit-tested against a fake
   mirror, 9/9 green (`resolver/test_answer_mirror.py`): good binding →
   A record; bad signature → NXDOMAIN; expired → NXDOMAIN; mirror
   silent → NXDOMAIN. Slices: stdlib codec (dns.py), answer handler
   (answer.py), daemon loop (daemon.py) — all commit-frozen before the
   tests. Forward/TTL paths unit-tested too, 9/9 green
   (`resolver/test_forward_ttl.py`): non-zone queries relayed byte-for-byte,
   dead upstream → SERVFAIL echoing the query id, TTL =
   min(seconds-to-expiry, 300s) floored at 0, MX → NODATA without ever
   asking the mirror. Codec unit-tested too, 35/35 green
   (`resolver/test_dns.py`): parse happy path (A/AAAA, rd echo), all
   refusals (QR set, qdcount ≠ 1, truncated header/tail), label grammar
   (pointer compression incl. the jump-off check, pointer cycles,
   0x40 length bits, over-long labels, non-ascii), build (id/flags/
   ancount echo, 0xC00C answer pointer, NXDOMAIN, RD echo, bad rcode/
   ttl refused), error_response (never raises, id echo, SERVFAIL).
   AAAA paths unit-tested too, 12/12 green
   (`resolver/test_answer_aaaa.py`): AAAA on a v4-only node → NODATA,
   AAAA on a v6 node → one 16-byte answer, A on a v6-only node →
   NODATA, `_family_addresses` dedupe + junk-url `[]` (never guesses).
   That suite caught a real `core.py` bug: the node_url grammar
   rejected bracketed IPv6 literals, so a v6 node could never announce
   (400) or resolve (NXDOMAIN) — one-line fix, junk/malformed/ftp
   still rejected.
   Config parsing unit-tested too, 25/25 green
   (`resolver/test_daemon_config.py`): `_env_str` unset/stripped/blank,
   `_env_int` unset/parsed/negative-floor/garbage/hex-refused,
   `_parse_upstream` all-malformed → 1.1.1.1:53, never a half-parse,
   `_config` defaults + overrides; frozen-not-blessed: bracketed/bare
   IPv6 upstreams fall back to the v4 default (the parser splits on the
   first colon — the seam to fix if v6 upstream is ever wanted).
   Serve loop unit-tested too, 11/11 green
   (`resolver/test_serve_loop.py`): garbage → SERVFAIL with id echo,
   empty datagram swallowed with the zone still answering after,
   raising-handler → SERVFAIL (the loop's guard, never the handler's
   silence), dead mirror → NXDOMAIN fail-closed, the real SIGTERM
   handler captured and invoked to stop `run()` clean, socket closed
   on exit; wire monkeypatched (the sandbox blocks UDP sends), the
   signal wiring real. Now 12/12 green: the TCP face (RFC 7766) is bound
   and listened alongside UDP on the same port, closed on exit.
   TCP transport (RFC 7766, 2-octet length prefix) now served on the same
   port as UDP: the same fail-closed handle_query() on both wires, one
   TCP connection served sequentially to EOF/timeout in the same
   single-threaded select() loop — no threads, no new trust. A network
   that eats UDP (NAT-blocked hosts, walled sandboxes) still has a wire
   path to the zone.
   Live wire exercise, first real one: the sandbox blocks UDP at the
   syscall layer (EPERM on sendto, even loopback) but allows TCP, so
   hidden_files/resolver-tcp-wire-loopback-test.py runs the REAL daemon
   loop in the main thread (real SIGINT/SIGTERM handlers), the REAL
   claim endpoint (mint_name), the REAL hostd announce (host.announce_once),
   and real length-prefixed TCP frames on loopback: 8/8 green —
   claim+announce+six-step resolves NOERROR with A answers, junk →
   NXDOMAIN, AAAA → NODATA, pipelined reuse on one connection, garbage →
   SERVFAIL with txid echo, off-zone → SERVFAIL. Test-only allowances:
   the 127.0.0.1 mirror/node rides the in-process SSRF-gate allowance and
   CYBERNET_PUBLIC_URL points at the test node; the daemon loop, the
   six-step, and the signal handling are untouched production code.
   The five UDP wire assertions stay frozen as DEFERRED in
   hidden_files/resolver-wire-loopback-test.py for HQ wiring (item 2).
2. **Wiring docs + scripts** — the three split-horizon configs above as
   copy-paste units; proven first on the HQ node (genesis resolving its
   own name — a fine smoke test), then on her machine when she's at it.
3. **Live end-to-end** — `curl genesis.cyberspace/api/v1/node` (or the
   configured genesis name) resolving through the daemon against the real
   registry, fail-closed cases demonstrated live. The ordered procedure is
   frozen in `docs/RESOLVER_RUNBOOK.md` (the two gates, deploy step [4/4],
   claim-then-resolve order, the three wiring units as the client half,
   item-3 flip rule, recovery notes) — read it before touching anything.

## Discipline

- Not a CA, not a registrar, not a clearnet bridge. The daemon answers
  one zone from one registry and forwards the rest.
- Phase 1's contract is untouched: the daemon is a reader of the registry,
  never a writer. Name claims still happen on the nodes.
- `.cyberspace` stays sacred in prose until the daemon runs somewhere
  real — the v0 note is a plan, not a place.
