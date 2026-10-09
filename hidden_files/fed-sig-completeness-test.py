"""Federation signature-verification completeness (structural audit).

Every /fed/* inbound POST handler must verify the envelope (Ed25519,
skew-bound, body-hash-checked) before trusting anything it carries.
/fed/ping is the exception by design: a GET that returns a SIGNED identity
card (the node signs outbound; the caller verifies). /api/v1/fed/* are
local agent endpoints authenticated by api key, not envelopes.

Outbound half: every code path that reads a peer's envelope (seed bootstrap,
name-claim live verification, pigeonhole proxy replies) must verify it, with
recipient/sender binding where replies are concerned.

Structural assertions over the real federation.py / routes_social.py /
core.py — no network, no DB.
"""
import re
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
fed = (ROOT / "federation.py").read_text()
core = (ROOT / "core.py").read_text()
social = (ROOT / "routes_social.py").read_text()

failures = []


def check(name, cond):
    print(("PASS " if cond else "FAIL ") + name)
    if not cond:
        failures.append(name)


def bodies(src):
    out = {}
    for m in re.finditer(r'(?m)^(async )?def (\w+)\(', src):
        nxt = src.find('\ndef ', m.end())
        out[m.group(2)] = src[m.end():(nxt if nxt != -1 else len(src))]
    return out


fb = bodies(fed)

# 1. Every inbound /fed/* POST route has a handler that verifies the envelope.
routes = re.findall(
    r'@router\.(?:get|post)\("(/fed/[^"]+)"\)(?:\s*#[^\n]*)?\s*\n(?:async )?def (\w+)',
    fed)
check("inbound fed routes enumerated (>=14)", len(routes) >= 14)
for route, fn in routes:
    if route == "/fed/ping":
        b = fb[fn]
        check(f"{route}: signs outbound card (make_envelope), never trusts inbound",
              "make_envelope" in b and "verify_envelope" not in b)
        continue
    check(f"{route}: handler {fn} calls verify_envelope",
          "verify_envelope" in fb.get(fn, ""))

# 2. Local /api/v1/fed/* endpoints use agent auth, not envelopes.
for fn in ("fed_subscribe", "fed_unsubscribe"):
    check(f"{fn}: agent-authed (_authed), not envelope-authed",
          "_authed(" in fb.get(fn, "") and "env: dict" not in fb.get(fn, ""))

# 3. _recv_attestation cryptographically binds the delta to the announced key.
m = re.search(r'(?m)^def _recv_attestation\(', fed)
att = fed[m.end():fed.find('\ndef ', m.end())]
check("attestation: node_pub must match the announcer's sender_pub",
      'str(row.get("node_pub"' in att)
check("attestation: ed25519 checkvalid over canonical payload",
      "checkvalid" in att and "_delta_payload(row, seq, retire)" in att)

# 4. Outbound peer-envelope reads all verify.
check("seed bootstrap verifies ping envelopes", bool(
    re.search(r'node_url \+ "/fed/ping".*?verify_envelope\(env\)', core, re.S)))
check("name-claim live verification verifies ping envelope", bool(
    re.search(r'verify_envelope\(ping\)', core)))
check("pigeonhole proxy reply verified + recipient/sender bound", bool(
    re.search(r'verify_envelope\(reply\)[\s\S]{0,200}reply\.get\("recipient"\) != _NODE_PUB',
              social)))

print(f"\n{len(failures)} failures")
raise SystemExit(1 if failures else 0)
