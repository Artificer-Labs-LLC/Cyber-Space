// Signed-binding gate harness (ART-20 port) — drives the REAL
// resolveCyberspaceInner + verifyNameBinding + classifyResolveError +
// buildFailurePage (resolver.js) with a stubbed fetch: the DoH POST answers
// an A record, GET /api/v1/names/<label> serves the binding under test.
// Vectors (binding-vectors.json) were signed with the repo's own
// fed.ed25519 (mint_name.sign over core._name_claim_payload); the genesis
// vector is the live HQ binding as served on 2026-10-12.
// Cases: valid resolves; tampered sig / wrong key / expired / missing sig /
// 404 (no binding served) / name mismatch all refuse with a named reason,
// return no address, cache nothing, and reach the failure page.
// Usage: node hidden_files/binding-signature-test.js
const fs = require("fs");
const path = require("path");
const vm = require("vm");
const EXT = path.dirname(__dirname);
const V = JSON.parse(fs.readFileSync(path.join(__dirname, "binding-vectors.json"), "utf8"));
const BRIDGE = "http://bridge.test/dns-query";

function dnsAnswer(query, ip) {
  const q = Buffer.from(query);
  const head = Buffer.from([q[0], q[1], 0x85, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
  const question = q.subarray(12);
  const ans = Buffer.from([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, ...ip.split(".").map(Number)]);
  const b = Buffer.concat([head, question, ans]);
  return b.buffer.slice(b.byteOffset, b.byteOffset + b.length);
}

function load(bindingFor) {
  const calls = [];
  const fetch = async (url, opts = {}) => {
    calls.push(url);
    if ((opts.method || "GET") === "POST") {
      const buf = dnsAnswer(opts.body, "10.9.8.7");
      return { ok: true, status: 200, headers: { get: (h) => (h === "Content-Type" ? "application/dns-message" : null) }, arrayBuffer: async () => buf };
    }
    const label = decodeURIComponent(new URL(url).pathname.split("/").pop());
    const b = bindingFor(label);
    if (b === undefined) return { ok: false, status: 404, text: async () => '{"detail":"No such name."}' };
    return { ok: true, status: 200, text: async () => JSON.stringify(b) };
  };
  const sandbox = { console, URL, String, RegExp, Error, Promise, setTimeout, clearTimeout, AbortController,
    Date, JSON, Math, Object, Array, Number, Map, Set, Uint8Array, TextEncoder, fetch, crypto: globalThis.crypto };
  const ctx = vm.createContext(sandbox);
  vm.runInContext(fs.readFileSync(path.join(EXT, "resolver.js"), "utf8"), ctx, { filename: "resolver.js" });
  return { ctx, calls };
}

const flip = (hex) => (hex[0] === "0" ? "1" : "0") + hex.slice(1);
const as = (b, name) => ({ ...b, name });

async function main() {
  let failures = 0;
  const check = (label, cond, detail) => {
    console.log(`${cond ? "PASS" : "FAIL"} ${label}${cond ? "" : " — " + detail}`);
    if (!cond) failures++;
  };
  const okCase = async (label, binding, name = "vectortest.cyberspace") => {
    const { ctx, calls } = load(() => binding);
    try {
      const ip = await ctx.resolveCyberspaceInner(name, BRIDGE, 2000);
      check(`${label}: resolves`, ip === "10.9.8.7", `got ${ip}`);
      check(`${label}: binding fetched from bridge origin`, calls.some((u) => u.startsWith("http://bridge.test/api/v1/names/")), calls.join(","));
    } catch (e) { check(`${label}: resolves`, false, e.message); }
  };
  const refuseCase = async (label, bindingFor, reasonRe, name = "vectortest.cyberspace") => {
    const { ctx } = load(bindingFor);
    let ip, err;
    try { ip = await ctx.resolveCyberspaceInner(name, BRIDGE, 2000); } catch (e) { err = e; }
    check(`${label}: refused (no address)`, !ip && err, `ip=${ip}`);
    if (!err) return;
    check(`${label}: reason named`, /^Name binding refused: /.test(err.message) && reasonRe.test(err.message), err.message);
    const c = ctx.classifyResolveError(err, "in the extension settings");
    check(`${label}: classified name-class with binding hint`, c.kind === "name" && /signed binding did not verify/.test(c.hint), JSON.stringify(c));
    const page = ctx.buildFailurePage({ name, bridge: BRIDGE, msg: err.message, hint: c.hint, retryUrl: `http://${name}/` });
    check(`${label}: failure page names reason`, decodeURIComponent(page).includes(err.message), "page lacks reason");
    check(`${label}: nothing cached`, ctx.cacheCheck(`${BRIDGE}|${name}`, BRIDGE) == null, "cache hit after refusal");
  };

  await okCase("valid binding", V.valid);
  await okCase("live genesis binding", V.genesis_live_2026_10_12, "genesis.cyberspace");
  await refuseCase("tampered signature", () => ({ ...V.valid, signature: flip(V.valid.signature) }), /does not verify/);
  await refuseCase("tampered payload (expires_at)", () => ({ ...V.valid, expires_at: "2098-01-01T00:00:00Z" }), /does not verify/);
  await refuseCase("wrong key", () => ({ ...V.valid, node_pubkey: V.other_key.node_pubkey }), /does not verify/);
  await refuseCase("expired", () => V.expired, /expired/);
  await refuseCase("missing signature", () => { const b = { ...V.valid }; delete b.signature; return b; }, /signature missing/);
  await refuseCase("no binding served (404)", () => undefined, /signed binding missing/);
  await refuseCase("binding for another name", () => as(V.genesis_live_2026_10_12, "genesis"), /binding is for genesis/);
  await refuseCase("non-UTC timestamp", () => ({ ...V.valid, issued_at: "2026-01-01T00:00:00-05:00" }), /canonical UTC/);
  // Direct verifier cases (no fetch).
  const { ctx } = load(() => undefined);
  const r = await ctx.verifyNameBinding({ ...V.valid, name: "VectorTest", signature: V.valid.signature.toUpperCase() }, "vectortest");
  check("verifier normalizes case like the mirror", r && r.pub === V.valid.node_pubkey, JSON.stringify(r));
  let notYet;
  try { await ctx.verifyNameBinding(V.valid, "vectortest", Date.UTC(2025, 0, 1)); } catch (e) { notYet = e.message; }
  check("not-yet-issued refused", /not yet issued/.test(notYet || ""), notYet);

  console.log(failures ? `\n${failures} FAILED` : "\nall passed");
  process.exit(failures ? 1 : 0);
}
main().catch((e) => { console.error(e); process.exit(1); });
