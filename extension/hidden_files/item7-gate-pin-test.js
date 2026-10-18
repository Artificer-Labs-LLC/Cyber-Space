// r7 item-7 group-1 pinning row (ART-37). Proves the extension never asks
// WebCrypto to verify a binding whose node_pubkey fails the key gate.
// Uses Cipher's frozen item-7 set (sha256 c8d4f448...dc6dd, 91 rows) and a
// spy `subtle` that would ACCEPT anything: any call to it counts as a failure
// for a gated key. Group 1 = the 9 rows only raw WebCrypto accepts.
// Usage: node hidden_files/item7-gate-pin-test.js
const fs = require("fs"), path = require("path"), vm = require("vm"), crypto = require("crypto");
const EXT = path.dirname(__dirname);
const FILE = path.join(__dirname, "item7-vectors.json");
const SHA = "c8d4f4486cd2935e68900c21d85e4c628fe074068f459640efa0e9005bfdc6dd";
const ctx = vm.createContext({ console, URL, TextEncoder, crypto: globalThis.crypto, setTimeout, clearTimeout, AbortController, fetch: async () => { throw new Error("no network"); } });
vm.runInContext(fs.readFileSync(path.join(EXT, "resolver.js"), "utf8"), ctx, { filename: "resolver.js" });
let failures = 0;
const check = (label, cond, detail) => { console.log(`${cond ? "PASS" : "FAIL"} ${label}${cond ? "" : " - " + detail}`); if (!cond) failures++; };
const GROUP1 = { 4: "small-order", 6: "small-order", 8: "small-order", 10: "small-order", 16: "small-order",
  79: "small-order", 80: "small-order", 81: "mixed-order", 90: "non-canonical" };
(async () => {
  const raw = fs.readFileSync(FILE);
  check("vector set sha256", crypto.createHash("sha256").update(raw).digest("hex") === SHA, "sha mismatch");
  const V = JSON.parse(raw).vectors;
  check("vector count 91", V.length === 91, V.length);
  const now = Date.UTC(2026, 9, 17);
  let gated = 0, gatedCalls = 0;
  for (let i = 0; i < V.length; i++) {
    const v = V[i];
    const calls = { n: 0 };
    const spy = { importKey: async () => { calls.n++; return {}; }, verify: async () => { calls.n++; return true; } };
    const binding = { name: "pin", node_pubkey: v.pk, signature: v.sig,
      issued_at: "2026-10-01T00:00:00Z", expires_at: "2027-10-01T00:00:00Z" };
    const reason = ctx.fetchedKeyReason(v.pk);
    let msg = "ACCEPTED";
    try { await ctx.verifyNameBinding(binding, "pin", now, spy); } catch (e) { msg = e.message; }
    if (reason) {
      gated++; gatedCalls += calls.n;
      check(`row ${i} ${v.name}: refused at key gate (${reason}), 0 WebCrypto calls`,
        msg.includes(`weak key (${reason})`) && calls.n === 0, `msg=${msg} calls=${calls.n}`);
    }
    if (i in GROUP1)
      check(`group-1 pin row ${i}: gate reason ${GROUP1[i]}`, reason === GROUP1[i], `got ${reason}`);
  }
  check("all 9 group-1 rows present and gated", Object.keys(GROUP1).every((i) => ctx.fetchedKeyReason(V[i].pk)), "missing");
  check("gated rows made zero WebCrypto calls in total", gatedCalls === 0, gatedCalls);
  console.log(`INFO gated rows ${gated}/91, WebCrypto calls on gated rows ${gatedCalls}`);
  console.log(failures ? `FAILED ${failures}` : "ALL PASS");
  process.exit(failures ? 1 : 0);
})();
