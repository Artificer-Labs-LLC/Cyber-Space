// Weak-key refusal harness (ART-20). Two parts:
// 1. Parity: resolver.js weakKeyReason() returns the same reason as the
//    node read seat (r6b 0542c395: weak_key.admission_reason(key.lower())) for every row of weak-key-vectors.json.
// 2. Forgery: a binding under the identity key (01 00..00) with signature
//    R = identity, S = 0 is refused by verifyNameBinding before WebCrypto
//    is consulted. Also reports whether raw WebCrypto alone accepts it.
// Usage: node hidden_files/weak-key-refusal-test.js
const fs = require("fs");
const path = require("path");
const vm = require("vm");
const EXT = path.dirname(__dirname);
const V = JSON.parse(fs.readFileSync(path.join(__dirname, "weak-key-vectors.json"), "utf8")).vectors;
const ctx = vm.createContext({ console, URL, TextEncoder, crypto: globalThis.crypto, setTimeout, clearTimeout, AbortController, fetch: async () => { throw new Error("no network"); } });
vm.runInContext(fs.readFileSync(path.join(EXT, "resolver.js"), "utf8"), ctx, { filename: "resolver.js" });
let failures = 0;
const check = (label, cond, detail) => { console.log(`${cond ? "PASS" : "FAIL"} ${label}${cond ? "" : " — " + detail}`); if (!cond) failures++; };
(async () => {
  for (const v of V) {
    const got = ctx.fetchedKeyReason(v.pubkey);
    check(`parity ${v.case}`, got === v.reason, `js=${got} node=${v.reason}`);
  }
  const idKey = "01" + "00".repeat(31);
  const sig = idKey + "00".repeat(32);
  const now = Date.UTC(2026, 9, 17);
  const binding = { name: "forged", node_pubkey: idKey, signature: sig,
    issued_at: "2026-10-01T00:00:00Z", expires_at: "2027-10-01T00:00:00Z" };
  let raw = "error";
  try {
    const hex = (h) => Uint8Array.from(h.match(/../g).map((b) => parseInt(b, 16)));
    const k = await crypto.subtle.importKey("raw", hex(idKey), { name: "Ed25519" }, false, ["verify"]);
    raw = await crypto.subtle.verify({ name: "Ed25519" }, k, hex(sig),
      new TextEncoder().encode(`name-claim|forged|${idKey}|${binding.issued_at}|${binding.expires_at}`));
  } catch (e) { raw = "threw: " + e.message; }
  console.log(`INFO raw WebCrypto on forged identity-key binding: ${raw}`);
  let msg = "";
  try { await ctx.verifyNameBinding(binding, "forged", now); msg = "ACCEPTED"; } catch (e) { msg = e.message; }
  check("forged identity-key binding refused as weak", /weak key \(small-order\)/.test(msg), msg);
  let z = "";
  try { await ctx.verifyNameBinding({ ...binding, node_pubkey: "00".repeat(32) }, "forged", now); z = "ACCEPTED"; } catch (e) { z = e.message; }
  check("all-zero node_pubkey refused as weak", /weak key \(small-order\)/.test(z), z);
  const H = "5866666666666666666666666666666666666666666666666666666666666666";
  for (const [lbl, k] of [["spaced", " " + H], ["63-char", H.slice(0, 63)], ["65-char", H + "6"]]) {
    let m = "";
    try { await ctx.verifyNameBinding({ ...binding, node_pubkey: k }, "forged", now); m = "ACCEPTED"; } catch (e) { m = e.message; }
    check(`${lbl} node_pubkey refused before verify (no trim)`, /weak-key: format/.test(m), m);
  }
  let u = "";
  try { await ctx.verifyNameBinding({ ...binding, node_pubkey: H.toUpperCase() }, "forged", now); u = "ACCEPTED"; } catch (e) { u = e.message; }
  check("uppercase honest key passes the key gate (fails only at signature)", /signature does not verify|could not be checked/.test(u), u);
  console.log(failures ? `${failures} FAILED` : "ALL PASS");
  process.exit(failures ? 1 : 0);
})();
