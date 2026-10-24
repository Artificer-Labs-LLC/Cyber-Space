// Weak-key refusal harness (ART-20). Two parts:
// 1. Parity: resolver.js fetchedKeyReason() returns the same reason as
//    weak_key.admission_reason(RAW key) (db15a900; strict case, ruled 52f465cd;
//    its "format" is spelled non-canonical-key at every seat -- see the
//    vectors' _source) for every row of weak-key-vectors.json.
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
    check(`${lbl} node_pubkey refused before verify (no trim)`, /weak-key: non-canonical-key/.test(m), m);
  }
  // Strict case (a391b7df, name-key read seats 52f465cd). The old row here used H, which is
  // digit-only (H.toUpperCase() === H), so it never exercised case. Case-twin
  // row on a real key with a-f letters and a REAL signature over the
  // lowercase payload: the lowercase spelling verifies; the uppercase and
  // mixed-case spellings of the same key are refused as non-canonical-key before
  // WebCrypto (spy counts calls), although the signature would verify.
  let kp, pubHex = "";
  do {
    kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
    pubHex = Buffer.from(await crypto.subtle.exportKey("raw", kp.publicKey)).toString("hex");
  } while (!/[a-f]/.test(pubHex));
  const tb = { name: "casetwin", node_pubkey: pubHex, issued_at: binding.issued_at, expires_at: binding.expires_at };
  const tsig = Buffer.from(await crypto.subtle.sign({ name: "Ed25519" }, kp.privateKey,
    new TextEncoder().encode(`name-claim|casetwin|${pubHex}|${tb.issued_at}|${tb.expires_at}`))).toString("hex");
  let lo = "";
  try { const r = await ctx.verifyNameBinding({ ...tb, signature: tsig }, "casetwin", now); lo = r.pub; } catch (e) { lo = e.message; }
  check("case-twin: lowercase spelling with a real signature verifies", lo === pubHex, lo);
  const mixed = pubHex.split("").map((c, i) => (i % 2 ? c.toUpperCase() : c)).join("");
  for (const [lbl, k] of [["uppercase", pubHex.toUpperCase()], ["mixed-case", mixed]]) {
    if (k === pubHex) continue;
    const calls = { n: 0 };
    const spy = { importKey: async (...a) => { calls.n++; return crypto.subtle.importKey(...a); },
      verify: async (...a) => { calls.n++; return crypto.subtle.verify(...a); } };
    let m = "";
    try { await ctx.verifyNameBinding({ ...tb, node_pubkey: k, signature: tsig }, "casetwin", now, spy); m = "ACCEPTED"; } catch (e) { m = e.message; }
    check(`case-twin: ${lbl} spelling of the same key refused as non-canonical-key, 0 WebCrypto calls`,
      /weak-key: non-canonical-key/.test(m) && calls.n === 0, `msg=${m} calls=${calls.n}`);
  }
  console.log(failures ? `${failures} FAILED` : "ALL PASS");
  process.exit(failures ? 1 : 0);
})();
