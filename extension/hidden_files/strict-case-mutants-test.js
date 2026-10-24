// Strict-case mutant harness (ART-37 a391b7df applied to the extension's
// name-binding read gate, ruled 52f465cd; refusal code non-canonical-key). Each mutant is a textual edit of
// resolver.js loaded into a fresh vm; the edit's target must be found exactly
// once (a mutant that does not apply fails the run, never a silent no-op).
// Rows: every weak-key-vectors.json row via fetchedKeyReason, plus a case-twin
// via verifyNameBinding with a real WebCrypto signature (lowercase verifies,
// uppercase / mixed case refused as non-canonical-key with 0 WebCrypto calls).
// The unmutated resolver must pass every row; every mutant must fail >= 1 row.
// Usage: node hidden_files/strict-case-mutants-test.js
const fs = require("fs"), path = require("path"), vm = require("vm");
const EXT = path.dirname(__dirname);
const SRC = fs.readFileSync(path.join(EXT, "resolver.js"), "utf8");
const V = JSON.parse(fs.readFileSync(path.join(__dirname, "weak-key-vectors.json"), "utf8")).vectors;
const GATE = 'const k = typeof pubHex === "string" ? pubHex : "";';
const CALL = "const keyReason = fetchedKeyReason(binding.node_pubkey);";
const RE = 'if (!/^[0-9a-f]{64}$/.test(k)) return "non-canonical-key";';
const MUTANTS = {
  "M-FKR-LOWER": [GATE, 'const k = typeof pubHex === "string" ? pubHex.toLowerCase() : "";'],
  "M-VNB-LOWER": [CALL, "const keyReason = fetchedKeyReason(pub);"],
  "M-FKR-RE-CI": [RE, 'if (!/^[0-9a-f]{64}$/i.test(k)) return "non-canonical-key";'],
  "M-CODE-FORMAT": [RE, 'if (!/^[0-9a-f]{64}$/.test(k)) return "format";'],
  "M-VNB-CODE": ['if (keyReason === "non-canonical-key") throw', 'if (keyReason === "format") throw'],
  "M-FKR-NORMALIZE": [GATE, 'const k = typeof pubHex === "string" ? pubHex.trim().toLowerCase() : "";'],
};
function load(src) {
  const ctx = vm.createContext({ console, URL, TextEncoder, crypto: globalThis.crypto, setTimeout, clearTimeout,
    AbortController, fetch: async () => { throw new Error("no network"); } });
  vm.runInContext(src, ctx, { filename: "resolver.js" });
  return ctx;
}
async function rows(ctx, twin) {
  let fail = 0; const failed = [];
  for (const v of V) if (ctx.fetchedKeyReason(v.pubkey) !== v.reason) { fail++; failed.push(v.case); }
  const now = Date.UTC(2026, 9, 17);
  const ok = await ctx.verifyNameBinding({ ...twin.b, node_pubkey: twin.pub }, "casetwin", now).then((r) => r.pub === twin.pub, () => false);
  if (!ok) { fail++; failed.push("twin-lower-verifies"); }
  for (const [lbl, k] of [["twin-upper", twin.pub.toUpperCase()], ["twin-mixed", twin.mixed]]) {
    const calls = { n: 0 };
    const spy = { importKey: async (...a) => { calls.n++; return crypto.subtle.importKey(...a); },
      verify: async (...a) => { calls.n++; return crypto.subtle.verify(...a); } };
    const m = await ctx.verifyNameBinding({ ...twin.b, node_pubkey: k }, "casetwin", now, spy).then(() => "ACCEPTED", (e) => e.message);
    if (!(/weak-key: non-canonical-key/.test(m) && calls.n === 0)) { fail++; failed.push(`${lbl}(${m.slice(0, 40)})`); }
  }
  return { fail, failed };
}
(async () => {
  let kp, pub = "";
  do {
    kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
    pub = Buffer.from(await crypto.subtle.exportKey("raw", kp.publicKey)).toString("hex");
  } while (!/[a-f]/.test(pub));
  const b = { name: "casetwin", issued_at: "2026-10-01T00:00:00Z", expires_at: "2027-10-01T00:00:00Z" };
  b.signature = Buffer.from(await crypto.subtle.sign({ name: "Ed25519" }, kp.privateKey,
    new TextEncoder().encode(`name-claim|casetwin|${pub}|${b.issued_at}|${b.expires_at}`))).toString("hex");
  const twin = { pub, b, mixed: pub.split("").map((c, i) => (i % 2 ? c.toUpperCase() : c)).join("") };
  let failures = 0;
  const base = await rows(load(SRC), twin);
  const nrows = V.length + 3;
  console.log(`${base.fail === 0 ? "PASS" : "FAIL"} unmutated resolver: ${nrows - base.fail}/${nrows} rows${base.fail ? " failed " + base.failed.join(",") : ""}`);
  if (base.fail) failures++;
  let killed = 0;
  for (const [name, [from, to]] of Object.entries(MUTANTS)) {
    const n = SRC.split(from).length - 1;
    if (n !== 1) { console.log(`FAIL ${name}: target found ${n} times (mutant would not apply)`); failures++; continue; }
    const r = await rows(load(SRC.replace(from, to)), twin);
    const k = r.fail > 0; if (k) killed++; else failures++;
    console.log(`${k ? "PASS" : "FAIL"} ${name} ${k ? "killed" : "SURVIVED"}: ${r.fail} row(s) fail${k ? " e.g. " + r.failed.slice(0, 4).join(",") : ""}`);
  }
  console.log(`INFO mutants killed ${killed}/${Object.keys(MUTANTS).length}`);
  console.log(failures ? `FAILED ${failures}` : "ALL PASS");
  process.exit(failures ? 1 : 0);
})();
