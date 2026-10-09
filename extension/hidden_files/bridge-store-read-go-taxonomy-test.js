// Dead-settings-store taxonomy harness — drives the REAL getDohUrl +
// classifyResolveError + classifyHealthError (resolver.js) with a stubbed
// chrome, asserting the popup Go path and the health check name the actual
// fault when the settings store dies:
//   A. chrome.storage.local.get rejects ("Extension context invalidated.")
//      -> getDohUrl throws with the "cannot read bridge setting" prefix;
//      classifyResolveError names the store ("settings could not be read"),
//      kind "bridge", NOT the endpoint hint ("set correctly") and NOT the
//      wire fallback (kind "wire", empty hint).
//   B. stored bridge fails validation -> classifyResolveError still routes
//      to the endpoint hint (no regression of the real config-value class).
//   C. classifyHealthError on the store-read error -> same unreadable hint,
//      NOT the endpoint hint ("is the bridge endpoint set correctly").
// Usage: node hidden_files/bridge-store-read-go-taxonomy-test.js
// Exit 0 when all assertions hold; exit 1 with the mismatch printed.
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const EXT = path.dirname(__dirname); // ~/workspace/cybernet/extension

function loadResolver(storageGet) {
  const sandbox = {
    console, URL, String, RegExp, Error, Promise,
    setTimeout, clearTimeout, AbortController, Date, JSON, Math, Object, Array, Number,
    chrome: {
      storage: { local: { get: storageGet } },
    },
  };
  const ctx = vm.createContext(sandbox);
  vm.runInContext(fs.readFileSync(path.join(EXT, "resolver.js"), "utf8"), ctx, { filename: "resolver.js" });
  return ctx;
}

async function main() {
  let failures = 0;
  const check = (label, cond, detail) => {
    console.log(`${cond ? "PASS" : "FAIL"} ${label}${cond ? "" : " — " + detail}`);
    if (!cond) failures++;
  };

  // Scenario A: the store can't be read at all.
  const ctxA = loadResolver(() => Promise.reject(new Error("Extension context invalidated.")));
  let errA = null;
  try { await ctxA.getDohUrl(); } catch (e) { errA = e; }
  check("A: getDohUrl throws", !!errA, "resolved instead of throwing");
  check("A: throw carries the read-fault prefix",
    !!errA && /^cannot read bridge setting/.test(errA.message), String(errA && errA.message));
  const taxA = ctxA.classifyResolveError(errA);
  check("A: taxonomy names the store, not the endpoint",
    taxA.kind === "bridge" && /settings could not be read/.test(taxA.hint),
    `kind=${taxA.kind} hint=${JSON.stringify(taxA.hint)}`);
  check("A: taxonomy does NOT point at the endpoint setting",
    !/set correctly/.test(taxA.hint),
    `endpoint mislabel: ${JSON.stringify(taxA.hint)}`);
  check("A: taxonomy does NOT fall through to wire fallback",
    taxA.hint !== "",
    "empty hint — fell through to the wire fallback");

  // Scenario B: stored bridge is a real config-value problem (no regression).
  const ctxB = loadResolver(() => Promise.resolve({ dohUrl: "http://[bad" }));
  let errB = null;
  try { await ctxB.getDohUrl(); } catch (e) { errB = e; }
  check("B: invalid stored bridge still throws Configured-DoH-bridge class",
    !!errB && /^Configured DoH bridge/.test(errB.message), String(errB && errB.message));
  const taxB = ctxB.classifyResolveError(errB);
  check("B: config-value fault still gets the endpoint hint",
    taxB.kind === "bridge" && /set correctly/.test(taxB.hint),
    `kind=${taxB.kind} hint=${JSON.stringify(taxB.hint)}`);

  // Scenario C: health check on the store-read error.
  const taxC = ctxA.classifyHealthError(errA);
  check("C: health taxonomy names the store, not the endpoint",
    taxC.kind === "bridge" && /settings could not be read/.test(taxC.hint),
    `kind=${taxC.kind} hint=${JSON.stringify(taxC.hint)}`);
  check("C: health taxonomy does NOT say the endpoint is wrong",
    !/endpoint set correctly/.test(taxC.hint),
    `endpoint mislabel: ${JSON.stringify(taxC.hint)}`);

  if (failures) { console.error(`${failures} assertion(s) failed`); process.exit(1); }
  console.log("bridge-store-read-go-taxonomy: all assertions passed");
}

main().catch((e) => { console.error("harness crashed:", e); process.exit(1); });
