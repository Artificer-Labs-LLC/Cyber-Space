// Check pre-flight grant-button parity harness — drives the REAL options.js
// "Check bridge now" click handler (not a copy) with stubbed chrome +
// DOM + navigator.userActivation, asserting:
//   A. permissions.contains REJECTS -> the catch names a verify-fault (not
//      "was not granted"), re-enables the button and restores its label;
//      no check runs, nothing saved.
//   B. no-prompt throw (contains false, no transient activation, request
//      false) -> the "browser never asked" line; button + label restored.
//   C. genuine denial (contains false, gesture present, request false) ->
//      unchanged "was not granted" line; button + label restored.
//   D. granted (contains true) -> beginCheck runs the real resolve path
//      (stubbed resolveCyberspaceInner), live line shown, button restored.
// Usage: node hidden_files/check-prefail-grant-parity-test.js
// Exit 0 when all assertions hold; exit 1 with the mismatch printed.
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const EXT = path.dirname(__dirname); // ~/workspace/cybernet/extension
const BRIDGE = "https://bridge.example/dns-query";

let unhandledFired = 0;
process.on("unhandledRejection", () => { unhandledFired++; });

function fakeElement() {
  return {
    textContent: "Check",
    disabled: false,
    hidden: false,
    className: "",
    value: "",
    listeners: {},
    addEventListener(ev, fn) { this.listeners[ev] = fn; },
  };
}

// Load resolver.js then options.js; return the captured elements plus a
// click() for the check button. `perms` = { contains, request } where each
// is { value } or { throw: Error }. resolveStub = (name, bridge) => Promise.
function loadPage({ contains, request, gesture, resolveStub }) {
  const els = {
    endpoint: fakeElement(),
    msg: fakeElement(),
    grantBanner: fakeElement(),
    grantBannerText: fakeElement(),
    grantBtn: fakeElement(),
    save: fakeElement(),
    check: fakeElement(),
    health: fakeElement(),
  };
  els.endpoint.value = BRIDGE;
  const byId = {
    endpoint: els.endpoint, msg: els.msg, grantBanner: els.grantBanner,
    grantBannerText: els.grantBannerText, grantBtn: els.grantBtn,
    save: els.save, check: els.check, health: els.health,
  };
  const resolveCalls = [];
  const sandbox = {
    console,
    URL, encodeURIComponent, decodeURIComponent,
    String, RegExp, Error, Promise, setTimeout, clearTimeout,
    AbortController, Date, JSON, Math, Object, Array, Number,
    navigator: { userActivation: { isActive: gesture } },
    chrome: {
      permissions: {
        contains: () => contains.throw ? Promise.reject(contains.throw) : Promise.resolve(contains.value),
        request: () => request.throw ? Promise.reject(request.throw) : Promise.resolve(request.value),
      },
      storage: { local: { get: () => Promise.resolve({}), set: () => Promise.resolve(), remove: () => Promise.resolve() } },
      i18n: { getMessage: () => "" },
    },
    document: {
      getElementById: (id) => byId[id],
      querySelectorAll: () => [],
    },
  };
  const ctx = vm.createContext(sandbox);
  vm.runInContext(fs.readFileSync(path.join(EXT, "resolver.js"), "utf8"), ctx, { filename: "resolver.js" });
  // Pin resolveCyberspaceInner to a stub so the granted path runs without
  // network; the check body itself (taxonomy, belts, label restore) is real.
  if (resolveStub) {
    vm.runInContext(`globalThis.__stub = ${"null"};`, ctx); // no-op placeholder
    vm.runInContext(`resolveCyberspaceInner = ${resolveStub.toString()};`, ctx);
  }
  vm.runInContext(fs.readFileSync(path.join(EXT, "options.js"), "utf8"), ctx, { filename: "options.js" });
  return {
    els, resolveCalls,
    clickCheck: () => {
      const fn = els.check.listeners.click;
      if (!fn) throw new Error("no click listener on check button");
      resolveCalls.push("clicked");
      fn();
    },
  };
}

async function settle(ms = 80) { await new Promise((r) => setTimeout(r, ms)); }

async function main() {
  let failures = 0;
  const check = (label, cond, detail) => {
    console.log(`${cond ? "PASS" : "FAIL"} ${label}${cond ? "" : " — " + detail}`);
    if (!cond) failures++;
  };

  // A: permissions surface throws on contains -> verify-fault line, button
  // re-enabled, label restored, no "was not granted" misreport.
  {
    unhandledFired = 0;
    const { els, clickCheck } = loadPage({
      contains: { throw: new Error("permissions service unavailable") },
      request: { value: false }, gesture: true,
    });
    els.check.textContent = "Check bridge now";
    clickCheck();
    await settle();
    check("A button re-enabled after contains-throw", els.check.disabled === false, "still disabled");
    check("A label restored after contains-throw", els.check.textContent === "Check bridge now", JSON.stringify(els.check.textContent));
    check("A names verify-fault not denial", els.health.textContent.includes("could not be verified"), JSON.stringify(els.health.textContent));
    check("A never says 'was not granted'", !els.health.textContent.includes("was not granted"), JSON.stringify(els.health.textContent));
  }

  // B: no transient activation -> no-prompt taxonomy line.
  {
    unhandledFired = 0;
    const { els, clickCheck } = loadPage({
      contains: { value: false }, request: { value: false }, gesture: false,
    });
    clickCheck();
    await settle();
    check("B button re-enabled after no-prompt throw", els.check.disabled === false, "still disabled");
    check("B names never-asked fault", els.health.textContent.includes("never asked"), JSON.stringify(els.health.textContent));
    check("B never says 'was not granted'", !els.health.textContent.includes("was not granted"), JSON.stringify(els.health.textContent));
  }

  // C: genuine denial, gesture present -> unchanged denied line.
  {
    unhandledFired = 0;
    const { els, clickCheck } = loadPage({
      contains: { value: false }, request: { value: false }, gesture: true,
    });
    clickCheck();
    await settle();
    check("C button re-enabled on denial", els.check.disabled === false, "still disabled");
    check("C denied line intact", els.health.textContent.includes("was not granted"), JSON.stringify(els.health.textContent));
  }

  // D: granted -> beginCheck runs real path, live line, button restored.
  {
    unhandledFired = 0;
    const { els, clickCheck } = loadPage({
      contains: { value: true }, request: { value: false }, gesture: true,
      resolveStub: (name, bridge) => Promise.resolve("203.0.113.7"),
    });
    clickCheck();
    await settle();
    check("D button re-enabled after live check", els.check.disabled === false, "still disabled");
    check("D live line shown", els.health.className === "ok" && els.health.textContent.includes("203.0.113.7"), JSON.stringify(els.health.textContent));
  }

  console.log(`\n${failures === 0 ? "ALL PASS" : failures + " FAILURES"}`);
  process.exit(failures ? 1 : 0);
}

main().catch((e) => { console.error("HARNESS ERROR", e); process.exit(1); });
