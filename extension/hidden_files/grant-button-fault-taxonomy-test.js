// Grant-button fault-taxonomy harness — drives the REAL grant-button click
// handlers in options.js and popup.js (not copies) with stubbed chrome +
// DOM + navigator.userActivation, asserting:
//   A. permissions.contains REJECTS -> the catch names a verify-fault (not
//      "was not granted"), the button is re-enabled, banner hidden state
//      untouched by the fault path (denial-line not reused for a throw).
//   B. no-prompt throw (contains false, no transient activation, request
//      false) -> the "browser never asked" line; never "was not granted".
//   C. genuine denial (contains false, gesture present, request false) ->
//      unchanged "was not granted" denial line on both pages.
// Usage: node hidden_files/grant-button-fault-taxonomy-test.js
// Exit 0 when all assertions hold; exit 1 with the mismatch printed.
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const EXT = path.dirname(__dirname); // ~/workspace/cybernet/extension
const BRIDGE = "https://bridge.example/dns-query";

let unhandledFired = 0;
process.on("unhandledRejection", () => { unhandledFired++; });

function fakeElement() {
  const el = {
    textContent: "Check",
    disabled: false,
    hidden: false,
    className: "",
    value: "",
    listeners: {},
    addEventListener(ev, fn) { this.listeners[ev] = fn; },
    focus() {}, select() {}, appendChild() {},
    click() { const fn = this.listeners.click; if (fn) fn(); },
  };
  Object.defineProperty(el, "innerHTML", {
    get() { return this.textContent; },
    set(v) { this.textContent = v; },
  });
  return el;
}

// Load resolver.js then the named page; return elements + clickGrant.
function loadPage(page, { contains, request, gesture }) {
  const ids = page === "options.js"
    ? ["endpoint", "msg", "grantBanner", "grantBannerText", "grantBtn", "save", "check", "health"]
    : ["status", "name", "endpoint", "epmsg", "grantBanner", "grantBannerText", "grantBtn",
       "save-bridge", "go", "recent", "open-options"];
  const els = {};
  const byId = {};
  for (const id of ids) { els[id] = fakeElement(); byId[id] = els[id]; }
  if (page === "popup.js") byId["open-options"] = null; // skip optional link
  els.endpoint.value = BRIDGE;
  els.status && (els.status.textContent = ""); // popup status starts set by load; harness asserts the click outcome below
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
      runtime: { openOptionsPage: () => Promise.resolve() },
    },
    document: {
      getElementById: (id) => byId[id],
      querySelectorAll: () => [],
      createElement: () => fakeElement(),
    },
  };
  const ctx = vm.createContext(sandbox);
  vm.runInContext(fs.readFileSync(path.join(EXT, "resolver.js"), "utf8"), ctx, { filename: "resolver.js" });
  vm.runInContext(fs.readFileSync(path.join(EXT, page), "utf8"), ctx, { filename: page });
  return {
    els,
    clickGrant: () => els.grantBtn.click(),
  };
}

async function settle(ms = 80) { await new Promise((r) => setTimeout(r, ms)); }

function msgOf(page, els) {
  return page === "options.js" ? els.msg.textContent : els.status.textContent;
}

async function main() {
  let failures = 0;
  const check = (label, cond, detail) => {
    console.log(`${cond ? "PASS" : "FAIL"} ${label}${cond ? "" : " — " + detail}`);
    if (!cond) failures++;
  };

  for (const page of ["options.js", "popup.js"]) {
    // A: permissions surface throws on contains -> verify-fault line.
    {
      unhandledFired = 0;
      const { els, clickGrant } = loadPage(page, {
        contains: { throw: new Error("permissions service unavailable") },
        request: { value: false }, gesture: true,
      });
      await settle();
      clickGrant();
      await settle();
      const msg = msgOf(page, els);
      check(`${page} A button re-enabled after contains-throw`, els.grantBtn.disabled === false, "still disabled");
      check(`${page} A names verify-fault not denial`, msg.includes("could not be verified"), JSON.stringify(msg));
      check(`${page} A never says 'was not granted'`, !msg.includes("was not granted"), JSON.stringify(msg));
    }
    // B: no transient activation -> never-asked line, never a denial.
    {
      unhandledFired = 0;
      const { els, clickGrant } = loadPage(page, {
        contains: { value: false }, request: { value: false }, gesture: false,
      });
      await settle();
      clickGrant();
      await settle();
      const msg = msgOf(page, els);
      check(`${page} B button re-enabled after no-prompt throw`, els.grantBtn.disabled === false, "still disabled");
      check(`${page} B names never-asked fault`, msg.includes("never asked"), JSON.stringify(msg));
      check(`${page} B never says 'was not granted'`, !msg.includes("was not granted"), JSON.stringify(msg));
    }
    // C: genuine denial, gesture present -> denial line intact.
    {
      unhandledFired = 0;
      const { els, clickGrant } = loadPage(page, {
        contains: { value: false }, request: { value: false }, gesture: true,
      });
      await settle();
      clickGrant();
      await settle();
      const msg = msgOf(page, els);
      check(`${page} C button re-enabled on denial`, els.grantBtn.disabled === false, "still disabled");
      check(`${page} C denied line intact`, msg.includes("was not granted"), JSON.stringify(msg));
    }
  }

  console.log(`\n${failures === 0 ? "ALL PASS" : failures + " FAILURES"}`);
  process.exit(failures ? 1 : 0);
}

main().catch((e) => { console.error("HARNESS ERROR", e); process.exit(1); });
