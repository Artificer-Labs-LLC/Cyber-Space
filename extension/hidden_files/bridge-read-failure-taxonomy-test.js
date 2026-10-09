// Storage-read failure taxonomy harness — drives the REAL background.js
// address-bar failure path with a stubbed chrome, asserting the failure
// page names the actual fault:
//   A. chrome.storage.local.get rejects ("Extension context invalidated.")
//      -> lead line says "cannot read bridge setting", NOT "invalid bridge"
//   B. stored bridge fails validation (getDohUrl's "Configured DoH bridge …"
//      throw) -> lead line keeps "invalid bridge", NOT "cannot read …"
// Usage: node hidden_files/bridge-read-failure-taxonomy-test.js
// Exit 0 when both assertions hold; exit 1 with the mismatch printed.
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const EXT = path.dirname(__dirname); // ~/workspace/cybernet/extension

function fireListener(storageGet) {
  const box = {};
  const sandbox = {
    console,
    URL, encodeURIComponent, decodeURIComponent,
    String, RegExp, Error, Promise, setTimeout, clearTimeout,
    AbortController, Date, JSON, Math, Object, Array, Number,
    importScripts: (f) =>
      vm.runInContext(fs.readFileSync(path.join(EXT, f), "utf8"), ctx, { filename: f }),
    chrome: {
      webNavigation: { onBeforeNavigate: { addListener: (fn) => { box.listener = fn; } } },
      storage: {
        local: {
          get: storageGet,
          set: () => Promise.resolve(),
          remove: () => Promise.resolve(),
        },
      },
      tabs: { update: (_id, props) => { box.page = props.url; return Promise.resolve(); } },
    },
  };
  const ctx = vm.createContext(sandbox);
  vm.runInContext(fs.readFileSync(path.join(EXT, "background.js"), "utf8"), ctx, { filename: "background.js" });
  if (typeof box.listener !== "function") throw new Error("listener not captured");
  return Promise.resolve(box.listener({ frameId: 0, url: "http://genesis.cyberspace/", tabId: 1 }))
    .then(() => box.page ? decodeURIComponent(box.page.replace(/^data:text\/html,/, "")) : null);
}

async function main() {
  let failures = 0;
  const check = (label, cond, detail) => {
    console.log(`${cond ? "PASS" : "FAIL"} ${label}${cond ? "" : " — " + detail}`);
    if (!cond) failures++;
  };

  // Scenario A: the store can't be read at all.
  const pageA = await fireListener(() => Promise.reject(new Error("Extension context invalidated.")));
  check("A: failure page rendered", !!pageA, "no page captured");
  check("A: dead store names 'cannot read bridge setting'",
    !!pageA && pageA.includes("cannot read bridge setting"),
    (pageA || "").slice(0, 400));
  check("A: dead store does NOT say 'invalid bridge'",
    !!pageA && !pageA.includes("invalid bridge"),
    "mislabel present");

  // Scenario B: store reads fine, value fails validation.
  const pageB = await fireListener(() => Promise.resolve({ dohUrl: "not a url" }));
  check("B: failure page rendered", !!pageB, "no page captured");
  check("B: invalid value keeps 'invalid bridge'",
    !!pageB && pageB.includes("invalid bridge"),
    (pageB || "").slice(0, 400));
  check("B: invalid value does NOT say 'cannot read bridge setting'",
    !!pageB && !pageB.includes("cannot read bridge setting"),
    "wrong label present");

  console.log(failures ? `\n${failures} assertion(s) failed` : "\nall assertions pass");
  process.exit(failures ? 1 : 0);
}

main().catch((e) => { console.error("harness error:", e); process.exit(1); });
