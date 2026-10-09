// Bridge-credential scrub harness — privacy hardening (2026-10-09):
// a stored bridge may legally carry basic-auth userinfo
// (https://user:pass@host/dns-query — fetch sends it, the permission
// origin strips it via new URL(...).origin). Before this fix, the
// user-visible bridge echoes — popup/options status lines and the
// address-bar failure page — rendered it in cleartext. This harness:
//   A. Unit-drives the REAL scrubBridgeCreds in resolver.js:
//      userinfo -> ***@, everything else byte-identical.
//   B. Drives the REAL background.js address-bar failure path with a
//      stored credentialed bridge and a dead resolver: the failure page
//      must NOT contain the password but MUST still name the host.
// Usage: node hidden_files/bridge-creds-scrub-test.js
// Exit 0 when all assertions hold; exit 1 with the mismatch printed.
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const EXT = path.dirname(__dirname);

let failures = 0;
const check = (label, cond, detail) => {
  console.log(`${cond ? "PASS" : "FAIL"} ${label}${cond ? "" : " — " + detail}`);
  if (!cond) failures++;
};

// --- A. the real scrubBridgeCreds, loaded straight from resolver.js ---
const utilCtx = vm.createContext({
  console, URL, encodeURIComponent, decodeURIComponent,
  String, RegExp, Error, Promise, setTimeout, clearTimeout,
  AbortController, Date, JSON, Math, Object, Array, Number,
});
// resolver.js has no importScripts/chrome at top level needed here: it is a
// plain script of function declarations referencing chrome only inside
// functions. Load it, then pull scrubBridgeCreds off the context.
vm.runInContext(fs.readFileSync(path.join(EXT, "resolver.js"), "utf8"), utilCtx, { filename: "resolver.js" });
const scrub = vm.runInContext("scrubBridgeCreds", utilCtx);

const cases = [
  // [input, expected]
  ["https://user:s3cret@private.example/dns-query", "https://***@private.example/dns-query"],
  ["https://onlyuser@private.example/dns-query", "https://***@private.example/dns-query"],
  ["http://u:p@[2001:db8::1]:8080/dns-query", "http://***@[2001:db8::1]:8080/dns-query"],
  ["https://private.example/dns-query", "https://private.example/dns-query"], // no userinfo: untouched
  ["Configured DoH bridge is not a valid URL: https://user:s3cret@private.example/dns-query",
   "Configured DoH bridge is not a valid URL: https://***@private.example/dns-query"], // inside a message
  ["not a url at all", "not a url at all"], // unparseable: rides through
  ["https://host/path/with/@/in/path", "https://host/path/with/@/in/path"], // @ in path, not authority
  ["", ""],
];
for (const [input, expected] of cases) {
  const got = scrub(input);
  check(`scrub ${JSON.stringify(input.slice(0, 40))}`, got === expected,
    `got ${JSON.stringify(got)}, want ${JSON.stringify(expected)}`);
}

// --- B. the real background.js failure path, stubbed chrome ---
const CRED = "https://vill:s3cret-pw@private.example/dns-query";
async function fireListener(storageGet) {
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
      storage: { local: { get: storageGet, set: () => Promise.resolve(), remove: () => Promise.resolve() } },
      tabs: { update: (_id, props) => { box.page = props.url; return Promise.resolve(); } },
    },
  };
  const ctx = vm.createContext(sandbox);
  vm.runInContext(fs.readFileSync(path.join(EXT, "background.js"), "utf8"), ctx, { filename: "background.js" });
  if (typeof box.listener !== "function") throw new Error("listener not captured");
  // fetch is NOT stubbed: the resolve dies as a network error, exercising
  // the failure page with the stored credentialed bridge as the "via".
  await box.listener({ frameId: 0, url: "http://genesis.cyberspace/", tabId: 1 });
  return box.page ? decodeURIComponent(box.page.replace(/^data:text\/html,/, "")) : null;
}

async function main() {
  const page = await fireListener(() => Promise.resolve({ dohUrl: CRED }));
  check("B: failure page rendered", !!page, "no page captured");
  check("B: password absent from failure page", !!page && !page.includes("s3cret-pw"),
    "credential leaked into the failure page");
  check("B: username absent from failure page", !!page && !page.includes("vill@") && !page.includes("vill:"),
    "username leaked into the failure page");
  check("B: bridge host still named", !!page && page.includes("private.example"),
    "scrubbing must not hide which bridge failed");
  check("B: scrub marker present", !!page && page.includes("***@"),
    "expected ***@ userinfo mask in the via line");

  // Scenario C: an INVALID bridge with creds — getDohUrl's throw names it.
  const pageC = await fireListener(() => Promise.resolve({ dohUrl: "ftp://user:s3cret-pw@private.example/dns-query" }));
  check("C: failure page rendered", !!pageC, "no page captured");
  check("C: password absent (invalid-bridge throw path)", !!pageC && !pageC.includes("s3cret-pw"),
    "credential leaked via the Configured-DoH-bridge throw");

  if (failures) process.exit(1);
  console.log("ALL PASS");
}

main().catch((e) => { console.error("HARNESS ERROR:", e); process.exit(1); });
