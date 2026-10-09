// No-prompt denial taxonomy harness — drives the REAL saveBridgeSetting /
// ensureBridgeHostPermission from resolver.js with stubbed chrome +
// navigator.userActivation, asserting the blur/Enter no-gesture case is
// distinguished from a genuine user denial:
//   A. no transient activation, request resolves false -> saveBridgeSetting
//      REJECTS with the "Host access could not be requested" prefix and
//      storage is untouched (the browser never asked — not a denial).
//   B. transient activation present, request resolves false -> resolves
//      false (genuine denial path, unchanged), storage untouched.
//   C. contains() true -> resolves true, bridge persisted.
// Usage: node hidden_files/bridge-save-no-prompt-test.js
// Exit 0 when all assertions hold; exit 1 with the mismatch printed.
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const EXT = path.dirname(__dirname); // ~/workspace/cybernet/extension
const BRIDGE = "https://bridge.example/dns-query";

function loadResolver({ contains, request, gesture }) {
  const box = { storageCalls: [] };
  const sandbox = {
    console,
    URL, encodeURIComponent, decodeURIComponent,
    String, RegExp, Error, Promise, setTimeout, clearTimeout,
    AbortController, Date, JSON, Math, Object, Array, Number,
    navigator: { userActivation: { isActive: gesture } },
    chrome: {
      permissions: {
        contains: () => Promise.resolve(contains),
        request: () => Promise.resolve(request),
      },
      storage: {
        local: {
          get: () => Promise.resolve({}),
          set: (obj) => { box.storageCalls.push({ op: "set", obj }); return Promise.resolve(); },
          remove: (k) => { box.storageCalls.push({ op: "remove", k }); return Promise.resolve(); },
        },
      },
    },
  };
  const ctx = vm.createContext(sandbox);
  vm.runInContext(
    fs.readFileSync(path.join(EXT, "resolver.js"), "utf8") + "\n;globalThis.__save = saveBridgeSetting;",
    ctx, { filename: "resolver.js" });
  const save = vm.runInContext("globalThis.__save", ctx);
  return { save, box };
}

async function main() {
  let failures = 0;
  const check = (label, cond, detail) => {
    console.log(`${cond ? "PASS" : "FAIL"} ${label}${cond ? "" : " — " + detail}`);
    if (!cond) failures++;
  };

  // A: no gesture, prompt could never be shown -> must THROW the no-prompt prefix.
  {
    const { save, box } = loadResolver({ contains: false, request: false, gesture: false });
    let thrown = null;
    try { await save(BRIDGE); } catch (e) { thrown = e; }
    check("A: no-gesture false rejects", !!thrown, "resolved instead of throwing");
    check("A: rejection carries the no-prompt prefix",
      !!thrown && /^Host access could not be requested/.test(thrown.message),
      thrown ? thrown.message : "no error");
    check("A: storage untouched", box.storageCalls.length === 0,
      JSON.stringify(box.storageCalls));
  }

  // B: gesture present, user denies at the prompt -> resolves false (unchanged).
  {
    const { save, box } = loadResolver({ contains: false, request: false, gesture: true });
    let thrown = null, val = "unset";
    try { val = await save(BRIDGE); } catch (e) { thrown = e; }
    check("B: gesture denial resolves false", !thrown && val === false,
      thrown ? "threw: " + thrown.message : "resolved " + val);
    check("B: storage untouched", box.storageCalls.length === 0,
      JSON.stringify(box.storageCalls));
  }

  // C: already granted -> resolves true, bridge persisted.
  {
    const { save, box } = loadResolver({ contains: true, request: false, gesture: false });
    let thrown = null, val = "unset";
    try { val = await save(BRIDGE); } catch (e) { thrown = e; }
    check("C: granted saves true", !thrown && val === true,
      thrown ? "threw: " + thrown.message : "resolved " + val);
    check("C: bridge persisted",
      box.storageCalls.length === 1 && box.storageCalls[0].op === "set" &&
      box.storageCalls[0].obj.dohUrl === BRIDGE,
      JSON.stringify(box.storageCalls));
  }

  process.exit(failures ? 1 : 0);
}

main().catch((e) => { console.error("HARNESS ERROR", e); process.exit(1); });
