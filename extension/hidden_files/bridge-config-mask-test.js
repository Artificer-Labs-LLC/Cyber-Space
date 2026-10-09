// Bridge-config masking harness — privacy hardening (2026-10-09):
// the options page and popup bridge input boxes are plain-text <input>s,
// so a stored bridge with embedded userinfo (https://user:pass@host)
// used to sit in the DOM in cleartext. The boxes now show displayBridge()'s
// masked form, and resolveBoxBridge() round-trips the RAW stored value when
// the box is unchanged. This harness drives the REAL displayBridge and
// resolveBoxBridge from resolver.js:
//   1. displayBridge masks userinfo, leaves credless bridges untouched.
//   2. An unchanged masked box resolves to the RAW stored URL (creds survive).
//   3. Any real edit to the box is normalized and saved as typed.
//   4. A cleared box still clears; empty stored value uses the box as-is.
//   5. Whitespace-padded masked box still round-trips (trim parity).
// Usage: node hidden_files/bridge-config-mask-test.js
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

const utilCtx = vm.createContext({
  console, URL, encodeURIComponent, decodeURIComponent,
  String, RegExp, Error, Promise, setTimeout, clearTimeout,
  AbortController, Date, JSON, Math, Object, Array, Number,
});
// resolver.js is a plain script of function declarations referencing chrome
// only inside functions. Load it, then pull the helpers off the context.
vm.runInContext(fs.readFileSync(path.join(EXT, "resolver.js"), "utf8"), utilCtx, { filename: "resolver.js" });
const displayBridge = vm.runInContext("displayBridge", utilCtx);
const resolveBoxBridge = vm.runInContext("resolveBoxBridge", utilCtx);

const CRED = "https://user:s3cret-pw@private.example/dns-query";
const MASKED = "https://***@private.example/dns-query";
const PLAIN = "https://private.example/dns-query";

// 1. displayBridge
check("display masks userinfo", displayBridge(CRED) === MASKED,
  `got ${JSON.stringify(displayBridge(CRED))}`);
check("display leaves credless bridge untouched", displayBridge(PLAIN) === PLAIN,
  `got ${JSON.stringify(displayBridge(PLAIN))}`);
check("display of empty stored value is empty", displayBridge("") === "",
  `got ${JSON.stringify(displayBridge(""))}`);
check("display idempotent", displayBridge(displayBridge(CRED)) === MASKED,
  `got ${JSON.stringify(displayBridge(displayBridge(CRED)))}`);
check("display never emits the password", !displayBridge(CRED).includes("s3cret-pw"),
  "password leaked into display form");

// 2. unchanged masked box round-trips the raw stored URL
check("masked box unchanged -> raw stored URL",
  resolveBoxBridge(MASKED, CRED) === CRED,
  `got ${JSON.stringify(resolveBoxBridge(MASKED, CRED))}`);
check("whitespace-padded masked box still round-trips",
  resolveBoxBridge("  " + MASKED + "  ", CRED) === CRED,
  `got ${JSON.stringify(resolveBoxBridge("  " + MASKED + "  ", CRED))}`);
check("credless stored bridge: unchanged box -> stored URL",
  resolveBoxBridge(PLAIN, PLAIN) === PLAIN,
  `got ${JSON.stringify(resolveBoxBridge(PLAIN, PLAIN))}`);

// 3. any real edit is normalized and saved as typed
const edited = resolveBoxBridge("https://***@other.example/dns-query", CRED);
check("edited host replaces the bridge honestly (creds not preserved)",
  edited === "https://***@other.example/dns-query",
  `got ${JSON.stringify(edited)}`);
check("fresh credless URL typed -> normalized",
  resolveBoxBridge("https://new.example/dns-query", CRED) === "https://new.example/dns-query",
  `got ${JSON.stringify(resolveBoxBridge("https://new.example/dns-query", CRED))}`);
check("bare host still normalizes with no stored bridge",
  resolveBoxBridge("1.2.3.4", "") === "https://1.2.3.4/dns-query",
  `got ${JSON.stringify(resolveBoxBridge("1.2.3.4", ""))}`);
check("new credentialed URL typed -> saved as typed (userinfo intact)",
  resolveBoxBridge("https://newuser:newpw@fresh.example/dns-query", CRED) ===
    "https://newuser:newpw@fresh.example/dns-query",
  `got ${JSON.stringify(resolveBoxBridge("https://newuser:newpw@fresh.example/dns-query", CRED))}`);

// 4. clearing still clears
check("cleared box clears", resolveBoxBridge("", CRED) === "",
  `got ${JSON.stringify(resolveBoxBridge("", CRED))}`);
check("whitespace-only box clears", resolveBoxBridge("   ", CRED) === "",
  `got ${JSON.stringify(resolveBoxBridge("   ", CRED))}`);

// 5. invalid box text is NOT silently mapped to the stored value
const bad = resolveBoxBridge("not a url", CRED);
check("invalid box text is not masked-mapped",
  bad !== CRED && bad === "not a url",
  `got ${JSON.stringify(bad)}`);

// 6. masked display form itself is still a valid, grant-safe bridge shape:
//    origin of the masked form equals origin of the raw form (userinfo
//    never affects new URL(...).origin).
check("masked origin matches raw origin",
  new URL(MASKED).origin === new URL(CRED).origin,
  `${new URL(MASKED).origin} vs ${new URL(CRED).origin}`);

console.log(failures === 0 ? "ALL PASS" : `${failures} FAILURES`);
process.exit(failures === 0 ? 0 : 1);
