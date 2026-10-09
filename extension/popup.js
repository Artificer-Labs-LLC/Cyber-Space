// Popup: health-check the DoH bridge and open a resolved name.
// Uses shared resolver.js globals: SUFFIX, resolveCyberspace, applyI18n.

// Static-text i18n first (fail-closed: English fallback already in the
// HTML), then the DOM lookups below — applyI18n no-ops without chrome.i18n.
applyI18n();

const status = document.getElementById("status");
const nameInput = document.getElementById("name");

// Focus the input on open and select any prefilled last name — typing starts
// replacing immediately instead of needing a click first.
nameInput.focus();
nameInput.select();

// Health check on open — result cached 60s in storage so every popup open
// doesn't cost a DoH round-trip against the genesis bridge.
const HEALTH_TTL = 60_000;
// The popup lives in the chrome-extension:// origin: never inject bridge-
// or user-derived text into innerHTML raw. The bridge is hostile territory
// (proxy errors, DoH failures) and the name box is free text. esc() is the
// shared helper from resolver.js.
function showStatus(ok, msg) {
  status.innerHTML = ok
    ? `<span class="ok">&#x25cf;</span> ${esc(msg)}`
    : `<span class="bad">&#x25cf;</span> ${esc(msg)}`;
}
// Canonical-shape check for the cached health entry (see the read chain
// below): the store can be hand-edited or foreign-written, so a mistyped
// entry must fail closed to a live re-check, never render junk. Only
// {ts: finite number, ok: boolean, msg: string} counts — with ts not in the
// future, since our own writes always precede the read that replays them.
function validHealthCache(h) {
  return !!h && typeof h === "object" &&
    Number.isFinite(h.ts) && h.ts <= Date.now() &&
    typeof h.ok === "boolean" && typeof h.msg === "string";
}
chrome.storage.local.get(["lastName", "health"]).then(({ lastName, health }) => {
  // The store can be hand-edited or foreign-written (same read-side shape
// contract as the recents junk filter and the health-cache shape guard): a
// non-string lastName would otherwise coerce into the input value
// ("[object Object]", "42") and confuse the next paste. Only a string
// counts — resolve preflight rejects anything else at submit time anyway.
// The length belt mirrors RECENT_NAME_MAX (line 258, the checkLabels
// whole-name cap): our own writes fire only after a successful resolve,
// which passed checkLabels (<=253 chars), so a foreign-written or
// hand-edited string longer than that can never be a real last visit —
// refuse to prefill it rather than dump a 10k-char blob into the input.
if (typeof lastName === "string" && lastName.length <= RECENT_NAME_MAX) nameInput.value = lastName;
  // Shape guard (mirrors the recents junk filter): a {ts: farFuture} entry
  // would otherwise render as "live" for millennia, a mistyped entry would
  // coerce junk into the status line, and a foreign 10k-char msg would
  // bypass the write-time truncateEcho bound. Anything non-canonical falls
  // through to a live re-check — which rewrites the whole key and self-heals
  // the store, so no write-side filter is needed (set() replaces the entry
  // wholesale, unlike recents' read-modify-write). The msg is re-bounded at
  // replay: our own writes are already ≤200 chars (byte-identical), a foreign
  // write's junk gets the same cap the live lines enforce.
  if (validHealthCache(health) && (Date.now() - health.ts < HEALTH_TTL)) {
    showStatus(health.ok, truncateEcho(health.msg));
    return;
  }
  // Name the effective bridge in the status, the way the failure page does
  // (a custom endpoint can be pointed anywhere, so "live" is meaningless
  // without saying which bridge answered). esc() handles hostile bridges.
  getDohUrl().then(bridge =>
    resolveCyberspace("genesis.cyberspace")
      .then(ip => {
        const msg = tHint("popupResolverLive",
          "resolver live — $1$ → genesis.cyberspace → $2$",
          // The bridge is hostile territory (a saved bridge is free text
          // that can be pasted arbitrarily long): bound the echo so a
          // 10k-char URL can't render a giant status line on every open.
          [truncateEcho(scrubBridgeCreds(bridge)), ip]);
        showStatus(true, msg);
        // Fire-and-forget: a failing write must not surface as an
        // unhandled rejection (the status it trails already rendered).
        chrome.storage.local.set({ health: { ts: Date.now(), ok: true, msg } }).catch(() => {});
      })
      .catch(e => {
        // Taxonomy, not raw internals: classifyHealthError re-routes the
        // hint so a health failure tells the user where to look.
        const { hint } = classifyHealthError(e);
        const msg = tHint("popupResolverDown", "resolver down ($1$): $2$",
          // Same truncation as the live line: the bridge is free text and
          // e.message comes from fetch — neither can be allowed to render
          // unbounded into the status line. The bridge half was always
          // bound; the e.message half rode raw until now (the comment
          // stated the contract, the code didn't honor it).
          [truncateEcho(scrubBridgeCreds(bridge)), truncateEcho(e && e.message ? e.message : e)]) + hint;
        showStatus(false, msg);
        chrome.storage.local.set({ health: { ts: Date.now(), ok: false, msg } }).catch(() => {});
      })
  ).catch(e => {
    // getDohUrl() itself reads chrome.storage — a failing read used to end
    // as an unhandled rejection with the status line left blank. Surface it.
    // getDohUrl names the read fault itself ("cannot read bridge setting:
    // …"), so don't double it; anything else keeps the old label.
    const em = String(e && e.message ? e.message : e);
    showStatus(false, /^cannot read bridge setting/.test(em)
      ? truncateEcho(em)
      : tHint("popupBridgeReadFailed", "cannot read bridge setting: $1$", [truncateEcho(em)]));
  });
}).catch(e => {
  // The popup's first storage read — if it fails, the whole health chain
  // above never runs. Say so instead of leaving the status line blank.
  showStatus(false, tHint("popupSettingsReadFailed", "cannot read settings: $1$", [truncateEcho(e && e.message ? e.message : e)]));
});

// Bridge endpoint settings — wires the README's reserved storage permission:
// the endpoint can be pointed at any DoH bridge, not just the genesis IP.
// The health cache is dropped on change so the next open re-checks live.
const endpointInput = document.getElementById("endpoint");
const epmsg = document.getElementById("epmsg");
// Privacy hardening (2026-10-09, config surface): the input box is a
// plain-text <input>, so a stored bridge with embedded userinfo
// (user:pass@host) would sit in the DOM in cleartext. The box shows only
// displayBridge()'s masked form; the raw stored URL rides storedBridgeRaw
// so an unchanged box round-trips its credentials (see resolveBoxBridge in
// resolver.js — standard password-mask behavior).
let storedBridgeRaw = "";
// On-load grant check (2026-10-09): mirrors the options page banner — a
// custom bridge stored before the permission-gating pass has no origin
// grant, so the popup's own on-load health check dies as a silent network
// error (the "resolver down" misdiagnosis). Read-only contains() on load,
// never request: the grant rides the banner's own Grant button below.
// Genesis rides the base host_permissions, so contains() is true and no
// banner shows.
const grantBanner = document.getElementById("grantBanner");
const grantBannerText = document.getElementById("grantBannerText");
const grantBtn = document.getElementById("grantBtn");
async function maybeShowGrantBanner(stored) {
  const v = String(stored == null ? "" : stored).trim();
  if (!v || bridgeError(v)) return; // genesis / clearing / invalid: nothing to grant
  let granted;
  try {
    granted = await chrome.permissions.contains({ origins: [bridgeOriginPattern(v)] });
  } catch {
    return; // fail-closed: no banner when the permissions surface itself errors
  }
  if (granted) return;
  // Hostile-echo belt: the stored value is user-configured territory, so
  // the banner belts it through truncateEcho before rendering.
  grantBannerText.textContent = tHint("popupGrantBanner",
    "Host access for $1$ is not granted — this bridge was saved before permission gating, so the resolver check will fail until you grant it.",
    [truncateEcho(scrubBridgeCreds(v))]);
  grantBanner.hidden = false;
}
// The Grant button's real click supplies the gesture context the on-load
// check lacks, so the origin grant can actually be requested. The grant
// covers the value currently in the box (what a save would persist next),
// and a denied grant changes nothing: the stored bridge stays, the banner
// stays, and the status line says why. The popup has no "msg" element —
// the popup has no "msg" element — showStatus(ok, msg) carries the outcome instead.
grantBtn.addEventListener("click", () => {
  // resolveBoxBridge (2026-10-09): the box may hold the masked display
  // form — the grant needs the real URL's origin, so the raw stored value
  // rides through when the box is unchanged (origin identical either way;
  // userinfo never affects it).
  const v = resolveBoxBridge(endpointInput.value, storedBridgeRaw);
  const err = bridgeError(v);
  if (err) {
    showStatus(false, tHint("bridgeSaveInvalid", "Enter a DoH bridge URL — a bare host or IP gets https:// and /dns-query, e.g. http://1.2.3.4/dns-query — $1$", [err]));
    return;
  }
  const bridge = v || DOH_URL;
  grantBtn.disabled = true;
  ensureBridgeHostPermission(bridge).then((granted) => {
    grantBtn.disabled = false;
    if (granted) {
      grantBanner.hidden = true;
      showStatus(true, tHint("popupGrantOk", "Host access granted — the stored bridge is live again."));
    } else {
      showStatus(false, tHint("popupGrantDenied", "Host access was not granted — the stored bridge stays, but lookups will keep failing until you grant it."));
    }
  }).catch((e) => {
    // Same never-report-a-throw-as-denial contract as the options page's
    // grant button (2026-10-09): a permissions-surface throw (contains /
    // request rejecting) is not a denial, and the no-prompt fault means the
    // browser never asked — so the status line names the fault instead of
    // reusing the "was not granted" denial line.
    const em = (e && e.message) || "";
    grantBtn.disabled = false;
    if (/^Host access could not be requested/.test(em)) {
      showStatus(false, tHint("popupGrantNoPrompt",
        "The browser never asked for host access for $1$ — so nothing was denied and the stored bridge stays. Click Grant again to retry.",
        [truncateEcho(scrubBridgeCreds(bridge))]));
      return;
    }
    showStatus(false, tHint("popupGrantFault",
      "Host access for $1$ could not be verified ($2$) — the stored bridge stays, but lookups will keep failing until it can be checked. Click Grant again to retry.",
      [truncateEcho(scrubBridgeCreds(bridge)), truncateEcho(em || "permission surface error")]));
  });
});
chrome.storage.local.get(["dohUrl"]).then(({ dohUrl }) => {
  // Masked display (2026-10-09): the raw stored bridge never lands in the
  // box — only its displayBridge() form, with userinfo scrubbed.
  storedBridgeRaw = dohUrl || "";
  endpointInput.value = displayBridge(storedBridgeRaw);
  maybeShowGrantBanner(dohUrl);
}).catch(e => {
  // A failing read would otherwise be an unhandled rejection and the input
  // would silently sit empty (not showing the saved bridge). Surface it.
  epmsg.textContent = tHint("popupBridgeReadFailed", "cannot read bridge setting: $1$", [truncateEcho(e && e.message ? e.message : e)]);
});
endpointInput.addEventListener("change", savePopupEndpoint);
endpointInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") endpointInput.blur();
});
// Stale-error clearing: a failed or superseded bridge save leaves its
// message in epmsg; once the user edits the input, that text no longer
// describes the current value, so clear it on the first keystroke. A fresh
// save or failure rewrites epmsg on commit, and the programmatic echo of
// the saved value (`.value = v` in savePopupEndpoint) fires no input event,
// so the "Saved" line survives its own echo.
endpointInput.addEventListener("input", () => {
  if (epmsg.textContent) epmsg.textContent = "";
});
// Explicit save button — parity with the options page's Save: the quick-change
// input committed only on blur/Enter, so a bridge typed and left sitting could
// be silently lost if the popup closed before a blur fired the change handler.
// savePopupEndpoint hoists the change-handler save logic (validate →
// set/remove → drop the health cache → name the outcome) so every commit path
// behaves identically; the click that follows a blur re-runs the same save,
// which is idempotent.
function savePopupEndpoint() {
  // Masked round-trip (2026-10-09): the box may hold the displayBridge()
  // masked form — if it is unchanged, resolveBoxBridge returns the RAW
  // stored URL so saved credentials survive; otherwise the box text is
  // normalized and saved as typed.
  const v = resolveBoxBridge(endpointInput.value, storedBridgeRaw);
  // Same validity the resolver enforces at resolve time (shared bridgeError
  // in resolver.js): a bad bridge fails here, at entry, instead of saving
  // cleanly and dying on every later resolve. Empty means "clear".
  const err = bridgeError(v);
  if (err) {
    epmsg.textContent = tHint("bridgeSaveInvalid", "Enter a DoH bridge URL — a bare host or IP gets https:// and /dns-query, e.g. http://1.2.3.4/dns-query — $1$", [err]);
    return;
  }
  // Privacy hardening (2026-10-09): same origin-grant gate as the
  // options page (shared saveBridgeSetting in resolver.js) — a custom
  // bridge is persisted only after its origin is granted via
  // optional_host_permissions; a denied grant leaves storage untouched and
  // the message tells the user to click Save again from a real gesture.
  saveBridgeSetting(v).then((saved) => {
    if (!saved) {
      epmsg.textContent = tHint("bridgeSaveDenied",
        "Host access for $1$ was not granted — the bridge was not saved. Click Save again to approve it.",
        [truncateEcho(scrubBridgeCreds(v))]);
      return;
    }
    chrome.storage.local.remove("health").catch(() => {});
    // Same stale-banner rule as the options page: a successful save means the
    // origin grant is secured (or the bridge was cleared), so the "not
    // granted" banner no longer describes reality — clear it.
    grantBanner.hidden = true;
    // Same screen-matches-storage echo as the options page: the box shows
    // the MASKED form (2026-10-09) of the normalized bridge — the raw
    // stored URL, with its userinfo, never lands in the DOM. An unchanged
    // box round-trips its credentials via storedBridgeRaw.
    storedBridgeRaw = v || "";
    endpointInput.value = displayBridge(v || "");
    epmsg.textContent = v
      ? tHint("popupBridgeSaveOk", "Saved — resolver re-checks against the new bridge on next open.")
      : tHint("bridgeSaveCleared", "Cleared — back to the genesis bridge.");
  }).catch((e) => {
    // Same no-prompt taxonomy as the options page (shared
    // ensureBridgeHostPermission in resolver.js): a blur/Enter commit may
    // carry no transient activation, so the browser never asked — name the
    // real fault instead of misreporting a denial the user never made.
    const em = (e && e.message) || "";
    if (/^Host access could not be requested/.test(em)) {
      epmsg.textContent = tHint("bridgeSaveNoPrompt",
        "The browser never asked for host access — that commit had no click gesture, so nothing was denied and nothing was saved. Click Save to approve it.");
      return;
    }
    epmsg.textContent = tHint("bridgeSaveFailed", "Could not save the bridge setting.");
  });
}
const saveBridgeBtn = document.getElementById("save-bridge");
saveBridgeBtn.addEventListener("click", savePopupEndpoint);
// Full settings live in options.html (manifest options_ui); the popup keeps
// the quick-change input above and links out for the full surface.
const openOptions = document.getElementById("open-options");
if (openOptions) {
  openOptions.addEventListener("click", (e) => {
    e.preventDefault();
    chrome.runtime.openOptionsPage().catch(() => {});
  });
}

document.getElementById("name").addEventListener("keydown", (e) => {
  if (e.key === "Enter") document.getElementById("go").click();
});

const goBtn = document.getElementById("go");
const recentEl = document.getElementById("recent");

// Recent places: every successful resolve is remembered (dedupe, newest
// first, capped) so the popup shows where you've been and a click takes you
// back — a name alone is forgettable; the places you've visited aren't.
// recents render-side junk filter: storage can be hand-edited or written
// by another client. A non-string entry must never reach the chips (a number
// coerces to a garbage chip, an object to "[object Object]"), and neither
// may a giant junk string — the write-side self-heal in resolver.js
// (recordRecent) heals these on the next successful resolve, but until then
// the render path would otherwise draw them raw into the popup. Uses the
// shared RECENT_NAME_MAX from resolver.js (const at resolver.js:702 — a
// second top-level const here would collide with it and kill the whole
// popup script at parse time, so this file must NOT redeclare it): legit
// names passed checkLabels at resolve time and can never exceed 253 chars,
// so anything longer is corruption, never a place anyone visited.
function loadRecent() {
  chrome.storage.local.get(["recent"]).then(({ recent }) => {
    // Storage can be hand-edited or written by another client: entries that
    // aren't strings must never reach the chips — a number coerces to a
    // garbage chip, an object to "[object Object]", and the chip click would
    // feed junk into resolveAndOpen. Giant strings get the same treatment:
    // a 260px popup can't render them and they can only come from a
    // hand-edited or foreign-written store. Filter at render so a corrupted
    // store reads as empty (the empty state below), never as broken.
    const list = (Array.isArray(recent) ? recent : [])
      .filter(n => typeof n === "string" && n.length <= RECENT_NAME_MAX);
    recentEl.innerHTML = "";
    if (!list.length) {
      // Empty state: a bare popup with no chips and no guidance reads as
      // broken — one dim line names what belongs here and how to get it.
      const empty = document.createElement("small");
      empty.textContent = tHint("recentEmpty", "Places you visit will appear here.");
      recentEl.appendChild(empty);
      return;
    }
    const label = document.createElement("small");
    label.textContent = tHint("recentLabel", "Recent");
    recentEl.appendChild(label);
    // Recent names accumulate — give the user a way to wipe them without
    // clearing all of the extension's storage.
    const clearBtn = document.createElement("button");
    clearBtn.className = "chip clear";
    clearBtn.textContent = tHint("recentClear", "clear");
    clearBtn.title = tHint("recentClearTitle", "Forget recent places");
    clearBtn.addEventListener("click", () => {
      // Fire-and-forget: a failing clear must not surface as an unhandled
      // rejection, and the UI empties either way — the clear button only
      // exists when the slot has entries. Re-render through loadRecent
      // (not just innerHTML = "") so the empty-state line ("Places you
      // visit will appear here.") survives the clear — a blank slot after
      // a successful clear reads as broken, not as empty.
      chrome.storage.local.remove("recent").then(loadRecent, loadRecent);
    });
    recentEl.appendChild(clearBtn);
    for (const name of list) {
      const b = document.createElement("button");
      b.className = "chip";
      b.textContent = name;
      // The popup is 260px wide: long names ellipsize, so the full name
      // rides along as a tooltip (DOM property, never innerHTML).
      b.title = name;
      // A chip click revisits the place: fill the input and run the same
      // single-flight resolve path the Go button uses.
      b.addEventListener("click", () => {
        nameInput.value = name;
        resolveAndOpen(name);
      });
      recentEl.appendChild(b);
    }
  }).catch(() => {
    // A failing storage read must not become an unhandled rejection that
    // kills the popup's other init paths — no recents just means no chips.
  });
}
loadRecent();

// resolveAndOpen (Go path) — resolve taxonomy (classifyResolveError /
// classifyHealthError) now lives as shared globals in resolver.js so the
// options page classifies the same way; call sites below are unchanged
// (default loc "below" keeps the popup's hint direction).

// Single-flight across ALL Go-path entry points — chips call
// resolveAndOpen directly, so the Go button's `disabled` guard does not cover
// a rapid double chip click: without this, two resolves race and two tabs
// open.
let goFlight = false;

// Pre-resolve edge: an already-an-address paste needs no resolution.
// normalizeName has already trimmed/lowercased/port-stripped it, so a
// dotted-quad here is unambiguous. IPv4-only: normalizeName's colon split
// mangles IPv6 literals, so those are detected on the RAW input by
// isIpv6Literal below instead of here.
function isIpv4Literal(name) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(name);
  return !!m && m.slice(1).every((oct) => Number(oct) <= 255);
}

// Pre-resolve edge, part two: IPv6 literals. Takes the RAW input candidate
// (scheme + path/query/hash stripped, colon INTACT — normalizeName's port
// split would mangle "2001:db8::1" into "2001"), so the caller checks this
// BEFORE normalizing. Returns { addr, port } — the canonical lowercased
// host (unbracketed) plus any port the paste carried ("" when none) — or
// null on no match. A bracketed paste may carry a port ("[2001:db8::1]:8080"):
// it is peeled off before the WHATWG validation so the literal still counts
// as an openable address (the caller re-brackets AND keeps the port when
// building the tab URL — dropping it would silently land on port 80). The
// URL parser is the real validator: it rejects zone ids, trailing ports on
// bare addresses, out-of-range ports (":99999" fails to parse — fail closed,
// not fail default-port), and malformed groups that the character pre-check
// alone would pass — and the WHATWG parser is what Chrome itself uses, so
// "valid here" means "openable there". (WHATWG also rejects short forms
// without "::" like "dead:beef": those stay on the resolve path, which is the
// right fail-closed — a browser couldn't open them as hosts anyway.) An
// unbracketed 8-group-looking input ("2001:db8::1:8080") parses as a valid
// 8-group address — the valid-address reading wins over the port reading,
// since guessing "port" would mis-open a real address; bracketed ports are
// the unambiguous form and peel before validation. IPv4 dotted-quads belong
// to isIpv4Literal, not here (they never reach this function with a colon).
function isIpv6Literal(host) {
  let h = String(host || "").trim();
  let port = "";
  // Bracketed pastes ("[2001:db8::1]/x", "[2001:db8::1]:8080/x") unwrap; a
  // dangling bracket stays and fails the character check below (fail closed,
  // not fail bracketed).
  const bracketed = /^\[([^\]]*)\](?::(\d{1,5}))?$/.exec(h);
  if (bracketed) {
    h = bracketed[1];
    port = bracketed[2] || "";
  } else if (h.startsWith("[") || h.endsWith("]")) {
    return null; // dangling bracket — fail closed
  }
  // At least one colon (else this is a name or a dotted-quad, not IPv6)
  // and only hex/dots/colons (the dotted tail covers ::ffff:1.2.3.4).
  if (!h.includes(":") || !/^[0-9a-fA-F:.]+$/.test(h)) return null;
  let parsed;
  try {
    parsed = new URL(`http://[${h}]${port ? ":" + port : ""}`);
  } catch {
    return null;
  }
  // WHATWG serializes IPv6 hosts bracketed — hostname KEEPS the brackets
  // (Chrome and Node agree) — so unwrap one pair and hand back the
  // canonical form; the caller re-brackets when building the tab URL.
  const canon = parsed.hostname;
  if (!canon.startsWith("[") || !canon.endsWith("]")) return null;
  return { addr: canon.slice(1, -1), port };
}

async function resolveAndOpen(rawName) {
  if (goFlight) return;
  goFlight = true;
  // IPv6-literal pre-resolve edge: normalizeName's colon split (port strip)
  // would mangle "2001:db8::1" into "2001", so the literal candidate is
  // pulled from the RAW input first — scheme + path/query/hash stripped,
  // colon intact — and checked before normalizing below.
  // Userinfo-audit guarantee (2026-10-08, harness /tmp/userinfo-test.js):
  // a paste carrying credentials ("http://alice:s3cret@host/x") cannot leak
  // them anywhere — normalizeName's colon split below reduces it to the bare
  // username ("alice" -> "alice.cyberspace" is the only thing ever queried),
  // the tab URL is built from ip/portSuffix/pathSuffix only (never the raw
  // paste, so the password never becomes part of a chrome.tabs.create URL),
  // and status lines echo the normalized name, never the paste. Key-presence
  // of "@" anywhere in the input is harmless: no path through this function
  // copies it onward.
  const rawHost = String(rawName || "").trim()
    .replace(/^[a-z][a-z0-9+.-]*:\/\//i, "").split(/[/?#]/)[0];
  const v6 = isIpv6Literal(rawHost);
  // The tab URL needs brackets around the literal AND the port (dropping a
  // pasted ":8080" would silently land on port 80); the status lines name
  // the same host the tab actually opened.
  const v6Host = v6 ? (v6.port ? `[${v6.addr}]:${v6.port}` : `[${v6.addr}]`) : "";
  // Port preservation for name + IPv4-literal pastes: normalizeName's colon
  // split strips a pasted ":port" (it must — names are LDH-only), but the
  // tab should land where the paste pointed — a dropped ":8080" silently
  // lands on port 80. The IPv6 path already carries its own port (v6Host
  // above), so this only runs when v6 is null; a single colon in rawHost
  // can then only be a port (an unbracketed multi-colon paste is a v6
  // candidate — never guess "port" there, per the 14:52 valid-address-wins
  // rule). The WHATWG parser is the validator: out-of-range or
  // non-numeric ports fail closed to "" (the port dies, never the resolve).
  let pastePort = "";
  if (!v6) {
    const parts = rawHost.split(":");
    if (parts.length === 2 && /^\d{1,5}$/.test(parts[1])) {
      try {
        pastePort = new URL(`http://${parts[0]}:${parts[1]}/`).port;
      } catch { /* fail closed — pastePort stays "" */ }
    }
  }
  const portSuffix = pastePort ? `:${pastePort}` : "";
  // Scheme-less percent-encoded paste guarantee (2026-10-08, harness
  // /tmp/schemeless-pct-test.js, 15/15): an encoded schemeless paste
  // ("%67%65%6e%65%73%69%73.cyberspace", with or without :port and
  // path/query/hash) takes a different path than the scheme-ful form the
  // 15:13 tick covered — rawHost keeps the escapes, pastePort validates
  // them through the WHATWG parser (which decodes the host but honors the
  // literal ":8080", so the port survives), and the pathSuffix block
  // re-parses with a prepended scheme. All three converge on normalizeName's
  // decode: the wire asks for the decoded name, the tab lands on the decoded
  // name's IP, status/recents name the decoded name. Malformed escapes fail
  // closed before any wire query or tab; an encoded IPv6 literal (which a
  // browser refuses outright — WHATWG TypeError) can never take the v6
  // fast-path, so production fails it as name-not-registered, never a tab.
  // Normalize pasted input (scheme, path, trailing dot…) before resolving.
  // (For an IPv6 literal the normalized name is mangled to "" by the colon
  // split above the fold — the v6 check is what keeps it alive, so the
  // empty-submit guard must not fire on it.)
  let name = normalizeName(rawName);
  if (!name && !v6) {
    // Empty submit must say something instead of silently doing nothing.
    showStatus(false, tHint("popupEmptyName", "Enter a .cyberspace name first"));
    goFlight = false;
    return;
  }
  // An already-an-address paste needs no resolution and must not get the
  // suffix appended (that would only die as "Name not registered").
  const literal = isIpv4Literal(name);
  if (!literal && !v6 && !name.endsWith(SUFFIX)) name += SUFFIX;
  // A pasted full URL carries path/query/hash that normalizeName strips —
  // keep it for the opened tab. The background worker preserves these from
  // address-bar navigation, so the popup's Go button must match: opening
  // "https://genesis.cyberspace/guide#top" pasted into the box should land
  // on the guide, not the root. Unparseable input leaves the suffix empty
  // and the resolve below reports the name as before.
  let pathSuffix = "";
  try {
    // A bare IPv6 paste needs brackets to survive URL parsing, so rebuild
    // from the canonical literal plus the raw tail (everything after the
    // host candidate in the scheme-stripped input).
    const noScheme = String(rawName || "").trim().replace(/^[a-z][a-z0-9+.-]*:\/\//i, "");
    const parseable = v6
      ? "http://" + v6Host + noScheme.slice(rawHost.length)
      : (/^[a-z][a-z0-9+.-]*:\/\//i.test(rawName) ? rawName : "http://" + rawName);
    const asUrl = new URL(parseable);
    pathSuffix = asUrl.pathname + asUrl.search + asUrl.hash;
  } catch (e) { /* not a URL — pathSuffix stays empty */ }
  // The goFlight guard at the top of this function already owns the
  // single-flight — this disables the button purely as visual feedback,
  // the busy label names what the button is doing while it is dead.
  // Display name for status lines: for v6 the normalized `name` is mangled
  // by the colon split ("" or "2001"), so the status shows the bracketed
  // literal it actually opened instead.
  const displayName = v6 ? v6Host : name;
  const goLabel = goBtn.textContent;
  goBtn.textContent = tHint("goResolving", "Resolving\u2026");
  goBtn.disabled = true;
  let ip;
  // A literal address skips the DoH round-trip: open it directly, keeping
  // any pasted path/query/hash. The IPv6 host needs brackets in the URL —
  // bare colons are not valid host characters.
  try {
    if (literal) {
      ip = name;
    } else if (v6) {
      ip = v6Host;
    } else {
      // (showStatus escapes the name — a hostile bridge can't inject here.)
      showStatus(true, tHint("popupResolving", "resolving $1$ …", [name]));
      ip = await resolveCyberspace(name);
    }
  } catch (e) {
    // Taxonomy, not raw internals: the resolver knows the failure class,
    // the popup knows how to say it. (Unreachable on the literal path —
    // there is nothing above that can throw there.)
    const { hint } = classifyResolveError(e);
    // Defense-in-depth belt (2026-10-08): the resolver's throws truncate
    // their echoed tails at the throw site, so msg SHOULD already be
    // bounded — but the contract is now enforced here too, because a single
    // future throw that forgets its belt would otherwise render a giant
    // status line. classifyResolveError ran on the raw error above, so
    // this belt can never re-route the taxonomy; only rejected inputs
    // (already-truncated tails of rejected content) change shape.
    const msg = truncateEcho(e && e.message ? e.message : e);
    // The hint is already localized by the classifier; the line shape is a
    // locale message so the "{name}: " framing localizes too. Truncate the
    // echoed name (shared truncateEcho in resolver.js): a pasted 10k-char
    // input would otherwise render a ~20k-char status line on top of the
    // already-truncated error message — only rejected inputs change shape.
    const shownName = truncateEcho(name);
    showStatus(false, tHint("popupResolveFailed", "$1$: $2$", [shownName, msg + hint]));
    return;
  } finally {
    goBtn.textContent = goLabel;
    goBtn.disabled = false;
    goFlight = false;
  }
  // Fire-and-forget like the background worker's lastName write: the tab
  // opens regardless, and a failing write stays silent instead of leaking
  // an unhandled rejection (an un-awaited set rejects outside this try).
  // Recents and the last-name prefill are name-visit features: a literal
  // address paste is not a name visit, so it joins neither.
  if (!literal && !v6) {
    chrome.storage.local.set({ lastName: name }).catch(() => {});
    recordRecent(name);
  }
  try {
    // The resolve already succeeded above — a tab-open failure here must
    // not be re-run through classifyResolveError (it isn't a resolver
    // problem): say where the name landed and name the failure plainly.
    await chrome.tabs.create({ url: `http://${ip}${portSuffix}${pathSuffix}` });
  } catch (e) {
    // displayName: for v6 the normalized `name` is mangled by the colon
    // split, so the failure line must name the bracketed literal it tried
    // to open (the success line below already does).
    // Belt the tab-open failure's $3$ echo: chrome.tabs.create errors are
    // browser-generated, so this is pure defense-in-depth against any
    // future huge error message rendering a giant status line. $1$/$2$
    // stay raw: the display name is already truncated and the IP is
    // wire-built from DNS answer bytes, bounded by construction.
    showStatus(false, tHint("popupTabOpenFailed",
      "resolved $1$ → $2$ but the tab failed to open: $3$",
      [displayName, ip + portSuffix, truncateEcho(e && e.message ? e.message : e)]));
    return;
  }
  // Leave evidence of where the name landed — until now the status stayed
  // stuck on "resolving …" even after the tab opened successfully.
  // (For v6 the normalized `name` is mangled by the colon split, so the
  // status shows the bracketed literal it actually opened instead.)
  showStatus(true, literal
    ? tHint("popupOpenedLiteral", "opened $1$$2$ (already an address — no resolve needed)",
      [ip + portSuffix, pathSuffix])
    : v6
    ? tHint("popupOpenedLiteral", "opened $1$$2$ (already an address — no resolve needed)",
      [ip + portSuffix, pathSuffix])
    : tHint("popupOpenedResolved", "opened $1$ → $2$$3$", [name, ip + portSuffix, pathSuffix]));
  loadRecent();
}
goBtn.addEventListener("click", () => resolveAndOpen(nameInput.value));
