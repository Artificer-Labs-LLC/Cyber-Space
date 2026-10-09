// Options page: the DoH bridge endpoint lives here too (the popup's
// "Bridge endpoint" details block stays as the quick-change path).
// Both read/write the same chrome.storage.local "dohUrl" key, so they
// never disagree — last writer wins, and a change on either side drops
// the "health" cache so the next popup open re-checks live.

// Static-text i18n first (fail-closed: English fallback already in the
// HTML), then the DOM lookups below — applyI18n no-ops without chrome.i18n.
applyI18n();

const endpointInput = document.getElementById("endpoint");
const msg = document.getElementById("msg");
const grantBanner = document.getElementById("grantBanner");
const grantBannerText = document.getElementById("grantBannerText");
const grantBtn = document.getElementById("grantBtn");

// On-load grant check (2026-10-09): a custom bridge stored before the
// permission-gating pass may sit in storage without its origin grant —
// every later resolve then dies as a silent network error. This is a
// contains() check only, never a request: permissions.request has no
// gesture context on page load (and background has none at all), so the
// grant rides the banner's own Grant button below. Genesis rides the base
// host_permissions, so contains() is true and no banner shows.
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
  grantBannerText.textContent = tHint("optionsGrantBanner",
    "Host access for $1$ is not granted — this bridge was saved before permission gating, so checks and lookups will fail until you grant it.",
    [truncateEcho(v)]);
  grantBanner.hidden = false;
}

// The Grant button's real click supplies the gesture context the on-load
// check lacks, so the origin grant can actually be requested. The grant
// covers the value currently in the box (what the user will check/save),
// and a denied grant changes nothing: the stored bridge stays, the banner
// stays, and the line says why.
grantBtn.addEventListener("click", () => {
  const raw = endpointInput.value.trim();
  const v = normalizeBridgeInput(raw) ?? raw;
  const err = bridgeError(v);
  if (err) {
    msg.className = "bad";
    msg.textContent = tHint("bridgeSaveInvalid", "Enter a DoH bridge URL — a bare host or IP gets https:// and /dns-query, e.g. http://1.2.3.4/dns-query — $1$", [err]);
    return;
  }
  const bridge = v || DOH_URL;
  grantBtn.disabled = true;
  ensureBridgeHostPermission(bridge).then((granted) => {
    grantBtn.disabled = false;
    if (granted) {
      grantBanner.hidden = true;
      msg.className = "ok";
      msg.textContent = tHint("optionsGrantOk", "Host access granted — the stored bridge is live again.");
    } else {
      msg.className = "bad";
      msg.textContent = tHint("optionsGrantDenied", "Host access was not granted — the stored bridge stays, but checks and lookups will keep failing until you grant it.");
    }
  }).catch((e) => {
    // Same never-report-a-throw-as-denial contract as the check pre-flight
    // above (2026-10-09): ensureBridgeHostPermission throws on a
    // permissions-surface fault (contains/request rejecting) and on the
    // no-prompt fault (no transient activation — the resolver comment says
    // a real click can't hit it, but a click without activation is still a
    // click, and the line must stay truthful either way). Neither is a
    // denial, so the catch never says "was not granted" — it names the
    // fault the way the check pre-flight does.
    const em = (e && e.message) || "";
    grantBtn.disabled = false;
    msg.className = "bad";
    if (/^Host access could not be requested/.test(em)) {
      msg.textContent = tHint("optionsGrantNoPrompt",
        "The browser never asked for host access for $1$ — so nothing was denied and the stored bridge stays. Click Grant again to retry.",
        [truncateEcho(bridge)]);
      return;
    }
    msg.textContent = tHint("optionsGrantGrantFault",
      "Host access for $1$ could not be verified ($2$) — the stored bridge stays, but checks and lookups will keep failing until it can be checked. Click Grant again to retry.",
      [truncateEcho(bridge), truncateEcho(em || "permission surface error")]);
  });
});

chrome.storage.local.get(["dohUrl"]).then(({ dohUrl }) => {
  if (dohUrl) endpointInput.value = dohUrl;
  maybeShowGrantBanner(dohUrl);
}).catch(e => {
  msg.className = "bad";
  msg.textContent = tHint("optionsBridgeReadFailed", "cannot read bridge setting: $1$", [truncateEcho(e && e.message ? e.message : e)]);
});

endpointInput.addEventListener("change", saveEndpoint);
endpointInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") endpointInput.blur();
});

// Stale-message clearing: a failed or superseded bridge save leaves its
// message in msg; once the user edits the input, that text no longer
// describes the current value, so clear it on the first keystroke. A fresh
// save or failure rewrites msg on commit, and the programmatic echo of the
// saved value (`.value = v` in saveEndpoint) fires no input event, so the
// "Saved" line survives its own echo. Same shape as the popup's epmsg
// clearing — the two pages share one UX contract.
endpointInput.addEventListener("input", () => {
  if (msg.textContent) msg.textContent = "";
});

// Explicit save button: the input used to commit only on blur/Enter, so a
// user who typed a new bridge and hit "Check bridge now" could reasonably
// assume the checked value was saved — it wasn't. saveEndpoint hoists the
// change-handler's save logic (validate → set/remove → drop the health
// cache → name the outcome) so both commit paths behave identically.
function saveEndpoint() {
  const raw = endpointInput.value.trim();
  // Bare-host convenience (shared normalizeBridgeInput): a pasted host or
  // IP normalizes to a full bridge URL instead of failing as "Not a valid
  // URL"; null means unsalvageable, and bridgeError then names the raw
  // input so the user sees what they actually typed.
  const v = normalizeBridgeInput(raw) ?? raw;
  // Same validity the resolver enforces at resolve time (shared bridgeError
  // in resolver.js): a bad bridge fails here, at entry, instead of saving
  // cleanly and dying on every later resolve. Empty means "clear".
  const err = bridgeError(v);
  if (err) {
    msg.className = "bad";
    msg.textContent = tHint("bridgeSaveInvalid", "Enter a DoH bridge URL — a bare host or IP gets https:// and /dns-query, e.g. http://1.2.3.4/dns-query — $1$", [err]);
    return;
  }
  // Privacy hardening (2026-10-09): a custom bridge fetches from a
  // user-chosen origin, so the save gates the optional host grant BEFORE
  // persisting (shared saveBridgeSetting in resolver.js) — a bridge saved
  // without its grant would die on every later resolve as a silent network
  // error. A denied grant leaves the stored bridge untouched; clicking
  // Save again re-runs the request from a real gesture (permissions.request
  // needs transient activation, which a blur-commit may lack).
  saveBridgeSetting(v).then((saved) => {
    if (!saved) {
      msg.className = "bad";
      msg.textContent = tHint("bridgeSaveDenied",
        "Host access for $1$ was not granted — the bridge was not saved. Click Save again to approve it.",
        [truncateEcho(v)]);
      return;
    }
    chrome.storage.local.remove("health").catch(() => {});
    // A successful save means the origin grant is now secured (saveBridgeSetting
    // persists only after it) or the bridge was cleared back to genesis — either
    // way the banner's "not granted" claim is stale, so clear it.
    grantBanner.hidden = true;
    msg.className = "ok";
    // Echo the normalized value back into the box: a typed bare host (e.g.
    // "1.2.3.4") stores as its full bridge URL, and what the screen shows
    // must be what storage holds — otherwise the next open re-displays the
    // stored form and the user reasonably suspects their save was altered.
    endpointInput.value = v;
    msg.textContent = v
      ? tHint("optionsBridgeSaveOk", "Saved — resolver re-checks against the new bridge on next popup open.")
      : tHint("bridgeSaveCleared", "Cleared — back to the genesis bridge.");
  }).catch((e) => {
    // No-prompt taxonomy (2026-10-09): a blur/Enter commit may carry no
    // transient activation, in which case permissions.request never showed
    // a prompt — naming that "was not granted" would misreport a denial
    // the user never made. The browser never asked, nothing was denied,
    // nothing was saved; the Save click is the first real ask, not a retry.
    const em = (e && e.message) || "";
    if (/^Host access could not be requested/.test(em)) {
      msg.className = "bad";
      msg.textContent = tHint("bridgeSaveNoPrompt",
        "The browser never asked for host access — that commit had no click gesture, so nothing was denied and nothing was saved. Click Save to approve it.");
      return;
    }
    msg.className = "bad";
    msg.textContent = tHint("bridgeSaveFailed", "Could not save the bridge setting.");
  });
}

const saveBtn = document.getElementById("save");
saveBtn.addEventListener("click", saveEndpoint);

// Bridge-health check — a live resolve of genesis.cyberspace against the
// endpoint currently in the box (unsaved edits included), no health-cache
// lookup: this page is the place you just changed the bridge, so the check
// must test what's on screen, not what storage had on page load.
// textContent-only: the bridge is hostile/user-configured territory and
// never lands in innerHTML.
const checkBtn = document.getElementById("check");
const health = document.getElementById("health");
checkBtn.addEventListener("click", () => {
  const raw = endpointInput.value.trim();
  // Same normalization as the save path: the check must test the
  // normalized value it would save, not the raw box text.
  const v = normalizeBridgeInput(raw) ?? raw;
  // Same validation shape as the save path: an invalid box fails before
  // anything touches the network, and nothing is saved here — checking
  // is read-only; the Save button (or blur/Enter) is the only writer.
  const err = bridgeError(v);
  if (err) {
    health.className = "bad";
    health.textContent = tHint("optionsCheckBridgeInvalid",
      "Enter a valid DoH bridge URL before checking, e.g. http://1.2.3.4/dns-query — $1$",
      [err]);
    return;
  }
  const bridge = v || DOH_URL;
  // Same busy-label pattern as the popup Go button (popup.js): a disabled
  // button with no label change reads as stuck. Capture the (localized)
  // label, swap in "Resolving…", restore it on settle.
  const checkLabel = checkBtn.textContent;
  checkBtn.textContent = tHint("goResolving", "Resolving\u2026");
  checkBtn.disabled = true;
  // Permission pre-flight (2026-10-09): a custom bridge outside the pinned
  // genesis origin may not have its optional host grant yet — without it
  // the fetch dies as a network error and the check misdiagnoses a healthy
  // bridge as "resolver down". This handler is a real click, so the
  // transient-activation condition for permissions.request is satisfied;
  // the check stays read-only (nothing is saved on grant — only a granted
  // bridge gets checked, and Save remains the only writer). A denied grant
  // gets its own line naming the remedy, not a fake "down".
  ensureBridgeHostPermission(bridge).then((granted) => {
    if (!granted) {
      health.className = "bad";
      health.textContent = tHint("optionsCheckBridgeDenied",
        "Host access for $1$ was not granted — the check can't reach the bridge, and nothing was saved. Click Save to request it.",
        [truncateEcho(bridge)]);
      checkBtn.disabled = false;
      checkBtn.textContent = checkLabel;
      return;
    }
  beginCheck(bridge, checkLabel);
  }).catch((e) => {
    // Grant-button parity (2026-10-09): the grant button's own
    // ensureBridgeHostPermission call has a catch that re-enables the
    // button and names the fault; the check pre-flight had none, so a
    // permissions-surface throw (contains/request rejecting — or the
    // no-prompt throw if the click somehow carries no transient
    // activation) left this button disabled on "Resolving…" forever with
    // an unhandled rejection. A throw is never a denial, so the lines
    // below never say "was not granted" — they name the fault.
    const em = (e && e.message) || "";
    checkBtn.disabled = false;
    checkBtn.textContent = checkLabel;
    health.className = "bad";
    if (/^Host access could not be requested/.test(em)) {
      // Same taxonomy as the save paths: the browser never asked.
      health.textContent = tHint("optionsCheckNoPrompt",
        "The browser never asked for host access for $1$ — so nothing was denied and nothing was saved. Click Check again to retry.",
        [truncateEcho(bridge)]);
      return;
    }
    health.textContent = tHint("optionsCheckGrantFault",
      "Host access for $1$ could not be verified ($2$) — the check can't reach the bridge, and nothing was saved. Click Check again to retry.",
      [truncateEcho(bridge), truncateEcho(em || "permission surface error")]);
  });
});

// The check body, deferred until the permission pre-flight above settles:
// granted (or genesis, already granted via base host_permissions) means the
// fetch can actually reach the bridge, so the resolve now diagnoses the
// resolver, not the permission surface.
function beginCheck(bridge, checkLabel) {
  health.className = "";
  // The running line echoes the on-screen value: truncateEcho bounds it
  // (same hostile-echo bite the down line has — a 10k-char paste would
  // otherwise render a giant status line on both Check paths).
  health.textContent = tHint("optionsCheckBridgeRunning", "checking $1$ …", [truncateEcho(bridge)]);
  // resolveCyberspaceInner takes the bridge explicitly (the storage-backed
  // resolveCyberspace wrapper reads the saved key, which may be stale —
  // the whole point of this button is to test the on-screen value).
  resolveCyberspaceInner("genesis.cyberspace", bridge, DOH_TIMEOUT_MS).then(
    ip => {
      health.className = "ok";
      // Live-line hostile-echo bite (audit): $1$ is the normalized box text,
      // and a valid-but-giant bridge URL would render a giant success line —
      // the running and down lines both belt the bridge; this one didn't.
      // $2$ is wire-built from DNS answer bytes (dotted quad / v6 groups),
      // bounded by construction.
      health.textContent = tHint("optionsCheckBridgeLive",
        "resolver live — $1$ → genesis.cyberspace → $2$", [truncateEcho(bridge), ip]);
    },
    e => {
      // Same taxonomy as the popup health check (shared globals in
      // resolver.js): a name-class failure for the fixed probe name is
      // never a spelling problem, so the hint points at the endpoint
      // setting — which sits above the Check button on this page, hence
      // loc "above" (the popup's default "below" keeps its own direction).
      const msg = truncateEcho(e && e.message ? e.message : e);
      const { hint } = classifyHealthError(e, "above");
      health.className = "bad";
      // Hostile-echo bite (audit): $1$ is the raw box text, so a 10k-char
      // paste rendered a ~10k-char status line. truncateEcho bounds it;
      // $2$ is an internal resolve error string, but it rides the SAME
      // hostile territory (bridge echoes, Content-Type/Content-Length
      // surfaces) the throw-site belts cover — so this line belts it too,
      // defense in depth: a future resolver throw that forgets its own
      // belt can't render a giant line here either. Taxonomy is computed
      // from the RAW error above, so truncating the echoed tail never
      // re-routes classification.
      health.textContent = tHint("optionsCheckBridgeDown",
        "resolver down ($1$): $2$", [truncateEcho(bridge), msg]) + hint;
    }
  ).finally(() => { checkBtn.disabled = false; checkBtn.textContent = checkLabel; });
}
