// Cyberspace Resolver — background service worker
// Intercepts *.cyberspace navigation, resolves via DoH, redirects to IP.

importScripts("resolver.js"); // DOH_URL, SUFFIX, resolveCyberspace

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return; // top frame only
  let url; // hoisted so the catch branch can name the failed host
  try {
    url = new URL(details.url);
    // Normalize before the suffix guard: a trailing-dot address ("genesis.cyberspace./")
    // keeps the dot in url.hostname, which would bypass a raw endsWith check.
    const name = hostToCyberspaceName(url.hostname); // shared helper in resolver.js
    if (!name) return; // not a .cyberspace name
    // Grant pre-flight rides inside resolveCyberspace (shared grantPreflight
    // in resolver.js): one read-only permissions.contains for every resolve
    // surface, so a stored custom bridge predating the permission-gating
    // pass names the missing origin grant here instead of dying as a
    // network error the failure page would misdiagnose as a dead resolver.
    const ip = await resolveCyberspace(name);
    // Keep the popup's last-name prefill and Recent chips in sync: a name
    // typed in the address bar counts as visited just like a popup resolve
    // does (recordRecent is the shared storage helper from resolver.js).
    // The prefill write is fire-and-forget: a failing storage write must
    // not surface as an unhandled rejection (recordRecent carries its own
    // catch, like here) or disturb the redirect it trails.
    chrome.storage.local.set({ lastName: name }).catch(() => {});
    recordRecent(name);
    const target = `http://${ip}${url.pathname}${url.search}${url.hash}`;
    // The tab can die between the resolve and the redirect (e.g. the user
    // closes it mid-flight): an un-awaited tabs.update would then reject
    // outside this listener's try — the success-path twin of the failure
    // page's guarded update below. A dead tab needs no redirect; log it.
    try {
      await chrome.tabs.update(details.tabId, { url: target });
    } catch (te) {
      console.error("Cyberspace redirect could not render (tab gone):", te);
    }
  } catch (e) {
    console.error("Cyberspace resolve failed:", e);
    // Never strand the user on a dead .cyberspace address: show why it failed.
    // buildFailurePage (shared in resolver.js) renders the data: URL with the
    // effective bridge named — a custom endpoint configured in the popup used
    // to be misreported as "genesis" — plus a Try-again button pointing back
    // at the original URL so a transient failure doesn't need a retype.
    // getDohUrl() validates the stored bridge and can throw on a
    // misconfigured value: an invalid bridge must not strand the tab by
    // crashing this very failure path. Name the configured problem instead.
    // Taxonomy: getDohUrl throws two different failure classes — a storage
    // READ failure (chrome.storage rejected; the setting may be perfectly
    // fine, the store just can't be read) and a config-value failure
    // ("Configured DoH bridge ..." — the stored value failed validation).
    // The old code labeled both "invalid bridge", which sends the user to
    // fix a setting that was fine when the real fault is the store. Name
    // the actual fault: only a Configured-DoH-bridge throw earns the
    // invalid-bridge label.
    let bridge;
    try {
      // Belt: getDohUrl validates parseability and scheme, not length — a
      // hand-edited/foreign-written store can hold a valid-but-10k-char
      // bridge URL that would otherwise bloat the failure page's "via"
      // lead line. Shared truncateEcho bounds it; taxonomy is untouched
      // (classifyResolveError ran on the raw error above, and the bridge
      // itself is never classified).
      bridge = truncateEcho(await getDohUrl());
    } catch (be) {
      const bem = truncateEcho((be && be.message) || be);
      bridge = /^Configured DoH bridge/.test(bem)
        ? `invalid bridge: ${bem}`
        : /^cannot read bridge setting/.test(bem)
        ? bem // getDohUrl names the fault itself now — don't double it
        : `cannot read bridge setting: ${bem}`;
    }
    const page = buildFailurePage({
      name: url ? url.hostname : details.url,
      bridge,
      msg: truncateEcho((e && e.message) || e),
      // Defense-in-depth belt: the failure page percent-encodes msg into a
      // giant paragraph, so a raw 10k-char resolver message (foreign store,
      // hostile bridge surface, future unbelted throw) would bloat the page.
      // classifyResolveError above ran on the RAW error, so taxonomy is
      // untouched — this belt only bounds what the page displays.
      // Taxonomy, not raw internals: the popup's Go path classifies with
      // classifyResolveError so a spelling problem doesn't read like a dead
      // bridge — the address-bar failure page now classifies the same way.
      // loc is "in the extension settings": the failure page carries no
      // endpoint widget of its own, so the bridge hint points at the
      // popup's quick-change input and the options page instead of
      // "below"/"above".
      hint: classifyResolveError(e, "in the extension settings").hint,
      retryUrl: details.url,
    });
    // The tab can die between the failed resolve and the failure page
    // (e.g. the user closes it on the hung spinner): an unhandled
    // tabs.update rejection would then escape this listener as noise in the
    // service worker. A dead tab needs no failure page — log it and stop.
    try {
      await chrome.tabs.update(details.tabId, { url: page });
    } catch (te) {
      console.error("Cyberspace failure page could not render (tab gone):", te);
    }
  }
});
