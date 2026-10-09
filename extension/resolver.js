// Cyberspace Resolver — shared DoH client (loaded by background via importScripts
// and by popup via <script>; defines globals DOH_URL, SUFFIX, resolveCyberspace).

const DOH_URL = "http://185.143.228.228/dns-query";
const SUFFIX = ".cyberspace";

// DNS-over-HTTPS bodies are DNS wire messages, and the TCP framing length
// prefix is 2 bytes — so no legitimate response ever exceeds 64 KiB. Used to
// refuse oversized DoH bodies before buffering them.
const MAX_DNS_MSG = 65535;

// A bridge that accepts the connection but never answers would otherwise
// stall the background service worker (address-bar resolves) or the popup's
// click handler indefinitely — fetch has no built-in timeout. Bound every
// DoH round-trip with an abort; the abort surfaces as a clear "timed out"
// error so the failure page and the popup's status line name the real
// problem instead of hanging. Overridable per call so tests can run fast.
const DOH_TIMEOUT_MS = 8000;

// Shared HTML-escape for error surfaces: the background worker's failure
// page and the popup's status line both inject bridge- or user-derived text
// into HTML. The bridge URL is user-configured, so it must be escaped too.
function esc(s) {
  return String(s).replace(/[&<>"']/g, c =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

// Build the background worker's failure page as a data: URL. Pure string
// builder (no chrome.* calls) so the popup and tests can share it.
// name/bridge/msg land inside the page's own URL, so they need URL-encoding,
// not HTML escaping: esc() would leave # ? % intact and a hostile custom
// bridge could truncate or rewrite the page's URL. encodeURIComponent also
// neutralizes HTML metacharacters (& < > " ') as %XX, so the output is safe
// in both contexts — no raw injection path anywhere.
// retryUrl is the original attempted URL: the page is a dead end otherwise,
// so it gets a "Try again" button. It is encodeURIComponent'd into a data-u
// attribute and decodeURIComponent'd at click time (an onclick can't carry
// the raw URL — the data: URL body is URL-encoded, which would corrupt it).
// hint is the classifyResolveError taxonomy line (background.js computes it
// the same way the popup's Go path does): the raw msg alone used to dump
// resolver internals with no guidance — a name spelling problem read exactly
// like a dead bridge. The canned third line is kept only as the fallback for
// wire-class failures with no actionable hint (wire-shape malformations now
// carry their own hint).
function buildFailurePage({ name, bridge, msg, hint, retryUrl }) {
  const failedName = encodeURIComponent(name);
  const safeBridge = encodeURIComponent(bridge);
  const safeMsg = encodeURIComponent(String(msg));
  const safeHint = hint ? encodeURIComponent(hint) : "";
  const safeRetry = encodeURIComponent(retryUrl);
  // i18n thread, third bite, fourth sub-bite (2026-10-08): the failure page
  // is the last user-facing surface with hard-coded English — its title,
  // lead line, hint-fallback line, and retry button now resolve through the
  // shared tHint() helper. The lead line's $1$/$2$ carry the already
  // encodeURIComponent'd (and <b>-wrapped) name and bridge, so the fallback
  // is byte-identical to today's HTML. A miss (no key, throwing i18n, no
  // chrome) fails closed to today's strings; the taxonomy hint passed in is
  // already localized at the call site.
  const title = tHint("failPageTitle", "Cyberspace Resolver");
  const leadLine = tHint("failCouldNotResolve",
    "Could not resolve <b>$1$</b> via <b>$2$</b>:", [failedName, safeBridge]);
  const hintMissing = tHint("failHintMissing",
    "The bridge was unreachable or the name is not claimed.");
  const tryAgain = tHint("failTryAgain", "Try again");
  const body =
    `<body style="background:%230d1117;color:%23c9d1d9;font:14px system-ui;padding:40px">` +
    `<h2>&#x2728; ${title}</h2>` +
    `<p>${leadLine}</p>` +
    `<p>${safeMsg}${safeHint}</p>` +
    (safeHint
      ? ""
      : `<p>${hintMissing}</p>`) +
    // The retry URL is decode-then-navigated at click time: never trust the
    // decoded value blindly. A javascript:/data: payload in data-u would
    // execute under location.href, so the handler validates the scheme
    // (http/https only) and fails closed on any decode/parse throw — a dead
    // button, never a navigation. data-u stays encodeURIComponent'd, so the
    // attribute itself can't break out.
    `<button data-u="${safeRetry}" ` +
    `onclick="try{var u=decodeURIComponent(this.dataset.u);var p=new URL(u).protocol;if(p==='http:'||p==='https:')location.href=u;}catch(e){}" ` +
    `style="background:%23161b22;color:%2358a6ff;border:1px solid %2330363d;border-radius:6px;padding:6px 12px;cursor:pointer">` +
    `${tryAgain}</button></body>`;
  return `data:text/html,${body}`;
}

// Configured bridge endpoint: chrome.storage.local "dohUrl", defaulting to
// the genesis bridge. Read fresh per resolve so the background worker and the
// popup always agree without a restart. The bridge is user-configured (the
// popup settings let anyone type one in), so validate before use: a typo'd
// value must fail here with a readable error — never slip through to fetch
// and surface as an opaque "Failed to parse URL" — and a silent fallback to
// genesis would leave the user's bridge configured-but-unused. Errors carry
// the configured value; callers name it through esc()/encodeURIComponent.
async function getDohUrl() {
  // The store can die ("Extension context invalidated."): a raw rejection
  // would reach classifyResolveError with no matching prefix and fall
  // through to the wire fallback — mislabeling a dead settings store as an
  // unreachable bridge (the popup Go path and health check had no
  // equivalent of background.js's "cannot read bridge setting" fault
  // naming). Prefix it so the taxonomy names the real fault; callers that
  // already self-label the read failure (background.js, the popup health
  // chain) discriminate this prefix and don't double it. The prefix stays
  // head-first through any truncation (same contract as the "Configured
  // DoH bridge" echoes below), and the store may hold a perfectly fine
  // bridge — so this is never routed to the endpoint hint.
  let stored;
  try {
    stored = await chrome.storage.local.get(["dohUrl"]);
  } catch (readErr) {
    throw new Error(`cannot read bridge setting: ${readErr && readErr.message ? readErr.message : readErr}`);
  }
  const { dohUrl } = stored;
  if (!dohUrl) return DOH_URL;
  const trimmed = String(dohUrl).trim();
  if (!trimmed) return DOH_URL;
  let parsed;
  try {
    parsed = new URL(trimmed);
  } catch {
    // The echoed bridge is truncated (shared truncateEcho): a hand-edited
    // or foreign-written store can hold a megabyte bridge, and this message
    // surfaces verbatim in the popup status line and failure page via
    // classifyResolveError — the prefix (which the taxonomy regex matches)
    // stays intact, only the tail is bounded. Same contract as bridgeError's
    // entry-time echoes.
    throw new Error(`Configured DoH bridge is not a valid URL: ${truncateEcho(scrubBridgeCreds(trimmed))}`);
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error(`Configured DoH bridge must use http or https: ${truncateEcho(scrubBridgeCreds(trimmed))}`);
  }
  return trimmed;
}

// Bridge-entry validation for the options/popup pages: the same validity
// getDohUrl enforces at resolve time. A typo'd value must fail here, at
// the moment of entry, instead of saving cleanly and failing every later
// resolve as "Configured DoH bridge is not a valid URL" — a save that
// only errors on first use is a silent misconfiguration. Returns an error
// message string, or null when the value is acceptable. Empty/blank is
// valid (means "clear — back to the genesis bridge"); both pages treat it
// as remove, exactly like getDohUrl treats a missing key.
function bridgeError(v) {
  const trimmed = String(v == null ? "" : v).trim();
  if (!trimmed) return null; // clearing
  let parsed;
  try {
    parsed = new URL(trimmed);
  } catch {
    // The echoed input is truncated (shared truncateEcho): a 10k-char
    // paste into the bridge box used to render a ~10k-char error line on
    // both the options and popup save paths.
    return `Not a valid URL: ${truncateEcho(trimmed)}`;
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return `DoH bridge must use http or https: ${truncateEcho(trimmed)}`;
  }
  return null;
}

// Privacy hardening (2026-10-09): the manifest no longer carries
// host_permissions "*://*/*" — install-time footprint is the pinned genesis
// origin only, and custom bridges ride optional_host_permissions. A bridge
// fetch to a host missing from the granted set silently fails as a network
// error under MV3, so the bridge-save paths must secure the origin grant
// BEFORE persisting: a bridge that saves without its grant would die on
// every later resolve with the stored setting looking healthy.
// bridgeOriginPattern scopes the request to the bridge's own origin
// ("https://host:port/*") — never the "*" wildcard — so a user granting one
// bridge grants exactly that bridge, nothing else.
function bridgeOriginPattern(bridgeUrl) {
  return new URL(bridgeUrl).origin + "/*";
}

// True when the bridge's origin is already granted (covers the pinned
// genesis origin via base host_permissions, and any previously-approved
// custom bridge), otherwise requests it. The promise resolves false when
// the user denies the prompt. The no-prompt case is a DIFFERENT fault:
// permissions.request needs transient activation, which a blur/Enter commit
// may lack — then the browser never asked at all, and resolving false would
// let the save paths misreport a denial the user never made. So a false
// with no transient activation throws with this prefix instead (sampled via
// navigator.userActivation BEFORE the request; the grant buttons and the
// check pre-flight always run on real clicks, so their false still means a
// genuine denial). The save paths discriminate the prefix and name the real
// fault — never asked — pointing at Save (a real click) as the first real
// ask, not a retry.
async function ensureBridgeHostPermission(bridgeUrl) {
  const pattern = bridgeOriginPattern(bridgeUrl);
  if (await chrome.permissions.contains({ origins: [pattern] })) return true;
  const hadGesture = typeof navigator !== "undefined" && !!(
    navigator.userActivation && navigator.userActivation.isActive);
  const granted = await chrome.permissions.request({ origins: [pattern] });
  if (!granted && !hadGesture) {
    throw new Error("Host access could not be requested: this commit had no click gesture, so the browser never showed the grant prompt");
  }
  return granted;
}

// Read-only grant pre-flight shared by every resolve path (2026-10-09):
// moved up from the background worker's address-bar pre-flight, which left
// the popup health check and Go path calling resolveCyberspace directly —
// an ungranted custom bridge died as a network error there and the taxonomy
// read it as a dead resolver. One check here covers all callers: genesis
// rides the base host_permissions and skips, stored-invalid bridges throw
// from getDohUrl before this runs, and a permissions-surface error fails
// OPEN (treated as granted) so the gate itself can never block a resolve.
// Never requests: no prompt without a user gesture — the grant rides the
// popup/options banner buttons. The message prefix is byte-identical to the
// background worker's pre-flight so classifyResolveError routes it to the
// Grant hint (never the endpoint hint) on every surface.
async function grantPreflight(bridge) {
  if (bridge === DOH_URL) return;
  let granted;
  try {
    granted = await chrome.permissions.contains({ origins: [bridgeOriginPattern(bridge)] });
  } catch {
    return; // fail-open: a broken permissions surface is never a reason to strand the resolve
  }
  if (!granted) {
    throw new Error(`Custom DoH bridge is missing its host permission — open the extension popup and click "${tHint("grantAccessLabel", "Grant access")}"`);
  }
}

// Shared bridge persistence for the options and popup save paths: callers
// validate first (shared bridgeError); this gates the origin grant, then
// persists. Resolves true on save. Resolves false when the grant was
// denied — the stored bridge is left untouched, never half-written. Throws
// the no-prompt error (see ensureBridgeHostPermission) when the request
// could not be shown for lack of a gesture — callers discriminate that
// prefix from a genuine denial. Clearing (falsy v) needs no grant: the
// genesis origin rides the base host_permissions.
async function saveBridgeSetting(v) {
  if (!v) {
    await chrome.storage.local.remove("dohUrl");
    return true;
  }
  if (!(await ensureBridgeHostPermission(v))) return false;
  await chrome.storage.local.set({ dohUrl: v });
  return true;
}

// Bridge-entry convenience for the options/popup pages: typing a full
// http(s) URL is the documented shape, but a user pasting a bare host or IP
// (the thing they'd copy out of a doc or a chat) used to die as "Not a valid
// URL" — a fixable-entry problem, not a real configuration error.
// normalizeBridgeInput upgrades schemeless input: prepends https://, and
// appends /dns-query when the path is empty (the genesis bridge's own path
// convention). A bare IPv6 literal is bracketed first (bracketUnbracketedIpv6)
// since WHATWG URLs require brackets around IPv6 hosts; a 2+-colon authority
// that doesn't validate as IPv6 fails closed to null immediately.
// Returns the normalized URL the save/check paths should use.
// "" comes back as "" (callers treat it as clear, exactly like bridgeError
// does); input that can't be salvaged comes back as null, and the caller
// then runs bridgeError on the RAW value so the failure message names what
// the user actually typed. https is the schemeless default because the
// bridge speaks DoH (RFC 8484) and a bare paste almost always means "just
// reach it securely" — a user who wants plaintext types http:// explicitly.
// The scheme regex requires "://" so "foo:bar" and "javascript:alert(1)"
// take the prepend path and fail closed in the URL parse; non-http(s)
// schemes (file:, ftp:) return null rather than normalizing into something
// bridgeError would later reject. Idempotent: full URLs round-trip
// unchanged (scheme present skips the prepend, non-empty path skips the
// /dns-query append).
function normalizeBridgeInput(raw) {
  const trimmed = String(raw == null ? "" : raw).trim();
  if (!trimmed) return "";
  // IPv6 bracketing first, so the rest of this function only ever sees
  // bracketed or non-IPv6 authorities: a bare 2001:db8::1 paste would
  // otherwise fail the URL parse and die as "Not a valid URL". null means
  // it looked like IPv6 but wasn't — fail closed on the spot.
  const bracketed = bracketUnbracketedIpv6(trimmed);
  if (bracketed === null) return null;
  const input = bracketed;
  // A full URL (scheme:// present) is not ours to upgrade — bridgeError
  // validates it as-is, so "file:///x" keeps its accurate error instead of
  // being mangled into something https-shaped.
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(input)) {
    let u;
    try {
      u = new URL(input);
    } catch {
      return null;
    }
    if (u.protocol !== "http:" && u.protocol !== "https:") return null;
    if (u.pathname === "/") u.pathname = "/dns-query";
    return u.toString();
  }
  // Schemeless input is treated as host[:port][/path] and upgraded — but
  // only if every character could plausibly belong there. WHATWG URL
  // parsing is lenient about host punctuation ("!" survives in a host),
  // so parsing alone can't fail closed: "ht!tp://[bad" would otherwise
  // normalize into "https://ht!tp//[bad" and get SAVED, worse than the old
  // entry-time rejection. Whitelisted chars: LDH + IPv4 dots, bracketed
  // IPv6, port colons, and path punctuation; anything else (spaces,
  // unicode, stray punctuation) returns null and bridgeError names the raw
  // input.
  if (!/^[A-Za-z0-9.\-_%~[\]:]+(\/[^\s]*)?$/.test(trimmed)) return null;
  let u;
  try {
    u = new URL("https://" + input);
  } catch {
    return null; // bad port, bad bracket, etc. — fail closed
  }
  if (u.pathname === "/") u.pathname = "/dns-query";
  return u.toString();
}

// Bracket an unbracketed IPv6 literal sitting in the authority position.
// URLs require brackets around IPv6 hosts, so a pasted bare 2001:db8::1
// (schemeless or after an explicit scheme) dies in the URL parse as "Not a
// valid URL" without this. An authority with 2+ colons can only be an
// IPv6 candidate — a port takes one colon — so a valid-looking literal is
// rewritten and anything else returns null (fail closed; the caller then
// runs bridgeError on the raw input). The WHATWG parser is the validator,
// the same one Chrome uses: zone ids, dangling brackets, and non-compressed
// short forms fail closed. Only the authority is touched; the path after it
// is passed through verbatim.
function bracketUnbracketedIpv6(raw) {
  const m = /^([a-zA-Z][a-zA-Z0-9+.-]*):\/\//.exec(raw);
  const hostPart = m ? raw.slice(m[0].length) : raw;
  const slash = hostPart.indexOf("/");
  const authority = slash === -1 ? hostPart : hostPart.slice(0, slash);
  const after = slash === -1 ? "" : hostPart.slice(slash);
  if (!authority.startsWith("[") && (authority.match(/:/g) || []).length >= 2) {
    try {
      new URL((m ? m[1] + "://" : "x://") + "[" + authority + "]" + "/");
    } catch {
      return null; // not actually an IPv6 literal — fail closed
    }
    return (m ? m[0] : "") + "[" + authority + "]" + after;
  }
  return raw;
}

// Normalize pasted input into a bare .cyberspace name: strip any scheme,
// path, query, hash, port, trailing dots, and whitespace; lowercase.
function normalizeName(raw) {
  let name = String(raw || "").trim().toLowerCase();
  name = name.replace(/^[a-z][a-z0-9+.-]*:\/\//, ""); // scheme://
  name = name.split(/[/?#]/)[0]; // path/query/hash
  // Percent-encoded pastes: the browser decodes the host before anything
  // else (new URL("http://%67.../").hostname is "genesis"), so the wire
  // name must be decoded too — otherwise the resolver queries the literal
  // "%67...cyberspace" while the tab semantics point at the decoded host.
  // Decoded AFTER the path strip so an encoded slash (%2F) becomes a label
  // character that checkLabels rejects (a browser won't open it as a host
  // either), and lowercased again since decoding can introduce case
  // (%41 -> "A"). A malformed escape fails closed to the raw string, which
  // checkLabels rejects exactly as today (2026-10-08, harness
  // /tmp/pct-host-test.js).
  try { name = decodeURIComponent(name); } catch { /* fail closed */ }
  name = name.toLowerCase();
  name = name.split(":")[0]; // port (a colon here can only be a port: valid
  // names are ASCII-LDH, so checkLabels would reject any colon in the name
  // itself; this also strips ports from address-bar hostnames
  return name.replace(/\.+$/, ""); // trailing dot(s)
}

// Map an address-bar hostname to the .cyberspace name it claims, or null.
// Trailing dots survive new URL() hostname parsing ("genesis.cyberspace."),
// so normalize BEFORE the suffix guard — the guard in the background worker
// previously checked the raw hostname, letting "genesis.cyberspace./" slip
// past interception. normalizeName also strips ports/schemes/pastes junk.
function hostToCyberspaceName(hostname) {
  const name = normalizeName(hostname);
  return name.endsWith(SUFFIX) ? name : null;
}

// Build a DNS wire-format query for an A record
// Each query gets a fresh random transaction ID (crypto.getRandomValues),
// read back from the built query in resolveCyberspace and enforced by
// parseAnswers — the 04:10 txid check only pays off if answers can't predict it.
function buildQuery(name) {
  const qname = [];
  for (const label of name.split(".")) {
    const bytes = new TextEncoder().encode(label);
    qname.push(bytes.length, ...bytes);
  }
  qname.push(0); // root
  const txid = new Uint8Array(2);
  crypto.getRandomValues(txid);
  const header = [txid[0], txid[1], 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
  const footer = [0x00, 0x01, 0x00, 0x01]; // QTYPE=A, QCLASS=IN
  return new Uint8Array([...header, ...qname, ...footer]);
}

// Read a (possibly compression-pointered) domain name from the message.
// Returns { name, end }: the decoded name and the offset just past the field
// as written (pointer jumps don't advance the field itself). The [min, max)
// window defaults to the whole message; callers decoding record rdata pass
// a tighter window so a name can't be built from bytes outside its own record.
function readName(view, offset, min = 0, max = view.byteLength) {
  const labels = [];
  let end = offset;
  let jumped = false;
  let guard = 0; // never loop a crafted message forever
  while (guard++ < 128) {
    // A truncated or crafted message must fail with a readable error,
    // never a RangeError from an out-of-bounds read.
    if (offset < min || offset >= max) throw new Error("Truncated DNS message");
    const len = view.getUint8(offset);
    if (len === 0) { if (!jumped) end = offset + 1; break; }
    if ((len & 0xc0) === 0xc0) {
      if (!jumped) end = offset + 2;
      jumped = true;
      const target = view.getUint16(offset) & 0x3fff;
      // A pointer is a reference to already-decoded bytes that form part of
      // this name, so it may not jump outside the caller's window: a CNAME
      // rdata pointing at the question section is not a self-contained record.
      if (target < min || target >= max) throw new Error("Truncated DNS message");
      offset = target;
      continue;
    }
    if (offset + 1 + len > max) throw new Error("Truncated DNS message");
    let label = "";
    for (let i = 0; i < len; i++) label += String.fromCharCode(view.getUint8(offset + 1 + i));
    labels.push(label);
    offset += len + 1;
    if (!jumped) end = offset;
  }
  return { name: labels.join("."), end };
}

// Parse the answer section: returns { ips, cname } — the A (type 1) and
// AAAA (type 28) records and the first CNAME alias target (type 5), so
// callers can chase aliases instead of misreporting "No address found" when
// a name has a CNAME but no A record — and so an AAAA answer a message
// carries is read as an address instead of silently dropped.
// txid is the query's transaction ID, read from the built query: the
// response must be at least a full DNS header, carry the txid back, have
// the QR bit set, and not be an NXDOMAIN (RCODE 3 — that fails fast as
// "Name not registered" rather than falling through to "No address found"
// downstream, which would imply the name exists but has no address).
// The echoed question must also BE our question (name, QTYPE, QCLASS from the
// built query): a crossed response for a different query carrying a matching
// txid fails as "Response question does not match query" instead of having
// its answers parsed for a name they were never asked about.
// A truncated or mismatched response (another query's answer, a racy
// buffer, our own query echoed back) fails with a readable error instead
// of a RangeError or a silently misresolved name. Answer records carrying
// a non-IN class are skipped like wrong-type records — a CHAOS-class TXT
// riding along with our answer must never land in ips/cname.
function parseAnswers(buf, txid, query) {
  const view = new DataView(buf);
  if (buf.byteLength < 12) throw new Error("Truncated DNS message");
  if (view.getUint16(0) !== txid) throw new Error("Mismatched DNS transaction ID");
  const flags = view.getUint16(2);
  // The QR bit (bit 15 of the flags field) must be set: this is a
  // response, not our own query echoed back (or someone else's query).
  if ((flags & 0x8000) === 0) throw new Error("Not a DNS response (QR bit clear)");
  // The TC (truncation) bit must be clear. TC=1 means the server is
  // telling us the answer section is incomplete and to retry over a
  // second channel — but DoH has no second channel, and a half-parsed
  // answer section would misresolve or claim "no address". Fail fast as
  // a bridge problem instead of parsing answers the server itself says
  // are incomplete. (The genesis bridge never sets it: it answers
  // registry lookups directly, never from a truncated upstream reply.)
  if (flags & 0x0200) throw new Error("DNS response truncated (TC bit set)");
  // OPCODE (bits 11-14) must be 0 (standard query, the only thing we send):
  // a response carrying IQUERY/STATUS/etc is answering an operation we
  // never performed — crossed or malformed, never parsed as our answer.
  if ((flags & 0x7800) !== 0) throw new Error("Unexpected DNS opcode in response");
  // The Z bit (bit 6) is reserved and must be zero per RFC 1035: a set Z
  // means the responder is not speaking conformant DNS, so the message is
  // not trusted as our answer.
  if ((flags & 0x0040) !== 0) throw new Error("DNS response has reserved (Z) bit set");
  // The AA (authoritative answer) bit must be SET: the genesis bridge is
  // authoritative for .cyberspace and always sets it (build_response
  // packs 0x8400 | rcode — QR | AA — on every reply, including NXDOMAIN).
  // A response with AA clear is not our bridge speaking as the authority
  // for this zone: fail fast as a bridge problem instead of trusting
  // answers a non-authoritative responder never vouched for.
  if ((flags & 0x0400) === 0) throw new Error("DNS response not authoritative (AA bit clear)");
  // AD and RA are read-and-ignored, deliberately. AD (authentic data) is
  // meaningless to us: we do no DNSSEC validation, and the bridge is the
  // trust anchor for .cyberspace anyway — a bridge's claim that it
  // validated something is not a promise we can cash, and we never show
  // the user anything that would imply we did. RA (recursion available)
  // is expected to be CLEAR from the genesis bridge: it answers
  // .cyberspace authoritatively from its own registry, and a set RA
  // would only say "this bridge recurses for other names", which is not
  // a signal we act on. Neither bit may steer resolution.
  // Response codes live in the low 4 bits of the flags word. RCODE 3
  // (NXDOMAIN) means the queried name is not registered — failing fast
  // with a distinct error keeps it from masquerading as "No address found"
  // downstream, which would imply the name exists but has no address.
  // Any other non-zero RCODE (SERVFAIL, REFUSED, ...) is the bridge's own
  // failure, not a name problem: fail fast as a bridge error instead of
  // falling through with an empty answer section to the same misleading
  // "No address found" (a SERVFAIL with zero answers used to read as if
  // the name existed but had no address).
  const rcode = flags & 0x000f;
  if (rcode === 3) throw new Error("Name not registered");
  if (rcode !== 0) throw new Error(`DoH bridge error (RCODE ${rcode})`);
  // The response must echo back exactly the one question we sent. With zero
  // questions the answer parse would start at offset 12 and misread answer
  // names; with several we would skip only the first, starting the answer
  // section mid-message and parsing garbage — fail fast instead.
  if (view.getUint16(4) !== 1) throw new Error("Unexpected question count in DNS response");
  // The echoed question must be OUR question: decode the query's question
  // and compare name (case-insensitively — DNS names are case-insensitive),
  // QTYPE, and QCLASS against the response's echoed question. Previously
  // the question was skipped without any comparison, so a crossed response
  // for a different query could have its answers parsed under our name.
  const qview = new DataView(query.buffer, query.byteOffset, query.byteLength);
  const expected = readName(qview, 12);
  const respQ = readName(view, 12);
  if (respQ.end + 4 > view.byteLength) throw new Error("Truncated DNS message");
  if (respQ.name.toLowerCase() !== expected.name.toLowerCase() ||
      view.getUint16(respQ.end) !== qview.getUint16(expected.end) ||
      view.getUint16(respQ.end + 2) !== qview.getUint16(expected.end + 2)) {
    throw new Error("Response question does not match query");
  }
  const ancount = view.getUint16(6);
  // The bridge answers .cyberspace authoritatively from its own registry —
  // it never emits referrals (NSCOUNT=0: build_response packs 0) nor
  // additional records (ARCOUNT=0: no glue, no OPT — error_response packs
  // 0,0). Sections we never read must be empty: silently skipping an
  // authority/additional section would let a crafted message's referral
  // ride along unnoticed while we resolved from the answer section — fail
  // fast as a bridge problem instead. Checked before the ancount===0 early
  // return so a no-answer message with sections smuggled in can't slip.
  if (view.getUint16(8) !== 0) throw new Error("Unexpected authority records in DNS response");
  if (view.getUint16(10) !== 0) throw new Error("Unexpected additional records in DNS response");
  // Wire TTLs: the expiry horizon for any cached mapping. Folded as the
  // minimum across collected records (A and CNAME alike) — a registry can
  // legitimately ask for a 60-second lifetime, and the cache must not hold
  // the mapping longer. The cache layer still caps at CACHE_TTL_MS.
  const out = { ips: [], cname: null, ttl: Infinity };
  if (ancount === 0) return out;
  // Skip header (12) + the verified question section. The question name is
  // parsed with readName (bounds-checked, like the answer names) instead of
  // a raw getUint8 loop: a crafted or truncated message must fail with the
  // readable "Truncated DNS message" error, never a RangeError.
  let offset = respQ.end + 4; // name field + QTYPE(2) + QCLASS(2)
  for (let i = 0; i < ancount; i++) {
    const nameField = readName(view, offset);
    offset = nameField.end;
    // Answer records must lie inside the message: a crafted rdlen or a
    // truncated tail must fail with the readable error, never a RangeError
    // from an out-of-bounds read (the last raw-read path parseAnswers had
    // after the readName hardening of the question and name fields).
    if (offset + 10 > view.byteLength) throw new Error("Truncated DNS message");
    const type = view.getUint16(offset); offset += 2;
    const qclass = view.getUint16(offset); offset += 2;
    const ttl = view.getUint32(offset); offset += 4; // wire TTL (seconds)
    const rdlen = view.getUint16(offset); offset += 2;
    if (offset + rdlen > view.byteLength) throw new Error("Truncated DNS message");
    // The response must answer the name we asked about: a record whose
    // owner name is not the queried name (case-insensitive — DNS names are
    // case-insensitive) is out of bailiwick and must never land in
    // out.ips / out.cname, exactly like wrong-class records are skipped
    // below. During a CNAME chase each round's query carries the chased
    // name, so this check re-anchors per round automatically.
    if (nameField.name.toLowerCase() !== expected.name.toLowerCase()) {
      offset += rdlen; continue;
    }
    // The question's QCLASS is enforced above, but an answer record can
    // carry any class on the wire: skip non-IN (class 1) records instead
    // of collecting them, exactly like wrong-type records are skipped
    // below. A CHAOS-class TXT riding along with our answer must never
    // land in out.ips / out.cname.
    if (qclass !== 1) { offset += rdlen; continue; }
    if (type === 1 && rdlen === 4) {
      out.ips.push([0, 1, 2, 3].map(k => view.getUint8(offset + k)).join("."));
      if (ttl < out.ttl) out.ttl = ttl;
    } else if (type === 28 && rdlen === 16) {
      // AAAA records are read as bracketed IPv6 literals ([2001:db8::1] style
      // host form, full 8-group, no :: compression — simple and unambiguous):
      // every consumer builds http://${ip}, and an unbracketed colon-form
      // would not parse as a URL host. ips[0] is returned straight into the
      // redirect target and the cache, so the bracketed form keeps the whole
      // downstream path URL-safe with no second change. A 16-byte rdata is
      // the only length accepted — a short/long AAAA rdata is skipped like
      // any wrong-shape record, never half-parsed.
      const groups = [];
      for (let k = 0; k < 8; k++) groups.push(view.getUint16(offset + 2 * k).toString(16));
      out.ips.push(`[${groups.join(":")}]`);
      if (ttl < out.ttl) out.ttl = ttl;
    } else if (type === 5) {
      // A name may own at most one CNAME (RFC 1034 §3.6.2): a second CNAME
      // record for the queried name is a malformed answer section. The old
      // code silently kept the first and dropped the rest, resolving a name
      // the bridge never consistently asserted — and a crafted message could
      // place a benign target first and a hostile one second, knowing only
      // the first would be read. Fail fast as a bridge problem instead.
      if (out.cname) throw new Error("Conflicting CNAME records in DNS response");
      // The CNAME target must be a self-contained name inside this record's
      // own rdata bytes: a crafted rdata whose name runs past rdlen (or a
      // compression pointer escaping the record) used to be decoded from
      // the following record's bytes, smuggling in a name the record never
      // actually asserted. readName's [min, max) window enforces that now.
      // (The genesis bridge never emits CNAME answers at all — only A/AAAA
      // rdatas — so this strictness costs nothing on legit traffic.)
      out.cname = readName(view, offset, offset, offset + rdlen).name;
      if (ttl < out.ttl) out.ttl = ttl;
    }
    offset += rdlen;
  }
  // A CNAME and address records for the same owner name must never coexist
  // (RFC 1034 §3.6.2: "If a CNAME RR is present at a node, no other data
  // should be present"): an answer section carrying both is malformed. The
  // old code silently merged them, letting a crafted message smuggle a
  // hostile address alongside a benign alias the chase would then follow —
  // fail fast as a bridge problem. Records owned by the alias TARGET never
  // reach here (the out-of-bailiwick skip above only collects the queried
  // name's records), so this check is strictly same-owner. The genesis
  // bridge never emits CNAME answers at all, so legit traffic is unaffected.
  if (out.cname && out.ips.length > 0) {
    throw new Error("Conflicting CNAME and address records in DNS response");
  }
  // IPv4-first ordering: A records sort before bracketed AAAA literals, so
  // ips[0] is deterministic regardless of wire order — a crafted message
  // cannot park an AAAA record first and steal the redirect target / cache
  // slot the consumers read. (No Happy Eyeballs here; the bridge speaks A
  // primarily and v4 wins as the primary path.)
  out.ips.sort((a, b) => (a[0] === "[") - (b[0] === "["));
  return out;
}

// Validate a .cyberspace name's labels before any network call: DNS labels
// must be 1-63 chars of [a-z0-9-], never start/end with a hyphen; the whole
// name must fit in 253 chars. Bad input fails fast with a readable error
// instead of a wasted DoH round-trip ending in a misleading "No address found".
// Long-input echo guard (2026-10-08, harness /tmp/long-name-test.js): the
// checkLabels errors echo the offending name and the popup's failure line
// echoes it again — a 10k-char paste rendered a ~20k-char status line. The
// classification regexes anchor on the "Invalid .cyberspace name" prefix, so
// truncating the echoed tail never re-routes the taxonomy; only inputs that
// were already rejected change shape.
function truncateEcho(s, max = 200) {
  const t = String(s);
  return t.length > max ? t.slice(0, max) + "…" : t;
}

// Credential-echo guard (2026-10-09): the stored bridge is free text and a
// private bridge may carry basic-auth userinfo (https://user:pass@host —
// legal, fetch sends it as auth, and the origin permission grant strips it
// via new URL(...).origin). But every user-visible echo of the bridge
// (popup/options status lines, the address-bar failure page, getDohUrl's
// own throw messages) used to render it in cleartext — a password sitting
// in the DOM of a status page a screenshot or a shoulder-surfer can read.
// Scrubbing replaces the userinfo with "***" and keeps host/path so the
// echo still names WHICH bridge failed. Unanchored (a getDohUrl throw
// carries its message prefix ahead of the URL); matches scheme://userinfo@
// only in the authority, so @ in a path is untouched. Idempotent.
function scrubBridgeCreds(s) {
  return String(s == null ? "" : s).replace(
    /([a-zA-Z][a-zA-Z0-9+.-]*:\/\/)([^\s/]*@)/g,
    "$1***@"
  );
}

// Config-surface masking (2026-10-09): the options page and popup bridge
// input boxes are plain-text <input>s, so a stored bridge with embedded
// userinfo (user:pass@host) would sit in the DOM in cleartext — readable by
// a screenshot, a shoulder-surfer, or DOM scrapers. The boxes therefore show
// displayBridge(): the scrubbed form (host+path, ***@ mask), never the raw
// stored URL. The raw value rides page state (storedBridgeRaw); when the box
// still holds exactly the masked form at save/check time, resolveBoxBridge()
// returns the RAW stored value so the credentials round-trip without ever
// being re-typed — standard password-mask behavior. Any actual edit to the
// box replaces the whole bridge with what was typed (re-enter userinfo to
// keep it); a cleared box clears. Empty stored value: the box text is used
// as-is (genesis default / no bridge saved).
function displayBridge(rawStored) {
  return scrubBridgeCreds(rawStored || "");
}
function resolveBoxBridge(boxText, rawStored) {
  const raw = String(boxText == null ? "" : boxText).trim();
  if (raw && rawStored && raw === scrubBridgeCreds(rawStored)) return rawStored;
  return normalizeBridgeInput(raw) ?? raw;
}

function checkLabels(name) {
  const lower = name.toLowerCase();
  if (lower.length > 253) throw new Error(`Invalid .cyberspace name: ${truncateEcho(name)}`);
  const labels = lower.slice(0, -SUFFIX.length).split(".");
  // No punycode, no IDN anywhere: the registry issues ASCII-LDH names only,
  // so a label with anything outside a-z0-9-hyphen is rejected outright.
  const labelOk = l => l.length > 0 && l.length <= 63 &&
    /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(l);
  if (labels.some(l => !labelOk(l))) {
    throw new Error(`Invalid .cyberspace name: ${name}`);
  }
  // No wire-octet check needed beyond the 253-char cap: wire bytes for the
  // full name = sum(len(label)+1) + 1 (root) = chars + 2 exactly, so
  // chars <= 253 already guarantees wire <= 255. (Re-verified 08:45 after a
  // false alarm: for a FULL name, length-octets+root add exactly 2 over the
  // char count; the "chars + 2" claim holds regardless of label count. An
  // added wire check was dead code and was reverted — the cap subsumes it.)
}

// In-memory positive-result cache: name -> { ip, bridge, expires }. A name
// resolved moments ago (same browser session, e.g. re-opening the popup or
// following a second link) reuses the cached address instead of burning
// another DoH round-trip — but never past the wire TTL: a registry saying
// TTL 60 means the mapping dies in 60 seconds even though the cache ceiling
// is CACHE_TTL_MS (failures are never cached — a dead name retries live on
// the next attempt). ttlSec is clamped to [0, CACHE_TTL_MS/1000]; TTL 0
// means "do not cache" — the put is skipped outright, so a zero-TTL mapping
// never occupies one of the 100 FIFO slots and the next resolve always goes
// to the network. The stored bridge is checked on read: if the
// configured endpoint changed mid-session, stale-bridge entries are
// evicted instead of re-served (same discipline as the health cache drop on
// endpoint change). The cache dies with the service worker, so a stale
// mapping can never outlive its TTL for long — and the map itself is
// capped at CACHE_MAX entries (oldest evicted first) so a long-lived
// session can't accumulate unboundedly.
const CACHE_TTL_MS = 5 * 60 * 1000;
// Bound the map: entries are evicted on read once stale, but a name resolved
// once and never re-read would otherwise linger until the worker dies. FIFO
// eviction (Map is insertion-ordered) caps the memory a long-lived session
// can hold, no matter how many distinct names get visited.
const CACHE_MAX = 100;
const resolveCache = new Map();

function cacheCheck(key, bridge) {
  const hit = resolveCache.get(key);
  if (hit && Date.now() < hit.expires && hit.bridge === bridge) return hit.ip;
  resolveCache.delete(key);
  return null;
}

function cachePut(key, ip, bridge, ttlSec) {
  // Wire TTL wins downward, cache ceiling wins upward: min(wire, 300s).
  const clamped = Math.min(Math.max(0, Number.isFinite(ttlSec) ? ttlSec : 0), CACHE_TTL_MS / 1000);
  if (clamped === 0) {
    // TTL 0 means "do not cache" (DNS semantics): skip the store outright.
    // Storing it would plant an instantly-stale entry that cacheCheck can
    // never hit, wasting one of the 100 FIFO slots (and, at a full map, a
    // pointless eviction) for a mapping that must go to the network anyway.
    return;
  }
  if (resolveCache.has(key)) {
    // Refresh position: Map.set on an existing key keeps its ORIGINAL
    // insertion slot, so a hot entry re-resolved every TTL cycle would sit at
    // the front and be the FIRST evicted by the FIFO cap below. Delete-then-
    // set moves it to the newest end, so the cap evicts genuinely-old entries.
    resolveCache.delete(key);
  } else {
    while (resolveCache.size >= CACHE_MAX) {
      resolveCache.delete(resolveCache.keys().next().value); // oldest first
    }
  }
  resolveCache.set(key, { ip, bridge, expires: Date.now() + clamped * 1000 });
}

// Recent places (shared storage helper, no DOM): both entry paths — popup
// resolves and address-bar resolves — record here so the popup's Recent
// chips show every visited place, not just the ones resolved from the popup.
// Deduped, newest first, capped; safe to call from the background worker.
const RECENT_MAX = 5;
// A legit recorded name passed checkLabels at resolve time, so it can never
// exceed the 253-char whole-name cap there. A stored string longer than that
// is corruption (hand-edited or foreign-written store), never a place anyone
// visited.
const RECENT_NAME_MAX = 253;
function recordRecent(name) {
  // A fire-and-forget side effect: a failing storage read or write must not
  // surface as an unhandled rejection (which in a service worker can look
  // like extension misbehavior) or disturb the resolve it trails. The set
  // promise is returned into the chain so a failed write is caught too.
  chrome.storage.local.get(["recent"]).then(({ recent }) => {
    // Write-side self-heal (mirrors the render-side filter in popup.js
    // loadRecent): a hand-edited or foreign-written store can carry
    // non-string entries (numbers, objects, null) or giant junk strings; the
    // type-only filter used to let the giant ones survive forever — read and
    // re-written verbatim on every resolve, rendered raw into a chip by the
    // render path. The length bound heals them outright on the next
    // successful resolve, and it can never drop a real entry (legit names
    // are capped at RECENT_NAME_MAX by checkLabels).
    const list = (Array.isArray(recent) ? recent : [])
      .filter(n => typeof n === "string" && n.length <= RECENT_NAME_MAX)
      .filter(n => n !== name);
    list.unshift(name);
    return chrome.storage.local.set({ recent: list.slice(0, RECENT_MAX) });
  }).catch(() => {}); // failed recent-place recording: resolve was fine, stay silent
}

// Resolve a .cyberspace name to its first address record (A or AAAA) via
// the configured DoH bridge.
// Refuses non-.cyberspace names at the shared layer so no caller can
// accidentally turn the extension into a general-purpose DoH resolver.
// timeoutMs bounds each DoH round-trip (default DOH_TIMEOUT_MS); a bridge
// that never answers aborts with "DoH bridge timed out" instead of hanging
// the service worker or the popup forever.
// One wire round-trip for a single chased name: build the query, POST it to
// the bridge under the abort-bounded timeout, and parse the answer into
// {ips, cname, ttl}. Pure wire work — no cache reads/writes, no TTL folding,
// no chase bookkeeping — so concurrent chases of different aliases can share
// one in-flight round via an INFLIGHT {kind:"round"} entry (see the chase
// loop below). Every waiter processes the result exactly as if its own fetch
// returned it; a rejection propagates to every waiter, same as the wrapper's
// single-flight — failures are never cached, the retry goes live.
async function fetchRound(name, dohUrl, timeoutMs = DOH_TIMEOUT_MS) {
  const query = buildQuery(name);
  const txid = (query[0] << 8) | query[1];
  // Abort-bounded round-trip: a hanging bridge (connection accepted, no
  // answer) must fail fast as "timed out", never stall the worker. One
  // AbortController + one timer spans the whole round-trip — headers AND
  // body: the body read rides the same signal, so a bridge that answers
  // headers fast but drips the body one byte a second aborts at the same
  // 8s budget instead of getting a second 8s for the body (the old
  // Promise.race body timer allowed 2x timeoutMs per round-trip). The
  // timer is cleared in the finally, whichever side settles first, so
  // fast responses leave no dangling timer per round-trip.
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let resp, buf;
  try {
    resp = await fetch(dohUrl, {
      method: "POST",
      // RFC 8484 §4.2: the client MUST set Accept to application/dns-message.
      // We declare Content-Type for the wire body we send; this declares the
      // wire body we want back — a bridge that serves something else (wrong
      // endpoint, captive portal) should see the mismatch and refuse rather
      // than silently serving non-DNS we then have to reject.
      headers: { "Content-Type": "application/dns-message", "Accept": "application/dns-message" },
      body: query,
      signal: controller.signal,
    });
    if (!resp.ok) throw new Error(`DoH ${resp.status}`);
    // The bridge must actually speak DNS: a 200 carrying text/html (a wrong
    // endpoint, a captive portal, a login page) would otherwise fall through
    // to parseAnswers and fail as a confusing "Truncated DNS message" or
    // "Mismatched DNS transaction ID". Refuse a declared non-DNS
    // Content-Type here so the failure page names the real problem. A
    // missing header still resolves — some proxies strip it, and host-
    // permissioned extension fetches see the real header when it's sent.
    const ctype = resp.headers.get("Content-Type") || "";
    if (ctype && !/^\s*application\/dns-message\b/i.test(ctype)) {
      // Server-controlled echo guard (2026-10-08): the Content-Type value
      // comes from the bridge (wrong endpoint, captive portal, hostile
      // endpoint) and rode untruncated into the popup status line and the
      // failure page's data: URL. truncateEcho bounds the tail; the fixed
      // prefix stays byte-identical so the classifyResolveError bridge-class
      // regex (^(...|DoH bridge did not return a DNS response|...)) still
      // matches and the taxonomy is untouched.
      throw new Error(`DoH bridge did not return a DNS response (Content-Type: ${truncateEcho(ctype)})`);
    }
    // A legitimate DNS response is at most 64 KiB — a larger body is never a
    // DNS message, just a hostile or broken bridge wasting memory. Refuse it
    // on the declared Content-Length before buffering a multi-megabyte
    // payload, and again after buffering for the chunked case (no declared
    // length). Junk lengths (NaN) fall through to the post-buffer check.
    const clen = resp.headers.get("Content-Length");
    if (clen !== null && Number(clen) > MAX_DNS_MSG) {
      // Same server-controlled echo guard as the Content-Type above: a junk
      // 5000-digit Content-Length ("9999...") parses to Infinity and would
      // otherwise ride the full digit string into the failure message.
      throw new Error(`DoH response too large (${truncateEcho(clen)} bytes)`);
    }
    // The request signal is still armed: a stalled body aborts the same
    // timer and surfaces as an AbortError here, mapped to the timeout
    // error below — no second race, no second timer.
    buf = await resp.arrayBuffer();
  } catch (err) {
    if (err && err.name === "AbortError") {
      throw new Error(`DoH bridge timed out after ${timeoutMs}ms`);
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
  if (buf.byteLength > MAX_DNS_MSG) {
    throw new Error(`DoH response too large (${buf.byteLength} bytes)`);
  }
  // parseAnswers refuses a truncated header, a response carrying another
  // query's transaction ID, or an echoed question that isn't our question —
  // a crossed answer misresolves silently without these.
  const { ips, cname, ttl } = parseAnswers(buf, txid, query);
  return { ips, cname, ttl };
}

async function resolveCyberspaceInner(name, dohUrl, timeoutMs = DOH_TIMEOUT_MS) {
  if (typeof name !== "string" || !name.toLowerCase().endsWith(SUFFIX)) {
    throw new Error(`Not a .cyberspace name: ${name}`);
  }
  checkLabels(name);
  // The bridge URL arrives from the single-flight wrapper, which already
  // read it once and keyed the cache/INFLIGHT entry by it. Re-reading
  // storage here would be a second read of the same key per resolve — and
  // worse, a mid-resolve bridge change would fetch from the new bridge
  // while caching under the old one's key.
  // (The cache is checked per chase round at the top of the loop below —
  // the original name is round 0, so no separate pre-loop check is needed.)
  const cacheKey = `${dohUrl}|${name.toLowerCase()}`;
  // Chase CNAME aliases (depth-capped): registries may answer an alias
  // instead of an A record. Alias targets outside .cyberspace are refused —
  // the suffix guard stays absolute so the extension never becomes a
  // general-purpose DoH resolver, even at the registry's suggestion.
  // Loops fail fast: a registry answering a CNAME to the queried name
  // itself (or ping-ponging between two aliases) would otherwise burn all 3
  // chase round-trips before failing "Alias chain too deep".
  const seen = new Set([name.toLowerCase()]);
  // Fold the wire TTL across chase rounds: intermediate CNAME records and
  // the final A record can each carry their own TTL, and the cached mapping
  // must not outlive the shortest of them.
  let wireTtl = Infinity;
  for (let depth = 0; depth < 3; depth++) {
    // Per-round cache check: the pre-loop check only covered the ORIGINAL
    // name, but a chase can land on a name whose mapping is already warm —
    // from a previous direct resolve, or a concurrent sibling chase that
    // just finished — and the old code burned another full DoH round-trip
    // for it anyway. The chased name is checked under its own key before
    // every round, so a warm alias target short-circuits the chase. The hit
    // carries its own stored expiry (set when it was resolved directly),
    // and nothing is written under the ORIGINAL key here: the a->ip mapping
    // is only valid while the alias holds, and the folded wireTtl (the
    // CNAME record's lifetime) binds that, not the target's — the next
    // resolve of the alias name re-checks its own record live, then hits
    // the target's cache again. Same evict-on-changed-bridge discipline as
    // the wrapper: entries cached under a different endpoint are dropped,
    // never re-served.
    const roundKey = `${dohUrl}|${name.toLowerCase()}`;
    const roundCached = cacheCheck(roundKey, dohUrl);
    if (roundCached) return roundCached;
    // Per-round in-flight dedup: two concurrent chases of DIFFERENT aliases
    // can land on the same chased name in the same instant (resolves for
    // a.cyberspace and c.cyberspace, both CNAMEs to b) — the old code fetched
    // the target twice. The round's wire fetch registers under roundKey as a
    // {kind:"round"} entry; a sibling reaching the same name awaits the
    // registered promise and processes its {ips,cname,ttl} as its own round
    // result (same TTL folding, same CNAME validation, same write-under-its-
    // own-original-key discipline — the shared unit is only the wire
    // round-trip). Round 0 never registers or dedups: the wrapper
    // single-flights the original name's key already, and awaiting the
    // wrapper's full-resolve promise from inside the inner chase would
    // deadlock (inner awaiting outer awaiting inner). A wrapper-registered
    // full-resolve entry under this same key (a direct resolve of the target
    // racing the chase) is left alone — no dedup, no overwrite — so the
    // wrapper's settled-clear identity check keeps working and its
    // single-flight is never clobbered.
    let round;
    if (depth > 0) {
      const sib = INFLIGHT.get(roundKey);
      if (sib && sib.kind === "round") round = await sib.promise;
    }
    if (!round) {
      const p = fetchRound(name, dohUrl, timeoutMs);
      if (!INFLIGHT.has(roundKey)) {
        INFLIGHT.set(roundKey, { kind: "round", promise: p });
        const clearRound = () => {
          const e = INFLIGHT.get(roundKey);
          if (e && e.promise === p) INFLIGHT.delete(roundKey);
        };
        p.then(clearRound, clearRound);
      }
      round = await p;
    }
    const { ips, cname, ttl } = round;
    if (ttl < wireTtl) wireTtl = ttl;
    if (ips.length) {
      cachePut(cacheKey, ips[0], dohUrl, wireTtl);
      return ips[0];
    }
    if (cname) {
      if (!cname.toLowerCase().endsWith(SUFFIX)) {
        throw new Error(`Alias points outside .cyberspace: ${cname}`);
      }
      // Re-validate the chased name: the target came off the wire from a
      // registry, not from our preflight — a hostile label (underscore,
      // overlong, empty) must fail here instead of reaching buildQuery.
      checkLabels(cname);
      const target = cname.toLowerCase();
      if (seen.has(target)) throw new Error(`Alias loop detected: ${cname}`);
      seen.add(target);
      name = cname;
      continue;
    }
    throw new Error("No address found");
  }
  throw new Error("Alias chain too deep");
}

// Single-flight wrapper around the resolver: concurrent resolves for the same
// name share one DoH round-trip. Double-clicking a recent chip (or the popup
// and the address-bar guard firing in the same instant) previously launched
// two identical chases that both wrote the same cache entry — now the second
// caller awaits the first's promise. Keyed by the same cacheKey as the
// cache (bridge + lowercased name), so the first caller's bridge/timeout
// wins for the shared flight. The bridge is read from storage once here
// and handed into the inner — the fetch and the cache key can never
// disagree on which bridge served the resolve. The in-flight entry is cleared in a settled
// handler on every outcome, so a failure leaves nothing behind: the retry
// goes live again, exactly like "failures are never cached".
const INFLIGHT = new Map();
async function resolveCyberspace(name, timeoutMs = DOH_TIMEOUT_MS) {
  if (typeof name !== "string" || !name.toLowerCase().endsWith(SUFFIX)) {
    throw new Error(`Not a .cyberspace name: ${name}`);
  }
  checkLabels(name);
  const dohUrl = await getDohUrl();
  // Grant pre-flight (2026-10-09): before the cache, so a stale cached
  // answer can never launder a resolve past the missing-origin grant.
  await grantPreflight(dohUrl);
  const cacheKey = `${dohUrl}|${name.toLowerCase()}`;
  const cached = cacheCheck(cacheKey, dohUrl);
  if (cached) return cached;
  const existing = INFLIGHT.get(cacheKey);
  // kind-less entries are full-resolve promises registered here; {kind:"round"}
  // entries are chase-round wire fetches registered by resolveCyberspaceInner
  // and settle to {ips,cname,ttl}, not an IP — awaiting one as a resolve
  // would hand the caller a DNS answer object. Ignored: this chase fetches
  // on its own, and the round's settled-clear owns its own entry.
  if (existing && !existing.kind) return existing;
  const p = resolveCyberspaceInner(name, dohUrl, timeoutMs);
  p.then(
    () => { if (INFLIGHT.get(cacheKey) === p) INFLIGHT.delete(cacheKey); },
    () => { if (INFLIGHT.get(cacheKey) === p) INFLIGHT.delete(cacheKey); }
  );
  INFLIGHT.set(cacheKey, p);
  return p;
}

// Error taxonomy for .cyberspace failures — shared by the popup and the
// options page (hoisted out of popup.js so both pages classify identically).
// Resolver errors are precise but internal; the UI should not show them raw.
// Classify so the page knows where the fault lies: the name (spelling/
// registration), the bridge (the endpoint setting), or the wire in between
// (everything else). `loc` is the word the bridge hint uses to point at the
// endpoint setting — "below" on the popup (the endpoint input sits under the
// health line), "above" on the options page (the endpoint input sits over the
// Check button).
// Spelling/registration problems are the name itself; alias-chain problems
// are the name's record data — both name-class (the fault lies with the
// name, not the bridge or the wire), but the health check re-routes them
// differently because the probe name is fixed.
const NAME_INPUT_PROBLEM = /^(Name not registered|Invalid \.cyberspace name|Not a \.cyberspace name)/;
const NAME_DATA_PROBLEM = /^Alias (points outside \.cyberspace|loop detected|chain too deep)/;
const NAME_NO_ADDRESS = /^No address found/;
// Wire-shape malformations the resolver itself raises — the bridge's bytes
// are wrong, not the name and not (directly) the endpoint setting. Name them
// plainly ("the bridge sent a malformed DNS message") instead of dumping
// resolver internals ("Mismatched DNS transaction ID") that a user can't act
// on. Note the odd-one-out: "Unexpected DNS opcode in response" reads "in
// response", not "in DNS response" like its siblings.
const WIRE_MALFORMED = /^(Truncated DNS message|Mismatched DNS transaction ID|Not a DNS response|DNS response (truncated|not authoritative|has reserved)|Unexpected (DNS opcode in response|question count in DNS response|authority records in DNS response|additional records in DNS response)|Response question does not match query|Conflicting CNAME)/;

// Dynamic-string i18n for the taxonomy hints — first sub-bite of the i18n
// thread's third bite (2026-10-08). chrome.i18n.getMessage(key, [loc]) is the
// lookup ($1 replaces the named $LOC$ placeholder declared in messages.json);
// any miss fails closed to the hard-coded English template with the same
// $1 substitution applied by hand, so a stub harness, a missing key, or a
// throwing getMessage can never change what the user sees today. Status
// lines (popup/options) and the background failure page were the remaining
// sub-bites (all done 2026-10-08).
function tHint(key, fallback, substitutions) {
  try {
    if (typeof chrome !== "undefined" && chrome && chrome.i18n &&
        typeof chrome.i18n.getMessage === "function") {
      const s = chrome.i18n.getMessage(key, substitutions);
      if (typeof s === "string" && s) return s;
    }
  } catch {
    // fall through to the English fallback
  }
  let s = fallback;
  if (Array.isArray(substitutions)) {
    for (let i = 0; i < substitutions.length; i++) {
      s = s.split("$" + (i + 1) + "$").join(String(substitutions[i]));
    }
  }
  return s;
}

function classifyResolveError(e, loc = "below") {
  const msg = e && e.message ? e.message : String(e);
  if (NAME_INPUT_PROBLEM.test(msg) || NAME_DATA_PROBLEM.test(msg))
    return { kind: "name", hint: tHint("hintNameSpelling", " — check the spelling, or claim it on the genesis node") };
  if (NAME_NO_ADDRESS.test(msg))
    // The bridge answered authoritatively; the name simply carries no
    // address records. Spelling/claiming advice would mislead, so this is
    // name-class with its own data hint.
    return { kind: "name", hint: tHint("hintNameNoAddress", " — the name has no address records on the bridge") };
  if (/^(DoH bridge timed out|DoH bridge error|DoH \d+|DoH response too large|DoH bridge did not return a DNS response|Configured DoH bridge)/.test(msg))
    return { kind: "bridge", hint: tHint("hintBridgeEndpoint", " — is the bridge endpoint set correctly $1$?", [loc]) };
  if (/^cannot read bridge setting/.test(msg))
    // The settings store rejected the read — the stored bridge may be
    // perfectly fine, so routing this to the endpoint hint (or letting it
    // fall to the wire fallback's "unreachable or not claimed" line) would
    // send the user to fix a setting that was fine. Name the store, not
    // the endpoint. (Same fault class background.js names on the
    // address-bar failure page; the popup Go path and health check never
    // got a branch for it — raw chrome rejections have no other prefix.)
    return { kind: "bridge", hint: tHint("hintBridgeUnreadable", " — the extension's settings could not be read; the bridge endpoint itself is probably fine") };
  if (/^Custom DoH bridge is missing its host permission/.test(msg))
    // The background worker's pre-flight fired: a stored custom bridge
    // predates the permission-gating pass, so the bridge fetch would die
    // as a network error. The endpoint is NOT the problem — the missing
    // origin grant is. Point at the popup's Grant button, not the endpoint
    // setting; misrouting to hintBridgeEndpoint replays the old
    // "resolver down" misdiagnosis the pre-flight exists to prevent.
    return { kind: "bridge", hint: tHint("hintGrantMissing",
      " — the bridge needs host access: open the extension popup and click \"$1$\"",
      [tHint("grantAccessLabel", "Grant access")]) };
  if (WIRE_MALFORMED.test(msg))
    // The bridge answered with bytes that aren't a well-formed DNS message
    // for our query: not the name's fault, so the canned third-line hint on
    // the failure page is replaced by this. Not re-routed to the endpoint
    // setting — a malformed reply on a user's own typed name is evidence
    // about the bridge's bytes, not necessarily about the setting.
    return { kind: "wire", hint: tHint("hintWireMalformed", " — the bridge sent a malformed DNS message") };
  return { kind: "wire", hint: "" };
}

// Health-check error taxonomy — same taxonomy as the resolve path, but
// scoped to the fixed probe name: the health check always resolves
// "genesis.cyberspace", so a name-class failure ("Name not registered") is
// not a spelling problem — it means the configured bridge answered as if
// it serves a different zone, which is a bridge problem. Re-route that
// hint to the endpoint setting instead of the input spelling.
function classifyHealthError(e, loc = "below") {
  const msg = e && e.message ? e.message : String(e);
  if (NAME_INPUT_PROBLEM.test(msg))
    // The spelling trio for the fixed probe name means the bridge answered
    // as if it serves a different zone — a bridge problem, not a spelling
    // one.
    return { kind: "bridge", hint: tHint("hintHealthUnknownProbe", " — the bridge doesn't know genesis.cyberspace: is the endpoint set correctly $1$?", [loc]) };
  if (NAME_DATA_PROBLEM.test(msg))
    // The bridge answered but served broken alias data for the fixed probe
    // name: still a bridge-data problem (the only thing the user can change
    // is the endpoint), so it keeps the generic bridge hint — the claim-it
    // Go-path hint makes no sense for the probe name.
    return { kind: "bridge", hint: tHint("hintBridgeEndpoint", " — is the bridge endpoint set correctly $1$?", [loc]) };
  if (NAME_NO_ADDRESS.test(msg))
    // The bridge answered authoritatively for the probe name but serves no
    // address records: the only user-changeable thing is the endpoint, so
    // re-route to the generic bridge hint like the alias trio.
    return { kind: "bridge", hint: tHint("hintBridgeEndpoint", " — is the bridge endpoint set correctly $1$?", [loc]) };
  if (WIRE_MALFORMED.test(msg))
    // The probe name is fixed and known-good on the genesis bridge, so a
    // malformed reply is the bridge's bytes misbehaving — bridge-class,
    // naming the malformation and the only thing the user can change.
    return { kind: "bridge", hint: tHint("hintWireMalformedHealth", " — the bridge sent a malformed DNS message: is the bridge endpoint set correctly $1$?", [loc]) };
  return classifyResolveError(e, loc);
}

// Static-text i18n for the popup/options pages — first bite of the i18n
// thread (2026-10-08). MV3 chrome.i18n.getMessage is the lookup (manifest
// carries default_locale "en"); applyI18n is a pure DOM walk so the stub
// harness can exercise it with a stubbed chrome.i18n and a fake document.
// data-i18n        → element.textContent
// data-i18n-ph     → input placeholder attribute
// data-i18n-title  → element title attribute
// data-i18n-html   → element.innerHTML — for static structured text with
//                     <code> spans (the options blurb). innerHTML is safe
//                     here because the string is a bundled locale message,
//                     never user/bridge data: dynamic strings (bridges, names,
//                     resolver errors) go through textContent/esc, never here.
// Missing keys fail closed: the hard-coded English already in the HTML is
// the fallback, so an i18n miss never blanks a label — and a page loaded
// without chrome.i18n (stub harness) or without a document simply no-ops
// instead of throwing. Out of scope for this bite: the dynamic JS strings
// (status lines, taxonomy hints) — next bite.
function applyI18n(root) {
  const doc = root || (typeof document !== "undefined" ? document : null);
  if (!doc || typeof doc.querySelectorAll !== "function") return;
  const hasI18n = typeof chrome !== "undefined" && chrome && chrome.i18n &&
    typeof chrome.i18n.getMessage === "function";
  const msg = (key) => {
    if (!hasI18n) return null;
    try {
      return chrome.i18n.getMessage(key) || null;
    } catch {
      return null;
    }
  };
  doc.querySelectorAll("[data-i18n]").forEach((el) => {
    const m = msg(el.getAttribute("data-i18n"));
    if (m) el.textContent = m;
  });
  doc.querySelectorAll("[data-i18n-ph]").forEach((el) => {
    const m = msg(el.getAttribute("data-i18n-ph"));
    if (m) el.setAttribute("placeholder", m);
  });
  doc.querySelectorAll("[data-i18n-title]").forEach((el) => {
    const m = msg(el.getAttribute("data-i18n-title"));
    if (m) el.setAttribute("title", m);
  });
  doc.querySelectorAll("[data-i18n-html]").forEach((el) => {
    const m = msg(el.getAttribute("data-i18n-html"));
    if (m) el.innerHTML = m; // missing key: hard-coded HTML stays
  });
}
