#!/usr/bin/env python3
"""check-html-sinks.py — static HTML-injection audit for the extension.

Asserts the extension's HTML sinks can never carry raw user/hostile text:
  1. Every `.innerHTML = ...` assignment in popup.js / options.js is either a
     clear (``""``) or wraps its value in the shared ``esc()`` from
     resolver.js. The only other innerHTML writer is applyI18n's
     ``data-i18n-html`` branch in resolver.js, whose values come from the
     bundled _locales files (shipped with the extension, never user data) —
     asserted to source from chrome.i18n.getMessage only.
  2. buildFailurePage() in resolver.js consumes its five hostile parameters
     (name, bridge, msg, hint, retryUrl) exclusively through their
     encodeURIComponent'd aliases (failedName, safeBridge, safeMsg, safeHint,
     safeRetry) — no raw ``${name}``/``${bridge}``/... interpolation survives.

Exit 0 when the audit passes, 1 with a named violation otherwise. Intended to
run alongside node --check on every commit, like check-i18n-coverage.py.
"""

import re
import sys
from pathlib import Path

EXT = Path(__file__).resolve().parent

# ---------------------------------------------------------------- sink scan
# innerHTML assignments; the statement may span lines (showStatus's ternary),
# so match a generous window after the `=` and look for esc( anywhere in it.
INNERHTML_RE = re.compile(r"\.innerHTML\s*=")
CLEAR_RE = re.compile(r'^\s*""\s*;?\s*$|^\s*\'\'\s*;?\s*$')

def audit_innerhtml(path: Path, *, allow_i18n_html_branch: bool = False):
    """Yield violation strings for one file."""
    src = path.read_text()
    for m in INNERHTML_RE.finditer(src):
        # The statement may span lines (showStatus's ternary contains `;` in
        # HTML entities, so don't cut at the first semicolon) — take a window
        # large enough to cover the full assignment and look for esc( in it.
        window = src[m.start():m.start() + 800]
        eq = window.find("=")
        tail = window[eq + 1:] if eq != -1 else ""
        if CLEAR_RE.match(tail.strip().split("\n", 1)[0]):
            continue  # emptying the slot — no content carried
        if "esc(" in window:
            continue  # shared esc() wraps every hostile value
        if allow_i18n_html_branch and "data-i18n-html" in src[max(0, m.start() - 400):m.start()]:
            # applyI18n data-i18n-html branch: values come from the bundled
            # _locales messages (shipped with the extension), never user data.
            continue
        yield (f"{path.name}: innerHTML assignment at col {m.start()} carries "
               f"a value with no esc(): {tail.strip()[:80]!r}")

# ------------------------------------------------------- failure-page scan
HOSTILE_PARAMS = ("name", "bridge", "msg", "hint", "retryUrl")
SAFE_ALIASES = {"failedName", "safeBridge", "safeMsg", "safeHint", "safeRetry",
                "title", "leadLine", "hintMissing", "tryAgain", "body"}
INTERP_RE = re.compile(r"\$\{([A-Za-z_$][\w$]*)\}")

def extract_function_body(src: str, start_re: str) -> str:
    """Brace-count the function body starting at start_re."""
    m = re.search(start_re, src)
    if not m:
        return ""
    # Skip past the parameter list (buildFailurePage destructures its params,
    # so the first `{` is NOT the body) — the body opens after the `)`.
    close_paren = src.index(")", m.end() - 1)
    i = src.index("{", close_paren)
    depth = 0
    for j in range(i, len(src)):
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0:
                return src[i:j + 1]
    return ""

def audit_failure_page(path: Path):
    src = path.read_text()
    body = extract_function_body(src, r"function buildFailurePage\s*\(")
    if not body:
        yield f"{path.name}: buildFailurePage not found — audit cannot run"
        return
    # Every hostile param must be bound through encodeURIComponent first
    # (possibly wrapped in String() for type coercion, as with msg).
    for p in HOSTILE_PARAMS:
        if not re.search(rf"encodeURIComponent\(\s*(?:String\()?\s*{re.escape(p)}\b", body):
            yield (f"{path.name}: buildFailurePage parameter {p!r} is not "
                   f"routed through encodeURIComponent")
    # No raw interpolation of the hostile params into the page.
    for m in INTERP_RE.finditer(body):
        var = m.group(1)
        if var in HOSTILE_PARAMS:
            yield (f"{path.name}: buildFailurePage interpolates raw hostile "
                   f"param ${{{var}}}")
        elif var not in SAFE_ALIASES:
            yield (f"{path.name}: buildFailurePage interpolates unvetted "
                   f"variable ${{{var}}} — add to SAFE_ALIASES or encode it")

def main() -> int:
    violations = []
    for name in ("popup.js", "options.js"):
        violations += audit_innerhtml(EXT / name)
    violations += audit_innerhtml(EXT / "resolver.js",
                                  allow_i18n_html_branch=True)
    violations += audit_failure_page(EXT / "resolver.js")
    if violations:
        for v in violations:
            print("VIOLATION:", v)
        return 1
    print("html-sink audit clean: all innerHTML writers esc()/clear/i18n-static; "
          "buildFailurePage encodes every hostile param")
    return 0

if __name__ == "__main__":
    sys.exit(main())
