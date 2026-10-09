#!/usr/bin/env python3
"""check-extension-messaging.py — static message-channel audit for the extension.

Asserts the resolver extension opens NO runtime-message channel at all:
  - no chrome.runtime.onMessage / .onMessageExternal listener
  - no chrome.runtime.sendMessage / chrome.tabs.sendMessage sender
  - no chrome.runtime.connect / chrome.tabs.connect port channel
  - no window.postMessage / 'message' event listener in any page

If any of these appear the audit fails and names the file:line, so a
message-echo (cross-tab, cross-page, or page->background) surface can only
be added by first updating this guard. Exits 0 when the audit passes, 1
with a named violation otherwise. Intended to run alongside
check-html-sinks.py on every commit.

As of the audit date the background service worker talks to nobody: it
only handles webNavigation.onBeforeNavigate and never echoes anything.
"""

import re
import sys
from pathlib import Path

EXT = Path(__file__).resolve().parent

# Every API that opens a message channel a hostile page/tab/extension could
# reach or that the extension could echo secrets over.
FORBIDDEN = [
    re.compile(r"\bchrome\.runtime\.onMessage\b"),
    re.compile(r"\bchrome\.runtime\.onMessageExternal\b"),
    re.compile(r"\bchrome\.runtime\.sendMessage\b"),
    re.compile(r"\bchrome\.tabs\.sendMessage\b"),
    re.compile(r"\bchrome\.runtime\.connect\b"),
    re.compile(r"\bchrome\.tabs\.connect\b"),
    re.compile(r"\bpostMessage\s*\("),
    re.compile(r"""addEventListener\s*\(\s*['"]message['"]"""),
]

def strip_comments(src: str) -> str:
    """Remove // and /* */ comments so a comment mentioning an API isn't
    mistaken for a channel. String literals survive — none of the scanned
    files legitimately carry these identifiers inside strings."""
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.DOTALL)
    out = []
    for line in src.split("\n"):
        # // inside a URL ("https://...") is not a comment start
        m = re.search(r"(?<!:)//", line)
        out.append(line[:m.start()] if m else line)
    return "\n".join(out)

def main() -> int:
    violations = []
    files = sorted(EXT.glob("*.js")) + sorted(EXT.glob("*.html"))
    for path in files:
        code = strip_comments(path.read_text())
        for lineno, line in enumerate(code.split("\n"), 1):
            for pat in FORBIDDEN:
                if pat.search(line):
                    violations.append(
                        f"{path.name}:{lineno}: message channel opened: "
                        f"{line.strip()[:90]!r}")
                    break
    if violations:
        for v in violations:
            print("VIOLATION:", v)
        return 1
    print("extension-messaging audit clean: no runtime message channels "
          "anywhere in the extension (background echoes nothing)")
    return 0

if __name__ == "__main__":
    sys.exit(main())
