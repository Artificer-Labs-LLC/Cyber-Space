#!/usr/bin/env python3
"""i18n key-coverage check for the Cyberspace Resolver extension.

Fails (non-zero exit) if:
  1. any key used in JS (tHint("...") / chrome.i18n.getMessage("...")),
     HTML (data-i18n / data-i18n-ph / data-i18n-title / data-i18n-html), or
     manifest __MSG_...__ references has no entry in _locales/en/messages.json;
  2. any key defined in _locales/en/messages.json is referenced nowhere
     (an orphan string the user can never see).

The fail-closed policy means an orphan is dead weight and a missing key
silently falls back to the hard-coded English — both are drift worth
catching at commit time.

Run:  python3 extension/check-i18n-coverage.py   (from the repo root)
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent  # extension/

used = set()

# tHint("key", ...) and chrome.i18n.getMessage("key", ...) in JS
for f in sorted(ROOT.glob("*.js")):
    src = f.read_text()
    for pat in (r'tHint\(\s*"([^"]+)"', r'getMessage\(\s*"([^"]+)"'):
        used.update(re.findall(pat, src))

# data-i18n / -ph / -title / -html attributes in HTML
for f in sorted(ROOT.glob("*.html")):
    src = f.read_text()
    used.update(re.findall(r'data-i18n(?:-ph|-title|-html)?="([^"]+)"', src))

# __MSG_key__ substitution references in manifest.json
src = (ROOT / "manifest.json").read_text()
used.update(re.findall(r"__MSG_([A-Za-z0-9_]+)__", src))

defined = set(json.loads((ROOT / "_locales" / "en" / "messages.json").read_text()))

missing = sorted(used - defined)
orphans = sorted(defined - used)

print(f"used: {len(used)}, defined: {len(defined)}")
if missing:
    print(f"MISSING (used, not defined): {missing}")
if orphans:
    print(f"ORPHANS (defined, never used): {orphans}")

if missing or orphans:
    sys.exit(1)
print("i18n key coverage: clean — every used key defined, no orphans")
