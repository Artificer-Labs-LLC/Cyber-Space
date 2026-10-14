"""Belt: the dotted-numeric isdigit() gates refuse Unicode-digit spellings.

Three seats decide "dotted all-numeric but not a valid IPv4 literal =>
can never resolve/bind as written" with a bare str.isdigit() test:
  - resolver/daemon._daemon_config_warnings (CYBERNET_RESOLVER_BIND)
  - resolver/client.main (--server gate)
  - resolver/wiring/smoke.main (--server gate)

isdigit() is Unicode-aware: Arabic-Indic / fullwidth digits return True,
and so do characters int() refuses (superscript '²'). The question this
belt answers empirically: does a Unicode-digit spelling alias through
any of the three seats (read as a dialable/bindable address under a
second spelling), the way bare int() spellings aliased through the
port/TTL/expiry seats (1212c00..5618102)?

Expected (and asserted): every Unicode-digit, superscript, and mixed
spelling is REFUSED at all three seats, exactly like its ASCII
dotted-numeric twin — the isdigit() branch only ever routes to refusal,
and the hostname branch behind it is ASCII-gated per character, so no
spelling reaches a dial. Valid ASCII controls (127.0.0.1, localhost)
pass the daemon seat.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "resolver"))

os.environ.setdefault("CYBERNET_DB_DIR", "/tmp/cybernet-belt-db")

from resolver import daemon  # noqa: E402
from resolver import client  # noqa: E402
from resolver.wiring import smoke  # noqa: E402

passed = failed = 0


def check(name, cond):
    global passed, failed
    if cond:
        passed += 1
        print(f"  ok  {name}")
    else:
        failed += 1
        print(f"  FAIL {name}")


AR = "١٢٣.٤٥٦"          # Arabic-Indic 123.456
FW = "１２３.４５６"      # fullwidth 123.456
SUPER = "².²"            # superscripts: isdigit() True, int() refuses
MIXED = "١٢٣.example"    # one Unicode-digit label + one ASCII label
ASCII_BAD = "999.999.1.1"  # ASCII dotted-numeric, not an IPv4 literal

BAD = [AR, FW, SUPER, MIXED, ASCII_BAD]

# --- daemon BIND seat -------------------------------------------------
saved = os.environ.get("CYBERNET_RESOLVER_BIND")
try:
    for raw in BAD:
        os.environ["CYBERNET_RESOLVER_BIND"] = raw
        probs = daemon._daemon_config_warnings()
        check(f"daemon BIND refuses {raw!r}",
              any("CYBERNET_RESOLVER_BIND" in p for p in probs))
    for raw in ("127.0.0.1", "localhost", "::1"):
        os.environ["CYBERNET_RESOLVER_BIND"] = raw
        probs = daemon._daemon_config_warnings()
        check(f"daemon BIND accepts {raw!r}",
              not any("CYBERNET_RESOLVER_BIND" in p for p in probs))
finally:
    if saved is None:
        os.environ.pop("CYBERNET_RESOLVER_BIND", None)
    else:
        os.environ["CYBERNET_RESOLVER_BIND"] = saved

# --- client --server seat (bad argument = return 2, before any wire) --
for raw in BAD:
    rc = client.main(["alice.cyberspace", "--server", raw])
    check(f"client --server refuses {raw!r} (rc 2)", rc == 2)

# --- smoke --server seat (bad argument = return 1, before any wire) ---
# smoke.main() takes no argv parameter; it parses sys.argv.
_saved_argv = sys.argv
try:
    for raw in BAD:
        sys.argv = ["smoke", "--server", raw]
        rc = smoke.main()
        check(f"smoke --server refuses {raw!r} (rc 1)", rc == 1)
finally:
    sys.argv = _saved_argv

print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
