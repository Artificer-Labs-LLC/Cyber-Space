#!/usr/bin/env python3
"""mint_name shape predicates belt: _valid_mirror/_valid_label are bool
predicates — every refused input must come back False, never a
TypeError/AttributeError from iterating or measuring a non-string
(main() always passes argv strings, but the library seat is the
anyone-can-mint surface of primitives 1 naming + 6 client daemon).
Valid shapes must keep their exact verdicts.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mint_name  # noqa: E402

fails = 0


def _check(fn, arg, want, why):
    global fails
    try:
        got = fn(arg)
    except Exception as e:  # noqa: BLE001
        print(f"FAIL: {why} raised {type(e).__name__}: {e}")
        fails += 1
        return
    if got is not want:
        print(f"FAIL: {why} -> {got!r}, want {want!r}")
        fails += 1


for bad in (123, 1.5, True, None, b"http://x:8471", ["http://x"], []):
    _check(mint_name._valid_mirror, bad, False, f"_valid_mirror({bad!r})")
for good in ("http://127.0.0.1:8471", "https://node.example",
             "http://x:65535"):
    _check(mint_name._valid_mirror, good, True, f"_valid_mirror({good!r})")
for bad in ("", "ftp://x", "http://", "http://x:0", "http://x:65536",
            "http://x:abc", " http://x", "http://x/\nEVIL=1"):
    _check(mint_name._valid_mirror, bad, False, f"_valid_mirror({bad!r})")

for bad in (123, 1.5, True, b"foo", ["foo"], None):
    _check(mint_name._valid_label, bad, False, f"_valid_label({bad!r})")
_check(mint_name._valid_label, "foo-bar1", True, "_valid_label('foo-bar1')")
for bad in ("", "Foo", "a.b", "-a", "a-", "a" * 64):
    _check(mint_name._valid_label, bad, False, f"_valid_label({bad!r})")

# _hostd_env_text: a non-string in any position must refuse as
# ValueError, never an AttributeError from .rstrip() and never a
# stringified literal (CYBERNET_NAME_PRIVKEY=None) written into the
# key-bearing env body. Valid text keeps its exact active lines.
_good_env = mint_name._hostd_env_text("foo", "ab" * 32, "http://x:8471/")
for _line in ("CYBERNET_HOSTED_NAME=foo\n",
              "CYBERNET_NAME_PRIVKEY=" + "ab" * 32 + "\n",
              "CYBERNET_MIRROR_URL=http://x:8471\n"):
    if _line not in _good_env:
        print(f"FAIL: valid _hostd_env_text missing {_line!r}")
        fails += 1
for _args in ((123, "ab" * 32, "http://x"), ("foo", None, "http://x"),
              ("foo", 123, "http://x"), ("foo", "ab" * 32, None),
              ("foo", "ab" * 32, 123), (None, "ab" * 32, "http://x")):
    try:
        mint_name._hostd_env_text(*_args)
        print(f"FAIL: _hostd_env_text{_args!r} did not refuse")
        fails += 1
    except ValueError:
        pass
    except Exception as e:  # noqa: BLE001
        print(f"FAIL: _hostd_env_text{_args!r} raised "
              f"{type(e).__name__}, want ValueError")
        fails += 1

if fails:
    print(f"test_mint_name: {fails} FAIL")
    sys.exit(1)
print("test_mint_name: OK")
