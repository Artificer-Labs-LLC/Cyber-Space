#!/usr/bin/env python3
"""Deploy gate: every /fed path the node sends is served by this app.

Scans core.py and federation.py for outbound `/fed/...` URL literals
(concatenated onto a peer node_url, or passed to `_post_to_peer_path`).
Route decorators are inbound and are not part of the set. Each outbound
(method, path) is requested in-process on the mounted app, against a
throwaway DB. A 404 or a 405 fails that row.

Mutant: the mounted POST /fed/names/gossip route is removed from the
same app tree. That row must then fail, and the other rows must still
be served. The route is put back afterwards.
"""
import ast
import os
import re
import secrets
import sys
import tempfile

os.environ["CYBERNET_DB_DIR"] = tempfile.mkdtemp(prefix="fed-route-parity-")
# Keep identity off disk so this process never opens a .node.key.
os.environ["CYBERNET_NODE_PRIVKEY"] = secrets.token_hex(32)
os.environ.pop("CYBERNET_SEED_URL", None)
os.environ.pop("CYBERNET_PUBLIC_URL", None)
os.environ.pop("CYBERNET_PEER_ALLOWLIST", None)

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from fastapi.testclient import TestClient  # noqa: E402

import core  # noqa: E402
core.init_db()
import app as appmod  # noqa: E402
import federation  # noqa: E402

PASS = FAIL = 0

# Paths this tree sends today. The scanner must still find every one;
# anything new it finds is probed too.
REQUIRED = frozenset({
    ("GET", "/fed/ping"),
    ("POST", "/fed/announce"),
    ("POST", "/fed/channel/join"),
    ("POST", "/fed/channel/leave"),
    ("POST", "/fed/channel/push"),
    ("POST", "/fed/directory/delta"),
    ("POST", "/fed/gossip"),
    ("POST", "/fed/names/gossip"),
})

_FED_PATH = re.compile(r"^/fed/[A-Za-z0-9_./-]+$")
_GET_CALLS = frozenset({"_resolve_peer_get_json", "_peer_urlopen"})


def check(label, cond, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok  {label}")
    else:
        FAIL += 1
        print(f"  FAIL {label} {extra}")


def _fed_const(node):
    if (isinstance(node, ast.Constant) and isinstance(node.value, str)
            and _FED_PATH.fullmatch(node.value)):
        return node.value
    return None


def _call_name(node):
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def _path_in(node):
    """A `/fed/...` literal, or one concatenated onto a base URL."""
    if node is None:
        return None
    direct = _fed_const(node)
    if direct:
        return direct
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _fed_const(node.left) or _fed_const(node.right)
    return None


class _OutboundFinder(ast.NodeVisitor):
    """Outbound sends only. `@router.post("/fed/...")` is not a send."""

    def __init__(self):
        self.found = []

    def visit_Call(self, node):
        name = _call_name(node)
        target = None
        args_tuple = None
        for kw in node.keywords:
            if kw.arg == "target":
                target = kw.value
            elif kw.arg == "args":
                args_tuple = kw.value
        if (isinstance(target, ast.Name) and target.id == "_post_to_peer_path"
                and isinstance(args_tuple, ast.Tuple)
                and len(args_tuple.elts) >= 2):
            path = _fed_const(args_tuple.elts[1])
            if path:
                self.found.append(("POST", path))
        if name == "_post_to_peer_path" and len(node.args) >= 2:
            path = _fed_const(node.args[1])
            if path:
                self.found.append(("POST", path))
        if name == "Request" and node.args:
            path = _path_in(node.args[0])
            has_data = any(kw.arg == "data" for kw in node.keywords) or len(node.args) >= 2
            if path:
                self.found.append(("POST" if has_data else "GET", path))
        if name in _GET_CALLS and node.args:
            path = _path_in(node.args[0])
            if path:
                self.found.append(("GET", path))
        self.generic_visit(node)


def outbound_targets():
    """Unique (method, path) pairs core.py and federation.py send."""
    found = set()
    for name in ("core.py", "federation.py"):
        with open(os.path.join(HERE, name), encoding="utf-8") as fh:
            src = fh.read()
        finder = _OutboundFinder()
        finder.visit(ast.parse(src, filename=name))
        found.update(finder.found)
    return tuple(sorted(found))


def probe(client, method, path):
    if method == "GET":
        return client.get(path).status_code
    return client.post(path, json={}).status_code


def parity_rows(client, targets):
    rows = []
    for method, path in targets:
        status = probe(client, method, path)
        rows.append((method, path, status, status not in (404, 405)))
    return rows


def _mark_routes_changed():
    """The app serves federation.router through an included-router cache.
    Dropping a route only shows up on the next request after the version
    bump the router itself uses when its route list changes."""
    federation.router._mark_routes_changed()


def detach_post(path):
    """Remove every POST route at `path` from the router the app mounts."""
    routes = federation.router.routes
    removed = []
    keep = []
    for route in routes:
        methods = getattr(route, "methods", None) or set()
        if getattr(route, "path", None) == path and "POST" in methods:
            removed.append(route)
        else:
            keep.append(route)
    routes[:] = keep
    _mark_routes_changed()
    return removed


targets = outbound_targets()
print("outbound /fed paths:")
for method, path in targets:
    print(f"  {method} {path}")

check("scanner found outbound /fed paths", len(targets) >= 1, targets)
missing = REQUIRED - set(targets)
check("scanner found every known outbound /fed path",
      not missing, sorted(missing))
check("POST /fed/names/gossip is one of the paths the core sends",
      ("POST", "/fed/names/gossip") in targets)

client = TestClient(appmod.app)
rows = parity_rows(client, targets)
for method, path, status, ok in rows:
    check(f"{method} {path} served by this app ({status})", ok)

removed = detach_post("/fed/names/gossip")
try:
    mutant_rows = parity_rows(client, targets)
finally:
    federation.router.routes.extend(removed)
    _mark_routes_changed()

check("mutant detached the mounted POST /fed/names/gossip route",
      len(removed) >= 1, len(removed))
gossip = [row for row in mutant_rows
          if row[0] == "POST" and row[1] == "/fed/names/gossip"]
others = [row for row in mutant_rows if row not in gossip]
if gossip:
    g_method, g_path, g_status, g_ok = gossip[0]
    print(f"  mutant {g_method} {g_path} -> {g_status} "
          f"({'row fails' if g_status in (404, 405) else 'row still served'})")
else:
    g_status, g_ok = None, True
check("mutant (POST /fed/names/gossip removed) fails that row",
      len(gossip) == 1 and g_status in (404, 405) and not g_ok,
      gossip)
check("mutant leaves the other outbound rows served",
      bool(others) and all(ok for _, _, _, ok in others),
      [(m, p, s) for m, p, s, ok in others if not ok])
restored = parity_rows(client, targets)
check("restored app serves every outbound row again",
      all(ok for _, _, _, ok in restored),
      [(m, p, s) for m, p, s, ok in restored if not ok])

print(f"{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
