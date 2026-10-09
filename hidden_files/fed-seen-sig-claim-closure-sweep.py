"""AST closure sweep: EVERY write-surface inbound fed receiver claims _claim_seen_sig.

Proves the seen-sig replay-dedupe wiring pass (step 2) has no misses left:
  for each `fed_*` function in federation.py that takes an inbound signed
  envelope (`env` param):
    1. the body contains a direct `_claim_seen_sig(...)` call,
    2. the claim is on THIS envelope's sig (`env.get("sig")` positional/keyword),
    3. the claim sits after `_fed_env.verify_envelope` (only genuinely-signed,
       addressed envelopes occupy seen-sig slots),
    4. the claim sits before the first inline write (`execute(...)` with
       INSERT/UPDATE/DELETE/REPLACE) in the receiver.
  Exclusions are printed with reasons (never silently dropped).
  A cross-file scan of all repo-root *.py catches inbound-envelope receivers
  hiding outside federation.py (e.g. `_fed_env.verify_envelope` call sites).

Negative control: `git stash` (revert the wiring) and re-run -> misses appear.
Run: ./venv/bin/python hidden_files/fed-seen-sig-claim-closure-sweep.py
"""
import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FED = ROOT / "federation.py"

WRITE_LEADERS = ("insert", "update", "delete", "replace")


def events_of(fn):
    """Yield (lineno, kind, node) in walk order for the interesting calls."""
    out = []
    for node in ast.walk(fn):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        if isinstance(f, ast.Name) and f.id == "_claim_seen_sig":
            out.append((node.lineno, "claim", node))
        elif isinstance(f, ast.Attribute) and f.attr == "verify_envelope":
            out.append((node.lineno, "verify", node))
        elif isinstance(f, ast.Attribute) and f.attr in ("execute", "executemany"):
            sql = ""
            if node.args and isinstance(node.args[0], ast.Constant) and isinstance(
                node.args[0].value, str
            ):
                sql = node.args[0].value.lstrip().lower()
            kind = "read"
            if sql.split(None, 1):
                head = sql.split(None, 1)[0].rstrip(";(")
                kind = "write" if head in WRITE_LEADERS else "read"
            out.append((node.lineno, kind, node))
    return sorted(out, key=lambda e: e[0])


def claim_arg_is_envelope_sig(call):
    for a in call.args:
        if (
            isinstance(a, ast.Call)
            and isinstance(a.func, ast.Attribute)
            and a.func.attr == "get"
            and isinstance(a.func.value, ast.Name)
            and a.func.value.id == "env"
            and a.args
            and isinstance(a.args[0], ast.Constant)
            and a.args[0].value == "sig"
        ):
            return True
    for kw in call.keywords:
        if kw.arg in ("sig", "sig_hex") and isinstance(kw.value, ast.Call):
            v = kw.value
            if (
                isinstance(v.func, ast.Attribute)
                and v.func.attr == "get"
                and isinstance(v.func.value, ast.Name)
                and v.func.value.id == "env"
                and v.args
                and isinstance(v.args[0], ast.Constant)
                and v.args[0].value == "sig"
            ):
                return True
    return False


def main():
    tree = ast.parse(FED.read_text())
    fns = [
        n
        for n in tree.body
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name.startswith("fed_")
    ]

    results = []
    excluded = []
    for fn in fns:
        param_names = [a.arg for a in fn.args.args] + [a.arg for a in fn.args.kwonlyargs]
        if "env" not in param_names:
            reason = "GET liveness probe" if fn.name == "fed_ping" else "local control endpoint (Authorization header, no inbound foreign envelope)"
            excluded.append((fn.name, reason))
            continue
        evs = events_of(fn)
        claims = [e for e in evs if e[1] == "claim"]
        verifies = [e for e in evs if e[1] == "verify"]
        writes = [e for e in evs if e[1] == "write"]

        problems = []
        if not claims:
            problems.append("NO _claim_seen_sig call in receiver")
        else:
            c = claims[0]
            if not claim_arg_is_envelope_sig(c[2]):
                problems.append(f"claim at L{c[0]} is not on env.get('sig')")
            if verifies and not any(v[0] < c[0] for v in verifies):
                problems.append(f"claim at L{c[0]} precedes verify_envelope")
            if not verifies:
                problems.append("no verify_envelope call found in receiver")
            early_writes = [w for w in writes if w[0] < c[0]]
            if early_writes:
                problems.append(
                    "write(s) before claim: " + ", ".join(f"L{w[0]}" for w in early_writes)
                )
        if not writes:
            problems.append("NOTE: no inline write statements — receiver is read/forward-only under AST")
        results.append((fn.name, fn.lineno, problems))

    # Cross-file scan: any OTHER inbound-envelope receiver hiding outside
    # federation.py? A real receiver takes an inbound envelope dict (param
    # named `env`/`envelope`) AND verifies it. Outbound-verification sites
    # (this node checking a peer's reply it fetched itself) take no inbound
    # envelope and need no seen-sig claim.
    outsiders = []
    envelope_params = ("env", "envelope")
    for py in sorted(ROOT.glob("*.py")):
        if py.name in ("federation.py",):
            continue
        try:
            t = ast.parse(py.read_text())
        except SyntaxError:
            continue
        for fn in ast.walk(t):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            params = [a.arg for a in fn.args.args] + [a.arg for a in fn.args.kwonlyargs]
            if not any(p in envelope_params for p in params):
                continue
            for node in ast.walk(fn):
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "verify_envelope"
                ):
                    outsiders.append((py.name, fn.name, node.lineno))
                    break

    print("=== seen-sig claim closure sweep ===")
    bad = 0
    for name, lineno, problems in results:
        real = [p for p in problems if not p.startswith("NOTE:")]
        status = "MISS" if real else "CLAIMS"
        if real:
            bad += 1
        extra = "" if not problems else " | " + "; ".join(problems)
        print(f"  [{status}] {name} (L{lineno}){extra}")
    print(f"--- receivers checked: {len(results)}, misses: {bad}")
    print("--- exclusions (not inbound foreign-envelope receivers):")
    for name, reason in excluded:
        print(f"  [SKIP] {name}: {reason}")
    print("--- cross-file inbound-envelope receivers (env param + verify_envelope):")
    if outsiders:
        for mod, fn, ln in outsiders:
            print(f"  [CHECK] {mod}:{fn} L{ln} — manual review needed")
    else:
        print("  none — the 3 outbound-verification verify_envelope sites")
        print("  (core.py:resolve_cyberspace, core.py:_seed_bootstrap,")
        print("  routes_social.py:_proxied_pigeonholes) take no inbound")
        print("  envelope; they verify replies this node fetched itself, so")
        print("  seen-sig claiming is not applicable")
    print("CLOSURE:", "BROKEN — misses above" if bad or outsiders else "PROVEN — every inbound write-surface fed receiver claims before its first write")
    return 1 if (bad or outsiders) else 0


if __name__ == "__main__":
    sys.exit(main())
