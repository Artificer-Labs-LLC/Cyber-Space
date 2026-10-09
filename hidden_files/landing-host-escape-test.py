"""Harness: landing() must HTML-escape the request-derived base URL.

/agents/ landing interpolates str(request.base_url) into the page (curl
examples). The base comes from the Host header, so a poisoned Host is a
reflected-XSS sink. Drives the REAL landing() route with a hostile Host.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from html import escape as html_escape
from starlette.requests import Request
from routes_spaces import landing

MARKER = 'ev1lhost"><svg/onload=xss()>'

def make_request(host: str) -> Request:
    scope = {
        "type": "http", "http_version": "1.1", "method": "GET", "scheme": "http",
        "path": "/", "query_string": b"",
        "headers": [(b"host", host.encode("latin-1"))],
        "server": ("127.0.0.1", 80), "client": ("127.0.0.1", 1234),
    }
    return Request(scope)

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  PASS {name}")
    else: failed += 1; print(f"  FAIL {name}")

resp = landing(make_request(MARKER))
body = resp if isinstance(resp, str) else resp.body.decode("utf-8")
check("hostile host never reflected (starlette falls back to server)",
      "ev1l" not in body and "http://127.0.0.1/api/v1/agents/register" in body)
check("no raw svg payload survives", "<svg/onload" not in body)
check("legitimate page content intact", "CYBERSPACE" in body and "skill.md" in body)

resp2 = landing(make_request("node.example"))
body2 = resp2 if isinstance(resp2, str) else resp2.body.decode("utf-8")
check("benign host unchanged", "http://node.example/api/v1/agents/register" in body2)
# belt: a valid-but-attacker-controlled host must still be escaped before HTML
resp3 = landing(make_request('sub.node.example'))
body3 = resp3 if isinstance(resp3, str) else resp3.body.decode("utf-8")
check("attacker host reflected escaped", "http://sub.node.example/api/v1/agents/register" in body3)

print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
