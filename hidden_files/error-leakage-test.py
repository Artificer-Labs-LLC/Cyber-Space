import os, sys, tempfile
os.environ["CYBERNET_DB_DIR"] = tempfile.mkdtemp()
sys.path.insert(0, "/home/hatch/workspace/cybernet")
from fastapi.testclient import TestClient
import app as appmod
c = TestClient(appmod.app, raise_server_exceptions=False)
checks = []
def check(name, cond, extra=""):
    checks.append((name, cond, extra))
    print(("PASS" if cond else "FAIL"), name, extra)

r = c.get("/api/v1/nope")
check("404 no traceback/path", r.status_code==404 and "Traceback" not in r.text and "home/hatch" not in r.text, r.status_code)
r = c.post("/api/v1/agents/register", json={"name": "x"})
check("register-name 400/422 no leak", r.status_code in (400,422) and "Traceback" not in r.text and 'File "' not in r.text, (r.status_code, r.text[:90]))
r = c.post("/api/v1/agents/register", json={"name": "BAD NAME!!", "pubkey": "00"*32, "node_url": "https://example.com"})
check("register bad-name no leak", r.status_code==400 and "Traceback" not in r.text, (r.status_code, r.text[:90]))
r = c.post("/api/v1/presence/beat")
b = r.text
check("beat 401 static", r.status_code==401 and "Traceback" not in b and 'File "' not in b, (r.status_code, b[:90]))
r = c.post("/api/v1/channels/none", data={"x": "y"*3_000_000})
check("413 static detail", r.status_code==413 and r.json().get("detail")=="Request body too large", r.status_code)
r = c.post("/api/v1/agents/register", content=b"{bad json", headers={"Content-Type":"application/json"})
check("bad-json no leak", r.status_code in (400,422) and "Traceback" not in r.text, r.status_code)
r = c.get("/api/v1/agents/register")
check("405 GET-on-POST no leak", r.status_code==405 and "Traceback" not in r.text, r.status_code)
r = c.get("/api/v1/directory", params={"cap": "bogus"})
check("directory cap 400/200 no leak", "Traceback" not in r.text and 'File "' not in r.text, r.status_code)
sys.exit(0 if all(ok for _,ok,_ in checks) else 1)
