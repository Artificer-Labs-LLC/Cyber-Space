"""Beat-rate audit test: drives the REAL /api/v1/presence/beat via TestClient.
presence_beat rode no rate bucket — a beat-looping agent could serialize the
node under the global _db_lock. The fix adds _check_rate(f"beat:{agent['id']}")
with BEAT_LIMIT (30/60s): 30 beats pass, 31st 429s, a DIFFERENT agent's beat
still 200s (per-agent, not per-node)."""
import os, sys, tempfile
tmp = tempfile.mkdtemp()
os.environ["CYBERNET_DB_DIR"] = tmp
sys.path.insert(0, os.path.expanduser("~/workspace/cybernet"))
import app as cyber
from fastapi.testclient import TestClient

passed = []
def check(name, fn):
    try:
        fn()
        passed.append((name, True))
    except AssertionError as e:
        passed.append((name, False)); print("FAIL", name, e)

with TestClient(cyber.app) as c:
    alice = c.post("/api/v1/agents/register", json={"name": "alice"}).json()["api_key"]
    bob = c.post("/api/v1/agents/register", json={"name": "bob"}).json()["api_key"]
    ahdr = {"Authorization": f"Bearer {alice}"}
    bhdr = {"Authorization": f"Bearer {bob}"}

    codes = []
    def t_first_thirty_pass():
        for i in range(30):
            rr = c.post("/api/v1/presence/beat", headers=ahdr)
            codes.append(rr.status_code)
            assert rr.status_code == 200, (i, rr.status_code, rr.text)
    def t_thirty_first_is_429():
        rr = c.post("/api/v1/presence/beat", headers=ahdr)
        assert rr.status_code == 429, (rr.status_code, rr.text)
    def t_other_agent_unaffected():
        rr = c.post("/api/v1/presence/beat", headers=bhdr)
        assert rr.status_code == 200, (rr.status_code, rr.text)
    def t_still_here_in_presence():
        rr = c.get("/api/v1/presence")
        agents = {a["name"]: a for a in rr.json()["agents"]}
        assert agents["alice"]["status"] == "here", agents["alice"]["status"]
    def t_429_body_names_bucket():
        rr = c.post("/api/v1/presence/beat", headers=ahdr)
        assert "Rate limit exceeded" in rr.json()["detail"], rr.text

check("first_thirty_pass", t_first_thirty_pass)
check("thirty_first_is_429", t_thirty_first_is_429)
check("other_agent_unaffected", t_other_agent_unaffected)
check("still_here_in_presence", t_still_here_in_presence)
check("429_body_names_bucket", t_429_body_names_bucket)

print(f"{sum(1 for _, ok in passed if ok)}/{len(passed)} green")
sys.exit(0 if all(ok for _, ok in passed) else 1)
