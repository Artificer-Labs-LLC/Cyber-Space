"""Chain-following client belt (primitive 4, identity): resolve_chain.py.

Drives the REAL /api/v1/names/{name}/rotations and /api/v1/names/{name}
routes on the REAL app (scratch DB, loopback uvicorn) against REAL Ed25519
keys, exercising resolve_chain.py the way an agent would:

  claim A -> rotate A->B -> rotate B->C ->
  walk the served chain offline with the original key pinned,
  with --with-live against the real binding,
  and against every way a chain can break (lineage gap, tampered sig,
  wrong-name hop, wrong pin).

A dead name (binding expired, chain intact) must read as dead, never as
broken. The genesis name is never touched; every key here is fresh and
dies with the run.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/resolve-chain-belt-test.py
"""

import datetime
import json
import os
import secrets
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

TMP = tempfile.mkdtemp(prefix="resolve-chain-")
os.environ["CYBERNET_DB_DIR"] = TMP
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

MIRROR_PORT = 18372
MIRROR = f"http://127.0.0.1:{MIRROR_PORT}"

import core  # noqa: E402
import uvicorn  # noqa: E402
from app import app  # noqa: E402
from fed import ed25519 as _fed_ed25519  # noqa: E402
import rotate_name  # noqa: E402
import resolve_chain  # noqa: E402

CASES = {"passed": 0, "failed": 0}


def check(name, cond, extra=""):
    if cond:
        CASES["passed"] += 1
        print(f"  ok  {name}")
    else:
        CASES["failed"] += 1
        print(f"  FAIL {name} {extra}")


_real_gate = core._reject_nonpublic_node_url


def _test_gate(url):
    if url.startswith(MIRROR):
        return "127.0.0.1"
    return _real_gate(url)


core._reject_nonpublic_node_url = _test_gate

config = uvicorn.Config(app, host="127.0.0.1", port=MIRROR_PORT, log_level="error")
server = uvicorn.Server(config)
threading.Thread(target=server.run, daemon=True).start()
for _ in range(100):
    try:
        urllib.request.urlopen(MIRROR + "/fed/ping", timeout=1)
        break
    except Exception:
        time.sleep(0.1)
else:
    check("mirror up", False)
    sys.exit(1)
check("mirror up", True)


def _keypair():
    seed = secrets.token_hex(32)
    return bytes.fromhex(seed), _fed_ed25519.publickey(bytes.fromhex(seed)).hex().lower()


def _fresh_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _mint_binding(label, priv, pub, issued_s, expires_s):
    sig = _fed_ed25519.sign(
        core._name_claim_payload(label, pub, issued_s, expires_s),
        priv, bytes.fromhex(pub)).hex().lower()
    return {"node_pubkey": pub, "issued_at": issued_s,
            "expires_at": expires_s, "signature": sig}


def _post(path, fields):
    body = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(MIRROR + path, data=body, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read())
        except Exception:
            return e.code, {"detail": str(e)}


def _get_json(path):
    with urllib.request.urlopen(MIRROR + path, timeout=8) as r:
        return json.loads(r.read())


def _cli(*argv, stdin_text=None):
    p = subprocess.run([sys.executable, "resolve_chain.py", *argv],
                       capture_output=True, text=True, input=stdin_text,
                       timeout=30)
    return p.returncode, p.stdout.strip(), p.stderr.strip()


# --- build a two-link chain: claim A -> rotate A->B -> rotate B->C --------
SK_A, PK_A = _keypair()
SK_B, PK_B = _keypair()
SK_C, PK_C = _keypair()
SK_Z, PK_Z = _keypair()  # stranger key, for the lineage-gap case
LABEL = "chainwalk"
LATER = _fresh_iso() and (datetime.datetime.now(datetime.timezone.utc)
                          + datetime.timedelta(days=30)).isoformat()

st, _ = _post("/api/v1/names/claim",
              {"name": LABEL, **_mint_binding(LABEL, SK_A, PK_A, _fresh_iso(), LATER)})
check("claim under A", st == 200, st)

rec_ab = rotate_name.mint_rotation(LABEL, SK_A, PK_B)
binding_b = _mint_binding(LABEL, SK_B, PK_B, _fresh_iso(), LATER)
st, out = _post("/api/v1/names/rotate", {
    "name": LABEL, "old_pubkey": rec_ab["old_pubkey"], "new_pubkey": rec_ab["new_pubkey"],
    "rotation_issued_at": rec_ab["issued_at"], "rotation_signature": rec_ab["signature"],
    "binding_issued_at": binding_b["issued_at"], "binding_expires_at": binding_b["expires_at"],
    "binding_signature": binding_b["signature"]})
check("rotate A->B accepted", st == 200, f"{st} {out}")

rec_bc = rotate_name.mint_rotation(LABEL, SK_B, PK_C)
binding_c = _mint_binding(LABEL, SK_C, PK_C, _fresh_iso(), LATER)
st, out = _post("/api/v1/names/rotate", {
    "name": LABEL, "old_pubkey": rec_bc["old_pubkey"], "new_pubkey": rec_bc["new_pubkey"],
    "rotation_issued_at": rec_bc["issued_at"], "rotation_signature": rec_bc["signature"],
    "binding_issued_at": binding_c["issued_at"], "binding_expires_at": binding_c["expires_at"],
    "binding_signature": binding_c["signature"]})
check("rotate B->C accepted", st == 200, f"{st} {out}")

doc = _get_json(f"/api/v1/names/{LABEL}/rotations")

# --- walk() on the served chain -------------------------------------------
terminal, hops = resolve_chain.walk(doc, LABEL, expect_original_key=PK_A)
check("walk walks clean, terminal == C",
      terminal == PK_C.lower() and len(hops) == 2, terminal)
check("hop fields pinned head and linkage",
      hops[0]["old_pubkey"] == PK_A.lower() and hops[0]["new_pubkey"] == PK_B.lower()
      and hops[1]["old_pubkey"] == PK_B.lower() and hops[1]["new_pubkey"] == PK_C.lower(),
      hops)

terminal2, _ = resolve_chain.walk(doc, LABEL)  # no pin: continuity alone
check("walk without pin still walks to C", terminal2 == PK_C.lower(), terminal2)


def _expect_broken(doc_mod, name, pin, needle):
    try:
        resolve_chain.walk(doc_mod, name, expect_original_key=pin)
    except resolve_chain.ChainError as e:
        return needle in str(e)
    return False


# wrong pin: the caller trusted a key that never headed this chain
check("wrong pinned original key breaks",
      _expect_broken(doc, LABEL, PK_Z, "not the pinned"), "")

# lineage gap: a REAL rotation signed by stranger Z (Z->C), spliced in as
# hop 1 — signature verifies, but Z never continues B.
rec_zc = rotate_name.mint_rotation(LABEL, SK_Z, PK_C)
gap_rows = [dict(doc["rotations"][0]),
            {"old_pubkey": rec_zc["old_pubkey"], "new_pubkey": rec_zc["new_pubkey"],
             "issued_at": rec_zc["issued_at"], "signature": rec_zc["signature"],
             "accepted_at": "x"}]
check("lineage gap breaks the walk",
      _expect_broken({"name": LABEL, "rotations": gap_rows}, LABEL, PK_A, "lineage gap"), "")

# tampered signature: hop 0 no longer vouched by its old key
bad_rows = [dict(doc["rotations"][0]), dict(doc["rotations"][1])]
sig = bad_rows[0]["signature"]
bad_rows[0]["signature"] = sig[:-1] + ("0" if sig[-1] != "0" else "1")
check("tampered designation signature breaks the walk",
      _expect_broken({"name": LABEL, "rotations": bad_rows}, LABEL, PK_A, "signature"), "")

# wrong-name hop: a real rotation for ANOTHER label spliced into this chain.
# The walker names the problem precisely (a naming-the-sides reason); the
# signature would fail too — the name is inside the signed payload — but
# the name check runs first, mirroring verify_name's pin semantics.
rec_other = rotate_name.mint_rotation("otherlabel", SK_B, PK_C)
mixed_rows = [dict(doc["rotations"][0]),
              {"name": rec_other["name"],
               "old_pubkey": rec_other["old_pubkey"], "new_pubkey": rec_other["new_pubkey"],
               "issued_at": rec_other["issued_at"], "signature": rec_other["signature"],
               "accepted_at": "x"}]
check("cross-label replay breaks with a naming reason",
      _expect_broken({"name": LABEL, "rotations": mixed_rows}, LABEL, PK_A,
                     "not the queried"), "")

# empty chain is not a chain
try:
    resolve_chain.walk({"name": LABEL, "rotations": []}, LABEL, PK_A)
    check("empty rotations document breaks", False, "walked?!")
except resolve_chain.ChainError:
    check("empty rotations document breaks", True)

# --- the CLI against the live mirror --------------------------------------
rc, out, err = _cli(LABEL, "--mirror", MIRROR,
                    "--expect-original-key", PK_A, "--with-live")
check("CLI --with-live exits 0 on a clean chain", rc == 0, f"rc={rc} err={err}")
check("CLI names the terminal key", PK_C.lower()[:16] in out, out.splitlines()[-2:])
check("CLI reports live agreement", "terminal key" in out and "live binding" in out, out)

# stdin mode: fully offline, same verdict
rc, out, err = _cli("-", stdin_text=json.dumps(doc))
check("CLI stdin mode walks offline", rc == 0 and PK_C.lower() in out,
      f"rc={rc} err={err}")

# never-rotated name: no chain here, exit 1 not 2
rc, out, err = _cli("norotations-ever", "--mirror", MIRROR)
check("never-rotated name fails cleanly (exit 1)", rc == 1, f"rc={rc} err={err}")

# --- dead name: binding expired, chain intact ------------------------------
SK_D, PK_D = _keypair()
SK_E, PK_E = _keypair()
DYING = "dyingname"
st, _ = _post("/api/v1/names/claim",
              {"name": DYING, **_mint_binding(DYING, SK_D, PK_D, _fresh_iso(), LATER)})
check("dying name claimed under D", st == 200, st)
rec_de = rotate_name.mint_rotation(DYING, SK_D, PK_E)
binding_e = _mint_binding(DYING, SK_E, PK_E, _fresh_iso(), LATER)
st, out = _post("/api/v1/names/rotate", {
    "name": DYING, "old_pubkey": rec_de["old_pubkey"], "new_pubkey": rec_de["new_pubkey"],
    "rotation_issued_at": rec_de["issued_at"], "rotation_signature": rec_de["signature"],
    "binding_issued_at": binding_e["issued_at"], "binding_expires_at": binding_e["expires_at"],
    "binding_signature": binding_e["signature"]})
check("dying name rotated D->E", st == 200, f"{st} {out}")

# expire the live binding straight in the scratch DB — the server is idle
import sqlite3  # noqa: E402
db_path = os.path.join(TMP, "cybernet.db")
conn = sqlite3.connect(db_path)
conn.execute("UPDATE name_bindings SET expires_at=? WHERE name=?",
             ("2000-01-01T00:00:00+00:00", DYING))
conn.commit()
conn.close()
try:
    urllib.request.urlopen(MIRROR + f"/api/v1/names/{DYING}", timeout=8)
    check("expired binding reads absent", False, "still resolves")
except urllib.error.HTTPError as e:
    check("expired binding reads absent", e.code == 404, e.code)

rc, out, err = _cli(DYING, "--mirror", MIRROR, "--with-live")
check("dead name reads dead (exit 0), never broken",
      rc == 0 and "no live binding" in out, f"rc={rc} out={out} err={err}")
check("dead name's chain still walks to E", PK_E.lower()[:16] in out, out)

print(f"\n{CASES['passed']} passed, {CASES['failed']} failed")
sys.exit(1 if CASES["failed"] else 0)
