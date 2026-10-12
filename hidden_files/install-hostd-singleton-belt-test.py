"""Install -> hostd singleton belt — install-agent.sh must not evict a name.

/etc/cybernet-hostd/hostd.env is a singleton: hostd hosts exactly ONE
name from it. Before this belt, the installer's hostd step copied the
chosen env over the installed one unconditionally — re-running the
one-command install with another name's env (explicit --hostd-env or a
glob hit) silently evicted the previously hosted name: that name went
dark, the new one took its place, and the only trace was the final
"hostd active" line naming the NEW name. The rotate side learned this
lesson in stages (c57449f/8fd9375/5d9fe9f: a different name's env is
NOT touched); the installer had not.

Fix pinned here: a guard in the hostd step, BEFORE the copy, compares
the installed env's CYBERNET_HOSTED_NAME with the incoming env's —
both present and different -> refuse (exit 1, both names printed);
same name (the documented re-run-to-update path), no installed env,
or either side not naming a host -> copy proceeds.

Static rows pin the guard's presence and ordering; functional rows
extract the REAL guard block from the script, retarget its paths at a
temp dir, and run it under bash.

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/install-hostd-singleton-belt-test.py
"""
import os
import re
import subprocess
import sys
import tempfile

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
INSTALLER = os.path.join(REPO, "deploy", "install-agent.sh")

passed = failed = 0


def check(label, cond):
    global passed, failed
    if cond:
        passed += 1
        print(f"  ok  {label}")
    else:
        failed += 1
        print(f" FAIL {label}")


with open(INSTALLER) as f:
    inst = f.read()

# --- static: guard exists, is ordered before the copy, and refuses ---
guard_at = inst.find("already hosts")
copy_at = inst.find('install -m 0600 "$HOSTD_ENV" /etc/cybernet-hostd/hostd.env')
check("installer has a different-name guard", guard_at != -1)
check("guard sits BEFORE the env copy", 0 <= guard_at < copy_at)
check("guard compares the installed env's HOSTED_NAME",
      "grep -E '^CYBERNET_HOSTED_NAME=' /etc/cybernet-hostd/hostd.env" in inst)
check("guard compares the incoming env's HOSTED_NAME",
      "grep -E '^CYBERNET_HOSTED_NAME=' \"$HOSTD_ENV\"" in inst)
check("guard refuses (exit 1) instead of warning-and-continuing",
      re.search(r"refusing to overwrite it with.*?exit 1", inst, re.S) is not None)

# --- functional: run the real guard block against temp env files ---
m = re.search(
    r"(    # hostd hosts exactly ONE name.*?^    fi\n)", inst, re.S | re.M)
check("guard block extractable for functional run", m is not None)
guard = m.group(1) if m else ""

ENV = "CYBERNET_HOSTED_NAME={name}\nCYBERNET_NAME_PRIVKEY={key}\n"


def run_guard(installed_text, incoming_text):
    with tempfile.TemporaryDirectory() as td:
        installed = os.path.join(td, "hostd.env")
        incoming = os.path.join(td, "incoming.env")
        if installed_text is not None:
            with open(installed, "w") as f:
                f.write(installed_text)
        with open(incoming, "w") as f:
            f.write(incoming_text)
        script = guard.replace("/etc/cybernet-hostd/hostd.env", installed)
        script = 'HOSTD_ENV="%s"\nset -u\n%s' % (incoming, script)
        r = subprocess.run(["bash", "-c", script],
                           capture_output=True, text=True)
        return r


if guard:
    r = run_guard(ENV.format(name="alice", key="aa"),
                  ENV.format(name="bob", key="bb"))
    check("different installed name -> guard exits 1", r.returncode == 1)
    check("refusal names BOTH names",
          "alice.cyberspace" in r.stderr and "bob.cyberspace" in r.stderr)
    r = run_guard(ENV.format(name="alice", key="aa"),
                  ENV.format(name="alice", key="cc"))
    check("same name (re-run to update) -> guard passes", r.returncode == 0)
    r = run_guard(None, ENV.format(name="bob", key="bb"))
    check("no installed env -> guard passes", r.returncode == 0)
    r = run_guard("CYBERNET_NAME_PRIVKEY=aa\n",
                  ENV.format(name="bob", key="bb"))
    check("installed env names no host -> guard passes", r.returncode == 0)
    r = run_guard(ENV.format(name="alice", key="aa"),
                  "CYBERNET_NAME_PRIVKEY=bb\n")
    check("incoming env names no host -> guard passes", r.returncode == 0)

print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
