"""NSS glue coupling belt — the systemd-resolved drop-in is only as good as its coupling.

The stub-zone glue (deploy/resolverd-nss.conf, installed by install-agent.sh --nss)
routes *.cyberspace from EVERY program on the box to the per-agent daemon.
Five couplings must hold or the glue lies:

  1. conf DNS= port == daemon's real listen default (daemon._DEFAULT_PORT)
  2. conf DNS= port == client's real query default (client._default_port())
  3. conf Domains= is a ROUTING domain (~cyberspace) — without the ~ prefix
     resolved treats it as a search domain and the glue silently does nothing
  4. installer's install path + installed filename match what the conf describes
  5. installer verifies the route post-install (resolvectl domain ~cyberspace)
     and is loud when systemd-resolved isn't running (manual steps printed)

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/nss-glue-test.py
"""
import os
import re
import sys

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, REPO)

from resolver import daemon  # noqa: E402
from resolver import client  # noqa: E402

CONF = os.path.join(REPO, "deploy", "resolverd-nss.conf")
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


with open(CONF) as f:
    conf = f.read()
with open(INSTALLER) as f:
    inst = f.read()

daemon_port = daemon._DEFAULT_PORT
client_port = client._default_port()

# --- 1+2: port triple coupling ---
m = re.search(r"^DNS=(\S+)$", conf, re.M)
check("conf has exactly one DNS= line", m is not None)
dns_entry = m.group(1) if m else ""
m2 = re.fullmatch(r"127\.0\.0\.1:(\d+)", dns_entry)
check("DNS= is 127.0.0.1:<port> (resolved port-suffix form)", m2 is not None)
conf_port = int(m2.group(1)) if m2 else -1
check(f"conf port {conf_port} == daemon default {daemon_port}", conf_port == daemon_port)
check(f"conf port {conf_port} == client default {client_port}", conf_port == client_port)
check("installer documents the same face (127.0.0.1:5353)", "127.0.0.1:5353" in inst)

# --- 3: routing-domain semantics ---
m3 = re.search(r"^Domains=(\S+)$", conf, re.M)
check("conf has exactly one Domains= line", m3 is not None)
domains = m3.group(1) if m3 else ""
check("Domains= is routing-only ~cyberspace (not a search domain)",
      domains == "~cyberspace")

# --- 4: install path consistency ---
check("installer installs the shipped conf file",
      '"$REPO_DIR/deploy/resolverd-nss.conf"' in inst)
check("installer installs to /etc/systemd/resolved.conf.d/cybernet-agent.conf",
      "/etc/systemd/resolved.conf.d/cybernet-agent.conf" in inst)

# --- 5: post-install verification + loud fallback ---
check("installer verifies ~cyberspace in resolvectl domain after install",
      "resolvectl domain" in inst and "~cyberspace" in inst)
check("installer prints manual glue steps when resolved is absent",
      "cp $REPO_DIR/deploy/resolverd-nss.conf" in inst)
check("dnsmasq alternative is documented",
      "server=/cyberspace/127.0.0.1#5353" in inst)
check("conf is loopback-only (never widens the face)",
      "127.0.0.1" in dns_entry and not re.search(r"DNS=\S*(0\.0\.0\.0|\*:)", conf))

print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
