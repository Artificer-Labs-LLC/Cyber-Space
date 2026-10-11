"""secret-write belt — name keys are never world-readable, even briefly.

mint_name.py and rotate_name.py used to write secrets with write_text()
then chmod(0o600): under a normal umask the file sat at 0644 until the
chmod landed. _write_secret() (mint_name) closes the window — the file is
born 0600 (O_CREAT mode 0o600, O_EXCL for fresh writes, temp+os.replace
for overwrites).

  1. fresh write is born 0600 even under umask 022, content byte-exact
  2. existing path without overwrite -> FileExistsError, original untouched
  3. overwrite path -> new content, still 0600, no .tmp sibling left behind
  4. real CLI mint (rotate_name.main, HOME patched): .next born 0600
  5. real promote_rotation: .prev born 0600, .key 0600 after replace,
     .next gone, keys still derive the recorded pubkeys

Run: cd ~/workspace/cybernet && ./venv/bin/python hidden_files/secret-write-belt-test.py
"""
import os
import stat
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mint_name import _write_secret  # noqa: E402
import rotate_name  # noqa: E402
from fed.ed25519 import publickey  # noqa: E402

PASS = []
FAIL = []


def check(name, cond, extra=""):
    (PASS if cond else FAIL).append(name)
    print(("PASS " if cond else "FAIL ") + name + (f" — {extra}" if extra else ""))


def mode600(path):
    return stat.S_IMODE(os.stat(path).st_mode) == 0o600


old_umask = os.umask(0o022)
try:
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        # 1. born 0600 under umask 022
        p = d / "secret.key"
        _write_secret(p, "deadbeef")
        check("fresh-born-600-under-umask-022", mode600(p),
              oct(stat.S_IMODE(os.stat(p).st_mode)))
        check("fresh-content-exact", p.read_text() == "deadbeef")
        # 2. no clobber without overwrite
        try:
            _write_secret(p, "new")
            check("excl-refuses-existing", False, "no error raised")
        except FileExistsError:
            check("excl-refuses-existing", True)
        check("excl-original-untouched", p.read_text() == "deadbeef")
        # 3. overwrite path
        q = d / "env.file"
        q.write_text("junk")
        os.chmod(q, 0o644)
        _write_secret(q, "replaced", overwrite=True)
        check("overwrite-600", mode600(q))
        check("overwrite-content", q.read_text() == "replaced")
        check("overwrite-no-tmp-left", not (d / "env.file.tmp").exists())

        # 4+5. real CLI mint + promote through the fixed sites
        home = d / "home"
        home.mkdir()
        os.environ["HOME"] = str(home)
        label = "secrettest"
        seed = os.urandom(32)
        cdir = home / ".cyberspace"
        cdir.mkdir(parents=True, exist_ok=True)
        kp = cdir / f"{label}-name.key"
        _write_secret(kp, seed.hex())  # pre-existing operator key
        rc = rotate_name.main([label])
        check("cli-mint-ok", rc == 0, f"rc={rc}")
        nxt = cdir / f"{label}-name.key.next"
        check("cli-mint-next-born-600", nxt.exists() and mode600(nxt))
        rec = cdir / f"{label}-rotate.json"
        check("cli-mint-record-public", rec.exists() and
              stat.S_IMODE(os.stat(rec).st_mode) != 0o600,
              "rotation record is served, not a secret")
        ok, msg = rotate_name.promote_rotation(label, cdir)
        check("promote-ok", ok, msg[:80])
        prev = cdir / f"{label}-name.key.prev"
        check("promote-prev-born-600", prev.exists() and mode600(prev))
        check("promote-key-600", mode600(kp))
        check("promote-next-gone", not nxt.exists())
        old_pub = publickey(seed).hex().lower()
        check("promote-prev-derives-old-pub",
              publickey(bytes.fromhex(prev.read_text().strip())).hex().lower() == old_pub)
finally:
    os.umask(old_umask)

print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
sys.exit(1 if FAIL else 0)
