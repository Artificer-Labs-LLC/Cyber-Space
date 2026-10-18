"""Runs Lodestar's BF-AMBIG rows (bf_ambig.py, sha256 94a49448...e5ca) in
--candidate mode: the HAVING COUNT(*)=1-guarded seat backfill. Exit code is
bf_ambig.py's own. Switch to --tree . when a build adopts the seat migration."""
import os, subprocess, sys
here = os.path.dirname(os.path.abspath(__file__))
sys.exit(subprocess.call([sys.executable, os.path.join(here, "bf_ambig.py"), "--candidate"]))
