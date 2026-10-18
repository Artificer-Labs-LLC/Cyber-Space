"""Runs BF-EMPTY-CS (bf_empty_cs.py) in --suite mode against this tree:
the candidate countersign pin must pass all rows and mutant M-CS-SKIP-EMPTY
must die on CS-EMPTY. The as-is tree is red by design (live theft) and is
not run here; run `python bf_empty_cs.py` to see it."""
import os, subprocess, sys
here = os.path.dirname(os.path.abspath(__file__))
sys.exit(subprocess.call([sys.executable, os.path.join(here, "bf_empty_cs.py"), "--suite", "--tree", here]))
