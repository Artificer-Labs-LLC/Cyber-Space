#!/usr/bin/env python3
"""Push one file to Artificer-Labs-LLC/Cyber-Space main via github MCP push_files.
Usage: push_one.py <path> <repo-path> <commit-message>

Exit codes: 0 = the push call ran (its RC is printed)
            2 = usage / unreadable / oversize input (no push attempted)
"""
import json, stat, subprocess, sys, os

# The github CLI takes --arguments-json as ONE argv entry, and the
# kernel caps a single argv entry at MAX_ARG_STRLEN (128KB, including
# the NUL). A file larger than that ceiling can never fit — even with
# zero JSON escaping — so read at most _FILE_MAX+1 and refuse oversize
# cleanly instead of slurping the whole file into memory and dying
# with an unhandled E2BIG traceback at exec time. JSON escaping only
# grows the string (a quote costs two chars), so the encoded arguments
# get a second check against the same ceiling before any push runs.
_FILE_MAX = 131072
_ARGV_MAX = _FILE_MAX - 1

_GITHUB_BIN = os.environ.get("CYBERNET_GITHUB_BIN", "/opt/hatch/bin/github")


def main(argv):
    if len(argv) != 4:
        print("usage: push_one.py <path> <repo-path> <commit-message>",
              file=sys.stderr)
        return 2
    path, repo_path, message = argv[1], argv[2], argv[3]
    try:
        # Only a regular file may be opened: open() on a FIFO blocks
        # until a writer appears, so a FIFO (or device) at the input
        # seat hung this push helper forever instead of refusing at
        # exit 2 — the twin of the verify_name S_ISREG gate. os.stat
        # follows symlinks, so a symlink TO a regular file stays
        # valid while a symlink to a FIFO is refused; a missing path
        # raises OSError into the cannot-read refusal below as before.
        if not stat.S_ISREG(os.stat(path).st_mode):
            print(f"refused: {path} is not a regular file",
                  file=sys.stderr)
            return 2
        with open(path, "r", encoding="utf-8") as f:
            content = f.read(_FILE_MAX + 1)
    except OSError as e:
        print(f"refused: cannot read {path}: {e}", file=sys.stderr)
        return 2
    if len(content) > _FILE_MAX:
        print(f"refused: {path} exceeds {_FILE_MAX} bytes — a single "
              "--arguments-json argv entry cannot carry it; no push "
              "attempted (large files go via the Git Data API)",
              file=sys.stderr)
        return 2
    args = {
        "owner": "Artificer-Labs-LLC",
        "repo": "Cyber-Space",
        "branch": "main",
        "files": [{"path": repo_path, "content": content}],
        "message": message,
    }
    arguments_json = json.dumps(args)
    if len(arguments_json) > _ARGV_MAX:
        print(f"refused: encoded arguments exceed {_ARGV_MAX} bytes "
              "(JSON escaping grows the file past the single-argv "
              "ceiling); no push attempted (large files go via the "
              "Git Data API)", file=sys.stderr)
        return 2
    r = subprocess.run(
        [_GITHUB_BIN, "call-tool", "--name", "push_files",
         "--arguments-json", arguments_json],
        capture_output=True, text=True, timeout=180,
    )
    print("RC:", r.returncode)
    print("STDOUT:", r.stdout[-2000:])
    print("STDERR:", r.stderr[-2000:])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
