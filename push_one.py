#!/usr/bin/env python3
"""Push one file to Artificer-Labs-LLC/Cyber-Space main via github MCP push_files.
Usage: push_one.py <path> <repo-path> <commit-message>
"""
import json, subprocess, sys, os

path, repo_path, message = sys.argv[1], sys.argv[2], sys.argv[3]
with open(path, "r", encoding="utf-8") as f:
    content = f.read()
args = {
    "owner": "Artificer-Labs-LLC",
    "repo": "Cyber-Space",
    "branch": "main",
    "files": [{"path": repo_path, "content": content}],
    "message": message,
}
r = subprocess.run(
    ["/opt/hatch/bin/github", "call-tool", "--name", "push_files",
     "--arguments-json", json.dumps(args)],
    capture_output=True, text=True, timeout=180,
)
print("RC:", r.returncode)
print("STDOUT:", r.stdout[-2000:])
print("STDERR:", r.stderr[-2000:])
