#!/usr/bin/env python3
"""A scripted stand-in for the OpenClaw agent: no model, same path a real agent takes.

Run it in the agent's own account (e.g. `su - openclaw`), after `synthe-task new` in yours:

  /Library/Synthe/venv/bin/python agent_stand_in.py --packet /Users/Shared/Synthe/inbox/TASK.json \
      --repo ~/synthe-test

It talks to the broker only through synthe-mcp (the tools OpenClaw gets): validate and claim the signed
task, commit one file on the task's branch in the clone, propose the push. The broker stages it; the
approver then runs synthe-approve. Nothing here holds a key or a GitHub credential.
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path

MCP = "/Library/Synthe/venv/bin/synthe-mcp"
SOCKET = "unix:///var/db/synthe-run/broker.sock"


def git(repo, *args):
    env_args = ["-c", "user.name=Synthe stand-in agent", "-c", "user.email=agent@synthe.invalid"]
    return subprocess.run(["git", "-C", str(repo), *env_args, *args], check=True, capture_output=True,
                          text=True).stdout.strip()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--packet", required=True, help="the signed task from synthe-task (shared inbox)")
    ap.add_argument("--repo", required=True, help="the agent's clone of the repo")
    ap.add_argument("--receiver", default="openclaw")
    a = ap.parse_args(argv)
    packet = json.loads(Path(a.packet).read_text())
    repo = Path(a.repo).expanduser().resolve()
    branch = next(p["params"]["branch"] for p in packet["handoff"]["planned_actions"] if p["name"] == "push_branch")

    mcp = subprocess.Popen([MCP, "--broker-url", SOCKET, "--as-receiver", a.receiver],
                           stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)

    def tool(i, name, **args):
        mcp.stdin.write(json.dumps({"jsonrpc": "2.0", "id": i, "method": "tools/call",
                                    "params": {"name": name, "arguments": args}}) + "\n")
        mcp.stdin.flush()
        reply = json.loads(mcp.stdout.readline())
        if "error" in reply:
            raise SystemExit(f"{name}: {reply['error']}")
        return reply["result"]["structuredContent"]

    try:
        print("1. validate and claim the signed task (synthe_validate_handoff)")
        v = tool(1, "synthe_validate_handoff", packet=packet, wait_for_approval=True)
        if v.get("decision") != "ACCEPT":
            raise SystemExit(f"   REJECTED: {json.dumps(v.get('reasons'), indent=2)}")
        print(f"   ACCEPT, claimed")

        print(f"2. commit on {branch} in {repo}")
        git(repo, "fetch", "-q", "origin")
        base = git(repo, "symbolic-ref", "--short", "refs/remotes/origin/HEAD")
        git(repo, "checkout", "-q", "-B", branch, base)
        (repo / "src").mkdir(exist_ok=True)
        (repo / "src" / "hello.md").write_text(f"Hello from the Synthe stand-in agent.\n\nTask: {packet['handoff']['purpose']}\n")
        git(repo, "add", "src/hello.md")
        git(repo, "commit", "-q", "-m", "Add src/hello.md (Synthe stand-in agent)")
        sha = git(repo, "rev-parse", "HEAD")
        print(f"   {sha[:12]}")

        print("3. propose the push (synthe_propose_effect)")
        r = tool(2, "synthe_propose_effect", packet=packet, claim_token=v["claim"]["token"], action="push_branch",
                 params={"remote": "origin", "branch": branch, "commit": sha}, source=str(repo),
                 wait_for_approval=True)
        if r.get("decision") != "staged":
            raise SystemExit(f"   not staged: {json.dumps(r, indent=2)}")
        print("   STAGED: the broker holds it until the approver signs.\n")
        print("Now, in the approver's account, run synthe-approve.")
        return 0
    finally:
        mcp.stdin.close()
        mcp.wait(timeout=20)


if __name__ == "__main__":
    sys.exit(main())
