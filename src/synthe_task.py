#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""synthe-task: give your agent a task as a signed Synthe handoff, in one command.

  synthe-task new "Fix the login redirect" --branch agent/login-fix [--home ~/.synthe] [--hours 24]

Builds a handoff from you to the agent (edit files, then push the branch, which needs your approval),
pins the task text by SHA-256, and signs it with your approver key (it asks for your passphrase). In
separate-user mode the broker validates the signed task and writes it into its workspace; dev mode
writes it directly. The packet is saved under HOME/tasks/. Hand that path to the agent; it validates
and claims the handoff, works, and proposes the push. You approve the push itself later, with
synthe-approve, after reading its diff.
"""
from __future__ import annotations

import argparse
import datetime as dt
import fnmatch
import hashlib
import json
import re
import os
import sys
import textwrap
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import synthe_client as scl  # noqa: E402
import synthe_sign as ss  # noqa: E402
import synthe_ui as sui  # noqa: E402


def _slug(text: str, limit: int = 40) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return (s[:limit].rstrip("-") or "task")


def _purpose(text: str) -> str:
    return " ".join(str(text).split())


def task_text(purpose: str, branch: str) -> str:
    return f"# Task\n\n{_purpose(purpose)}\n\nBranch: {branch}\n"


def setup_of(home: Path) -> dict:
    """What `synthe-init setup` wrote (setup.json and the registry): who sends, who receives, where the
    workspace is and what may be pushed. Works for dev isolation and for the macOS broker user."""
    import synthe_init as si
    info = si.read_setup(home)
    try:
        registry = json.loads(Path(info["registry"]).read_text())
        remote = info.get("remote")
        if remote is None:  # a dev setup from before setup.json
            config = json.loads(Path(info["broker_config"]).read_text())
            remote = ((config.get("effects") or {}).get("git_push") or {}).get("remotes", {}).get("origin") or {}
    except (OSError, json.JSONDecodeError, KeyError):
        raise SystemExit(f"no Synthe setup under {home}; run synthe-init setup first")
    agents = registry.get("agents") or {}
    humans = [n for n, a in agents.items() if a.get("kind") == "human"]
    receivers = [n for n, a in agents.items() if a.get("kind") == "agent"]
    if len(humans) != 1 or len(receivers) != 1:
        raise SystemExit("synthe-task handles one approver and one agent; write this packet by hand (docs/COMMIT.md)")
    policy = agents[receivers[0]].get("policy") or {}
    return {"sender": humans[0], "receiver": receivers[0], "remote": remote, "policy": policy,
            "workspace": Path(info["workspace"]).resolve(), "mode": info.get("mode", "dev"),
            "broker": info.get("broker")}


def build_task(home: Path, purpose: str, branch: str, hours: float = 24, now: dt.datetime | None = None,
               write_task: bool = True) -> tuple[dict, Path]:
    """The unsigned handoff and task path it pins. Dev mode writes directly; separate-user mode
    submits the signed packet and bytes to the broker after this returns."""
    purpose = _purpose(purpose)
    if not purpose:
        raise SystemExit("say what the task is, e.g. synthe-task new \"Fix the login redirect\" --branch agent/login")
    s = setup_of(home)
    patterns = s["remote"].get("branches") or []
    if not any(fnmatch.fnmatchcase(branch, p) for p in patterns):
        raise SystemExit(f"branch {branch!r} is not one the broker may push ({', '.join(patterns)})")
    max_ttl = s["policy"].get("max_ttl_hours")
    if not 0 < hours <= (max_ttl or hours):
        raise SystemExit(f"--hours must be between 0 and the receiver's maximum of {max_ttl}")
    now = now or dt.datetime.now(dt.timezone.utc)
    slug = _slug(purpose)
    stamp = now.strftime("%Y%m%d%H%M%S")
    repo = re.sub(r"\.git$", "", Path(str(s["remote"].get("url", "repo")).rstrip("/")).name) or "repo"
    rel = f"tasks/{stamp}-{slug}.md"
    task_file = s["workspace"] / rel
    content = task_text(purpose, branch)
    sha = hashlib.sha256(content.encode()).hexdigest()
    if write_task:
        task_file.parent.mkdir(parents=True, exist_ok=True)
        task_file.write_text(content)
    h = {"schema_version": "0.1", "id": f"h-{slug[:24]}-{stamp}", "trace_id": f"t-{slug[:24]}-{stamp}",
         "idempotency_key": f"{repo}:{branch}:{slug}", "on_failure": "reject",
         "from": s["sender"], "to": s["receiver"], "purpose": purpose,
         "inputs": {"artifact_refs": [{"path": rel, "sha256": sha}], "state_revision": stamp},
         "scope": {"forbidden": []},
         "authority": {"allowed_tools": ["edit_files", "git_push"], "approval_required_for": ["git_push"],
                       "approvals": []},
         "planned_actions": [{"name": "edit", "tool": "edit_files"},
                             {"name": "push_branch", "tool": "git_push",
                              "params": {"remote": "origin", "branch": branch}}],
         "acceptance": {"expires_at": (now + dt.timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "output_schema": "synthe.commit.v1",
                        "required_evidence": ["test_output"],
                        "evidence": [{"kind": "test_output", "ref": rel}]}}
    return {"handoff": h}, task_file


def issue(home: Path, purpose: str, branch: str, key: dict, hours: float = 24) -> Path:
    """Build, sign and hand over one task with an unlocked approver key. Returns where the agent reads
    the signed packet. In separate-user mode the broker validates it and writes the task file."""
    setup = setup_of(home)
    brokered = setup["mode"] == "macos-user"
    packet, task_file = build_task(home, purpose, branch, hours, write_task=not brokered)
    if key.get("agent") != packet["handoff"]["from"]:
        raise SystemExit(f"the approver key belongs to {key.get('agent')!r}, not {packet['handoff']['from']!r}")
    ss.sign_packet(packet, key)
    if brokered:
        result = scl.BrokerClient(setup["broker"]).call(
            "submit_task", packet=packet,
            content=task_text(packet["handoff"]["purpose"], branch),
        )
        if not isinstance(result, dict) or result.get("decision") != "ACCEPT":
            codes = ", ".join(r.get("code", "unknown") for r in (result or {}).get("reasons", []))
            raise SystemExit(f"the broker refused the signed task: {codes or 'unknown reason'}")
    out = home / "tasks" / f"{task_file.stem}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(packet, indent=2) + "\n")
    if brokered:  # the agent runs as another user and can't read HOME; the packet is signed, not secret
        inbox = Path(setup.get("inbox") or Path(setup["workspace"]).parent / "inbox")
        inbox.mkdir(parents=True, exist_ok=True)
        os.chmod(inbox, 0o755)  # only you write here; the agent reads
        out = inbox / out.name
        out.write_text(json.dumps(packet, indent=2) + "\n")
        os.chmod(out, 0o644)
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Give your agent a task as a signed Synthe handoff.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    n = sub.add_parser("new", help="create and sign a task")
    n.add_argument("purpose", help="what the agent should do, in one sentence")
    n.add_argument("--branch", required=True, help="the agent branch it pushes, e.g. agent/login-fix")
    n.add_argument("--hours", type=float, default=24, help="how long the task stays open (default 24)")
    n.add_argument("--home", default="~/.synthe")
    a = ap.parse_args(argv)
    home = Path(a.home).expanduser()
    setup_of(home)  # a missing or broken setup fails here, before the passphrase prompt
    key = ss.load_key(str(home / "approver.key.json"), require_encrypted=True)
    out = issue(home, a.purpose, a.branch, key, a.hours)
    prompt = (f"Use the synthe skill. Your Synthe task is the handoff in {out}. Validate it with "
              f"wait_for_approval, work on branch {a.branch} in your clone of the repo, and propose the push "
              f"with synthe_propose_effect (source = your clone, wait_for_approval = true).")
    ui = sui.UI()
    if not ui.color:
        print(f"Task ready: {out}\n\nTell OpenClaw:\n  {prompt}\n\n"
              f"When it says the push is staged, run synthe-approve to read the diff and approve it.")
        return 0
    print(ui.header("task"))
    print(ui.check("PASS", "signed with your key", f"{a.branch}", 22))
    print(ui.kv("handoff", str(out), 10))
    print("\n" + ui.c("Tell OpenClaw", "brand", bold=True) + ui.c("  (paste this into its chat)", "muted"))
    for line in textwrap.wrap(prompt, 76):
        print(f"  {ui.c('│', 'muted')} {line}")
    print("\n" + ui.c("When it says the push is staged", "brand", bold=True))
    print(ui.cmd("SYNTHE_BROKER=unix:///var/db/synthe-run/broker.sock synthe-approve"
                 if setup_of(home)["mode"] == "macos-user" else "synthe-approve"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
