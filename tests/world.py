"""Shared test world for the commit broker: a broker, a registry, a 'GitHub'
(bare repo) and an agent's clone, all on disk. Needs `git`, no network.
Keys here are throwaway test keys generated per test."""
import datetime as dt
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import handoff_check as hc      # noqa: E402
import synthe_commit as cm      # noqa: E402
import synthe_crypto as sc      # noqa: E402
import synthe_sign as ss        # noqa: E402

GIT_ENV = {"GIT_AUTHOR_NAME": "agent", "GIT_AUTHOR_EMAIL": "agent@example.test",
           "GIT_COMMITTER_NAME": "agent", "GIT_COMMITTER_EMAIL": "agent@example.test",
           "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}


def git(cwd, *args):
    env = {**os.environ, **GIT_ENV}
    return subprocess.run(["git", *args], cwd=cwd, env=env, check=True,
                          capture_output=True, text=True).stdout.strip()


def ts(delta):
    return (hc.now_utc() + delta).strftime("%Y-%m-%dT%H:%M:%SZ")


def mkkey(agent):
    secret = sc.generate_secret()
    key = {"agent": agent, "kid": f"{agent}-1", "alg": sc.ALG, "private_key": sc.b64u(secret)}
    pub = {"kid": key["kid"], "alg": sc.ALG, "public_key": sc.b64u(sc.public_key(secret))}
    return {**key, "_secret": secret}, pub


def codes(receipt):
    return {r["code"] for r in receipt["reasons"]}


class World:
    """A broker, a registry, a 'GitHub' (bare repo) and an agent's clone."""

    def __init__(self, tmp: Path, branches=("feature/*", "main"), policy=None):
        self.tmp = tmp
        self.keys, pubs = {}, {}
        for a in ("planner", "builder", "rishab", "mallory", "synthe-broker"):
            self.keys[a], pubs[a] = mkkey(a)
        builder_policy = {
            "allowed_tools": ["read_repo", "edit_files", "run_tests", "git_push"],
            "forbidden": ["force_push"],
            "approval_required_for": ["git_push"],
            "trusted_approvers": ["rishab"],
            "budget": {"tokens": 200000, "usd": 10, "minutes": 120},
            "require_signatures": True, "require_signed_approvals": True,
            "require_planned_actions": True,
            "allowed_paths": ["src/**", "tests/**", "docs/**"],
            "forbidden_paths": ["src/secrets/**"],
            "defaults": {"owned_paths": ["src/**", "tests/**"], "output_schema": "code_change.v1",
                         "budget": {"tokens": 100000, "usd": 5, "minutes": 60}}}
        builder_policy.update(policy or {})
        self.registry = {"agents": {
            "planner": {"role": "sender", "keys": [pubs["planner"]]},
            "builder": {"role": "receiver", "keys": [pubs["builder"]], "policy": builder_policy},
            "rishab": {"role": "approver", "kind": "human", "keys": [pubs["rishab"]]},
            "mallory": {"role": "untrusted human", "kind": "human", "keys": [pubs["mallory"]]},
            "synthe-broker": {"role": "commit broker", "kind": "service", "keys": [pubs["synthe-broker"]]},
        }}
        self.save_registry()
        (tmp / "workspace").mkdir()
        (tmp / "workspace" / "task.md").write_text("add a flag\n")
        key_file = tmp / "broker.key.json"
        key_file.write_text(json.dumps({k: v for k, v in self.keys["synthe-broker"].items() if k != "_secret"}))
        # "GitHub"
        self.remote = tmp / "remote.git"
        git(tmp, "init", "-q", "--bare", "-b", "main", str(self.remote))
        self.agent = tmp / "agent"
        git(tmp, "clone", "-q", str(self.remote), str(self.agent))
        (self.agent / "src").mkdir()
        (self.agent / "src" / "app.py").write_text("print('v1')\n")
        (self.agent / "README.md").write_text("# app\n")
        git(self.agent, "add", "-A")
        git(self.agent, "commit", "-qm", "init")
        git(self.agent, "push", "-q", "origin", "HEAD:main")
        self.config_path = tmp / "broker.json"
        self.config_path.write_text(json.dumps({
            "broker_id": "synthe-broker", "key": "broker.key.json", "registry": "registry.json",
            "ledger": "ledger.json", "receipts": "receipts.jsonl", "workspace": "workspace",
            "state_dir": "state", "source_roots": [str(self.agent)],
            # tests drive the broker in-process (dev mode); test_isolation.py
            # covers the isolated daemon
            "isolation": {"mode": "none"},
            "effects": {"git_push": {"remotes": {"origin": {"url": str(self.remote),
                                                            "branches": list(branches)}}}}}))
        self.cfg = cm.BrokerConfig(self.config_path)

    def save_registry(self):
        (self.tmp / "registry.json").write_text(json.dumps(self.registry))

    # -- packets ---------------------------------------------------------------
    def packet(self, idem="k1", branch="feature/x", approver="rishab", approve=True,
               pin_params=True, approval_exp=None, owned_paths=None, extra_actions=(),
               depends_on=None, expires=None):
        task = self.tmp / "workspace" / "task.md"
        h = {"schema_version": "0.1", "id": f"h-{idem}", "trace_id": f"t-{idem}",
             "idempotency_key": idem, "on_failure": "reject", "from": "planner", "to": "builder",
             "purpose": "add a flag and push it",
             "inputs": {"artifact_refs": [{"path": "task.md", "sha256": hc.sha256_file(task)}],
                        "state_revision": "rev-1"},
             "scope": {"forbidden": []},
             "authority": {"allowed_tools": ["edit_files", "git_push"],
                           "approval_required_for": ["git_push"], "approvals": []},
             "planned_actions": [{"name": "edit", "tool": "edit_files"},
                                 {"name": "push_branch", "tool": "git_push",
                                  "params": {"remote": "origin", "branch": branch}}, *extra_actions],
             "acceptance": {"expires_at": expires or ts(dt.timedelta(days=30)),
                            "required_evidence": ["test_output"],
                            "evidence": [{"kind": "test_output", "ref": "task.md"}]}}
        if owned_paths is not None:
            h["scope"]["owned_paths"] = owned_paths
        if depends_on is not None:
            h["depends_on"] = depends_on
        p = {"handoff": h}
        if approve:
            params = ss.planned_params(h, "push_branch") if pin_params else None
            ss.approve_packet(p, self.keys[approver], "push_branch",
                              approval_exp or ts(dt.timedelta(days=7)), params)
        return ss.sign_packet(p, self.keys["planner"])

    def check(self, packet, **kw):
        return hc.check(packet, registry=self.registry, ledger_path=self.tmp / "ledger.json",
                        workspace=self.tmp / "workspace", **kw)

    def claim(self, packet):
        v = self.check(packet)
        assert v["decision"] == "ACCEPT", v
        return v["claim"]["token"]

    # -- agent work ------------------------------------------------------------
    def commit(self, files: dict, msg="work", delete=()):
        for rel, text in files.items():
            p = self.agent / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text)
        for rel in delete:
            (self.agent / rel).unlink()
        git(self.agent, "add", "-A")
        git(self.agent, "commit", "-qm", msg)
        return git(self.agent, "rev-parse", "HEAD")

    def propose(self, packet, token, commit, branch="feature/x", action="push_branch", **extra):
        params = {"remote": "origin", "branch": branch, "commit": commit, **extra.pop("params", {})}
        proposal = {"packet": packet, "claim_token": token, "action": action, "params": params,
                    "source": extra.pop("source", str(self.agent)), **extra}
        return cm.propose(self.cfg, proposal)

    def remote_ref(self, branch):
        out = subprocess.run(["git", "ls-remote", str(self.remote), f"refs/heads/{branch}"],
                             capture_output=True, text=True).stdout.split()
        return out[0] if out else None

    def ledger(self):
        return json.loads((self.tmp / "ledger.json").read_text())

    def ledger_entry(self, idem="k1"):
        return self.ledger()[idem]

    def chain(self):
        return cm.verify_receipts(self.cfg.receipts_path, self.registry)
