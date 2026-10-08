#!/usr/bin/env python3
"""Throwaway world for the isolation selftests (run as root or the operator).

Writes into a broker directory: a registry (planner, builder with its receiver
policy, an approver, the broker's public key), the workspace artifact, and the
git remote in broker.json; and writes one signed, approved handoff packet that
pushes to REMOTE_NAME:BRANCH. Every key except the broker's is generated here,
held in memory, and discarded: nothing can sign for this world afterwards.

  selftest_world.py [--src SRC] --broker-dir DIR --remote-url URL --packet OUT
                    [--new-broker-key] [--clients user,...] [--remote-name github]
                    [--branch feature/selftest]

--new-broker-key writes a fresh broker key and a complete broker.json
(isolation mode "user"); without it, the key and broker.json made by
`synthe_commit.py init` are kept and only the remote (and clients) are set.
"""
import argparse
import datetime as dt
import json
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
if "--src" in sys.argv[:-1]:  # before the imports below
    SRC = Path(sys.argv[sys.argv.index("--src") + 1])
sys.path.insert(0, str(SRC))
import handoff_check as hc   # noqa: E402
import synthe_crypto as sc   # noqa: E402
import synthe_sign as ss     # noqa: E402


def keypair(agent):
    secret = sc.generate_secret()
    return ({"agent": agent, "kid": f"{agent}-1", "alg": sc.ALG, "private_key": sc.b64u(secret), "_secret": secret},
            {"kid": f"{agent}-1", "alg": sc.ALG, "public_key": sc.b64u(sc.public_key(secret))})


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--src", help="the Synthe src/ to use (default: this repo's)")
    ap.add_argument("--broker-dir", required=True)
    ap.add_argument("--remote-url", required=True)
    ap.add_argument("--remote-name", default="github")
    ap.add_argument("--branch", default="feature/selftest")
    ap.add_argument("--packet", required=True)
    ap.add_argument("--new-broker-key", action="store_true")
    ap.add_argument("--clients", default="")
    a = ap.parse_args(argv)
    b = Path(a.broker_dir)
    keys, pubs = {}, {}
    for agent in ("planner", "builder", "approver"):
        keys[agent], pubs[agent] = keypair(agent)
    cfg_path = b / "broker.json"
    if a.new_broker_key:
        key, pubs["synthe-broker"] = keypair("synthe-broker")
        (b / "broker.key.json").write_text(json.dumps({k: v for k, v in key.items() if k != "_secret"}))
        cfg = {"broker_id": "synthe-broker", "key": "broker.key.json", "registry": "registry.json",
               "ledger": "ledger.json", "receipts": "receipts.jsonl", "workspace": "workspace",
               "state_dir": "state", "isolation": {"mode": "user"}}
    else:
        cfg = json.loads(cfg_path.read_text())
        key = json.loads((b / cfg["key"]).read_text())
        pubs["synthe-broker"] = {"kid": key["kid"], "alg": sc.ALG,
                                 "public_key": sc.b64u(sc.public_key(sc.unb64u(key["private_key"])))}
    if a.clients:
        cfg.setdefault("isolation", {"mode": "user"})["clients"] = a.clients.split(",")
    cfg.setdefault("effects", {}).setdefault("git_push", {}).setdefault("remotes", {})[a.remote_name] = {
        "url": a.remote_url, "branches": ["feature/*"]}
    cfg_path.write_text(json.dumps(cfg, indent=2))

    policy = {"allowed_tools": ["edit_files", "git_push"], "approval_required_for": ["git_push"],
              "trusted_approvers": ["approver"], "require_signatures": True, "require_signed_approvals": True,
              "require_planned_actions": True, "allowed_paths": ["src/**", "tests/**"],
              "defaults": {"owned_paths": ["src/**", "tests/**"], "output_schema": "code_change.v1",
                           "budget": {"tokens": 100000, "usd": 5, "minutes": 60}}}
    (b / cfg.get("registry", "registry.json")).write_text(json.dumps({"agents": {
        "planner": {"role": "sender", "keys": [pubs["planner"]]},
        "builder": {"role": "receiver", "keys": [pubs["builder"]], "policy": policy},
        "approver": {"role": "approver (throwaway selftest key)", "kind": "human", "keys": [pubs["approver"]]},
        "synthe-broker": {"role": "commit broker", "kind": "service", "keys": [pubs["synthe-broker"]]}}},
        indent=2))
    ws = b / cfg.get("workspace", "workspace")
    ws.mkdir(parents=True, exist_ok=True)
    (ws / "task.md").write_text("add a flag\n")

    def ts(days):
        return (hc.now_utc() + dt.timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")

    h = {"schema_version": "0.1", "id": "h-selftest", "trace_id": "t-selftest", "idempotency_key": "selftest:1",
         "on_failure": "reject", "from": "planner", "to": "builder", "purpose": "add a flag and push it for review",
         "inputs": {"artifact_refs": [{"path": "task.md", "sha256": hc.sha256_file(ws / "task.md")}],
                    "state_revision": "rev-1"},
         "scope": {"forbidden": []},
         "authority": {"allowed_tools": ["edit_files", "git_push"], "approval_required_for": ["git_push"],
                       "approvals": []},
         "planned_actions": [{"name": "edit", "tool": "edit_files"},
                             {"name": "push_branch", "tool": "git_push",
                              "params": {"remote": a.remote_name, "branch": a.branch}}],
         "acceptance": {"expires_at": ts(1), "required_evidence": ["test_output"],
                        "evidence": [{"kind": "test_output", "ref": "task.md"}]}}
    p = {"handoff": h}
    ss.approve_packet(p, keys["approver"], "push_branch", ts(1), ss.planned_params(h, "push_branch"))
    Path(a.packet).write_text(json.dumps(ss.sign_packet(p, keys["planner"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
