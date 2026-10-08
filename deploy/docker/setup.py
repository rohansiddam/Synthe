#!/usr/bin/env python3
"""Set up the broker container's volume in one command (isolation mode "container").

    python3 deploy/docker/setup.py \\
        --repo-url https://github.com/ACME/app.git --branches 'agent/*' \\
        --github-token-file ~/.synthe/github.token \\
        --approver alice=alice.pub.json \\
        --agent claude-code --allowed-paths 'src/**,tests/**,docs/**'

It writes the broker's key, broker.json, registry.json and the GitHub token file into a docker
volume owned by the container's unprivileged user, then prints the next commands. It never
reads a human's private key: each approver passes the public key `synthe-sign keygen` printed.
The token is read from a file and copied into the volume (0600); it is never printed or put in argv.

--stage DIR writes the volume's contents to DIR and stops (no docker): for review and for tests.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
import synthe_crypto as sc  # noqa: E402

BROKER_ID = "synthe-broker"
FORBIDDEN_PATHS = [".github/**", "**/*.key.json", "**/.env", "**/*.pem"]


def _pub_key(path: Path) -> dict:
    obj = json.loads(path.read_text())
    if "private_key" in obj:
        raise SystemExit(f"{path} holds a PRIVATE key; pass the public key synthe-sign keygen printed")
    keys = obj.get("keys") if isinstance(obj.get("keys"), list) else [obj]
    for k in keys:
        if not (isinstance(k, dict) and k.get("kid") and k.get("public_key") and k.get("alg") == sc.ALG):
            raise SystemExit(f"{path}: expected {{kid, alg: {sc.ALG}, public_key}}")
    return keys[0]


def _broker_key() -> tuple[dict, dict]:
    secret = sc.generate_secret()
    kid = f"{BROKER_ID}-1"
    return ({"agent": BROKER_ID, "kid": kid, "alg": sc.ALG, "private_key": sc.b64u(secret)},
            {"kid": kid, "alg": sc.ALG, "public_key": sc.b64u(sc.public_key(secret))})


def stage(a, out: Path) -> dict:
    """Write the volume's files into `out`. Returns a summary with no secrets in it."""
    approvers = {}
    for spec in a.approver:
        name, _, path = spec.partition("=")
        if not name or not path:
            raise SystemExit(f"--approver {spec!r}: expected NAME=PUBKEY.json")
        approvers[name] = _pub_key(Path(path).expanduser())
    branches = [b.strip() for b in a.branches.split(",") if b.strip()]
    if not branches:
        raise SystemExit("--branches: give at least one pattern, e.g. 'agent/*'")
    if any(b in ("*", "**", "main", "master") for b in branches):
        raise SystemExit("--branches: agents land on their own branches and a human merges; "
                         "'main', 'master' and '*' are refused")
    allowed = [p.strip() for p in a.allowed_paths.split(",") if p.strip()]
    if not allowed:
        raise SystemExit("--allowed-paths: give at least one glob, e.g. 'src/**'")

    out.mkdir(parents=True, exist_ok=True)
    (out / "keys").mkdir(exist_ok=True)
    (out / "workspace").mkdir(exist_ok=True)
    key, pub = _broker_key()
    keyfile = out / "keys" / f"{BROKER_ID}.key.json"
    keyfile.write_text(json.dumps(key, indent=2) + "\n")
    os.chmod(keyfile, 0o600)

    remote = {"url": a.repo_url, "branches": branches}
    if a.github_token_file:
        token = Path(a.github_token_file).expanduser().read_text().strip()
        if not token:
            raise SystemExit(f"{a.github_token_file} is empty")
        (out / "github.token").write_text(token + "\n")
        os.chmod(out / "github.token", 0o600)
        remote["token_file"] = "github.token"
    (out / "broker.json").write_text(json.dumps({
        "broker_id": BROKER_ID, "key": f"keys/{BROKER_ID}.key.json",
        "registry": "registry.json", "ledger": "ledger.sqlite3", "receipts": "receipts.jsonl",
        "workspace": "workspace", "state_dir": "state", "source_roots": [],
        "isolation": {"mode": "container"},
        "effects": {"git_push": {"max_commits": 200, "remotes": {a.remote_name: remote}}}}, indent=2) + "\n")

    agents = {BROKER_ID: {"role": "commit broker", "kind": "service", "keys": [pub]}}
    for name, k in approvers.items():
        agents[name] = {"role": "approver and sender", "kind": "human", "keys": [k]}
    agent_keys = [_pub_key(Path(a.agent_pubkey).expanduser())] if a.agent_pubkey else []
    agents[a.agent] = {"role": "receiver", "kind": "agent", "keys": agent_keys, "policy": {
        "allowed_tools": ["read_repo", "edit_files", "run_tests", "git_push"],
        "forbidden": ["force_push"],
        "approval_required_for": ["git_push"],
        "trusted_approvers": sorted(approvers),
        "budget": {"tokens": 500000, "usd": 25, "minutes": 240},
        "require_signatures": True, "require_signed_approvals": True,
        "require_planned_actions": True,
        "allowed_paths": allowed, "forbidden_paths": FORBIDDEN_PATHS,
        "defaults": {"owned_paths": allowed, "budget": {"tokens": 200000, "usd": 10, "minutes": 120}}}}
    (out / "registry.json").write_text(json.dumps({"agents": agents}, indent=2) + "\n")
    return {"broker_kid": pub["kid"], "approvers": sorted(approvers), "agent": a.agent,
            "remote": a.remote_name, "branches": branches, "allowed_paths": allowed,
            "token_file": bool(a.github_token_file)}


def sh(*cmd, **kw):
    return subprocess.run(cmd, check=True, text=True, capture_output=True, **kw)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--repo-url", required=True, help="the repo the broker pushes to")
    ap.add_argument("--remote-name", default="origin")
    ap.add_argument("--branches", required=True, help="comma-separated branch patterns agents may push")
    ap.add_argument("--github-token-file", help="file holding a fine-grained token (contents: write)")
    ap.add_argument("--approver", action="append", required=True, metavar="NAME=PUBKEY.json")
    ap.add_argument("--agent", required=True, help="the agent's id, e.g. claude-code")
    ap.add_argument("--agent-pubkey", help="the agent's public key, if it signs completions")
    ap.add_argument("--allowed-paths", required=True, help="comma-separated globs the agent may change")
    ap.add_argument("--volume", default="docker_synthe-data", help="the compose volume (default docker_synthe-data)")
    ap.add_argument("--image", default="synthe-broker:0.6")
    ap.add_argument("--stage", metavar="DIR", help="write the files to DIR and stop (no docker)")
    a = ap.parse_args(argv)

    if a.stage:
        summary = stage(a, Path(a.stage))
        print(json.dumps(summary, indent=2))
        return 0
    if shutil.which("docker") is None:
        raise SystemExit("docker is not available")
    tmp = Path(tempfile.mkdtemp(prefix="synthe-setup-"))
    try:
        summary = stage(a, tmp / "vol")
        exists = subprocess.run(["docker", "volume", "inspect", a.volume], capture_output=True).returncode == 0
        if exists:
            ls = subprocess.run(["docker", "run", "--rm", "--user", "root", "-v", f"{a.volume}:/synthe",
                                 "--entrypoint", "sh", a.image, "-c", "ls -A /synthe"],
                                capture_output=True, text=True)
            if ls.stdout.strip():
                raise SystemExit(f"volume {a.volume} already holds a broker; refusing to overwrite its "
                                 "key, ledger and receipts (remove it yourself if you mean to start over)")
        else:
            sh("docker", "volume", "create", a.volume)
        sh("docker", "run", "--rm", "--user", "root", "-v", f"{a.volume}:/synthe",
           "-v", f"{tmp / 'vol'}:/in:ro", "--entrypoint", "sh", a.image, "-c",
           "cp -a /in/. /synthe/ && chown -R synthe:synthe /synthe && chmod 700 /synthe "
           "&& chmod 600 /synthe/keys/*.key.json && (chmod 600 /synthe/github.token 2>/dev/null || true) "
           "&& chmod -R go-w /synthe")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print(json.dumps(summary, indent=2))
    print(f"\nvolume {a.volume} is ready. Next:\n"
          "  export SYNTHE_BROKER_TOKEN=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')\n"
          "  docker compose -f deploy/docker/compose.yaml up -d\n"
          "  SYNTHE_BROKER=tcp://127.0.0.1:8791 synthe-client hello", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
