#!/usr/bin/env python3
"""Smoke test for the broker container (isolation mode "container").

Builds the image, starts it on 127.0.0.1 with a random bearer token, and from
the host (the "agent", holding no keys) runs hello, a claim and one push over
TCP. The "GitHub" is a bare repo inside the container's volume and every key
is a throwaway made for this run. The container and volume are removed after.

    python3 deploy/docker/smoke_test.py [--no-build] [--image synthe-broker:0.6]
"""
import argparse
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests"))
from world import World  # noqa: E402  (throwaway keys, registry, remote, agent clone)
import synthe_client as scl  # noqa: E402

FAILS = []


def sh(*args, check=True, env=None):
    return subprocess.run(args, capture_output=True, text=True, check=check, env=env, cwd=ROOT)


def check(name, ok, detail=""):
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail else ""))
    if not ok:
        FAILS.append(name)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--image", default="synthe-broker:0.6")
    ap.add_argument("--no-build", action="store_true")
    a = ap.parse_args()
    if shutil.which("docker") is None or sh("docker", "info", check=False).returncode != 0:
        print("docker is not available (install it, or start Docker Desktop)")
        return 2
    if not a.no_build:
        sh("docker", "build", "-q", "-f", "deploy/docker/Dockerfile", "-t", a.image, ".")
    info = sh("docker", "version", "--format", "{{.Server.Version}} {{.Server.Os}}/{{.Server.Arch}}").stdout.strip()
    print(f"Synthe broker container smoke test: image {a.image}, docker {info}\n")
    tag = secrets.token_hex(4)
    name = volume = f"synthe-smoke-{tag}"
    tmp = Path(tempfile.mkdtemp(prefix="synthe-smoke-"))
    started = False
    try:
        (tmp / "world").mkdir()
        w = World(tmp / "world")
        vol = tmp / "vol"
        vol.mkdir()
        for f in ("broker.key.json", "registry.json"):
            shutil.copy(w.tmp / f, vol / f)
        shutil.copytree(w.tmp / "workspace", vol / "workspace")
        shutil.copytree(w.remote, vol / "remote.git")
        (vol / "broker.json").write_text(json.dumps({
            "broker_id": "synthe-broker", "key": "broker.key.json", "registry": "registry.json",
            "ledger": "ledger.json", "receipts": "receipts.jsonl", "workspace": "workspace", "state_dir": "state",
            "isolation": {"mode": "container"},
            "effects": {"git_push": {"remotes": {"origin": {"url": "/synthe/remote.git",
                                                            "branches": ["feature/*"]}}}}}, indent=2))
        sh("docker", "volume", "create", volume)
        sh("docker", "run", "--rm", "--user", "root", "-v", f"{volume}:/synthe", "-v", f"{vol}:/in:ro",
           "--entrypoint", "sh", a.image, "-c",
           "cp -a /in/. /synthe/ && chown -R synthe:synthe /synthe && chmod 700 /synthe "
           "&& chmod 600 /synthe/broker.key.json && chmod -R go-w /synthe")
        token = secrets.token_urlsafe(24)  # passed by name only, so it never sits in argv
        sh("docker", "run", "-d", "--name", name, "-e", "SYNTHE_BROKER_TOKEN", "-p", "127.0.0.1::8791",
           "--read-only", "--tmpfs", "/tmp", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
           "-v", f"{volume}:/synthe", a.image, env={**os.environ, "SYNTHE_BROKER_TOKEN": token})
        started = True
        port = sh("docker", "port", name, "8791/tcp").stdout.split()[0].rsplit(":", 1)[1]
        url = f"tcp://127.0.0.1:{port}"
        client = scl.BrokerClient(url, token=token, timeout=60)
        hello, deadline = None, time.time() + 30
        while hello is None and time.time() < deadline:
            try:
                hello = client.call("hello")
            except scl.BrokerError:
                time.sleep(0.5)
        check("broker answers hello over tcp on 127.0.0.1", hello is not None, url)
        if hello is None:
            return 1
        iso = hello["isolation"]
        check("hello: isolation 'container' (declared by the operator, not verifiable from inside)",
              iso["mode"] == "container" and iso["verified"] is False)
        for bad in ("", "wrong-token"):
            try:
                scl.BrokerClient(url, token=bad).call("hello")
                refused = None
            except scl.BrokerError as exc:
                refused = exc.code
            check(f"{'no' if not bad else 'a wrong'} bearer token: unauthorized", refused == "unauthorized", refused)
        doc = sh("docker", "exec", name, "python3", "/opt/synthe/src/synthe_commit.py", "doctor",
                 "--config", "/synthe/broker.json", check=False)
        check("broker doctor inside the container: key 0600, state private", doc.returncode == 0,
              json.loads(doc.stdout or "{}").get("problems"))
        user = sh("docker", "exec", name, "id", "-un").stdout.strip()
        check("broker runs as the unprivileged user 'synthe'", user == "synthe", user)

        p = w.packet()
        v = client.call("claim", packet=p)
        check("agent claims the handoff over tcp: ACCEPT", v.get("decision") == "ACCEPT")
        sha = w.commit({"src/app.py": "print('from the container smoke test')\n"})
        r = scl.push(client, p, v["claim"]["token"], "push_branch", "origin", "feature/x", repo=w.agent)
        check("agent proposes a push (bundle over tcp): executed", r.get("decision") == "executed",
              ", ".join(x["code"] for x in r.get("reasons", [])))
        check("receipt: via tcp, isolation container, commits from a bundle",
              r.get("via") == "tcp" and (r.get("isolation") or {}).get("mode") == "container"
              and str(r.get("commits_from", "")).startswith("bundle sha256:"))
        remote = sh("docker", "exec", name, "git", "--git-dir", "/synthe/remote.git", "rev-parse",
                    "refs/heads/feature/x", check=False).stdout.strip()
        check("the container's remote has feature/x at the agent's commit", remote == sha, sha[:12])
        chain = client.call("receipts")
        check("receipt chain verifies (1 receipt)", chain["ok"] and chain["count"] == 1)
        print(f"\n      receipt #{r.get('seq')}: {r.get('decision')}, via {r.get('via')}, isolation "
              f"{(r.get('isolation') or {}).get('mode')}, {str(r.get('commits_from'))[:23]}...")
        print("\nbroker log:")
        for line in sh("docker", "logs", name, check=False).stderr.splitlines():
            print(f"  {line}")
    finally:
        if started:
            sh("docker", "rm", "-f", name, check=False)
        sh("docker", "volume", "rm", "-f", volume, check=False)
        shutil.rmtree(tmp, ignore_errors=True)
    print("\nSMOKE TEST PASS" if not FAILS else f"\nSMOKE TEST FAIL ({len(FAILS)} failed)")
    return 0 if not FAILS else 1


if __name__ == "__main__":
    sys.exit(main())
