#!/usr/bin/env python3
"""Time to the first approved push, phase by phase (step 4 of the OpenClaw plan).

  python scripts/time_to_first_push.py [--openclaw] [--install] [--out results.json]

Runs the whole product flow in a temporary directory, in dev isolation, with a local bare repo as the
remote: setup (keys, broker), optional OpenClaw wiring into a throwaway OPENCLAW_HOME, broker start,
a signed task, the agent's claim and proposal through the real synthe-mcp server over stdio, the
approval with the sealed key, the push, and receipt verification. It prints and saves the seconds
each phase took.

This is MACHINE time only: no model thinking, no human reading or typing. It's the floor under what
a person experiences. The person-in-the-loop number comes from timing a real first-time user (run (c)
in the plan); this script's numbers must never be quoted as that.
"""
from __future__ import annotations

import argparse
import contextlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import synthe_approve as sa  # noqa: E402
import synthe_broker as sb  # noqa: E402
import synthe_client as scl  # noqa: E402
import synthe_commit as cm  # noqa: E402
import synthe_init as si  # noqa: E402
import synthe_sign as ss  # noqa: E402
import synthe_task as st  # noqa: E402

PASS = "timing run passphrase, not a real one"
ENV = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
       "GIT_AUTHOR_NAME": "agent", "GIT_AUTHOR_EMAIL": "agent@example.invalid",
       "GIT_COMMITTER_NAME": "agent", "GIT_COMMITTER_EMAIL": "agent@example.invalid"}


def git(cwd, *args):
    return subprocess.run(["git", "-C", str(cwd), *args], env=ENV, capture_output=True, text=True, check=True).stdout.strip()


class Clock:
    def __init__(self):
        self.phases, self.t0 = [], time.monotonic()

    @contextlib.contextmanager
    def phase(self, name):
        t = time.monotonic()
        yield
        self.phases.append({"phase": name, "seconds": round(time.monotonic() - t, 3)})


def run(openclaw: bool, install: bool) -> dict:
    tmp = Path(tempfile.mkdtemp(prefix="synthe-ttfp-"))
    sock_dir = tempfile.mkdtemp(prefix="sy", dir="/tmp")
    clock = Clock()
    try:
        if install:
            with clock.phase("install (fresh venv + pip install)"):
                subprocess.run([sys.executable, "-m", "venv", str(tmp / "venv")], check=True)
                subprocess.run([str(tmp / "venv" / "bin" / "pip"), "install", "-q", str(ROOT)], check=True)
        remote, seed, clone, home = (tmp / n for n in ("remote.git", "seed", "clone", "home"))
        with clock.phase("test repo (bare remote + agent clone)"):
            subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(remote)], env=ENV, check=True)
            subprocess.run(["git", "clone", "-q", str(remote), str(seed)], env=ENV, check=True, capture_output=True)
            (seed / "src").mkdir()
            (seed / "src" / "app.py").write_text("print('hi')\n")
            git(seed, "add", "-A")
            git(seed, "commit", "-q", "-m", "init")
            git(seed, "push", "-q", "origin", "main")
            subprocess.run(["git", "clone", "-q", str(remote), str(clone)], env=ENV, check=True, capture_output=True)
        with clock.phase("synthe-init setup (sealed approver key, broker)"):
            home.mkdir()
            pub = si.approver_public_key(home, "human", passphrase=PASS)
            si.write_broker(home, repo_url=str(remote), branches=["agent/*"], allowed_paths=["src/**"],
                            approver="human", approver_pub=pub, agent="openclaw", token_file=None)
        if openclaw:
            oc_bin = si.find_openclaw()
            if oc_bin is None:
                raise SystemExit("--openclaw: the openclaw CLI was not found")
            with clock.phase("OpenClaw wiring (MCP server, plugin, skill)"):
                oc = si.OpenClaw(oc_bin, env={"OPENCLAW_HOME": str(tmp / "oc")})
                steps = si.wire_openclaw(oc, home, assume_yes=True)
                if not all(ok for _, ok, _ in steps):
                    raise SystemExit(f"OpenClaw wiring failed: {steps}")
        with clock.phase("broker start"):
            srv = sb.make_server(cm.BrokerConfig(home / "broker" / "broker.json"),
                                 socket_path=os.path.join(sock_dir, "b.sock"))
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            url = f"unix://{sock_dir}/b.sock"
            scl.BrokerClient(url).call("hello")
        with clock.phase("synthe-task (signed task)"):
            packet, _ = st.build_task(home, "Add a greeting to the app", "agent/greet")
            ss.sign_packet(packet, ss.load_key(str(home / "approver.key.json"), passphrase=PASS, require_encrypted=True))
        mcp = subprocess.Popen([sys.executable, str(ROOT / "src" / "synthe_mcp.py"), "--broker-url", url],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)

        def tool(i, name, **args):
            mcp.stdin.write(json.dumps({"jsonrpc": "2.0", "id": i, "method": "tools/call",
                                        "params": {"name": name, "arguments": args}}) + "\n")
            mcp.stdin.flush()
            return json.loads(mcp.stdout.readline())["result"]["structuredContent"]

        with clock.phase("agent: validate + claim (MCP)"):
            v = tool(1, "synthe_validate_handoff", packet=packet, wait_for_approval=True)
            assert v["decision"] == "ACCEPT", v
        with clock.phase("agent: commit on its branch"):
            git(clone, "checkout", "-q", "-B", "agent/greet", "origin/main")
            (clone / "src" / "greet.py").write_text("print('hello')\n")
            git(clone, "add", "-A")
            git(clone, "commit", "-q", "-m", "greet")
            sha = git(clone, "rev-parse", "HEAD")
        with clock.phase("agent: propose (bundle to broker, staged)"):
            r = tool(2, "synthe_propose_effect", packet=packet, claim_token=v["claim"]["token"], action="push_branch",
                     params={"remote": "origin", "branch": "agent/greet", "commit": sha},
                     source=str(clone), wait_for_approval=True)
            assert r["decision"] == "staged", r
        mcp.stdin.close()
        mcp.wait(timeout=20)
        human = scl.BrokerClient(url)
        with clock.phase("human: open the diff (staged_detail)"):
            [w] = sa.waiting_for_approval(human.call("staged")["staged"])
            detail = human.call("staged_detail", id=f"{w['idempotency_key']}/{w['action']}")
        with clock.phase("human: unlock key + sign + submit (push executes)"):
            key = ss.load_key(str(home / "approver.key.json"), passphrase=PASS, require_encrypted=True)
            out = human.call("submit_approval", approval=sa.build_approval(detail, key))
            assert [c["decision"] for c in out["commits"]] == ["executed"], out
        with clock.phase("verify the receipt chain"):
            chain = human.call("receipts", limit=50)
            assert chain["ok"], chain
        assert git(remote, "rev-parse", "refs/heads/agent/greet") == sha
        srv.shutdown()
        srv.server_close()
        total = round(time.monotonic() - clock.t0, 3)
        oc_version = None
        if openclaw:
            oc_version = subprocess.run([si.find_openclaw(), "--version"], capture_output=True, text=True).stdout.strip()
        return {"kind": "machine time only (no model, no human reading or typing)", "total_seconds": total,
                "phases": clock.phases, "receipts": chain["count"],
                "machine": platform.platform(), "cpu": platform.processor() or platform.machine(),
                "python": platform.python_version(), "openclaw": oc_version,
                "crypto_backend": __import__("synthe_crypto").BACKEND,
                "when": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
        shutil.rmtree(sock_dir, ignore_errors=True)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Time to the first approved push (machine time).")
    ap.add_argument("--openclaw", action="store_true", help="also wire a throwaway OpenClaw (needs the CLI)")
    ap.add_argument("--install", action="store_true", help="also time a fresh venv + pip install")
    ap.add_argument("--out", help="write the JSON result here too")
    a = ap.parse_args(argv)
    result = run(a.openclaw, a.install)
    text = json.dumps(result, indent=2)
    print(text)
    if a.out:
        Path(a.out).write_text(text + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
