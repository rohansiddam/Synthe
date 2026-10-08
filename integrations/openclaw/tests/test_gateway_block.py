"""End to end in OpenClaw's real gateway: the Synthe plugin blocks pushes, lets everything else through.

A throwaway OPENCLAW_HOME (never your ~/.openclaw) gets the Synthe plugin plus a test-only plugin whose
"shell" tool echoes its command and runs nothing. Calls go through the gateway's /tools/invoke, the
same before_tool_call pipeline an agent's tool calls take, with no model involved.

Needs the openclaw CLI (2026.9.8+) on PATH or under ~/.nvm; skipped otherwise. About 30 s.
"""
import glob
import json
import os
import secrets
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
PLUGIN = HERE.parent / "plugin"
ECHO = HERE / "echo-shell-plugin"


def _openclaw():
    found = shutil.which("openclaw")
    if found:
        return found
    candidates = sorted(glob.glob(os.path.expanduser("~/.nvm/versions/node/*/bin/openclaw")))
    return candidates[-1] if candidates else None


OPENCLAW = _openclaw()
pytestmark = pytest.mark.skipif(OPENCLAW is None, reason="openclaw CLI not installed")


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _invoke(port, token, tool, args):
    req = urllib.request.Request(f"http://127.0.0.1:{port}/tools/invoke", method="POST",
                                 data=json.dumps({"tool": tool, "args": args}).encode(),
                                 headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=90) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


@pytest.fixture
def gateway(tmp_path):
    env = {**os.environ, "OPENCLAW_HOME": str(tmp_path / "home"),
           "PATH": f"{Path(OPENCLAW).parent}{os.pathsep}{os.environ.get('PATH', '')}"}
    run = lambda *a: subprocess.run([OPENCLAW, *a], env=env, capture_output=True, text=True, timeout=300)  # noqa: E731
    for plugin in (PLUGIN, ECHO):
        out = run("plugins", "install", "-l", str(plugin), "--force", "--accept-capabilities")
        assert out.returncode == 0, out.stdout + out.stderr
    port, token = _free_port(), secrets.token_urlsafe(32)
    for key, value in (("gateway.mode", "local"), ("gateway.bind", "loopback"), ("gateway.port", str(port)),
                       ("gateway.auth.mode", "token"), ("gateway.auth.token", token),
                       ("gateway.tools.allow", '["shell"]')):
        assert run("config", "set", key, value).returncode == 0
    proc = subprocess.Popen([OPENCLAW, "gateway", "run", "--port", str(port)], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 90
        while True:
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=2)
                break
            except OSError:
                if time.monotonic() > deadline or proc.poll() is not None:
                    pytest.fail("the test gateway did not start")
                time.sleep(0.5)
        yield port, token
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            proc.kill()


def test_the_skill_installs_and_is_eligible(tmp_path):
    env = {**os.environ, "OPENCLAW_HOME": str(tmp_path / "home"),
           "PATH": f"{Path(OPENCLAW).parent}{os.pathsep}{os.environ.get('PATH', '')}"}
    out = subprocess.run([OPENCLAW, "skills", "install", str(HERE.parent / "skill" / "synthe"), "--force"],
                         env=env, capture_output=True, text=True, timeout=300)
    assert out.returncode == 0, out.stdout + out.stderr
    info = subprocess.run([OPENCLAW, "skills", "info", "synthe", "--json"], env=env, capture_output=True,
                          text=True, timeout=300)
    skill = json.loads(info.stdout)
    skill = skill.get("skill", skill)
    assert skill["name"] == "synthe" and skill["eligible"] is True and not skill.get("disabled"), skill
    assert len(skill["description"]) < 160


def test_pushes_are_blocked_in_the_real_gateway_and_other_commands_pass(gateway):
    port, token = gateway
    for command in ("git push origin main", "git -c credential.helper=store push origin HEAD:main",
                    "gh pr merge 12 --squash", "gh api repos/o/r/merges -f base=main -f head=agent/x"):
        status, body = _invoke(port, token, "shell", {"command": command})
        assert status == 403 and body["error"]["type"] == "tool_call_blocked", (command, status, body)
        assert "synthe_propose_effect" in body["error"]["message"]
    status, body = _invoke(port, token, "shell", {"command": "git status"})
    assert status == 200 and body["result"]["details"]["command"] == "git status", body
