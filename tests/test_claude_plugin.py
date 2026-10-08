import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / "integrations/claude-code"
HOOK = PLUGIN / "hooks/pre_tool_use.py"
spec = importlib.util.spec_from_file_location("synthe_claude_hook", HOOK)
hook = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hook)


def event(command):
    return {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": command}}


@pytest.mark.parametrize("command", ["git push", "git -C /tmp/repo push origin main", "env X=1 /usr/bin/git push",
    "git -c core.sshCommand=x push", "git \\\npush", "git send-pack x", "gh pr merge 1", "gh release create v1",
    "gh api /repos/example/repo/git/refs", "curl -X POST https://api.github.com/repos/example/repo",
    'python -c \'subprocess.run(["git", "push"])\'', "true; git push origin HEAD", "$(git push)"])
def test_direct_publication_denied(command):
    assert hook.denied(event(command))


@pytest.mark.parametrize("command", ["git status", "git diff", "git commit -m local", "python -m pytest", "git log -1"])
def test_no_permission_override_for_local_work(command):
    assert not hook.denied(event(command))


def test_approval_delivery_blocked():
    assert hook.denied({"hook_event_name": "PreToolUse", "tool_name": "mcp__plugin_synthe_local__synthe_submit_approval"})


@pytest.mark.parametrize("raw", ["{", "[]", "null", "{}", '{"tool_name":"Bash","tool_input":null}', "x" * 256001])
def test_malformed_input_denied_without_echo(raw):
    result = subprocess.run([sys.executable, str(HOOK)], input=raw, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0
    assert json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert not result.stderr


def test_cli_does_not_echo_secrets_or_grant_permission():
    for command in ("git push https://TEST-SENTINEL@example.invalid/repo", "git diff"):
        result = subprocess.run([sys.executable, str(HOOK)], input=json.dumps(event(command)),
                                capture_output=True, text=True, timeout=10)
        assert "TEST-SENTINEL" not in result.stdout + result.stderr
        if command == "git diff":
            assert result.stdout == ""


def test_plugin_layout_and_broker_only_mcp():
    assert json.loads((PLUGIN / ".claude-plugin/plugin.json").read_text())["name"] == "synthe"
    server = json.loads((PLUGIN / ".mcp.json").read_text())["mcpServers"]["synthe-local"]
    assert server == {"command": "synthe-mcp", "args": ["--broker-url", "${SYNTHE_BROKER}"]}
    config = json.loads((PLUGIN / "hooks/hooks.json").read_text())["hooks"]["PreToolUse"][0]
    assert "Bash" in config["matcher"] and "synthe_submit_approval" in config["matcher"]
    assert "${CLAUDE_PLUGIN_ROOT}/hooks/pre_tool_use.py" in config["hooks"][0]["command"]
