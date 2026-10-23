"""Run the plugin's declared command over stdio, against a real temporary broker."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_openclaw_flow import broker, world  # noqa: E402,F401 (pytest fixture)

ROOT = Path(__file__).resolve().parents[1]
SERVER = json.loads((ROOT / "integrations/claude-code/.mcp.json").read_text())["mcpServers"]["synthe-local"]


def launch(home, **overrides):
    env = {k: v for k, v in os.environ.items() if k not in
           {"SYNTHE_BROKER", "SYNTHE_BROKER_TOKEN", "SYNTHE_BROKER_UID"}}
    env.update({"HOME": str(home), "PYTHONPATH": str(ROOT / "src"),
                "PATH": str(Path(sys.executable).parent) + os.pathsep + env["PATH"], **overrides})
    assert shutil.which(SERVER["command"], path=env["PATH"]), "install the project to expose synthe-mcp"
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params":
         {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    ]
    return subprocess.run([SERVER["command"], *SERVER["args"]],
                          input="".join(json.dumps(r) + "\n" for r in requests),
                          capture_output=True, text=True, env=env, timeout=15)


def configured(home, url):
    (home / ".synthe").mkdir(exist_ok=True)
    (home / ".synthe/setup.json").write_text(json.dumps({"broker": url}))


def test_declared_command_initializes_with_broker_environment_unset(world):
    with broker(world["home"]) as url:
        configured(world["home"], url)
        result = launch(world["home"])
    assert result.returncode == 0 and not result.stderr, result.stderr
    responses = {r["id"]: r for r in map(json.loads, result.stdout.splitlines()) if "id" in r}
    assert "serverInfo" in responses[1]["result"]
    assert len(responses[2]["result"]["tools"]) == 8     # v0.7: synthe_start_task


def test_dead_broker_exits_with_one_clear_stderr_line(tmp_path):
    configured(tmp_path, "unix:///tmp/synthe-nonexistent-test-broker.sock")
    result = launch(tmp_path)
    assert result.returncode == 1 and result.stdout == ""
    assert result.stderr.splitlines() == [
        "synthe-mcp: broker_unreachable; start the isolated broker or set SYNTHE_BROKER."]


def test_absent_discovery_has_no_argparse_usage(monkeypatch, capsys):
    import synthe_client as scl
    import synthe_mcp as sm
    monkeypatch.delenv("SYNTHE_BROKER", raising=False)
    monkeypatch.setattr(scl, "configured_broker", lambda: None)
    assert sm.main([]) == 1
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err.splitlines() == [
        "synthe-mcp: no broker found; start the isolated broker or set SYNTHE_BROKER."]


def test_discovery_preserves_uid_pin(world):
    with broker(world["home"]) as url:
        configured(world["home"], url)
        result = launch(world["home"], SYNTHE_BROKER_UID=str(os.getuid() + 1))
    assert result.returncode == 1 and result.stdout == ""
    assert "broker_not_isolated" in result.stderr
    assert len(result.stderr.splitlines()) == 1


def test_env_address_takes_precedence_over_setup(world):
    configured(world["home"], "unix:///tmp/synthe-nonexistent-test-broker.sock")
    with broker(world["home"]) as url:
        assert launch(world["home"], SYNTHE_BROKER=url).returncode == 0
