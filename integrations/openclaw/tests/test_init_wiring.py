"""synthe-init wires a real OpenClaw (2026.9.8+) correctly, in a throwaway OPENCLAW_HOME: the MCP server
without the approval tool, the barrier plugin pointed at the broker, and the skill. Then doctor's
OpenClaw checks pass. Needs the openclaw CLI; skipped otherwise. About 20 s."""
import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))
import synthe_init as si  # noqa: E402

OPENCLAW = si.find_openclaw()
pytestmark = pytest.mark.skipif(OPENCLAW is None, reason="openclaw CLI not installed")


def test_setup_wires_openclaw_and_doctor_sees_it(tmp_path):
    oc = si.OpenClaw(OPENCLAW, env={"OPENCLAW_HOME": str(tmp_path / "oc")})
    home = tmp_path / "synthe"
    home.mkdir()
    si.write_setup(home, {"broker": f"unix://{home / 'broker.sock'}", "receiver": "openclaw"})
    steps = si.wire_openclaw(oc, home, assume_yes=True)
    assert all(ok for _, ok, _ in steps), steps
    assert [n for n, _, _ in steps] == ["mcp server", "mcp tool filter", "barrier plugin",
                                        "plugin broker address", "plugin status line", "skill"]
    cfg = json.loads(oc.config_path().read_text())
    server = cfg["mcp"]["servers"][si.MCP_NAME]
    assert server["args"][-4:] == ["--broker-url", si.broker_address(home), "--as-receiver", "openclaw"]
    assert "synthe_submit_approval" in json.dumps(server)          # filtered out: the agent never approves
    assert cfg["plugins"]["entries"][si.PLUGIN_ID]["config"]["brokerSocket"] == si.broker_address(home)
    # the status line hook is allowed (OpenClaw blocks before_prompt_build for non-bundled plugins otherwise)
    assert cfg["plugins"]["entries"][si.PLUGIN_ID]["hooks"]["allowConversationAccess"] is True
    by = {c["check"]: c["status"] for c in si.openclaw_checks(oc)}
    assert by == {"barrier plugin": "PASS", "barrier plugin mode": "WARN", "synthe skill": "PASS",
                  "mcp server": "PASS", "openclaw github identity": "PASS"}, by
    # re-running setup replaces Synthe's own entries and touches nothing else
    assert all(ok for _, ok, _ in si.wire_openclaw(oc, home, assume_yes=True))


def test_doctor_flags_an_openclaw_github_identity(tmp_path):
    oc = si.OpenClaw(OPENCLAW, env={"OPENCLAW_HOME": str(tmp_path / "oc")})
    path = oc.config_path()
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"tools": {"github": {"profileId": "ghp_test_only"}}}))
    by = {c["check"]: c["status"] for c in si.openclaw_checks(oc)}
    assert by["openclaw github identity"] == "FAIL" and by["barrier plugin"] == "FAIL"
