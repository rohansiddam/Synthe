"""Agent-neutral setup retains the credential wall; no privileged installer is executed."""
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import synthe_init as si


def prep(tmp_path, monkeypatch, platform="darwin", **kw):
    monkeypatch.setattr(si.sys, "platform", platform)
    monkeypatch.setattr(si.os, "geteuid", lambda: 501)
    monkeypatch.setattr(si.shutil, "which", lambda x: "/usr/bin/" + x if x in ("git", "systemctl") else None)
    monkeypatch.setattr(si, "source_root", lambda: ROOT)
    args = dict(repo_url="https://github.com/example/repo.git", branches=["agent/*"], allowed_paths=["src/**"],
                agent_account="worker", approver="human", python="/usr/bin/python3", script_path=ROOT / "src/synthe_init.py",
                node=tmp_path / "absent-node", agent_kind="none")
    args.update(kw)
    return si.prepare(tmp_path / "setup", **args)


@pytest.mark.parametrize("platform,isolation", [("darwin", "macos-user"), ("linux", "linux-user")])
def test_no_node_needed_and_finish_is_private(tmp_path, monkeypatch, platform, isolation):
    script = prep(tmp_path, monkeypatch, platform)
    assert "--agent-kind 'none'" in script.read_text()
    assert f"--isolation {isolation}" in script.read_text()
    assert script.stat().st_mode & 0o777 == 0o700
    assert subprocess.run(["bash", "-n", str(script)]).returncode == 0
    assert not list(script.parent.rglob("*.key.json"))


@pytest.mark.parametrize("account", ["human", "root", "synthe", "_synthe", "x;echo BAD", "../worker"])
def test_none_does_not_relax_account_separation(tmp_path, monkeypatch, account):
    with pytest.raises(SystemExit):
        prep(tmp_path, monkeypatch, agent_account=account)


def test_default_openclaw_still_requires_node(tmp_path, monkeypatch):
    with pytest.raises(SystemExit, match="Node"):
        prep(tmp_path, monkeypatch, agent_kind="openclaw")


def test_linux_git_helper_defaults_and_clone_use_linux_inbox(monkeypatch):
    import runpy
    monkeypatch.setattr(sys, "platform", "linux")
    namespace = runpy.run_path(str(ROOT / "src/synthe_git_remote.py"))
    assert namespace["DEFAULT_INBOX"] == "/var/lib/synthe-shared/inbox"
    assert namespace["DEFAULT_BROKER"] == si.LINUX_SOCKET
    assert 'config synthe.inbox "$SHARED/inbox"' in (ROOT / "deploy/linux/finish.sh").read_text()


def test_none_agent_setup_never_wires_openclaw(tmp_path, monkeypatch):
    monkeypatch.setattr(si, "wire_openclaw", lambda *a: pytest.fail("OpenClaw wiring in generic setup"))
    monkeypatch.setattr(si, "configure_gateway", lambda *a: pytest.fail("gateway wiring in generic setup"))
    assert si.agent_setup(tmp_path, None, "worker", True, "none") == 0
    assert si.read_setup(tmp_path)["role"] == "agent"
    assert si.read_setup(tmp_path)["agent_kind"] == "none"
    assert not list(tmp_path.glob("*.key.json"))
    (tmp_path / "approver.key.json").write_text("{}")  # not a key; existence must be enough to refuse
    with pytest.raises(SystemExit, match="approver key"):
        si.agent_setup(tmp_path, None, "worker", True, "none")


def test_doctor_none_skips_only_integration_not_security(tmp_path, monkeypatch):
    import synthe_client as scl
    si.write_setup(tmp_path, {"agent_kind": "none"})
    monkeypatch.setattr(si, "host_checks", lambda _: [{"status": "FAIL", "check": "gh login"}])
    monkeypatch.setattr(scl, "doctor", lambda *a, **k: [{"status": "PASS", "check": "broker isolation"}])
    monkeypatch.setattr(si, "openclaw_checks", lambda _: pytest.fail("must skip OpenClaw"))
    report = si.run_doctor(tmp_path, None)
    assert report["level"] == "ADVISORY"
    assert any(c["check"] == "gh login" for c in report["checks"])
    si.write_setup(tmp_path, {"agent_kind": "typo"})
    assert si.run_doctor(tmp_path, None)["level"] == "ADVISORY"


def linux_stage(tmp_path, **kw):
    args = dict(repo_url="https://github.com/example/repo.git", branches=["agent/*"], allowed_paths=["src/**"],
                approver="human", approver_pub={"kid": "fixture", "alg": "Ed25519", "public_key": "fixture"},
                agent="worker", agent_user="worker", token_file=None, repo_root=ROOT, agent_kind="none")
    args.update(kw)
    return si.stage_linux(tmp_path, **args)


def test_linux_stages_no_credentials_and_scoped_clients(tmp_path):
    import shlex
    script = linux_stage(tmp_path)
    assert script.stat().st_mode & 0o777 == 0o700
    args = shlex.split(script.read_text().splitlines()[-1])
    assert len(args[3:]) == 8 and args[-1] == "v1"
    patch = json.loads((tmp_path / "linux-stage/config-patch.json").read_text())
    assert patch["clients"] == ["human", "worker"]
    assert patch["workspace"] == str(si.LINUX_WORKSPACE)
    assert si.read_setup(tmp_path)["broker"] == si.LINUX_SOCKET
    assert si.read_setup(tmp_path)["mode"] == "linux-user"
    for name in ("finish.sh", "install.sh"):
        assert subprocess.run(["bash", "-n", str(ROOT / "deploy/linux" / name)]).returncode == 0
    assert not list(tmp_path.rglob("*.key.json"))


@pytest.mark.parametrize("kw", [{"agent_user": "human"}, {"agent_user": "root"}, {"agent_user": "$(bad)"},
                               {"branches": ["main"]}, {"agent_kind": "typo"}])
def test_linux_bad_stage_refused(tmp_path, kw):
    with pytest.raises(SystemExit):
        linux_stage(tmp_path, **kw)


def test_installer_keeps_workspace_and_token_permissions_separate():
    text = (ROOT / "deploy/linux/finish.sh").read_text()
    for guard in ('[ "$AGENT_USER" != "$APPROVER" ]', '[ "${SUDO_USER:-}" = "$APPROVER" ]',
                  '[ ! -e "$STATE/broker.json" ]', 'install -o synthe -g synthe -m 600 "$TOKEN"',
                  'install -d -o synthe -g synthe -m 755 "$SHARED/workspace"',
                  'install -d -o "$APPROVER" -m 755 "$SHARED/inbox"', 'if [ "$AGENT_KIND" = openclaw ]; then'):
        assert guard in text
    unit = (ROOT / "deploy/linux/synthe-broker.service").read_text()
    assert "ProtectSystem=strict" in unit
    assert "ReadWritePaths=-/var/lib/synthe-shared/workspace" in unit


@pytest.mark.parametrize("ready_after,expected_calls,expected_code", [(1, 1, 0), (3, 3, 0), (100, 40, 1)])
def test_linux_waits_before_clone_without_retrying_an_effect(tmp_path, ready_after, expected_calls, expected_code):
    # Execute only the extracted readiness stanza, never the privileged installer.
    text = (ROOT / "deploy/linux/finish.sh").read_text()
    stanza = text.split("# BEGIN broker readiness:", 1)[1].split("\n", 1)[1].split("# END broker readiness", 1)[0]
    assert text.index("# END broker readiness") < text.index('"$APP/bin/synthe-client" --broker')
    assert '.call("hello")' in stanza and 'timeout=1' in stanza
    assert 'expected_broker_uid=pwd.getpwnam("synthe").pw_uid' in stanza
    fake = tmp_path / "fake-client"
    fake.write_text(f"#!{sys.executable}\n" +
                    'import os\nfrom pathlib import Path\np = Path(os.environ["READY_COUNT"])\n' +
                    'n = int(p.read_text()) + 1 if p.exists() else 1\np.write_text(str(n))\n' +
                    'raise SystemExit(0 if n >= int(os.environ["READY_AFTER"]) else 1)\n')
    fake.chmod(0o700)
    count = tmp_path / "calls"
    script = "set -euo pipefail\nAS_AGENT=(env)\nBPY=" + shlex.quote(str(fake)) + "\nsleep() { :; }\n" + stanza
    result = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=10,
                            env={**os.environ, "READY_COUNT": str(count), "READY_AFTER": str(ready_after)})
    assert result.returncode == expected_code
    assert int(count.read_text()) == expected_calls
    assert result.stdout == ""
    if expected_code:
        assert "setup stopped before clone" in result.stderr


def test_macos_generic_script_guards_all_openclaw_steps(tmp_path):
    script = si.stage_macos(tmp_path, repo_url="/tmp/example.git", branches=["agent/*"], allowed_paths=["src/**"],
                            approver="human", approver_pub={}, agent="worker", agent_user="worker", token_file=None,
                            repo_root=ROOT, workspace=tmp_path / "workspace", agent_kind="none")
    text = script.read_text()
    assert "AGENT_KIND='none'" in text
    assert 'if [ "$AGENT_KIND" = openclaw ] &&' in text
    assert text.count('if [ "$AGENT_KIND" = openclaw ]; then') == 2
    assert '--agent-kind "$AGENT_KIND"' in text
    assert si.read_setup(tmp_path)["agent_kind"] == "none"
    assert subprocess.run(["bash", "-n", str(script)]).returncode == 0


@pytest.mark.parametrize("clients", [["human", "worker"], ["root", "worker"], ["human", "human"],
                                    [{}, "worker"], None, ["human"]])
def test_apply_linux_clients_fails_closed_before_writing(tmp_path, clients):
    import synthe_crypto as sc
    state, stage = tmp_path / "state", tmp_path / "stage"
    (state / "keys").mkdir(parents=True)
    stage.mkdir()
    # Throwaway synthetic broker state; never reads a machine's real key or token.
    secret = sc.generate_secret()
    (state / "keys/synthe-broker.key.json").write_text(json.dumps({"kid": "test", "private_key": sc.b64u(secret)}))
    config = {"isolation": {"mode": "user", "clients": ["original"]}}
    (state / "broker.json").write_text(json.dumps(config))
    (stage / "registry.json").write_text('{"agents":{}}')
    (stage / "config-patch.json").write_text(json.dumps({"clients": clients, "workspace": str(tmp_path / "workspace"),
                                                        "receiver": "worker", "remote": {"url": "example"}}))
    if clients == ["human", "worker"]:
        si.apply_config(state, stage)
        assert json.loads((state / "broker.json").read_text())["isolation"]["clients"] == clients
    else:
        with pytest.raises(SystemExit, match="client accounts"):
            si.apply_config(state, stage)
        assert json.loads((state / "broker.json").read_text()) == config
        assert not (state / "registry.json").exists()
