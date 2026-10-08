"""ENFORCED on macOS, everything short of sudo: synthe-init setup --isolation macos-user prepares the one
admin step; apply-config (what that step runs as root) merges the staged registry and config into a
broker state made by the same `synthe_commit.py init` deploy/macos/install.sh runs; the result loads,
passes the broker's own doctor, and a synthe-task signed against it is accepted. The sudo parts (the
_synthe user, launchd) need a person and are covered by docs/ISOLATION.md's checks."""
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
ORIGINAL_ROOT = Path(os.environ.get("SYNTHE_REPO_ROOT", ROOT))
sys.path.insert(0, str(ROOT / "src"))
import handoff_check as hc  # noqa: E402
import synthe_broker as sb  # noqa: E402
import synthe_commit as cm  # noqa: E402
import synthe_init as si  # noqa: E402
import synthe_sign as ss  # noqa: E402
import synthe_task as st  # noqa: E402

PASS = "a long enough test passphrase"
TOKEN_TEXT = "github_pat_TEST_ONLY_not_a_real_token_0123456789"


@pytest.fixture
def staged(tmp_path):
    home, ws = tmp_path / "home", tmp_path / "shared" / "workspace"
    home.mkdir()
    token = tmp_path / "gh.token"
    token.write_text(TOKEN_TEXT + "\n")
    token.chmod(0o600)
    pub = si.approver_public_key(home, "rohan", passphrase=PASS)
    script = si.stage_macos(home, repo_url="https://github.com/example/synthe-test.git", branches=["agent/*"],
                            allowed_paths=["src/**"], approver="rohan", approver_pub=pub, agent="openclaw",
                            agent_user="rohan", token_file=token, repo_root=ROOT, workspace=ws)
    return {"home": home, "ws": ws, "token": token, "script": script, "tmp": tmp_path}


def _broker_state(tmp_path) -> Path:
    """What deploy/macos/install.sh leaves in /var/db/synthe, made here as the current user."""
    state = tmp_path / "state"
    run = subprocess.run([sys.executable, str(ROOT / "src" / "synthe_commit.py"), "init", "--dir", str(state),
                          "--isolation", "user"], capture_output=True, text=True)
    assert run.returncode == 0, run.stderr
    cfg = json.loads((state / "broker.json").read_text())
    cfg["isolation"]["clients"] = ["rohan"]
    (state / "broker.json").write_text(json.dumps(cfg))
    return state


def test_staging_writes_the_admin_step_with_no_secret_in_it(staged):
    home, script = staged["home"], staged["script"]
    text = script.read_text()
    assert script.stat().st_mode & 0o777 == 0o700
    assert TOKEN_TEXT not in text and str(staged["token"]) in text            # the path, never the token
    assert "install.sh\" --agent-user" in text and "apply-config" in text and "launchctl bootstrap" in text
    assert subprocess.run(["bash", "-n", str(script)]).returncode == 0        # valid bash
    for f in (home / "macos-stage").iterdir():
        assert TOKEN_TEXT not in f.read_text()
    setup = json.loads((home / "setup.json").read_text())
    assert setup["mode"] == "macos-user" and setup["broker"] == si.MACOS_SOCKET
    assert si.broker_address(home) == si.MACOS_SOCKET
    assert staged["ws"].is_dir() and staged["ws"].stat().st_mode & 0o777 == 0o755
    patch = json.loads((home / "macos-stage" / "config-patch.json").read_text())
    assert patch["remote"]["token_file"] == "github.token" and patch["workspace"] == str(staged["ws"])
    assert patch["receiver"] == "openclaw"


def test_staging_refuses_main_and_a_missing_token(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    pub = si.approver_public_key(home, "rohan", passphrase=PASS)
    kw = dict(repo_url="x", allowed_paths=["src/**"], approver="rohan", approver_pub=pub, agent="openclaw",
              agent_user="rohan", repo_root=ROOT, workspace=tmp_path / "ws")
    with pytest.raises(SystemExit, match="refused"):
        si.stage_macos(home, branches=["main"], token_file=None, **kw)
    with pytest.raises(SystemExit, match="missing or empty"):
        si.stage_macos(home, branches=["agent/*"], token_file=tmp_path / "nope.token", **kw)


def test_apply_config_merges_into_the_installers_broker_and_it_passes_the_brokers_doctor(staged):
    state = _broker_state(staged["tmp"])
    out = si.apply_config(state, staged["home"] / "macos-stage")
    (state / "github.token").write_text(TOKEN_TEXT + "\n")   # what the script's `install -m 600` does
    (state / "github.token").chmod(0o600)
    cfg = cm.BrokerConfig(state / "broker.json")
    assert cfg.isolation == {"mode": "user", "clients": ["rohan"]}            # untouched
    assert cfg.receiver_id == "openclaw"
    assert cfg.ledger_path.name == "ledger.sqlite3"
    assert cfg.workspace == staged["ws"].resolve()
    remote = cfg.effects["git_push"]["remotes"]["origin"]
    assert remote["branches"] == ["agent/*"] and remote["token_file"] == "github.token"
    assert cfg.effects["git_push"]["require_approval_commit_pin"] is True
    reg = json.loads((state / "registry.json").read_text())
    key = json.loads((state / "keys" / "synthe-broker.key.json").read_text())
    assert reg["agents"]["synthe-broker"]["keys"][0]["kid"] == key["kid"] == out["broker_kid"]
    assert set(reg["agents"]) == {"rohan", "openclaw", "synthe-broker"}
    for f in ("registry.json", "broker.json"):
        assert (state / f).stat().st_mode & 0o777 == 0o600
    state.chmod(0o700)  # the installer makes /var/db/synthe 0700
    assert sb.isolation_problems(cfg) == []   # the broker's own refusal-to-start checks


def test_apply_config_runs_from_the_command_line_the_way_the_admin_script_calls_it(staged):
    """enforce-macos.sh runs `python src/synthe_init.py apply-config --state --stage`, as root, with no --home.
    The first real run crashed here (Namespace has no attribute 'home'), so this goes through the CLI."""
    state = _broker_state(staged["tmp"])
    run = subprocess.run([sys.executable, str(ROOT / "src" / "synthe_init.py"), "apply-config",
                          "--state", str(state), "--stage", str(staged["home"] / "macos-stage")],
                         capture_output=True, text=True)
    assert run.returncode == 0, run.stderr
    assert json.loads(run.stdout)["broker_kid"]
    assert cm.BrokerConfig(state / "broker.json").receiver_id == "openclaw"


def test_apply_config_refuses_a_broker_that_is_not_in_user_mode(staged):
    state = _broker_state(staged["tmp"])
    cfg = json.loads((state / "broker.json").read_text())
    cfg["isolation"]["mode"] = "none"
    (state / "broker.json").write_text(json.dumps(cfg))
    with pytest.raises(SystemExit, match="not 'user'"):
        si.apply_config(state, staged["home"] / "macos-stage")


def test_a_task_signed_against_the_macos_setup_is_accepted(staged):
    home = staged["home"]
    state = _broker_state(staged["tmp"])
    si.apply_config(state, home / "macos-stage")
    cfg = cm.BrokerConfig(state / "broker.json")
    broker = sb.Broker(cfg, "unix")
    packet, task_file = st.build_task(home, "Add a greeting", "agent/greet", write_task=False)
    content = st.task_text("Add a greeting", "agent/greet")
    assert task_file.parent.parent == staged["ws"]                             # in the shared workspace
    assert not task_file.exists()                                              # the human cannot write there
    key = ss.load_key(str(home / "approver.key.json"), passphrase=PASS, require_encrypted=True)
    ss.sign_packet(packet, key)
    submitted = broker.op_submit_task({"packet": packet, "content": content}, {"mode": "separate-user"})
    assert submitted["decision"] == "ACCEPT" and submitted["task"]["created"] is True
    assert task_file.read_text() == content and task_file.stat().st_mode & 0o777 == 0o644
    again = broker.op_submit_task({"packet": packet, "content": content}, {"mode": "separate-user"})
    assert again["decision"] == "ACCEPT" and again["task"]["created"] is False  # idempotent
    registry = json.loads((state / "registry.json").read_text())
    v = hc.check(packet, registry=registry, ledger_path=None, workspace=staged["ws"], dry_run=True,
                 defer_approvals={"push_branch"})
    assert v["decision"] == "ACCEPT", v


def test_task_submission_refuses_tampering_unsigned_packets_and_nonhuman_senders(staged):
    home = staged["home"]
    state = _broker_state(staged["tmp"])
    si.apply_config(state, home / "macos-stage")
    broker = sb.Broker(cm.BrokerConfig(state / "broker.json"), "unix")
    key = ss.load_key(str(home / "approver.key.json"), passphrase=PASS, require_encrypted=True)

    packet, task_file = st.build_task(home, "Signed task", "agent/signed", write_task=False)
    content = st.task_text("Signed task", "agent/signed")
    ss.sign_packet(packet, key)
    with pytest.raises(sb.Refused, match="does not match") as mismatch:
        broker.op_submit_task({"packet": packet, "content": content + "tampered\n"}, {})
    assert mismatch.value.code == "task_hash_mismatch" and not task_file.exists()
    with pytest.raises(sb.Refused) as large:
        broker.op_submit_task({"packet": packet, "content": "x" * (sb.MAX_TASK_BYTES + 1)}, {})
    assert large.value.code == "task_too_large"

    extra = json.loads(json.dumps(packet))
    extra["handoff"]["inputs"]["artifact_refs"].append(extra["handoff"]["inputs"]["artifact_refs"][0])
    ss.sign_packet(extra, key)
    with pytest.raises(sb.Refused) as shape:
        broker.op_submit_task({"packet": extra, "content": content}, {})
    assert shape.value.code == "task_artifact_invalid"

    unsigned, unsigned_file = st.build_task(home, "Unsigned task", "agent/unsigned", write_task=False)
    rejected = broker.op_submit_task({"packet": unsigned,
                                      "content": st.task_text("Unsigned task", "agent/unsigned")}, {})
    assert rejected["decision"] == "REJECT"
    assert "signature_missing" in {r["code"] for r in rejected["reasons"]}
    assert not unsigned_file.exists()                                          # rejected writes roll back

    nonhuman, _ = st.build_task(home, "Wrong sender", "agent/wrong-sender", write_task=False)
    nonhuman["handoff"]["from"] = "openclaw"
    ss.sign_packet(nonhuman, {**key, "agent": "openclaw"})
    with pytest.raises(sb.Refused) as sender:
        broker.op_submit_task({"packet": nonhuman,
                               "content": st.task_text("Wrong sender", "agent/wrong-sender")}, {})
    assert sender.value.code == "task_sender_not_human"


def test_task_submission_refuses_paths_symlinks_and_conflicting_bytes(staged):
    home = staged["home"]
    state = _broker_state(staged["tmp"])
    si.apply_config(state, home / "macos-stage")
    broker = sb.Broker(cm.BrokerConfig(state / "broker.json"), "unix")
    key = ss.load_key(str(home / "approver.key.json"), passphrase=PASS, require_encrypted=True)

    packet, task_file = st.build_task(home, "Original", "agent/original", write_task=False)
    content = st.task_text("Original", "agent/original")
    ss.sign_packet(packet, key)
    assert broker.op_submit_task({"packet": packet, "content": content}, {})["decision"] == "ACCEPT"

    task_file.chmod(0o666)
    with pytest.raises(sb.Refused) as writable:
        broker.op_submit_task({"packet": packet, "content": content}, {})
    assert writable.value.code == "task_conflict"
    task_file.chmod(0o644)

    conflict = json.loads(json.dumps(packet))
    different = content.replace("Original", "Changed")
    conflict["handoff"]["inputs"]["artifact_refs"][0]["sha256"] = hashlib.sha256(different.encode()).hexdigest()
    ss.sign_packet(conflict, key)
    with pytest.raises(sb.Refused) as reused:
        broker.op_submit_task({"packet": conflict, "content": different}, {})
    assert reused.value.code == "task_conflict" and task_file.read_text() == content

    escaped = json.loads(json.dumps(packet))
    escaped["handoff"]["inputs"]["artifact_refs"][0]["path"] = "../outside.md"
    ss.sign_packet(escaped, key)
    with pytest.raises(sb.Refused) as path:
        broker.op_submit_task({"packet": escaped, "content": content}, {})
    assert path.value.code == "task_path_invalid"

    task_file.unlink()
    task_file.parent.rmdir()
    redirected = staged["ws"] / "redirected"
    redirected.mkdir()
    task_file.parent.symlink_to(redirected, target_is_directory=True)
    with pytest.raises(sb.Refused) as symlink:
        broker.op_submit_task({"packet": packet, "content": content}, {})
    assert symlink.value.code == "task_path_invalid" and list(redirected.iterdir()) == []


def test_synthe_task_cli_routes_macos_tasks_through_the_broker(staged, monkeypatch):
    home = staged["home"]
    key = ss.load_key(str(home / "approver.key.json"), passphrase=PASS, require_encrypted=True)
    seen = {}

    class Client:
        def __init__(self, url):
            assert url == si.MACOS_SOCKET

        def call(self, op, **args):
            seen.update({"op": op, **args})
            return {"decision": "ACCEPT", "task": {"created": True}}

    monkeypatch.setattr(st.ss, "load_key", lambda *a, **kw: key)
    monkeypatch.setattr(st.scl, "BrokerClient", Client)
    assert st.main(["new", "CLI task", "--branch", "agent/cli", "--home", str(home)]) == 0
    assert seen["op"] == "submit_task" and seen["content"] == st.task_text("CLI task", "agent/cli")
    rel = seen["packet"]["handoff"]["inputs"]["artifact_refs"][0]["path"]
    assert not (staged["ws"] / rel).exists()                                  # only the broker may write it
    saved = list((home / "tasks").glob("*.json"))
    assert len(saved) == 1 and json.loads(saved[0].read_text())["signature"]["signer"] == "rohan"
    # The agent runs as another user and can't read HOME: a copy goes to the shared inbox, readable by it.
    inbox = staged["ws"].parent / "inbox"
    shared = inbox / saved[0].name
    assert shared.read_text() == saved[0].read_text()
    assert shared.stat().st_mode & 0o777 == 0o644 and inbox.stat().st_mode & 0o777 == 0o755


# ---- the agent in its own macOS account (OpenClaw as `openclaw`, the approver as you) ------------------

@pytest.fixture(autouse=True)
def _plugin_files(monkeypatch):
    """The real plugin and skill. The mutation run copies only src/ and tests/, and names the original repo."""
    monkeypatch.setattr(si, "integration_dir", lambda: ORIGINAL_ROOT / "integrations" / "openclaw")


class _FakeOpenClaw:
    """Records the wiring calls; agent_setup's job is what it writes and refuses, not OpenClaw itself."""
    def __init__(self):
        self.calls = []

    def run(self, *args, interactive=False):
        self.calls.append(args)
        return subprocess.CompletedProcess(args, 0, "", "")


def test_agent_setup_wires_openclaw_with_no_key_and_no_token(tmp_path):
    home, oc = tmp_path / "agent-home", _FakeOpenClaw()
    assert si.agent_setup(home, oc, "openclaw", assume_yes=True) == 0
    setup = json.loads((home / "setup.json").read_text())
    assert setup == {"mode": "macos-user", "role": "agent", "broker": si.MACOS_SOCKET,
                     "workspace": str(si.MACOS_WORKSPACE), "receiver": "openclaw"}
    assert sorted(p.name for p in home.iterdir()) == ["setup.json"]          # no key, no token, nothing else
    assert home.stat().st_mode & 0o777 == 0o700
    mcp = next(c for c in oc.calls if c[:2] == ("mcp", "add"))
    assert si.MACOS_SOCKET in mcp and "--as-receiver" in mcp and "openclaw" in mcp
    assert ("mcp", "tools", si.MCP_NAME, "--exclude", "synthe_submit_approval") in oc.calls


def test_agent_setup_refuses_the_approvers_own_account(staged):
    with pytest.raises(SystemExit, match="approver key"):
        si.agent_setup(staged["home"], _FakeOpenClaw(), "openclaw", assume_yes=True)


def test_doctor_counts_no_approver_key_as_right_only_in_the_agents_account(tmp_path):
    agent_home, plain_home = tmp_path / "agent", tmp_path / "plain"
    si.agent_setup(agent_home, _FakeOpenClaw(), "openclaw", assume_yes=True)
    plain_home.mkdir()
    key_check = lambda home: next(c for c in si.host_checks(home) if c["check"] == "approver key")["status"]
    assert key_check(agent_home) == "PASS"
    assert key_check(plain_home) == "FAIL"   # an ordinary setup with its key missing is still broken


def test_add_agent_user_script_is_valid_and_holds_no_secret():
    script = ROOT / "deploy" / "macos" / "add-agent-user.sh"
    assert subprocess.run(["bash", "-n", str(script)]).returncode == 0
    text = script.read_text()
    assert "github.token" not in text and ".key.json" not in text
    assert 'the agent and the approver must be different users' in text


# ---- setup refuses what can't work, before you choose a passphrase ------------------------------------

GH = "https://github.com/rohansiddam/synthe-test.git"


@pytest.mark.parametrize("text, ok", [
    (TOKEN_TEXT, True),
    ("ghp_" + "a" * 36, True),
    ("pbpaste > ~/synthe-test.token && chmod 600 ~/synthe-test.token", False),   # what the first run saved
    ("", False),
    ("github_pat_abc def", False),
])
def test_the_token_file_must_hold_a_github_token(tmp_path, text, ok):
    f = tmp_path / "t.token"
    f.write_text(text + "\n")
    if ok:
        si.check_token_file(f, GH)
    else:
        with pytest.raises(SystemExit) as e:
            si.check_token_file(f, GH)
        assert "pbpaste" not in str(e.value) and "abc" not in str(e.value)   # never echoes the file


def test_setup_refuses_a_bad_token_before_asking_for_a_passphrase(tmp_path, monkeypatch):
    f = tmp_path / "t.token"
    f.write_text("pbpaste > ~/synthe-test.token\n")
    asked = []
    monkeypatch.setattr(si, "approver_public_key", lambda *a, **k: asked.append(1))
    with pytest.raises(SystemExit, match="doesn't hold a GitHub token"):
        si.main(["setup", "--isolation", "macos-user", "--home", str(tmp_path / "home"), "--repo-url", GH,
                 "--allowed-paths", "src/**", "--github-token-file", str(f), "--no-openclaw"])
    assert asked == []


def test_the_installer_is_found_from_the_source_directory(tmp_path, monkeypatch):
    monkeypatch.setattr(si, "__file__", str(tmp_path / "site-packages" / "synthe_init.py"))  # a regular install
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit, match="Synthe source directory"):
        si.source_root()
    monkeypatch.chdir(ORIGINAL_ROOT)
    assert si.source_root() == ORIGINAL_ROOT.resolve()


def test_the_agent_can_read_its_task_under_the_daemons_umask(staged):
    """The real run: the LaunchDaemon's umask 077 left tasks/ at 0700, and the agent (another user)
    got 'Permission denied' on its own task. The broker sets the modes itself."""
    home = staged["home"]
    state = _broker_state(staged["tmp"])
    si.apply_config(state, home / "macos-stage")
    broker = sb.Broker(cm.BrokerConfig(state / "broker.json"), "unix")
    packet, task_file = st.build_task(home, "Add a greeting", "agent/greet", write_task=False)
    key = ss.load_key(str(home / "approver.key.json"), passphrase=PASS, require_encrypted=True)
    ss.sign_packet(packet, key)
    old = os.umask(0o077)
    try:
        r = broker.op_submit_task({"packet": packet, "content": st.task_text("Add a greeting", "agent/greet")}, {})
    finally:
        os.umask(old)
    assert r["decision"] == "ACCEPT", r
    assert task_file.parent.stat().st_mode & 0o777 == 0o755
    assert task_file.stat().st_mode & 0o777 == 0o644


# ---- agent-assisted setup: prepare (agent-safe), one human command, the agent's own account -----------

def _prep(tmp_path, **kw):
    node = tmp_path / "node"
    node.write_text("")
    args = dict(repo_url=GH, branches=["agent/*"], allowed_paths=["src/**"], agent_account="openclaw",
                approver="rohan", python="/usr/bin/python3", script_path=ROOT / "src" / "synthe_init.py", node=node)
    args.update(kw)
    return si.prepare(tmp_path / "home", **args)


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS setup")
def test_prepare_writes_one_command_for_the_human_and_no_secret(tmp_path, monkeypatch):
    monkeypatch.chdir(ORIGINAL_ROOT)
    finish = _prep(tmp_path)
    text = finish.read_text()
    assert finish.stat().st_mode & 0o777 == 0o700
    assert subprocess.run(["bash", "-n", str(finish)]).returncode == 0
    assert "--github-token-prompt" in text and "--agent-user 'openclaw'" in text and "sudo bash" in text
    assert "github_pat_" not in text and "token-file" not in text      # no token, and no token file to read
    for bad, why in ((dict(agent_account="rohan"), "must not be yours"),
                     (dict(agent_account="Bad Name"), "not a valid macOS account"),
                     (dict(node=tmp_path / "no-node"), "brew install node"),
                     (dict(branches=["main"]), "refused")):
        with pytest.raises(SystemExit, match=why):
            _prep(tmp_path, **bad)


def test_the_prompted_token_stays_private_and_a_wrong_one_is_refused_unechoed(tmp_path):
    stage = tmp_path / "stage"
    path = si.prompt_token(stage, GH, read=lambda: TOKEN_TEXT)
    assert path.read_text().strip() == TOKEN_TEXT
    assert path.stat().st_mode & 0o777 == 0o600 and stage.stat().st_mode & 0o777 == 0o700
    with pytest.raises(SystemExit) as e:
        si.prompt_token(stage, GH, read=lambda: "pbpaste > ~/synthe-test.token")
    assert "pbpaste" not in str(e.value) and not path.exists()   # never echoed; the bad copy is gone


def test_setup_with_a_prompted_bad_token_stops_before_the_passphrase(tmp_path, monkeypatch):
    import getpass
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": "not a token")
    asked = []
    monkeypatch.setattr(si, "approver_public_key", lambda *a, **k: asked.append(1))
    monkeypatch.chdir(ORIGINAL_ROOT)
    with pytest.raises(SystemExit, match="doesn't hold a GitHub token"):
        si.main(["setup", "--isolation", "macos-user", "--home", str(tmp_path / "home"), "--repo-url", GH,
                 "--allowed-paths", "src/**", "--agent-user", "openclaw", "--github-token-prompt", "--no-openclaw"])
    assert asked == []


def test_the_admin_step_creates_the_agents_account_before_installing_and_drops_the_token(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    pub = si.approver_public_key(home, "rohan", passphrase=PASS)
    token = si.prompt_token(home / "macos-stage", GH, read=lambda: TOKEN_TEXT)
    script = si.stage_macos(home, repo_url=GH, branches=["agent/*"], allowed_paths=["src/**"], approver="rohan",
                            approver_pub=pub, agent="openclaw", agent_user="openclaw", token_file=token,
                            repo_root=ROOT, workspace=tmp_path / "ws")
    text = script.read_text()
    assert subprocess.run(["bash", "-n", str(script)]).returncode == 0
    assert TOKEN_TEXT not in text and "TOKEN_STAGED=1" in text
    assert text.index("sysadminctl -addUser") < text.index("install.sh\" --agent-user")   # the account first
    for step in ("add-agent-user.sh", "agent-setup --yes", f"openclaw@{si.OPENCLAW_VERSION}", "doctor --repo",
                 'chmod 700 "/Users/$APPROVER"', "cd /",
                 'ln -sf "$APP/venv/bin/git-remote-synthe" "/Users/$AGENT_USER/.local/bin/git-remote-synthe"',
                 "com.synthe.openclaw-gateway", "<key>UserName</key><string>$AGENT_USER</string>",
                 'launchctl bootstrap system "$GW_PLIST"'):
        assert step in text, step


class _GatewayOC(_FakeOpenClaw):
    def __init__(self, token=""):
        super().__init__()
        self.token = token

    def run(self, *args, interactive=False):
        self.calls.append(args)
        out = self.token if args[:3] == ("config", "get", "gateway.auth.token") else ""
        return subprocess.CompletedProcess(args, 0, out, "")


def test_agent_setup_configures_a_local_token_gateway_and_keeps_an_existing_token():
    oc = _GatewayOC()
    names = [n for n, ok, _ in si.configure_gateway(oc)]
    assert names == ["gateway mode", "gateway bind", "gateway auth", "gateway token"]
    assert ("config", "set", "gateway.bind", "loopback") in oc.calls
    set_token = [c for c in oc.calls if c[:3] == ("config", "set", "gateway.auth.token")]
    assert len(set_token) == 1 and len(set_token[0][3]) == 48
    oc = _GatewayOC(token="already-set")
    si.configure_gateway(oc)
    assert not [c for c in oc.calls if c[:3] == ("config", "set", "gateway.auth.token")]


def test_every_tool_setup_runs_or_links_from_the_system_install_has_a_launcher(tmp_path):
    """A clean-Mac finding (2026-10-07): setup linked git-remote-synthe into the agent's PATH, but
    add-agent-user.sh never wrote that launcher, so the link pointed at nothing and `git push` to a
    synthe:: origin failed. Every $APP/venv/bin/<tool> the admin step uses must be written by it."""
    import re
    home = tmp_path / "home"
    home.mkdir()
    pub = si.approver_public_key(home, "rohan", passphrase=PASS)
    text = si.stage_macos(home, repo_url=GH, branches=["agent/*"], allowed_paths=["src/**"], approver="rohan",
                          approver_pub=pub, agent="openclaw", agent_user="openclaw", token_file=None,
                          repo_root=ROOT, workspace=tmp_path / "ws").read_text()
    used = set(re.findall(r'\$APP/venv/bin/([\w-]+)', text)) - {"python", "pip"}
    adder = (ROOT / "deploy" / "macos" / "add-agent-user.sh").read_text()
    loop = re.search(r"for name in ([\w ]+); do", adder).group(1).split()
    written = {f"synthe-{n}" for n in loop} | set(re.findall(r'> "\$APP/venv/bin/([\w-]+)"', adder))
    assert "git-remote-synthe" in used
    assert used <= written, f"the admin step uses tools nobody installs: {sorted(used - written)}"
