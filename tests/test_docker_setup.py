"""deploy/docker/setup.py --stage: the broker volume a design partner gets from one command."""
import importlib.util
import json
import stat
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))
import handoff_check as hc  # noqa: E402
import synthe_commit as cm  # noqa: E402
from world import mkkey  # noqa: E402

spec = importlib.util.spec_from_file_location("docker_setup", ROOT / "deploy" / "docker" / "setup.py")
setup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(setup)

TOKEN = "ghp_PLANTEDsecretVALUE0123456789"


@pytest.fixture
def env(tmp_path):
    key, pub = mkkey("alice")
    (tmp_path / "alice.pub.json").write_text(json.dumps(pub))
    (tmp_path / "alice.key.json").write_text(json.dumps({k: v for k, v in key.items() if k != "_secret"}))
    (tmp_path / "gh.token").write_text(TOKEN + "\n")
    return tmp_path


def args(env, *extra):
    return ["--repo-url", "https://github.com/acme/app.git", "--branches", "agent/*",
            "--github-token-file", str(env / "gh.token"), "--approver", f"alice={env / 'alice.pub.json'}",
            "--agent", "claude-code", "--allowed-paths", "src/**,tests/**",
            "--stage", str(env / "vol"), *extra]


def test_stage_writes_a_broker_that_loads(env, capsys):
    assert setup.main(args(env)) == 0
    out = capsys.readouterr()
    vol = env / "vol"
    cfg = cm.BrokerConfig(vol / "broker.json")
    assert cfg.raw["isolation"]["mode"] == "container"
    remote = cfg.raw["effects"]["git_push"]["remotes"]["origin"]
    assert remote == {"url": "https://github.com/acme/app.git", "branches": ["agent/*"], "token_file": "github.token"}
    reg, problems = hc.load_registry(str(vol / "registry.json"))
    assert not problems
    policy = reg["agents"]["claude-code"]["policy"]
    assert policy["trusted_approvers"] == ["alice"]
    assert policy["approval_required_for"] == ["git_push"]
    assert policy["allowed_paths"] == ["src/**", "tests/**"]
    assert reg["agents"]["synthe-broker"]["keys"][0]["kid"] == json.loads(out.out)["broker_kid"]


def test_secrets_are_0600_and_never_printed(env, capsys):
    setup.main(args(env))
    out = capsys.readouterr()
    vol = env / "vol"
    for f in (vol / "github.token", vol / "keys" / "synthe-broker.key.json"):
        assert stat.S_IMODE(f.stat().st_mode) == 0o600, f
    assert (vol / "github.token").read_text().strip() == TOKEN
    assert TOKEN not in out.out + out.err
    for f in ("broker.json", "registry.json"):
        assert TOKEN not in (vol / f).read_text()
    assert "private_key" not in (vol / "registry.json").read_text()


def test_refuses_a_private_key_as_an_approver(env):
    with pytest.raises(SystemExit, match="PRIVATE key"):
        setup.main(args(env, "--approver", f"bob={env / 'alice.key.json'}"))
    assert not (env / "vol" / "registry.json").exists()


@pytest.mark.parametrize("branches", ["main", "agent/*,master", "*", "**", ""])
def test_refuses_main_and_wildcard_branches(env, branches):
    a = args(env)
    a[a.index("--branches") + 1] = branches
    with pytest.raises(SystemExit):
        setup.main(a)


def test_refuses_empty_token_and_empty_paths(env):
    (env / "gh.token").write_text("\n")
    with pytest.raises(SystemExit, match="empty"):
        setup.main(args(env))
    (env / "gh.token").write_text(TOKEN)
    a = args(env)
    a[a.index("--allowed-paths") + 1] = " , "
    with pytest.raises(SystemExit, match="allowed-paths"):
        setup.main(a)


def test_without_a_token_file_the_remote_has_none(env):
    a = args(env)
    i = a.index("--github-token-file")
    del a[i:i + 2]
    setup.main(a)
    remote = json.loads((env / "vol" / "broker.json").read_text())["effects"]["git_push"]["remotes"]["origin"]
    assert "token_file" not in remote and not (env / "vol" / "github.token").exists()
