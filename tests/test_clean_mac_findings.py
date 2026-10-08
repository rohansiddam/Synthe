"""What a founder's clean-Mac run found (2026-10-07, macOS 26.1), each pinned by a test.

1. Homebrew's Python 3.14.8 (and 3.12) were installed but broken: pyexpat couldn't load, so
   `python3 -m venv` died in ensurepip. A version check alone picked the broken one, in the quickstart
   and again in the system installer. deploy/macos/find-python.sh picks one that works.
2. The installer reused a half-built /Library/Synthe/venv (no pip) on a rerun.
3. The installer ran a step as _synthe from a folder inside the user's home, which _synthe can't
   enter: PermissionError. It now runs from /, and so does the admin step.
4. The admin step lets the installer pick its own Python; it now passes the one that built the
   user's working environment.
"""
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import synthe_init as si  # noqa: E402

FIND = ROOT / "deploy" / "macos" / "find-python.sh"
INSTALL = (ROOT / "deploy" / "macos" / "install.sh").read_text()
GH = "https://github.com/example/synthe-test.git"


def fake(d: Path, name: str, body: str) -> Path:
    p = d / name
    p.write_text("#!/bin/sh\n" + body + "\n")
    p.chmod(0o755)
    return p


@pytest.fixture
def pythons(tmp_path):
    good = tmp_path / "good-python"
    good.symlink_to(sys.executable)                       # a real, working interpreter
    # Like Homebrew's 3.14.8 on macOS 26.1: a real, new enough Python whose pyexpat won't load.
    shadow = tmp_path / "no-expat"
    shadow.mkdir()
    (shadow / "pyexpat.py").write_text("raise ImportError('dlopen pyexpat: Symbol not found: _XML_SetAllocTrackerActivationThreshold')\n")
    broken = fake(tmp_path, "broken-python", f'PYTHONPATH="{shadow}" exec "{sys.executable}" "$@"')
    return {"good": str(good), "broken": str(broken), "missing": str(tmp_path / "nope")}


def find(*args, candidates=None):
    env = {**os.environ}
    if candidates is not None:
        env["SYNTHE_PY_CANDIDATES"] = " ".join(candidates)
    return subprocess.run(["bash", str(FIND), *args], capture_output=True, text=True, env=env)


def test_a_broken_python_first_in_line_is_skipped_for_one_that_works(pythons):
    r = find(candidates=[pythons["missing"], pythons["broken"], pythons["good"]])
    assert r.returncode == 0 and r.stdout.strip() == pythons["good"]


def test_with_only_broken_pythons_it_fails_and_says_what_to_do(pythons):
    r = find(candidates=[pythons["broken"], pythons["missing"]])
    assert r.returncode != 0 and r.stdout == ""
    assert pythons["broken"] in r.stderr and "pyexpat" in r.stderr and "python@3.13" in r.stderr


def test_an_explicit_python_is_checked_not_trusted(pythons):
    assert find("--check", pythons["good"]).stdout.strip() == pythons["good"]
    bad = find("--check", pythons["broken"])
    assert bad.returncode != 0 and bad.stdout == "" and "pyexpat" in bad.stderr


def test_the_check_really_loads_pyexpat_and_ensurepip():
    text = FIND.read_text()
    assert "import sys, pyexpat, ensurepip, venv" in text


def test_the_installer_uses_the_checked_python_for_both_the_default_and_an_explicit_one():
    assert 'find-python.sh" --check "$PY"' in INSTALL and 'PY=$(bash "$HERE/deploy/macos/find-python.sh")' in INSTALL
    assert "sys.version_info < (3, 10))' 2>/dev/null && { PY=$c" not in INSTALL     # the old version-only pick


def test_the_installer_rebuilds_a_venv_that_has_no_working_pip():
    assert '"$APP/venv/bin/python" -m pip --version' in INSTALL
    assert INSTALL.index('rm -rf "$APP/venv"') < INSTALL.index('"$PY" -m venv "$APP/venv"')
    assert '[ -x "$APP/venv/bin/python" ] || "$PY" -m venv' not in INSTALL


def test_the_installer_runs_from_root_before_anything_runs_as_synthe_but_after_finding_its_source():
    first_as_synthe = INSTALL.index("sudo -u _synthe")
    cd_root = INSTALL.index("\ncd /\n")
    assert INSTALL.index('HERE=$(cd "$(dirname "$0")/../.." && pwd)') < cd_root < first_as_synthe


def _stage(tmp_path, **kw):
    home = tmp_path / "home"
    home.mkdir()
    pub = si.approver_public_key(home, "rohan", passphrase="a long enough test passphrase")
    return si.stage_macos(home, repo_url=GH, branches=["agent/*"], allowed_paths=["src/**"], approver="rohan",
                          approver_pub=pub, agent="openclaw", agent_user="openclaw", token_file=None,
                          repo_root=ROOT, workspace=tmp_path / "ws", **kw).read_text()


def test_the_admin_step_runs_the_installer_from_root_with_the_python_that_already_worked(tmp_path):
    text = _stage(tmp_path, base_python="/opt/homebrew/bin/python3.13")
    assert subprocess.run(["bash", "-n"], input=text, text=True).returncode == 0
    line = next(ln for ln in text.splitlines() if "install.sh\" --agent-user" in ln)
    assert line.endswith("--python '/opt/homebrew/bin/python3.13'")
    assert text.index("\ncd /  #") < text.index("install.sh\" --agent-user")


def test_without_a_usable_base_python_the_installer_finds_its_own(tmp_path):
    line = next(ln for ln in _stage(tmp_path, base_python=None).splitlines() if "install.sh\" --agent-user" in ln)
    assert "--python" not in line


def test_a_python_inside_a_home_folder_is_not_handed_to_the_broker(monkeypatch):
    monkeypatch.setattr(sys, "_base_executable", "/Users/YOU/.pyenv/versions/3.13.5/bin/python3", raising=False)
    assert si.base_python() is None
    monkeypatch.setattr(sys, "_base_executable", "/opt/homebrew/opt/python@3.13/bin/python3.13", raising=False)
    assert si.base_python() == "/opt/homebrew/opt/python@3.13/bin/python3.13"


def test_the_quickstart_builds_its_environment_with_the_checked_python():
    qs = (ROOT / "QUICKSTART_OPENCLAW.md").read_text()
    assert "deploy/macos/find-python.sh" in qs
    assert "python3 -m venv ~/synthe-venv" not in qs
    skill = (ROOT / "skills" / "synthe-setup" / "SKILL.md").read_text()
    assert "deploy/macos/find-python.sh" in skill and "python3 -m venv ~/synthe-venv" not in skill


# --- found later in the same run: the first proposal and the first sync -----------------------------

def test_an_agent_shell_without_synthe_broker_finds_the_broker_its_setup_recorded(tmp_path, monkeypatch):
    import json
    import synthe_client as scl
    monkeypatch.delenv("SYNTHE_BROKER", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    with pytest.raises(scl.BrokerError) as e:                       # nothing recorded: still a clear error
        scl.BrokerClient()
    assert e.value.code == "broker_unset"
    (tmp_path / ".synthe").mkdir()
    (tmp_path / ".synthe" / "setup.json").write_text(json.dumps({"broker": si.MACOS_SOCKET}))
    assert scl.BrokerClient().url == si.MACOS_SOCKET
    monkeypatch.setenv("SYNTHE_BROKER", "unix:///tmp/explicit.sock")   # an explicit address still wins
    assert scl.BrokerClient().url == "unix:///tmp/explicit.sock"
    monkeypatch.delenv("SYNTHE_BROKER")
    (tmp_path / ".synthe" / "setup.json").write_text(json.dumps({"broker": "/not/an/address"}))
    with pytest.raises(scl.BrokerError):
        scl.BrokerClient()


def test_the_agent_is_told_base_is_a_branch_never_a_commit():
    import synthe_mcp as sm
    desc = sm.PROPOSE_TOOL["description"]
    assert "base = the remote BRANCH" in desc and "never a commit" in desc
    skill = (ROOT / "integrations" / "openclaw" / "skill" / "synthe" / "SKILL.md").read_text()
    assert "Leave `base` out" in skill and "`base_missing`" in skill
    broker = (ROOT / "src" / "synthe_commit.py").read_text()
    assert broker.count("(base names a branch there, e.g. main, not a commit)") == 2


def test_the_quickstart_warns_that_onboarding_opens_an_embedded_chat_the_plugin_skips():
    qs = (ROOT / "QUICKSTART_OPENCLAW.md").read_text()
    assert "local embedded" in qs and "Skip for now" in qs and "ws://127.0.0.1" in qs


# --- gateway auto-start (live on a founder's Mac 2026-10-07; fresh-account behavior checked with an empty
# OPENCLAW_HOME: no config -> exits 78 "Missing config"; with setup's gateway settings it starts before
# onboarding, and onboarding's model change is hot-reloaded without a restart) ----------------------

def test_a_failed_gateway_service_start_doesnt_stop_setup_before_the_doctor(tmp_path):
    text = _stage(tmp_path, base_python=None)
    i = text.index('launchctl bootstrap system "$GW_PLIST"')
    assert text[i:i + 200].split("\n")[1].strip().startswith("|| echo"), "a failed bootstrap must not abort setup"
    assert i < text.index("doctor --repo")


def test_the_quickstart_no_longer_asks_for_a_gateway_window_or_a_token():
    qs = (ROOT / "QUICKSTART_OPENCLAW.md").read_text()
    assert "openclaw gateway run" not in qs and "auth-token" not in qs
    assert "Gateway service:** skip installing it" in qs
