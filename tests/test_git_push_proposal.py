"""A plain `git push` becomes a Synthe proposal (git-remote-synthe), end to end with real git.

The agent's clone is made through the broker, so its `origin` is `synthe::<broker>`. Every test drives
the real `git` binary, which runs the real helper; the broker is real (dev isolation) and the remote is
a real bare repository. Nothing may reach the remote until the human approves.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import synthe_approve as sa  # noqa: E402
import synthe_client as scl  # noqa: E402
import synthe_sign as ss  # noqa: E402
from test_openclaw_flow import ENV, PASS, _task, broker, git, world  # noqa: E402,F401  (world: a fixture)


@pytest.fixture
def agent(world, tmp_path):
    """The agent's side: a bin dir with git-remote-synthe on PATH and an inbox for signed tasks."""
    bindir, inbox = tmp_path / "bin", tmp_path / "inbox"
    bindir.mkdir()
    inbox.mkdir()
    helper = bindir / "git-remote-synthe"
    helper.write_text(f"#!/bin/sh\nexec {sys.executable} {ROOT / 'src' / 'synthe_git_remote.py'} \"$@\"\n")
    helper.chmod(0o755)
    env = {**ENV, "PATH": f"{bindir}{os.pathsep}{ENV['PATH']}", "SYNTHE_INBOX": str(inbox)}
    env.pop("SYNTHE_BROKER_UID", None)
    env.pop("SYNTHE_TASK", None)
    return {**world, "inbox": inbox, "env": env, "work": tmp_path / "agent-clone"}


def give_task(agent, purpose, branch):
    packet = _task(agent, purpose, branch)
    path = agent["inbox"] / f"{packet['handoff']['id']}.json"
    path.write_text(json.dumps(packet, indent=2))
    return packet


def run_git(agent, *args):
    return subprocess.run(["git", "-C", str(agent["work"]), *args], env=agent["env"], capture_output=True,
                          text=True, timeout=120)


def commit(agent, branch, files):
    work = agent["work"]
    git(work, "checkout", "-q", "-B", branch, "origin/main")
    for path, text in files.items():
        (work / path).parent.mkdir(parents=True, exist_ok=True)
        (work / path).write_text(text)
    git(work, "add", "-A")
    git(work, "commit", "-q", "-m", f"work on {branch}")
    return git(work, "rev-parse", "HEAD")


def on_remote(agent, branch):
    return git(agent["remote"], "branch", "--list", branch)


def approve_all(url, home):
    human = scl.BrokerClient(url)
    [waiting] = sa.waiting_for_approval(human.call("staged")["staged"])
    detail = human.call("staged_detail", id=f"{waiting['idempotency_key']}/{waiting['action']}")
    key = ss.load_key(str(home / "approver.key.json"), passphrase=PASS, require_encrypted=True)
    return detail, human.call("submit_approval", approval=sa.build_approval(detail, key))


def test_a_plain_git_push_is_proposed_and_lands_only_after_approval(agent):
    give_task(agent, "Add a greeting", "agent/greet")
    with broker(agent["home"]) as url:
        scl.clone(scl.BrokerClient(url), str(agent["work"]))
        assert git(agent["work"], "remote", "get-url", "origin") == f"synthe::{url}"
        sha = commit(agent, "agent/greet", {"src/greet.py": "print('hello')\n"})

        p = run_git(agent, "push", "origin", "agent/greet")
        assert p.returncode == 0, p.stderr
        assert "proposed for approval, not pushed yet" in p.stderr and "synthe-approve" in p.stderr
        assert on_remote(agent, "agent/greet") == ""                       # nothing reached the remote
        # git doesn't pretend it did: no remote-tracking ref for the proposed branch
        assert git(agent["work"], "for-each-ref", "refs/remotes/origin/agent") == ""
        claim = next((agent["work"] / ".git" / "synthe" / "claims").glob("*.json"))
        assert oct(claim.stat().st_mode & 0o777) == "0o600"

        detail, out = approve_all(url, agent["home"])
        assert [f["path"] for f in detail["changes"]["files"]] == ["src/greet.py"]
        assert [c["decision"] for c in out["commits"]] == ["executed"], out
    assert git(agent["remote"], "rev-parse", "refs/heads/agent/greet") == sha


def test_plain_git_push_with_no_arguments_proposes_the_current_branch(agent):
    give_task(agent, "No-argument push", "agent/bare")
    with broker(agent["home"]) as url:
        scl.clone(scl.BrokerClient(url), str(agent["work"]))
        commit(agent, "agent/bare", {"src/bare.py": "b = 1\n"})
        p = run_git(agent, "push")                                         # push.default=current
        assert p.returncode == 0, p.stderr
        assert "agent/bare at" in p.stderr and "proposed for approval" in p.stderr
        assert on_remote(agent, "agent/bare") == ""


def test_git_pull_reads_through_the_broker(agent, tmp_path):
    remote = agent["remote"]
    with broker(agent["home"]) as url:
        scl.clone(scl.BrokerClient(url), str(agent["work"]))
        other = tmp_path / "other"
        subprocess.run(["git", "clone", "-q", str(remote), str(other)], env=ENV, check=True, capture_output=True)
        (other / "src" / "new.py").write_text("x = 1\n")
        git(other, "add", "-A")
        git(other, "commit", "-q", "-m", "upstream change")
        git(other, "push", "-q", "origin", "main")
        p = run_git(agent, "pull", "-q", "--ff-only")
        assert p.returncode == 0, p.stderr
    assert git(agent["work"], "rev-parse", "HEAD") == git(remote, "rev-parse", "main")
    assert (agent["work"] / "src" / "new.py").read_text() == "x = 1\n"


def test_a_push_with_no_task_for_the_branch_is_refused_and_says_what_to_do(agent):
    give_task(agent, "Some other branch", "agent/other")
    with broker(agent["home"]) as url:
        scl.clone(scl.BrokerClient(url), str(agent["work"]))
        commit(agent, "agent/untasked", {"src/u.py": "u = 1\n"})
        p = run_git(agent, "push", "origin", "agent/untasked")
        assert p.returncode != 0
        assert "no_task_for_branch" in p.stderr and "synthe-task new" in p.stderr
        main_push = run_git(agent, "push", "origin", "HEAD:main")
        assert main_push.returncode != 0 and "no_task_for_branch" in main_push.stderr
    assert on_remote(agent, "agent/untasked") == ""
    assert git(agent["remote"], "rev-parse", "main") != git(agent["work"], "rev-parse", "HEAD")   # main unmoved


def test_an_expired_task_is_not_used(agent):
    packet = give_task(agent, "Expired work", "agent/old")
    path = agent["inbox"] / f"{packet['handoff']['id']}.json"
    stale = json.loads(path.read_text())
    stale["handoff"]["acceptance"]["expires_at"] = "2020-01-01T00:00:00Z"   # (its signature no longer matters)
    path.write_text(json.dumps(stale))
    with broker(agent["home"]) as url:
        scl.clone(scl.BrokerClient(url), str(agent["work"]))
        commit(agent, "agent/old", {"src/o.py": "o = 1\n"})
        p = run_git(agent, "push", "origin", "agent/old")
    assert p.returncode != 0 and "no_task_for_branch" in p.stderr


def test_the_broker_still_decides_a_push_outside_the_lane_is_denied_with_a_receipt(agent):
    give_task(agent, "Touch CI", "agent/ci")
    with broker(agent["home"]) as url:
        scl.clone(scl.BrokerClient(url), str(agent["work"]))
        commit(agent, "agent/ci", {".github/workflows/ci.yml": "on: push\n"})
        p = run_git(agent, "push", "origin", "agent/ci")
        chain = scl.BrokerClient(url).call("receipts", limit=10)
    assert p.returncode != 0
    assert "Synthe refused this push" in p.stderr and "path_outside_scope" in p.stderr
    assert "Nothing was pushed" in p.stderr
    assert on_remote(agent, "agent/ci") == ""
    assert chain["ok"] and chain["receipts"][-1]["decision"] == "denied"


def test_deleting_a_branch_is_not_a_proposal(agent):
    with broker(agent["home"]) as url:
        scl.clone(scl.BrokerClient(url), str(agent["work"]))
        tip = git(agent["remote"], "rev-parse", "main")
        p = run_git(agent, "push", "origin", ":main")
        staged = scl.BrokerClient(url).call("staged")["staged"]
    # The helper lists no remote branches for a push, so git itself refuses the deletion before asking it
    # (and the helper refuses one anyway: it has no proposal for a deletion).
    assert p.returncode != 0 and "unable to delete 'main'" in p.stderr
    assert git(agent["remote"], "rev-parse", "main") == tip and staged == []


def test_the_helper_itself_refuses_a_deletion_if_git_ever_asks(agent, monkeypatch):
    import io
    import synthe_git_remote as gr
    with broker(agent["home"]) as url:
        scl.clone(scl.BrokerClient(url), str(agent["work"]))
        monkeypatch.chdir(agent["work"])
        monkeypatch.setenv("GIT_DIR", str(agent["work"] / ".git"))
        out = io.StringIO()
        gr.Helper("origin", url, out=out).run(io.StringIO("push :refs/heads/main\n\n"))
    assert out.getvalue() == "error refs/heads/main deletion is not a proposal\n\n"


def test_a_task_claimed_in_another_session_says_so_instead_of_failing_obscurely(agent):
    packet = give_task(agent, "Claimed elsewhere", "agent/twice")
    with broker(agent["home"]) as url:
        client = scl.BrokerClient(url)
        assert client.call("claim", packet=packet, wait_for_approval=True)["decision"] == "ACCEPT"
        scl.clone(client, str(agent["work"]))
        commit(agent, "agent/twice", {"src/t.py": "t = 1\n"})
        p = run_git(agent, "push", "origin", "agent/twice")
    assert p.returncode != 0 and "task_claimed_elsewhere" in p.stderr
    assert on_remote(agent, "agent/twice") == ""


def test_the_helper_refuses_a_broker_that_is_not_the_one_the_clone_came_from(agent):
    give_task(agent, "Pinned broker", "agent/pin")
    with broker(agent["home"]) as url:
        scl.clone(scl.BrokerClient(url), str(agent["work"]))
        assert git(agent["work"], "config", "synthe.brokerUid") == str(os.getuid())
        git(agent["work"], "config", "synthe.brokerUid", str(os.getuid() + 4242))   # a swapped socket
        commit(agent, "agent/pin", {"src/p.py": "p = 1\n"})
        p = run_git(agent, "push", "origin", "agent/pin")
        staged = scl.BrokerClient(url).call("staged")["staged"]
    assert p.returncode != 0 and "broker_not_isolated" in p.stderr
    assert staged == [] and on_remote(agent, "agent/pin") == ""             # nothing was even sent


def test_doctor_on_a_broker_clone_probes_the_real_remote_not_the_synthe_origin(agent):
    with broker(agent["home"]) as url:
        client = scl.BrokerClient(url)
        scl.clone(client, str(agent["work"]))
        checks = scl.doctor(client, repo=str(agent["work"]), git_remote="origin")
    [push] = [c for c in checks if c["check"] == "direct push"]
    # dev isolation with a local remote: the agent's user can write it, and doctor must say so
    assert push["status"] == "FAIL" and str(agent["remote"]) in push["detail"]
