"""The product flow for an OpenClaw user, end to end, with everything real except the model:

synthe-init writes the keys and the broker (dev isolation); synthe-task signs a task; the agent side is
the real synthe-mcp server driven over stdio, the way OpenClaw drives it (validate with
wait_for_approval, commit in its clone, propose, staged); the human approves through synthe-approve's
own code with the passphrase-sealed key; the broker pushes and the receipt chain verifies. Then the
same broker denies a push outside the allowed paths, and doctor says ADVISORY, because in dev isolation
with a local remote the agent could still write the repository itself.
"""
import contextlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import synthe_approve as sa  # noqa: E402
import synthe_broker as sb  # noqa: E402
import synthe_client as scl  # noqa: E402
import synthe_commit as cm  # noqa: E402
import synthe_init as si  # noqa: E402
import synthe_sign as ss  # noqa: E402
import synthe_task as st  # noqa: E402

PASS = "a long enough test passphrase"
ENV = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
       "GIT_AUTHOR_NAME": "agent", "GIT_AUTHOR_EMAIL": "agent@example.invalid",
       "GIT_COMMITTER_NAME": "agent", "GIT_COMMITTER_EMAIL": "agent@example.invalid"}


def git(cwd, *args):
    return subprocess.run(["git", "-C", str(cwd), *args], env=ENV, capture_output=True, text=True,
                          check=True).stdout.strip()


@contextlib.contextmanager
def broker(home: Path):
    d = tempfile.mkdtemp(prefix="sy", dir="/tmp")  # unix socket paths are capped at 104 bytes on macOS
    srv = sb.make_server(cm.BrokerConfig(home / "broker" / "broker.json"), socket_path=os.path.join(d, "b.sock"))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield f"unix://{d}/b.sock"
    finally:
        srv.shutdown()
        srv.server_close()
        shutil.rmtree(d, ignore_errors=True)


class Mcp:
    """synthe-mcp over stdio, one JSON-RPC line at a time (what OpenClaw does with a stdio server)."""

    def __init__(self, url):
        self.p = subprocess.Popen([sys.executable, str(ROOT / "src" / "synthe_mcp.py"), "--broker-url", url],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        self.n = 0

    def call(self, method, params=None):
        self.n += 1
        self.p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": self.n, "method": method, "params": params or {}}) + "\n")
        self.p.stdin.flush()
        return json.loads(self.p.stdout.readline())

    def tool(self, name, **args):
        r = self.call("tools/call", {"name": name, "arguments": args})["result"]
        return r.get("structuredContent") or json.loads(r["content"][0]["text"])

    def close(self):
        self.p.stdin.close()
        self.p.wait(timeout=20)


@pytest.fixture
def world(tmp_path):
    remote, seed, clone, home = (tmp_path / n for n in ("remote.git", "seed", "clone", "home"))
    subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(remote)], env=ENV, check=True)
    subprocess.run(["git", "clone", "-q", str(remote), str(seed)], env=ENV, check=True, capture_output=True)
    (seed / "src").mkdir()
    (seed / "src" / "app.py").write_text("print('hi')\n")
    git(seed, "add", "-A")
    git(seed, "commit", "-q", "-m", "init")
    git(seed, "push", "-q", "origin", "main")
    subprocess.run(["git", "clone", "-q", str(remote), str(clone)], env=ENV, check=True, capture_output=True)
    home.mkdir()
    pub = si.approver_public_key(home, "rohan", passphrase=PASS)
    si.write_broker(home, repo_url=str(remote), branches=["agent/*"], allowed_paths=["src/**"],
                    approver="rohan", approver_pub=pub, agent="openclaw", token_file=None)
    return {"remote": remote, "clone": clone, "home": home}


def _task(world, purpose, branch):
    packet, _ = st.build_task(world["home"], purpose, branch)
    return ss.sign_packet(packet, ss.load_key(str(world["home"] / "approver.key.json"), passphrase=PASS,
                                              require_encrypted=True))


def _commit(clone, branch, files):
    git(clone, "checkout", "-q", "-B", branch, "origin/main")
    for path, text in files.items():
        (clone / path).parent.mkdir(parents=True, exist_ok=True)
        (clone / path).write_text(text)
    git(clone, "add", "-A")
    git(clone, "commit", "-q", "-m", f"work on {branch}")
    return git(clone, "rev-parse", "HEAD")


def test_setup_writes_a_sealed_approver_key_and_a_fail_closed_broker(world):
    home = world["home"]
    assert ss.is_encrypted(json.loads((home / "approver.key.json").read_text()))
    assert (home / "approver.key.json").stat().st_mode & 0o777 == 0o600
    reg = json.loads((home / "broker" / "registry.json").read_text())
    policy = reg["agents"]["openclaw"]["policy"]
    assert policy["max_ttl_hours"] == si.DEFAULT_MAX_TTL_HOURS and policy["require_signed_approvals"]
    assert policy["approval_required_for"] == ["git_push"] and policy["trusted_approvers"] == ["rohan"]
    cfg = json.loads((home / "broker" / "broker.json").read_text())
    assert cfg["effects"]["git_push"]["require_approval_commit_pin"] is True
    assert (home / "broker").stat().st_mode & 0o777 == 0o700
    with pytest.raises(SystemExit, match="already holds a broker"):
        si.write_broker(home, repo_url="x", branches=["agent/*"], allowed_paths=["src/**"], approver="rohan",
                        approver_pub={}, agent="openclaw", token_file=None)
    for bad in (["main"], ["*"], []):
        with pytest.raises(SystemExit):
            si.write_broker(home / "other", repo_url="x", branches=bad, allowed_paths=["src/**"], approver="rohan",
                            approver_pub={}, agent="openclaw", token_file=None)


def test_a_plaintext_approver_key_is_refused_by_setup(tmp_path):
    (tmp_path / "approver.key.json").write_text(json.dumps({"agent": "rohan", "kid": "k", "alg": "Ed25519",
                                                             "private_key": "AAAA"}))
    with pytest.raises(ss.KeyFileError, match="plaintext"):
        si.approver_public_key(tmp_path, "rohan", passphrase=PASS)


def test_task_refuses_branches_the_broker_may_not_push_and_overlong_lifetimes(world):
    with pytest.raises(SystemExit, match="not one the broker may push"):
        st.build_task(world["home"], "do it", "main")
    with pytest.raises(SystemExit, match="maximum"):
        st.build_task(world["home"], "do it", "agent/x", hours=si.DEFAULT_MAX_TTL_HOURS + 1)


def test_the_whole_flow_task_claim_propose_approve_push(world):
    clone, home = world["clone"], world["home"]
    packet = _task(world, "Add a greeting to the app", "agent/greet")
    with broker(home) as url:
        mcp = Mcp(url)
        try:
            names = {t["name"] for t in mcp.call("tools/list")["result"]["tools"]}
            assert {"synthe_validate_handoff", "synthe_propose_effect"} <= names
            v = mcp.tool("synthe_validate_handoff", packet=packet, wait_for_approval=True)
            assert v["decision"] == "ACCEPT", v
            token = v["claim"]["token"]
            sha = _commit(clone, "agent/greet", {"src/greet.py": "print('hello')\n"})
            r = mcp.tool("synthe_propose_effect", packet=packet, claim_token=token, action="push_branch",
                         params={"remote": "origin", "branch": "agent/greet", "commit": sha},
                         source=str(clone), wait_for_approval=True)
            assert r["decision"] == "staged", r
            assert git(world["remote"], "branch", "--list", "agent/greet") == ""  # nothing pushed yet
        finally:
            mcp.close()

        human = scl.BrokerClient(url)
        [waiting] = sa.waiting_for_approval(human.call("staged")["staged"])
        sid = f"{waiting['idempotency_key']}/{waiting['action']}"
        detail = human.call("staged_detail", id=sid)
        assert [f["path"] for f in detail["changes"]["files"]] == ["src/greet.py"]
        assert "+print('hello')" in detail["changes"]["patch"]
        key = ss.load_key(str(home / "approver.key.json"), passphrase=PASS, require_encrypted=True)
        out = human.call("submit_approval", approval=sa.build_approval(detail, key))
        assert [c["decision"] for c in out["commits"]] == ["executed"], out
        chain = human.call("receipts", limit=50)
    assert git(world["remote"], "rev-parse", "refs/heads/agent/greet") == sha
    assert chain["ok"] and [r["decision"] for r in chain["receipts"]][-3:] == ["staged", "approval_accepted", "executed"]


@pytest.mark.parametrize("branch, files, code", [
    ("agent/ci", {".github/workflows/ci.yml": "on: push\n"}, "path_outside_scope"),   # outside the src/** lane
    ("agent/key", {"src/deploy.key.json": "{}\n"}, "path_forbidden"),                 # inside it, but forbidden
])
def test_the_broker_denies_a_push_outside_the_allowed_paths(world, branch, files, code):
    clone, home = world["clone"], world["home"]
    packet = _task(world, f"Change {next(iter(files))}", branch)
    with broker(home) as url:
        mcp = Mcp(url)
        try:
            v = mcp.tool("synthe_validate_handoff", packet=packet, wait_for_approval=True)
            sha = _commit(clone, branch, files)
            r = mcp.tool("synthe_propose_effect", packet=packet, claim_token=v["claim"]["token"], action="push_branch",
                         params={"remote": "origin", "branch": branch, "commit": sha},
                         source=str(clone), wait_for_approval=True)
        finally:
            mcp.close()
    assert r["decision"] == "denied", r
    assert code in {x["code"] for x in r["reasons"]}, r["reasons"]
    assert git(world["remote"], "branch", "--list", branch) == ""


def test_doctor_is_honest_about_dev_isolation(world):
    with broker(world["home"]) as url:
        report = si.run_doctor(world["home"], None, repo=str(world["clone"]), broker=url)
    by = {c["check"]: c["status"] for c in report["checks"]}
    assert report["level"] == "ADVISORY", report
    assert by["broker isolation"] == "FAIL"          # the broker runs as this same user
    assert by["direct push"] == "FAIL"               # this user can write the local remote
    assert by["approver key"] == "PASS"              # but the approval still needs the passphrase


def test_levels():
    def c(*pairs):
        return [{"check": k, "status": s, "detail": ""} for k, s in pairs]
    plugin = ("barrier plugin", "PASS")
    assert si.level(c(("broker isolation", "PASS"), plugin, ("approver key", "PASS"))) == "ENFORCED"
    assert si.level(c(("broker isolation", "FAIL"), plugin, ("approver key", "PASS"))) == "GUARDED"
    assert si.level(c(("broker isolation", "WARN"), ("container runtime", "WARN"), plugin)) == "GUARDED"
    assert si.level(c(("broker isolation", "WARN"), plugin)) == "ENFORCED"
    assert si.level(c(("broker isolation", "PASS"), plugin, ("direct push", "FAIL"))) == "ADVISORY"
    assert si.level(c(("broker isolation", "PASS"), ("barrier plugin", "FAIL"))) == "ADVISORY"
    assert si.level(c(("broker isolation", "FAIL"), plugin, ("approver key", "FAIL"))) == "ADVISORY"


# ---- what the first real GitHub push found (2026-10-07) ------------------------------------------------

def _approve_push(world, branch):
    """Task, claim, commit, propose and approve one push; returns the broker's commit results."""
    clone, home = world["clone"], world["home"]
    packet = _task(world, f"Work on {branch}", branch)
    with broker(home) as url:
        mcp = Mcp(url)
        try:
            v = mcp.tool("synthe_validate_handoff", packet=packet, wait_for_approval=True)
            sha = _commit(clone, branch, {"src/x.py": "x = 1\n"})
            r = mcp.tool("synthe_propose_effect", packet=packet, claim_token=v["claim"]["token"],
                         action="push_branch", params={"remote": "origin", "branch": branch, "commit": sha},
                         source=str(clone), wait_for_approval=True)
            assert r["decision"] == "staged", r
        finally:
            mcp.close()
        human = scl.BrokerClient(url)
        [waiting] = sa.waiting_for_approval(human.call("staged")["staged"])
        detail = human.call("staged_detail", id=f"{waiting['idempotency_key']}/{waiting['action']}")
        key = ss.load_key(str(home / "approver.key.json"), passphrase=PASS, require_encrypted=True)
        out = human.call("submit_approval", approval=sa.build_approval(detail, key))
        return out["commits"], human.call("staged")["staged"]


def _remote_hook(world, script):
    hook = world["remote"] / "hooks" / "pre-receive"
    hook.write_text("#!/bin/sh\n" + script)
    hook.chmod(0o755)


def test_a_server_error_from_the_remote_is_retried_not_final(world):
    # GitHub answered the first real pushes "[remote rejected] (failure)" / "Internal Server Error".
    _remote_hook(world, 'echo "fatal error in commit_refs" >&2; echo "Internal Server Error" >&2; exit 1\n')
    commits, staged = _approve_push(world, "agent/flaky")
    assert [c["decision"] for c in commits] == ["errored"], commits
    assert {r["code"] for r in commits[0]["reasons"]} == {"push_failed"}
    assert [s["state"] for s in staged] == ["STAGED"]          # still queued: the broker tries again later
    assert git(world["remote"], "branch", "--list", "agent/flaky") == ""


def test_a_real_refusal_from_the_remote_stays_final(world):
    _remote_hook(world, 'echo "protected branch: pushes to this branch are not allowed" >&2; exit 1\n')
    commits, staged = _approve_push(world, "agent/refused")
    assert [c["decision"] for c in commits] == ["denied"], commits
    assert {r["code"] for r in commits[0]["reasons"]} == {"push_rejected"}
    assert [s["state"] for s in staged] == ["DENIED"]


@pytest.mark.parametrize("url, token, user", [
    ("https://github.com/rohansiddam/synthe-test.git", "github_pat_11ABC", "rohansiddam"),   # fine-grained PAT
    ("https://github.com/acme/app.git", "ghp_abc", "acme"),                                   # classic PAT
    ("https://github.com/acme/app.git", "ghs_installationtoken", "x-access-token"),           # App token
    ("https://gitlab.example/acme/app.git", "github_pat_11ABC", "x-access-token"),            # not GitHub
    ("https://github.com/-bad/app.git", "github_pat_11ABC", "x-access-token"),                # not an owner name
])
def test_the_https_username_matches_the_token_kind(url, token, user):
    assert cm.git_username(url, token) == user


# ---- read access through the broker: the agent's account needs no GitHub credential, even to read ------

def test_the_agent_clones_and_syncs_through_the_broker_and_proposes_from_that_clone(world, tmp_path):
    remote, home = world["remote"], world["home"]
    with broker(home) as url:
        client = scl.BrokerClient(url)
        work = tmp_path / "agent-clone"
        out = scl.clone(client, str(work))
        assert out["ref"] == "main" and out["tip"] == git(remote, "rev-parse", "main")
        assert (work / "src" / "app.py").read_text() == "print('hi')\n"
        # origin is Synthe itself: a push there is a proposal (git-remote-synthe), never a direct push
        assert git(work, "remote", "get-url", "origin") == f"synthe::{url}"
        with pytest.raises(scl.BrokerError, match="not empty"):
            scl.clone(client, str(work))
        # the remote moves on; sync brings the new tip, touching nothing of the agent's
        other = tmp_path / "other"
        subprocess.run(["git", "clone", "-q", str(remote), str(other)], env=ENV, check=True, capture_output=True)
        (other / "src" / "new.py").write_text("x = 1\n")
        git(other, "add", "-A")
        git(other, "commit", "-q", "-m", "upstream change")
        git(other, "push", "-q", "origin", "main")
        s = scl.sync(client, str(work))
        assert s["updated"] and s["tip"] == git(remote, "rev-parse", "main")
        assert git(work, "rev-parse", "refs/remotes/synthe/main") == s["tip"]
        assert not (work / "src" / "new.py").exists()          # the working tree is the agent's to update
        assert scl.sync(client, str(work))["updated"] is False
        # a branch outside the readable list is refused
        with pytest.raises(scl.BrokerError) as e:
            client.call("fetch_bundle", ref="release/secret")
        assert e.value.code == "read_not_allowed"
        # and the agent proposes from the broker-made clone
        packet = _task(world, "Work from a broker clone", "agent/from-bundle")
        mcp = Mcp(url)
        try:
            v = mcp.tool("synthe_validate_handoff", packet=packet, wait_for_approval=True)
            git(work, "checkout", "-q", "-B", "agent/from-bundle", "refs/remotes/synthe/main")
            (work / "src" / "b.py").write_text("b = 1\n")
            git(work, "add", "-A")
            git(work, "commit", "-q", "-m", "from a bundle clone")
            r = mcp.tool("synthe_propose_effect", packet=packet, claim_token=v["claim"]["token"], action="push_branch",
                         params={"remote": "origin", "branch": "agent/from-bundle",
                                 "commit": git(work, "rev-parse", "HEAD")},
                         source=str(work), wait_for_approval=True)
            assert r["decision"] == "staged", r
        finally:
            mcp.close()


def test_a_remote_not_marked_readable_serves_no_bundle(world):
    cfg_path = world["home"] / "broker" / "broker.json"
    cfg = json.loads(cfg_path.read_text())
    cfg["effects"]["git_push"]["remotes"]["origin"]["readable"] = False
    cfg_path.write_text(json.dumps(cfg))
    with broker(world["home"]) as url:
        with pytest.raises(scl.BrokerError) as e:
            scl.BrokerClient(url).call("fetch_bundle", remote="origin", ref="main")   # named: no default to hide behind
        assert e.value.code == "read_not_allowed"


def test_doctor_probes_the_real_remote_from_a_broker_clone_instead_of_passing_on_nothing(world, tmp_path):
    """A broker clone has no `origin`: a push to it fails for the wrong reason. The doctor must test the
    broker's actual remote. Here (dev, one user) that remote is writable, so the honest answer is FAIL."""
    with broker(world["home"]) as url:
        client = scl.BrokerClient(url)
        work = tmp_path / "agent-clone"
        scl.clone(client, str(work))
        checks = {c["check"]: c for c in scl.doctor(client, repo=str(work), git_remote="origin")}
    assert checks["direct push"]["status"] == "FAIL", checks["direct push"]
    assert str(world["remote"]) in checks["direct push"]["detail"]
