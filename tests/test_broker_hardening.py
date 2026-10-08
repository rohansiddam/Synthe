"""Regression tests for review fixes: .git tree entries, corrupt staged store, version."""
import pytest
from test_speculative import PUSH, speculative_claim
from world import World, cm, codes, git


@pytest.fixture
def w(tmp_path):
    return World(tmp_path)


def _project_version():
    import re
    from pathlib import Path
    text = (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text()
    return re.search(r'^version = "([^"]+)"', text, re.M).group(1)


def test_broker_version_matches_package():
    assert cm.VERSION == _project_version()


def test_mcp_server_version_matches_package():
    """The Lab's MCP handshake reports this (serverInfo): agents saw 'synthe 0.4.0'."""
    import synthe_mcp
    assert synthe_mcp.SERVER_VERSION == _project_version()


def _commit_with_entry(w, path):
    """A commit whose tree holds `path`, built with plumbing (`git add` refuses
    .git entries, an attacker would not)."""
    def run(*a, stdin=None):
        import os
        import subprocess
        env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
               "GIT_AUTHOR_NAME": "a", "GIT_AUTHOR_EMAIL": "a@x.test",
               "GIT_COMMITTER_NAME": "a", "GIT_COMMITTER_EMAIL": "a@x.test"}
        return subprocess.run(["git", "-C", str(w.agent), *a], input=stdin, capture_output=True,
                              text=True, env=env, check=True).stdout.strip()
    parts = path.split("/")
    obj = run("hash-object", "-w", "--stdin", stdin="x\n")
    entry = f"100644 blob {obj}\t{parts[-1]}\n"
    for name in reversed(parts[:-1]):
        tree = run("mktree", "--missing", stdin=entry)
        entry = f"040000 tree {tree}\t{name}\n"
    tree = run("mktree", "--missing", stdin=entry)
    return run("commit-tree", tree, "-p", run("rev-parse", "HEAD"), "-m", "evil")


@pytest.mark.parametrize("path", [".git/config", "src/.GIT/hooks", "src/.git"])
def test_dotgit_entry_is_commit_unavailable_whatever_fsck_says(w, path):
    p = w.packet(idem="g1", owned_paths=["**"])
    tok = w.claim(p)
    sha = _commit_with_entry(w, path)
    r = w.propose(p, tok, sha)
    assert r["decision"] == "denied" and codes(r) == {"commit_unavailable"}, r
    assert w.remote_ref("feature/x") is None


def test_corrupt_staged_store_does_not_block_receipts(w):
    """Refusing a corrupt store must not take down the read-only receipt path."""
    p = w.packet(idem="c1", branch="feature/x", approve=False)
    tok = speculative_claim(w, p)
    w.cfg.staged_path.parent.mkdir(parents=True, exist_ok=True)
    w.cfg.staged_path.write_text("{ not json")
    sha = w.commit({"src/app.py": "print(1)\n"})
    with pytest.raises(cm.StagedStoreCorrupt):
        w.propose(p, tok, sha, branch="feature/x", wait_for_approval=True)


def test_claim_tokens_never_start_with_a_dash(tmp_path):
    """FINDING (Soarer): a claim token starting with "-" is read by argparse as an
    option, so `--claim-token TOKEN` failed for 1 token in 64."""
    import handoff_check as hc
    import synthe_sign as ss
    from world import mkkey, ts
    import datetime as dt
    w = World(tmp_path)
    seen = set()
    for i in range(300):
        p = w.packet(idem=f"tok-{i}", approve=False)
        v = hc.check(p, registry=w.registry, ledger_path=w.tmp / "ledger.json", workspace=w.tmp / "workspace",
                     defer_approvals={"push_branch"})
        assert v["decision"] == "ACCEPT", v
        seen.add(v["claim"]["token"])
    assert len(seen) == 300 and not any(t.startswith("-") for t in seen)
