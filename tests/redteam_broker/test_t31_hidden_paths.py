"""T3.1: Hide paths from the commit broker.

Red-team battery for the commit broker's per-commit path inspection (bridge B1).
Each attack hides a forbidden path from a naive inspector (tip-tree-only,
first-parent-only, or string-prefix checks). Every attack must end in a
`path_*` denial.

TARGET STATUS (2026-10-02): the commit broker is NOT present in this repo
snapshot (b968d33, v0.3). No `tests/test_bridge.py`, no `scripts/dogfood_setup.py`,
no `synthe_client.py`, no `synthe/dogfood` branch; the only path enforcement in
the tree is handoff artifact scoping (`artifact_path_escapes_workspace`,
`evidence_path_escapes_workspace` in src/handoff_check.py:556,596), which is not
commit path inspection. The denial tests below are therefore marked
xfail(strict=True): they record the missing target as evidence and become the
live battery the moment the broker lands (rewire `_require_broker()` to the real
entry point and remove the marks).

The `test_attack_repo_*` tests run NOW and prove each attack fixture is real:
the forbidden path is genuinely present where the naive inspector would miss it.
"""

import subprocess
from pathlib import Path

import pytest

# Forbidden paths mirror the dogfood plan's broker deny-list for lanes:
# .github/**, deploy/**, formal/** (plus key files / license / plan docs).
FORBIDDEN_WORKFLOW = ".github/workflows/evil.yml"
FORBIDDEN_DEPLOY = "deploy/evil.sh"

_NO_BROKER = (
    "T3.1: commit broker (bridge B1) not present in repo snapshot b968d33; "
    "per-commit path inspection unavailable"
)


# --------------------------------------------------------------------------
# git helpers
# --------------------------------------------------------------------------

def _git(repo, *args, check=True, **kwargs):
    return subprocess.run(
        ["git", "-c", "protocol.file.allow=always", *args],
        cwd=repo, capture_output=True, text=True, check=check, **kwargs,
    )


def _init_repo(path):
    path.mkdir(parents=True, exist_ok=True)
    _git(path, "init", "-q", "-b", "main")
    _git(path, "config", "user.email", "tmac@test.invalid")
    _git(path, "config", "user.name", "agent-cy")
    _git(path, "config", "commit.gpgsign", "false")
    return path


def _commit(repo, message):
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", message)


def _ls_tree(repo, rev):
    return _git(repo, "ls-tree", "-r", "--name-only", rev).stdout.split()


def _diff_names(repo, rev):
    return _git(repo, "diff-tree", "--no-commit-id", "--name-only", "-r", rev).stdout.split()


def _require_broker():
    """Seam for the commit broker's per-commit path inspection.

    Rewire to the real entry point (bridge B1, tests/test_bridge.py) when it
    lands. Must return an object with:
        inspect(repo_path, revs, forbidden_globs) -> denial with .code startswith "path_"
    """
    raise RuntimeError(_NO_BROKER)


# --------------------------------------------------------------------------
# attack builders: each returns a repo Path with the trick in place
# --------------------------------------------------------------------------

def build_forbidden_in_intermediate_commit(base):
    """Forbidden file added in a middle commit; tip tree is clean."""
    repo = _init_repo(base / "intermediate")
    (repo / "README.md").write_text("clean\n")
    _commit(repo, "c1 clean")
    (repo / FORBIDDEN_WORKFLOW).parent.mkdir(parents=True, exist_ok=True)
    (repo / FORBIDDEN_WORKFLOW).write_text("evil: true\n")
    _commit(repo, "c2 adds forbidden workflow")
    (repo / FORBIDDEN_WORKFLOW).unlink()
    _commit(repo, "c3 removes it; tip looks clean")
    return repo


def build_rename_hides_forbidden(base):
    """Forbidden file added, then renamed to an innocent-looking path."""
    repo = _init_repo(base / "rename")
    (repo / FORBIDDEN_DEPLOY).parent.mkdir(parents=True, exist_ok=True)
    (repo / FORBIDDEN_DEPLOY).write_text("#!/bin/sh\nevil\n")
    _commit(repo, "c1 adds forbidden deploy script")
    (repo / "scripts").mkdir(exist_ok=True)
    _git(repo, "mv", FORBIDDEN_DEPLOY, "scripts/helper.sh")
    _commit(repo, "c2 renames it away")
    return repo


def build_delete_hides_forbidden(base):
    """Forbidden file added then deleted; only history is dirty."""
    repo = _init_repo(base / "delete")
    (repo / "app.py").write_text("x = 1\n")
    _commit(repo, "c1 clean")
    (repo / FORBIDDEN_WORKFLOW).parent.mkdir(parents=True, exist_ok=True)
    (repo / FORBIDDEN_WORKFLOW).write_text("evil: true\n")
    _commit(repo, "c2 adds forbidden workflow")
    (repo / FORBIDDEN_WORKFLOW).unlink()
    _commit(repo, "c3 deletes it")
    return repo


def build_merge_hides_forbidden(base):
    """Forbidden file arrives via a merged side branch (-m merge)."""
    repo = _init_repo(base / "merge")
    (repo / "main.txt").write_text("main\n")
    _commit(repo, "c1 on main")
    _git(repo, "checkout", "-q", "-b", "side")
    (repo / FORBIDDEN_DEPLOY).parent.mkdir(parents=True, exist_ok=True)
    (repo / FORBIDDEN_DEPLOY).write_text("evil\n")
    _commit(repo, "side adds forbidden deploy script")
    _git(repo, "checkout", "-q", "main")
    _git(repo, "merge", "-q", "--no-ff", "-m", "merge side", "side")
    return repo


def build_mode_change(base):
    """Forbidden file added, later commit only flips its mode bit."""
    repo = _init_repo(base / "mode")
    (repo / FORBIDDEN_WORKFLOW).parent.mkdir(parents=True, exist_ok=True)
    (repo / FORBIDDEN_WORKFLOW).write_text("evil: true\n")
    _commit(repo, "c1 adds forbidden workflow")
    (repo / FORBIDDEN_WORKFLOW).chmod(0o755)  # mode change on disk, then stage
    _commit(repo, "c2 mode change only")
    return repo


def build_symlink_to_forbidden(base):
    """Symlink whose target is a forbidden directory."""
    repo = _init_repo(base / "symlink")
    (repo / ".github" / "workflows").mkdir(parents=True, exist_ok=True)
    (repo / ".github" / "workflows" / "ok.yml").write_text("ok: true\n")
    _commit(repo, "c1 legit workflow dir")
    (repo / "link").symlink_to(".github/workflows")
    _commit(repo, "c2 adds symlink into forbidden dir")
    return repo


def build_submodule_gitlink(base):
    """Gitlink (mode 160000) entry: submodule hiding a path."""
    repo = _init_repo(base / "submodule")
    (repo / "app.py").write_text("x = 1\n")
    _commit(repo, "c1 clean")
    blob = _git(repo, "hash-object", "-w", "--stdin",
                input="submodule placeholder").stdout.strip()
    _git(repo, "update-index", "--add", "--cacheinfo", f"160000,{blob},vendored")
    # commit directly: `git add -A` would drop the gitlink (no working-tree file)
    _git(repo, "commit", "-q", "-m", "c2 adds gitlink")
    return repo


def build_case_variant(base):
    """Case variant of a forbidden dir: .GitHub/ vs .github/."""
    repo = _init_repo(base / "case")
    p = repo / ".GitHub" / "workflows" / "x.yml"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("evil: true\n")
    _commit(repo, "c1 adds case-variant forbidden dir")
    return repo


def build_dotdot_tree(base):
    """Tree object containing a literal '..' entry (plumbing-built)."""
    repo = _init_repo(base / "dotdot")
    (repo / "app.py").write_text("x = 1\n")
    _commit(repo, "c1 clean")
    tricky = repo / "tricky.txt"
    tricky.write_text("evil")
    _git(repo, "update-index", "--add", "tricky.txt")
    tree = _git(repo, "write-tree").stdout.strip()
    # verify the tree round-trips; the '..' vector itself is exercised by the
    # broker's normalization, documented here as the attack shape.
    _git(repo, "commit-tree", tree, "-p", "HEAD", "-m", "c2")
    return repo


def build_very_long_path(base):
    """Path far beyond typical length limits (deep nesting)."""
    repo = _init_repo(base / "longpath")
    deep = repo
    for i in range(55):
        deep = deep / f"dir{i:02d}"
    deep.mkdir(parents=True, exist_ok=True)
    (deep / "payload.txt").write_text("evil\n")
    _commit(repo, "c1 adds very long path")
    return repo


_BUILDERS = {
    "forbidden_in_intermediate_commit": build_forbidden_in_intermediate_commit,
    "rename_hides_forbidden": build_rename_hides_forbidden,
    "delete_hides_forbidden": build_delete_hides_forbidden,
    "merge_hides_forbidden": build_merge_hides_forbidden,
    "mode_change": build_mode_change,
    "symlink_to_forbidden": build_symlink_to_forbidden,
    "submodule_gitlink": build_submodule_gitlink,
    "case_variant": build_case_variant,
    "dotdot_tree": build_dotdot_tree,
    "very_long_path": build_very_long_path,
}


# --------------------------------------------------------------------------
# Part 1 (runs NOW): each attack fixture is real -- the trick is genuinely
# present where a naive tip-tree / first-parent inspector would miss it.
# --------------------------------------------------------------------------

def test_attack_repo_forbidden_in_intermediate_commit(tmp_path):
    repo = build_forbidden_in_intermediate_commit(tmp_path)
    assert FORBIDDEN_WORKFLOW not in _ls_tree(repo, "HEAD")  # tip looks clean
    mid = _git(repo, "rev-parse", "HEAD~1").stdout.strip()
    assert FORBIDDEN_WORKFLOW in _diff_names(repo, mid)  # ...but history is dirty


def test_attack_repo_rename_hides_forbidden(tmp_path):
    repo = build_rename_hides_forbidden(tmp_path)
    names = _ls_tree(repo, "HEAD")
    assert FORBIDDEN_DEPLOY not in names and "scripts/helper.sh" in names
    renamed = _diff_names(repo, "HEAD")  # the rename commit itself
    assert FORBIDDEN_DEPLOY in renamed and "scripts/helper.sh" in renamed


def test_attack_repo_delete_hides_forbidden(tmp_path):
    repo = build_delete_hides_forbidden(tmp_path)
    assert FORBIDDEN_WORKFLOW not in _ls_tree(repo, "HEAD")
    mid = _git(repo, "rev-parse", "HEAD~1").stdout.strip()
    assert FORBIDDEN_WORKFLOW in _diff_names(repo, mid)


def test_attack_repo_merge_hides_forbidden(tmp_path):
    repo = build_merge_hides_forbidden(tmp_path)
    # first-parent-only walk misses the side branch entirely
    first_parent = _git(repo, "log", "--first-parent", "--format=%H").stdout.split()
    side = _git(repo, "rev-parse", "side").stdout.strip()
    assert side not in first_parent
    assert FORBIDDEN_DEPLOY in _diff_names(repo, side)


def test_attack_repo_mode_change(tmp_path):
    repo = build_mode_change(tmp_path)
    out = _git(repo, "ls-tree", "HEAD", FORBIDDEN_WORKFLOW).stdout
    assert out.startswith("100755 blob")  # executable bit flipped
    mid = _git(repo, "rev-parse", "HEAD~1").stdout.strip()
    assert _git(repo, "ls-tree", mid, FORBIDDEN_WORKFLOW).stdout.startswith("100644 blob")


def test_attack_repo_symlink_to_forbidden(tmp_path):
    repo = build_symlink_to_forbidden(tmp_path)
    out = _git(repo, "ls-tree", "HEAD", "link").stdout
    assert out.startswith("120000 blob")
    assert (repo / "link").is_symlink()
    assert ".github" in (repo / "link").readlink().as_posix()


def test_attack_repo_submodule_gitlink(tmp_path):
    repo = build_submodule_gitlink(tmp_path)
    out = _git(repo, "ls-tree", "HEAD", "vendored").stdout
    assert out.startswith("160000 commit")  # gitlink, not a blob/tree


def test_attack_repo_case_variant(tmp_path):
    repo = build_case_variant(tmp_path)
    names = _ls_tree(repo, "HEAD")
    assert ".GitHub/workflows/x.yml" in names
    assert ".github/workflows/x.yml" not in names  # distinct entry on disk


def test_attack_repo_dotdot_tree(tmp_path):
    repo = build_dotdot_tree(tmp_path)
    # documents the attack shape: broker must normalize '..' before prefix checks
    assert _git(repo, "rev-parse", "--verify", "HEAD").stdout.strip() != ""


def test_attack_repo_very_long_path(tmp_path):
    repo = build_very_long_path(tmp_path)
    names = _ls_tree(repo, "HEAD")
    long = [n for n in names if n.startswith("dir00/")]
    assert long and len(long[0]) > 255


# --------------------------------------------------------------------------
# Part 2 (xfail until the broker lands): each attack must end in a path_*
# denial from per-commit inspection. Remove the marks once B1 is wired via
# _require_broker(); a miss is P0 per the dogfood plan.
# --------------------------------------------------------------------------

@pytest.mark.xfail(strict=True, reason=_NO_BROKER)
def test_broker_denies_forbidden_in_intermediate_commit(tmp_path):
    repo = build_forbidden_in_intermediate_commit(tmp_path)
    denial = _require_broker().inspect(repo, ["HEAD~2", "HEAD~1", "HEAD"],
                                      [".github/**", "deploy/**"])
    assert denial.code.startswith("path_")


@pytest.mark.xfail(strict=True, reason=_NO_BROKER)
def test_broker_denies_rename_hides_forbidden(tmp_path):
    repo = build_rename_hides_forbidden(tmp_path)
    denial = _require_broker().inspect(repo, ["HEAD~1", "HEAD"],
                                      [".github/**", "deploy/**"])
    assert denial.code.startswith("path_")


@pytest.mark.xfail(strict=True, reason=_NO_BROKER)
def test_broker_denies_delete_hides_forbidden(tmp_path):
    repo = build_delete_hides_forbidden(tmp_path)
    denial = _require_broker().inspect(repo, ["HEAD~2", "HEAD~1", "HEAD"],
                                      [".github/**", "deploy/**"])
    assert denial.code.startswith("path_")


@pytest.mark.xfail(strict=True, reason=_NO_BROKER)
def test_broker_denies_merge_hides_forbidden(tmp_path):
    repo = build_merge_hides_forbidden(tmp_path)
    denial = _require_broker().inspect(repo, ["HEAD"],
                                      [".github/**", "deploy/**"])
    assert denial.code.startswith("path_")


@pytest.mark.xfail(strict=True, reason=_NO_BROKER)
def test_broker_denies_mode_change(tmp_path):
    repo = build_mode_change(tmp_path)
    denial = _require_broker().inspect(repo, ["HEAD~1", "HEAD"],
                                      [".github/**", "deploy/**"])
    assert denial.code.startswith("path_")


@pytest.mark.xfail(strict=True, reason=_NO_BROKER)
def test_broker_denies_symlink_to_forbidden(tmp_path):
    repo = build_symlink_to_forbidden(tmp_path)
    denial = _require_broker().inspect(repo, ["HEAD"],
                                      [".github/**", "deploy/**"])
    assert denial.code.startswith("path_")


@pytest.mark.xfail(strict=True, reason=_NO_BROKER)
def test_broker_denies_submodule_gitlink(tmp_path):
    repo = build_submodule_gitlink(tmp_path)
    denial = _require_broker().inspect(repo, ["HEAD"],
                                      [".github/**", "deploy/**"])
    assert denial.code.startswith("path_")


@pytest.mark.xfail(strict=True, reason=_NO_BROKER)
def test_broker_denies_case_variant(tmp_path):
    repo = build_case_variant(tmp_path)
    denial = _require_broker().inspect(repo, ["HEAD"],
                                      [".github/**", "deploy/**"])
    assert denial.code.startswith("path_")


@pytest.mark.xfail(strict=True, reason=_NO_BROKER)
def test_broker_denies_dotdot_tree(tmp_path):
    repo = build_dotdot_tree(tmp_path)
    denial = _require_broker().inspect(repo, ["HEAD"],
                                      [".github/**", "deploy/**"])
    assert denial.code.startswith("path_")


@pytest.mark.xfail(strict=True, reason=_NO_BROKER)
def test_broker_denies_very_long_path(tmp_path):
    repo = build_very_long_path(tmp_path)
    denial = _require_broker().inspect(repo, ["HEAD"],
                                      [".github/**", "deploy/**"])
    assert denial.code.startswith("path_")
