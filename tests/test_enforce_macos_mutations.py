"""Mutation check for the macOS separate-user setup guards.

Each mutation weakens one security boundary in a copy of the repository.  The
ordinary enforced-mode tests must catch every one.

Set SYNTHE_SKIP_MUTATIONS=1 to skip the subprocess checks.
"""
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

MUTATIONS = {
    "protected branches accepted": (
        "src/synthe_init.py",
        '    if not branches or any(b in ("*", "**", "main", "master") for b in branches):\n',
        "    if False:\n",
    ),
    "missing token accepted": (
        "src/synthe_init.py",
        "    if not token:\n        raise SystemExit(f\"{token_file} is missing or empty\")\n",
        "    if False:\n        raise SystemExit(f\"{token_file} is missing or empty\")\n",
    ),
    "agent account may hold the approver key": (
        "src/synthe_init.py",
        '    if (home / "approver.key.json").exists():\n        raise SystemExit(f"{home} holds an approver key',
        '    if False:\n        raise SystemExit(f"{home} holds an approver key',
    ),
    "missing approver key passes outside an agent account": (
        "src/synthe_init.py",
        '    agent_only = read_setup(home).get("role") == "agent"\n',
        '    agent_only = True\n',
    ),
    "any text accepted as a GitHub token": (
        "src/synthe_init.py",
        '    if "github.com" in repo_url and (not token.startswith(GITHUB_TOKEN_PREFIXES)',
        '    if False and (not token.startswith(GITHUB_TOKEN_PREFIXES)',
    ),
    "task folder left to the umask": (
        "src/synthe_broker.py",
        "            os.chmod(tasks, 0o755)\n",
        "            pass\n",
    ),
    "task file left to the umask": (
        "src/synthe_broker.py",
        "                os.fchmod(fd, 0o644)\n",
        "                pass\n",
    ),
    "the agent may run in the approver's account": (
        "src/synthe_init.py",
        "    if agent_account == approver:\n",
        "    if False:\n",
    ),
    "a prompted token is not checked": (
        "src/synthe_init.py",
        "    try:\n        check_token_file(path, repo_url)\n",
        "    try:\n        pass\n",
    ),
    "non-user broker accepted": (
        "src/synthe_init.py",
        '    if (cfg.get("isolation") or {}).get("mode") != "user":\n',
        "    if False:\n",
    ),
    "receiver binding omitted from broker config": (
        "src/synthe_init.py",
        '    cfg["receiver"] = patch["receiver"]\n',
        "    pass\n",
    ),
    "ledger v2 not selected": (
        "src/synthe_init.py",
        '    cfg["ledger"] = "ledger.sqlite3"\n',
        '    cfg["ledger"] = "ledger.json"\n',
    ),
    "private output made public": (
        "src/synthe_init.py",
        "    os.fchmod(fd, 0o600)  # O_CREAT's mode only applies to a new file; an existing one keeps its mode otherwise\n",
        "    os.fchmod(fd, 0o644)\n",
    ),
    "task content hash ignored": (
        "src/synthe_broker.py",
        "        if not hmac.compare_digest(actual, expected):\n",
        "        if False:\n",
    ),
    "task size unbounded": (
        "src/synthe_broker.py",
        "        if len(raw) > MAX_TASK_BYTES:\n",
        "        if False:\n",
    ),
    "task sender need not be human": (
        "src/synthe_broker.py",
        '        if not isinstance(sender, dict) or sender.get("kind") != "human":\n',
        "        if False:\n",
    ),
    "task signature validation skipped": (
        "src/synthe_broker.py",
        "            verdict = hc.check(packet, registry=registry, ledger_path=None, workspace=self.cfg.workspace,\n",
        "            verdict = {\"decision\": \"ACCEPT\"} if True else hc.check(packet, registry=registry, ledger_path=None, workspace=self.cfg.workspace,\n",
    ),
    "task path can overwrite": (
        "src/synthe_broker.py",
        "            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, \"O_NOFOLLOW\", 0)\n",
        "            flags = os.O_WRONLY | os.O_CREAT | getattr(os, \"O_NOFOLLOW\", 0)\n",
    ),
    "writable task reused": (
        "src/synthe_broker.py",
        "                if st.st_uid != self.uid or st.st_mode & 0o022:\n",
        "                if False:\n",
    ),
    "task symlink accepted": (
        "src/synthe_broker.py",
        "        if tasks.is_symlink():\n",
        "        if False:\n",
    ),
    "task CLI bypasses broker": (
        "src/synthe_task.py",
        '    brokered = setup["mode"] in ("macos-user", "linux-user")\n',
        "    brokered = False\n",
    ),
}


def _copy_repo(dst: Path) -> None:
    for name in ("src", "deploy"):
        shutil.copytree(ROOT / name, dst / name, ignore=shutil.ignore_patterns("__pycache__", "*.egg-info"))
    (dst / "tests").mkdir()
    shutil.copy2(ROOT / "tests" / "test_enforce_macos.py", dst / "tests" / "test_enforce_macos.py")


def _run(dst: Path) -> subprocess.CompletedProcess:
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "SYNTHE_REPO_ROOT": str(ROOT)}
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider",
         str(dst / "tests" / "test_enforce_macos.py")],
        cwd=dst,
        env=env,
        capture_output=True,
        text=True,
        timeout=600,
        stdin=subprocess.DEVNULL,
    )


@pytest.mark.skipif(os.environ.get("SYNTHE_SKIP_MUTATIONS") == "1", reason="SYNTHE_SKIP_MUTATIONS=1")
def test_unmutated_copy_passes(tmp_path):
    _copy_repo(tmp_path)
    run = _run(tmp_path)
    assert run.returncode == 0, run.stdout[-2000:] + run.stderr[-2000:]


@pytest.mark.skipif(os.environ.get("SYNTHE_SKIP_MUTATIONS") == "1", reason="SYNTHE_SKIP_MUTATIONS=1")
@pytest.mark.parametrize("name", sorted(MUTATIONS))
def test_mutation_is_caught(name, tmp_path):
    rel, original, mutated = MUTATIONS[name]
    _copy_repo(tmp_path)
    target = tmp_path / rel
    text = target.read_text()
    assert text.count(original) == 1, f"mutation anchor for {name!r} not found exactly once in {rel}"
    target.write_text(text.replace(original, mutated))
    run = _run(tmp_path)
    assert run.returncode != 0, f"mutation {name!r} survived: the enforced-mode tests did not notice"
