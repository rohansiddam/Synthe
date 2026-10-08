"""Mutation check for the ledger-v2 storage guards."""
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

MUTATIONS = {
    "claim loads every row": (
        "src/handoff_check.py",
        "    def get(self, key, default=None):\n        if dict.__contains__(self, key):\n",
        "    def get(self, key, default=None):\n        self._load_all()\n        if dict.__contains__(self, key):\n",
    ),
    "WAL disabled": (
        "src/handoff_check.py",
        '    conn.execute("PRAGMA journal_mode=WAL")\n',
        '    conn.execute("PRAGMA journal_mode=DELETE")\n',
    ),
    "full sync disabled": (
        "src/handoff_check.py",
        '    conn.execute("PRAGMA synchronous=FULL")\n',
        '    conn.execute("PRAGMA synchronous=OFF")\n',
    ),
    "migration overwrites destination": (
        "src/handoff_check.py",
        "    if destination.exists():\n        raise FileExistsError(destination)\n",
        "    if False:\n        raise FileExistsError(destination)\n",
    ),
    "receipt append rescans history": (
        "src/synthe_commit.py",
        "        tip = _receipt_tip(cfg.receipts_path)\n",
        "        tip = _rebuild_receipt_tip(cfg.receipts_path)\n",
    ),
    "same-size receipt rewrite trusted": (
        "src/synthe_commit.py",
        "    if not valid:\n        # Same byte count but different content",
        "    if False:\n        # Same byte count but different content",
    ),
}


def _copy_repo(dst: Path) -> None:
    shutil.copytree(ROOT / "src", dst / "src", ignore=shutil.ignore_patterns("__pycache__", "*.egg-info"))
    (dst / "tests" / "ledger").mkdir(parents=True)
    for rel in ("tests/world.py", "tests/ledger/test_sqlite_v2.py", "tests/ledger/test_receipt_tip.py"):
        target = dst / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / rel, target)


def _run(dst: Path) -> subprocess.CompletedProcess:
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "SYNTHE_MUTATION_CHILD": "1"}
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider",
         str(dst / "tests" / "ledger" / "test_sqlite_v2.py"),
         str(dst / "tests" / "ledger" / "test_receipt_tip.py")],
        cwd=dst, env=env, capture_output=True, text=True, timeout=600, stdin=subprocess.DEVNULL,
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
    assert text.count(original) == 1, f"mutation anchor for {name!r} not found exactly once"
    target.write_text(text.replace(original, mutated))
    run = _run(tmp_path)
    assert run.returncode != 0, f"mutation {name!r} survived: ledger-v2 tests did not notice"
