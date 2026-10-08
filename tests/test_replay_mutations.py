"""Mutation check: removing any replay equivalence/evidence guard must fail test_replay.py."""
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

MUTATIONS = {
    "changed effect accepted": (
        "src/synthe_commit.py",
        "    if not hmac.compare_digest(prior_fp, fingerprint):\n",
        "    if False:\n",
    ),
    "receipt identity ignored": (
        "src/synthe_commit.py",
        '        and rh.get("idempotency_key") == h.get("idempotency_key")\n',
        '        and True\n',
    ),
}


def _copy_repo(dst: Path) -> None:
    for name in ("src", "examples", "schema"):
        shutil.copytree(ROOT / name, dst / name, ignore=shutil.ignore_patterns("__pycache__", "*.egg-info"))
    (dst / "tests").mkdir()
    for name in ("test_replay.py", "world.py"):
        shutil.copy2(ROOT / "tests" / name, dst / "tests" / name)


def _run(dst: Path) -> subprocess.CompletedProcess:
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "SYNTHE_SKIP_MUTATIONS": "1"}
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider",
         str(dst / "tests" / "test_replay.py")],
        cwd=dst, env=env, capture_output=True, text=True, timeout=600,
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
    assert run.returncode != 0, f"mutation {name!r} survived: replay tests did not notice"
