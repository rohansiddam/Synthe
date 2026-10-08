"""Mutation check for tests/test_approve.py: each guard removed in a copy must make that file fail.

Set SYNTHE_SKIP_MUTATIONS=1 to skip (each mutation runs the approval tests in a subprocess).
The terminal check in synthe_sign.prompt_passphrase is not mutated here: without it getpass
would wait on a terminal and hang the run instead of failing it."""
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

MUTATIONS = {
    "agent text printed raw": ("src/synthe_approve.py", "    return _CONTROL.sub(esc, s)\n", "    return s\n"),
    "approval does not pin the commit": ("src/synthe_approve.py", '{**params, "commit": commit})', "params)"),
    "approval lifetime unbounded": ("src/synthe_approve.py", "    if not 0 < expires_in_min <= MAX_EXPIRES_MIN:\n",
                                    "    if False:\n"),
    "diff/commit mismatch ignored": ("src/synthe_approve.py",
                                     'if ch.get("available") and ch.get("commit") != commit:',
                                     "if False:"),
    "detail leaks the claim token": ("src/synthe_commit.py",
                                     '"agent_says": {"purpose": h.get("purpose")}}',
                                     '"agent_says": {"purpose": h.get("purpose")}, "claim_token": rec.get("claim_token")}'),
    "key derivation unbounded": ("src/synthe_sign.py",
                                 "    if n not in (2 ** 15, 2 ** 16, 2 ** 17, 2 ** 18) or r not in (8,) or p not in (1, 2):\n",
                                 "    if False:\n"),
    "plaintext approver key accepted": ("src/synthe_sign.py", "        if require_encrypted:\n            raise KeyFileError(",
                                        "        if False:\n            raise KeyFileError("),
    "key metadata not bound": ("src/synthe_sign.py",
                               '    return sc.canonical_json({"v": KEY_FORMAT, "agent": key.get("agent"), "kid": key.get("kid"),\n'
                               '                              "alg": key.get("alg", sc.ALG)})',
                               '    return sc.canonical_json({"v": KEY_FORMAT})'),
}


def _copy_repo(dst: Path) -> None:
    for name in ("src", "examples", "lab", "schema"):
        if not (ROOT / name).exists():  # the Lab isn't in the public repo
            continue
        shutil.copytree(ROOT / name, dst / name, ignore=shutil.ignore_patterns("__pycache__", "*.egg-info"))
    (dst / "tests").mkdir()
    for name in ("test_approve.py", "world.py", "test_isolation.py", "test_speculative.py"):
        shutil.copy2(ROOT / "tests" / name, dst / "tests" / name)


def _run(dst: Path) -> subprocess.CompletedProcess:
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    return subprocess.run([sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider",
                           str(dst / "tests" / "test_approve.py")],
                          cwd=dst, env=env, capture_output=True, text=True, timeout=600, stdin=subprocess.DEVNULL)


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
    assert run.returncode != 0, f"mutation {name!r} survived: the approval tests did not notice"
