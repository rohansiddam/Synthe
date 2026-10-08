"""Mutation check for tests/test_synthe_verify.py: each guard removed in a copy must make that file fail.

Set SYNTHE_SKIP_MUTATIONS=1 to skip (each mutation runs the verifier tests in a subprocess)."""
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
F = "src/synthe_verify.py"

MUTATIONS = {
    "s >= L accepted": (F, "    if s >= _q:\n        return False\n", "    if False:\n        return False\n"),
    "domain tag dropped": (F, 'return RECEIPT_SIG_DOMAIN + b"\\n" + canonical_json(body)', "return canonical_json(body)"),
    "any signer trusted": (F, 'if signer != trust["signer"]:', "if False:"),
    "prev not checked": (F, 'if linked and r.get("prev") != prev_digest:', "if False:"),
    "seq not checked": (F, "elif seq != count:", "elif False:"),
    "bool accepted as seq": (F, "if not isinstance(seq, int) or isinstance(seq, bool):",
                             "if not isinstance(seq, int):"),
    "duplicate fields allowed": (F, "        if k in out:\n            raise _Strict(", "        if False:\n            raise _Strict("),
    "NaN accepted": (F, "parse_constant=_bad_constant)", ")"),
    "overflow to infinity accepted": (F, "    if math.isinf(value):\n        raise _Strict(", "    if False:\n        raise _Strict("),
    "loose base64 accepted": (F, 'if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != text:', "if False:"),
    "checkpoint ignored": (F, "elif digests[seq] != want:", "elif False:"),
    "missing checkpoint ignored": (F, "        if seq not in digests:\n            fail(", "        if False:\n            fail("),
    "empty chain accepted": (F, "    if count == 0:\n        fail(", "    if False:\n        fail("),
    "invalid key point accepted": (F, "len(raw) == 32 and _decompress(raw) is not None and _valid_public_point(_decompress(raw))", "len(raw) == 32"),
    "small order signer accepted": (F, "return point is not None and not _equal(_mul(8, point), _IDENTITY) and _equal(_mul(_q, point), _IDENTITY)", "return point is not None"),
    "duplicate key id accepted": (F, "if len(found) != len(keys):", "if False:"),
    "published key for another signer": (F, "if signer is not None and signer != named:", "if False:"),
}


def _copy(dst: Path) -> None:
    (dst / "src").mkdir()
    (dst / "tests").mkdir()
    for name in ("synthe_verify.py", "synthe_crypto.py"):
        shutil.copy2(ROOT / "src" / name, dst / "src" / name)
    shutil.copy2(ROOT / "tests" / "test_synthe_verify.py", dst / "tests" / "test_synthe_verify.py")


def _run(dst: Path) -> subprocess.CompletedProcess:
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    return subprocess.run([sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider",
                           str(dst / "tests" / "test_synthe_verify.py")],
                          cwd=dst, env=env, capture_output=True, text=True, timeout=300, stdin=subprocess.DEVNULL)


@pytest.mark.skipif(os.environ.get("SYNTHE_SKIP_MUTATIONS") == "1", reason="SYNTHE_SKIP_MUTATIONS=1")
def test_unmutated_copy_passes(tmp_path):
    _copy(tmp_path)
    run = _run(tmp_path)
    assert run.returncode == 0, run.stdout[-2000:] + run.stderr[-2000:]


@pytest.mark.skipif(os.environ.get("SYNTHE_SKIP_MUTATIONS") == "1", reason="SYNTHE_SKIP_MUTATIONS=1")
@pytest.mark.parametrize("name", sorted(MUTATIONS))
def test_mutation_is_caught(tmp_path, name):
    rel, old, new = MUTATIONS[name]
    _copy(tmp_path)
    target = tmp_path / rel
    text = target.read_text()
    assert text.count(old) == 1, f"mutation {name!r} no longer matches {rel} exactly once"
    target.write_text(text.replace(old, new))
    run = _run(tmp_path)
    assert run.returncode != 0, f"mutation {name!r} survived: the tests no longer guard it"


# The broker's own `receipts verify` pins its signer: guarded by tests/test_synthe_verify_broker.py.
BROKER_MUTATIONS = {
    "broker verify trusts any registered signer": (
        "src/synthe_commit.py", 'if broker_id is not None and r.get("broker") != broker_id:', "if False:"),
}


def _copy_broker(dst: Path) -> None:
    for name in ("src", "examples", "schema"):
        shutil.copytree(ROOT / name, dst / name, ignore=shutil.ignore_patterns("__pycache__", "*.egg-info"))
    (dst / "tests").mkdir()
    for name in ("test_synthe_verify_broker.py", "world.py"):
        shutil.copy2(ROOT / "tests" / name, dst / "tests" / name)


@pytest.mark.skipif(os.environ.get("SYNTHE_SKIP_MUTATIONS") == "1", reason="SYNTHE_SKIP_MUTATIONS=1")
@pytest.mark.parametrize("name", sorted(BROKER_MUTATIONS) + [None])
def test_broker_mutation_is_caught(tmp_path, name):
    _copy_broker(tmp_path)
    if name:
        rel, old, new = BROKER_MUTATIONS[name]
        text = (tmp_path / rel).read_text()
        assert text.count(old) == 1, f"mutation {name!r} no longer matches {rel} exactly once"
        (tmp_path / rel).write_text(text.replace(old, new))
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    run = subprocess.run([sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider",
                          str(tmp_path / "tests" / "test_synthe_verify_broker.py")],
                         cwd=tmp_path, env=env, capture_output=True, text=True, timeout=300, stdin=subprocess.DEVNULL)
    if name:
        assert run.returncode != 0, f"mutation {name!r} survived: the tests no longer guard it"
    else:
        assert run.returncode == 0, run.stdout[-2000:] + run.stderr[-2000:]
