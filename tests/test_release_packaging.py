import hashlib
import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def test_standalone_staging_has_no_broker_or_dependency(tmp_path):
    build = module("build_verifier")
    build.stage(tmp_path)
    assert {p.name for p in tmp_path.iterdir()} == {"synthe_verify.py", "LICENSE", "pyproject.toml", "README.md"}
    assert "dependencies = []" in (tmp_path / "pyproject.toml").read_text()
    assert 'license = "Apache-2.0"' in (tmp_path / "pyproject.toml").read_text()
    with pytest.raises(ValueError, match="empty"):
        build.stage(tmp_path)


def test_formula_pins_artifact_and_refuses_injection(tmp_path):
    brew = module("homebrew_verifier")
    artifact = tmp_path / "synthe_verify-0.6.0.tar.gz"
    artifact.write_bytes(b"TEST_ONLY artifact bytes")
    url = "https://github.com/example/repo/releases/download/v0.6.0/synthe_verify-0.6.0.tar.gz"
    result = brew.formula(artifact, "0.6.0", url)
    assert hashlib.sha256(artifact.read_bytes()).hexdigest() in result
    for bad in (url + '\";exec', url + "?token=TEST_ONLY", url.replace("https:", "http:"),
                url.replace("v0.6.0", "latest"), url.replace("github.com", "u:p@github.com")):
        with pytest.raises(ValueError):
            brew.formula(artifact, "0.6.0", bad)


def test_release_workflow_builds_without_publish_authority():
    text = (ROOT / ".github/workflows/release-candidate.yml").read_text()
    assert "workflow_dispatch:" in text and "contents: read" in text
    for forbidden in ("contents: write", "id-token: write", "twine upload", "pypa/gh-action-pypi-publish", "tags:"):
        assert forbidden not in text


def test_source_root_finds_wheel_assets_outside_checkout(tmp_path, monkeypatch):
    sys.path.insert(0, str(ROOT / "src"))
    import synthe_init as si
    root = tmp_path / "share/synthe/source"
    (root / "deploy/macos").mkdir(parents=True)
    (root / "src").mkdir()
    (root / "deploy/macos/install.sh").write_text("# fixture")
    (root / "src/synthe_commit.py").write_text("# fixture")
    monkeypatch.setattr(si, "__file__", str(tmp_path / "lib/site-packages/synthe_init.py"))
    monkeypatch.setattr(sys, "prefix", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    assert si.source_root() == root
