"""The pip package: every module ships, every console script resolves, the console finds its page."""
import importlib
import sys
from pathlib import Path

import pytest

tomllib = pytest.importorskip("tomllib")

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
PROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text())


def test_every_src_module_is_packaged():
    shipped = set(PROJECT["tool"]["setuptools"]["py-modules"])
    on_disk = {p.stem for p in (ROOT / "src").glob("*.py")}
    assert shipped == on_disk


@pytest.mark.parametrize("name,target", sorted(PROJECT["project"]["scripts"].items()))
def test_console_script_resolves(name, target):
    module, func = target.split(":")
    assert module in PROJECT["tool"]["setuptools"]["py-modules"], name
    assert callable(getattr(importlib.import_module(module), func)), name


def test_data_files_exist():
    for files in PROJECT["tool"]["setuptools"]["data-files"].values():
        for f in files:
            matches = list(ROOT.glob(f))
            assert matches and all(p.is_file() for p in matches), f


def test_console_page_found_in_checkout_and_when_installed(tmp_path, monkeypatch):
    import synthe_commit as cm
    assert cm._ui_file() == ROOT / "src" / "synthe_commit_ui.html"
    # Installed layout: the module sits in site-packages, the page under <prefix>/share/synthe.
    site = tmp_path / "site"
    site.mkdir()
    page = tmp_path / "share" / "synthe" / "synthe_commit_ui.html"
    page.parent.mkdir(parents=True)
    page.write_text("<html></html>")
    monkeypatch.setattr(cm, "__file__", str(site / "synthe_commit.py"))
    monkeypatch.setattr(sys, "prefix", str(tmp_path))
    assert cm._ui_file() == page
    # Neither present: the checkout path, so the console answers 404 rather than crashing.
    page.unlink()
    assert cm._ui_file() == site / "synthe_commit_ui.html"
