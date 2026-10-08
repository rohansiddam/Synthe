"""The GitHub Action ships its own copy of the checker; it must be byte-identical to src/.

Found Oct 7: the v0.7 hardening (strict JSON, kid required, max lifetime, receiver_mismatch) reached
src/ but not github-action/checker/, so every Action user still ran the v0.6 checker. Nothing tested
the copy, so each merge drifted it silently.
"""
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("name", ["handoff_check.py", "synthe_crypto.py"])
def test_action_checker_is_byte_identical_to_src(name):
    src = (ROOT / "src" / name).read_bytes()
    copy = (ROOT / "github-action" / "checker" / name).read_bytes()
    assert copy == src, f"github-action/checker/{name} differs from src/{name}: copy it over (cp src/{name} github-action/checker/)"
