"""Conformance: every reason code emitted by handoff_check.py is documented in SPEC.md section 10.

Findings from a spec-code audit. Each test fails
until the code is added to SPEC.md section 10 under its state.
"""
from pathlib import Path

import pytest

SPEC = Path(__file__).resolve().parent.parent.parent / "SPEC.md"


def section_10() -> str:
    text = SPEC.read_text()
    start = text.index("## 10. Reason codes")
    end = text.index("## 11.", start)
    return text[start:end]


@pytest.mark.xfail(strict=True, reason="h-board-T1.1-v2/F1: SPEC section 10 omits effect_already_executed")
def test_spec_documents_effect_already_executed():
    assert "effect_already_executed" in section_10()


@pytest.mark.xfail(strict=True, reason="h-board-T1.1-v2/F2: SPEC section 10 omits effect_outcome_unknown")
def test_spec_documents_effect_outcome_unknown():
    assert "effect_outcome_unknown" in section_10()


@pytest.mark.xfail(strict=True, reason="h-board-T1.1-v2/F3: SPEC section 10 blocked list omits approval_params_mismatch")
def test_spec_blocked_list_documents_approval_params_mismatch():
    assert "approval_params_mismatch" in section_10()
