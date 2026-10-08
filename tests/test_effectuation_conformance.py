"""EF-1..EF-8 of draft-das-agentic-effectuation-boundary-00, mapped to the tests that exercise them.

docs/EFFECTUATION_CONFORMANCE.md is the human-readable table; this file is its source of truth and
keeps it honest: every cited test must exist (so a rename or deletion can't leave a dangling claim),
every requirement cites at least two tests, and the doc lists every requirement with its status.
Wording rule: "mapped to" and "tested against", never "compliant" or "certified".
"""
import ast
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "EFFECTUATION_CONFORMANCE.md"

# status: "covered" = every part of the requirement has a passing test here;
#         "partial" = covered except the named gap.
EF = {
    "EF-1": ("Exact-Act Binding", "covered", None, [
        "tests/test_v05_checker.py::test_sender_cannot_retarget_a_pinned_approval",
        "tests/test_v05_checker.py::test_pinned_params_are_inside_the_approval_signature",
        "tests/test_finding_approval_commit_pin.py::test_swapped_commit_is_not_covered_when_the_pin_is_required",
        "tests/test_finding_approval_commit_pin.py::test_control_commit_pinned_approval_never_covers_a_different_commit",
    ]),
    "EF-2": ("Commit-Time Revalidation", "covered", None, [
        "tests/test_invalidation.py::test_approval_expires_between_claim_and_commit",
        "tests/test_invalidation.py::test_approver_removed_from_trusted_approvers_after_claim",
        "tests/test_invalidation.py::test_receiver_narrows_allowed_paths_after_claim",
        "tests/test_invalidation.py::test_remote_moved_during_commit_caught_by_cas",
    ]),
    "EF-3": ("Anti-Replay", "covered", None, [
        "tests/test_speculative.py::test_replaying_the_proposal_after_commit_is_a_duplicate",
        "tests/test_speculative.py::test_same_approval_twice_is_a_duplicate",
        "tests/test_invalidation.py::test_stale_holder_cannot_commit_twice",
        "tests/ledger/test_concurrency.py::test_50_parallel_claims_one_winner",
    ]),
    "EF-4": ("Epoch/Fencing", "partial",
             "Revocation is enforced for removed keys, removed approvers and narrowed policy; revocation "
             "of an already-issued authority by lookup is specified but not built "
             "(tests/redteam_broker/test_tm_revoke_spec.py, strict xfail).", [
        "tests/test_invalidation.py::test_released_claim_old_token_is_refused",
        "tests/test_invalidation.py::test_approver_key_removed_from_registry_after_claim",
        "tests/ledger/test_concurrency.py::test_parallel_reclaim_denied_then_epoch2_after_release",
        "tests/test_claims.py::test_trace_ttl_reclaim_zombie_cannot_act_twice",
    ]),
    "EF-5": ("Fail-Closed Unknowns", "covered", None, [
        "tests/test_depends.py::test_unknown_dependency_is_denied_at_commit",
        "tests/test_v03_trust.py::test_evidence_verification_without_workspace_fails_closed",
        "tests/test_broker_hardening.py::test_dotgit_entry_is_commit_unavailable_whatever_fsck_says",
        "tests/test_conformance.py::test_crash_before_complete_past_ttl_rejected_unknown",
    ]),
    "EF-6": ("Path Completeness", "partial",
             "Inside the broker every path of every pushed commit is inspected. Paths around the broker "
             "(an agent that still holds its own git credentials) are an identified exception: the "
             "client doctor reports them as `direct push: FAIL`, and closing them is a deployment step.", [
        "tests/redteam_broker/test_t31_hidden_paths.py::test_attack_repo_forbidden_in_intermediate_commit",
        "tests/redteam_broker/test_t31_hidden_paths.py::test_attack_repo_rename_hides_forbidden",
        "tests/redteam_broker/test_t31_hidden_paths.py::test_attack_repo_symlink_to_forbidden",
        "tests/test_commit.py::test_secret_in_intermediate_commit_is_caught",
    ]),
    "EF-7": ("Sink-Local Verification", "covered", None, [
        "tests/test_invalidation.py::test_packet_tampered_after_signing_refused_at_commit",
        "tests/test_commit.py::test_holder_of_packet_without_claim_token",
        "tests/test_speculative.py::test_untrusted_approver_is_rejected",
        "tests/test_client_broker_uid.py::test_pinned_client_refuses_a_fake_broker_before_sending_anything",
    ]),
    "EF-8": ("Recoverable Commit Semantics", "covered", None, [
        "tests/ledger/test_crash.py::test_crash_after_push_never_pushes_twice",
        "tests/ledger/test_crash.py::test_crash_before_receipt_never_pushes_twice",
        "tests/test_speculative.py::test_crashed_commit_attempt_is_retried_through_the_fence",
        "tests/ledger/test_concurrency.py::test_fenced_holder_wins_race_late_claimants_duplicate",
    ]),
}


def _defined_tests(path: Path) -> set:
    """Test functions in the file, minus any marked xfail or skip: those prove nothing."""
    tree = ast.parse(path.read_text())
    out = set()
    for n in tree.body:
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            marks = " ".join(ast.unparse(d) for d in n.decorator_list)
            if not any(w in marks for w in ("xfail", "skip")):
                out.add(n.name)
    return out


@pytest.mark.parametrize("ef", sorted(EF))
def test_every_cited_test_exists(ef):
    for node in EF[ef][3]:
        file, name = node.split("::")
        path = ROOT / file
        assert path.is_file(), f"{ef}: {file} is gone"
        assert name in _defined_tests(path), f"{ef}: {node} is gone, renamed, or marked xfail/skip"


def test_every_requirement_has_at_least_two_tests_and_a_status():
    assert sorted(EF) == [f"EF-{i}" for i in range(1, 9)]
    for ef, (_, status, gap, tests) in EF.items():
        assert len(set(tests)) >= 2, ef
        assert status in ("covered", "partial"), ef
        assert (status == "partial") == bool(gap), f"{ef}: a partial row must name its gap"


def test_doc_matches_the_map_and_never_overclaims():
    text = DOC.read_text()
    for ef, (title, status, _, tests) in EF.items():
        row = next((l for l in text.splitlines() if l.startswith(f"| {ef} ")), None)
        assert row, f"{ef} missing from {DOC.name}"
        assert title in row and status in row, f"{ef}: title or status differs from the map"
        for node in tests:
            assert node.split("::")[1] in text, f"{ef}: {node} not cited in the doc"
    for line in text.splitlines():  # any mention of these words must be a denial
        if re.search(r"\b(compliant|compliance|conformant|certified|certificate)\b", line, re.I):
            assert re.search(r"\b(not|never|no)\b", line, re.I), f"overclaim: {line}"
