# Synthe mapped to the effectuation-boundary draft (EF-1 to EF-8)

**Source:** IETF Internet-Draft `draft-das-agentic-effectuation-boundary-00` (September 2026). The
draft defines a *finality sink*: "the component or boundary whose successful action first makes
the governed consequence effective". In Synthe that is the commit broker: agents propose, and only
the broker performs the effect.

**What this is:** each requirement mapped to the automated tests that exercise it, kept honest in
CI by `tests/test_effectuation_conformance.py` (it fails if a cited test disappears). This is not a
certificate and not a statement of conformance: the draft is an individual draft, not a standard,
and it has no official test suite. "Covered" means our tests exercise the requirement; "partial"
names what is missing.

## Status

| Req | Name | Status | How Synthe meets it | Tests |
|---|---|---|---|---|
| EF-1 | Exact-Act Binding | covered | Approvals sign the exact effect params (and optionally the commit); a retargeted or swapped act is refused (`approval_params_mismatch`). | `test_sender_cannot_retarget_a_pinned_approval`<br>`test_pinned_params_are_inside_the_approval_signature`<br>`test_swapped_commit_is_not_covered_when_the_pin_is_required`<br>`test_control_commit_pinned_approval_never_covers_a_different_commit` |
| EF-2 | Commit-Time Revalidation | covered | The broker re-runs validation inside the commit fence; expiry, trust and policy changes after the claim are caught, and the push is compare-and-swap. | `test_approval_expires_between_claim_and_commit`<br>`test_approver_removed_from_trusted_approvers_after_claim`<br>`test_receiver_narrows_allowed_paths_after_claim`<br>`test_remote_moved_during_commit_caught_by_cas` |
| EF-3 | Anti-Replay | covered | Completed exact retries return the stored signed result without another effect or receipt; changed effects conflict, duplicate detached approvals are rejected, and 50 parallel claims yield one winner. | `test_replaying_the_proposal_after_commit_returns_the_stored_result`<br>`test_same_approval_twice_is_a_duplicate`<br>`test_stale_holder_cannot_commit_twice`<br>`test_50_parallel_claims_one_winner` |
| EF-4 | Epoch/Fencing | partial | Claim epochs fence stale holders; removed keys or approvers and narrowed policy invalidate earlier authority at commit. | `test_released_claim_old_token_is_refused`<br>`test_approver_key_removed_from_registry_after_claim`<br>`test_parallel_reclaim_denied_then_epoch2_after_release`<br>`test_trace_ttl_reclaim_zombie_cannot_act_twice` |
| EF-5 | Fail-Closed Unknowns | covered | Unknown dependencies, missing workspaces, unconfirmed outcomes and corrupt ledgers are explicit denials, never a pass. | `test_unknown_dependency_is_denied_at_commit`<br>`test_evidence_verification_without_workspace_fails_closed`<br>`test_dotgit_entry_is_commit_unavailable_whatever_fsck_says`<br>`test_crash_before_complete_past_ttl_rejected_unknown` |
| EF-6 | Path Completeness | partial | Every path of every pushed commit (intermediate commits, renames, deletes, merges, symlinks, submodules) is inspected against policy. | `test_attack_repo_forbidden_in_intermediate_commit`<br>`test_attack_repo_rename_hides_forbidden`<br>`test_attack_repo_symlink_to_forbidden`<br>`test_secret_in_intermediate_commit_is_caught` |
| EF-7 | Sink-Local Verification | covered | The broker never trusts an upstream ACCEPT: it re-verifies signatures, claim tokens and approvers itself; clients can pin the broker's uid. | `test_packet_tampered_after_signing_refused_at_commit`<br>`test_holder_of_packet_without_claim_token`<br>`test_untrusted_approver_is_rejected`<br>`test_pinned_client_refuses_a_fake_broker_before_sending_anything` |
| EF-8 | Recoverable Commit Semantics | covered | Kill -9 inside the fence before the push, after the push and before the receipt never yields a second effect; races resolve through the fence. | `test_crash_after_push_never_pushes_twice`<br>`test_crash_before_receipt_never_pushes_twice`<br>`test_crashed_commit_attempt_is_retried_through_the_fence`<br>`test_fenced_holder_wins_race_late_claimants_duplicate` |

**Summary:** 6 of 8 covered, 2 partial, 0 missing.

## Gaps

- **EF-4 (Epoch/Fencing):** Revocation is enforced for removed keys, removed approvers and narrowed policy; revocation of an already-issued authority by lookup is specified but not built (tests/redteam_broker/test_tm_revoke_spec.py, strict xfail).
- **EF-6 (Path Completeness):** Inside the broker every path of every pushed commit is inspected. Paths around the broker (an agent that still holds its own git credentials) are an identified exception: the client doctor reports them as `direct push: FAIL`, and closing them is a deployment step.

## The requirements, quoted

- **EF-1 Exact-Act Binding:** "authority is bound to a deterministic representation of the execution-relevant act"
- **EF-2 Commit-Time Revalidation:** "state designated as execution-critical is checked at or immediately before the effectuation boundary"
- **EF-3 Anti-Replay:** "the same authority cannot silently create multiple governed effects unless multiplicity is explicitly authorized"
- **EF-4 Epoch/Fencing:** "revocation, policy change, delegation change, or schema revision can invalidate previously issued authority when the deployment requires it"
- **EF-5 Fail-Closed Unknowns:** "required but unavailable lineage or state is represented as UNKNOWN rather than inferred to mean unrestricted authority"
- **EF-6 Path Completeness:** "all paths capable of producing the governed consequence are included in the enforcement model or explicitly identified as exceptions"
- **EF-7 Sink-Local Verification:** "the effectuation component does not rely solely on an upstream statement that validation occurred"
- **EF-8 Recoverable Commit Semantics:** "crash, timeout, retry, and split-brain behavior cannot silently turn one authorized act into multiple effects"

## Re-run

```bash
python3 -m pytest -q tests/test_effectuation_conformance.py
```

The cited tests themselves run in the full suite.
