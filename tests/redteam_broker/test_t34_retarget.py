"""T3.4: Retarget -- reuse approvals, replay proposals, steal claim tokens.

Intent key: redteam-retarget. Playbook: P7 (re-check before every reuse),
G1 (fail closed). Includes finding D1 (approval pins the target, not the
commit): an approval that names a target branch must not authorize a
different commit, a different branch, or a different claimant.

Done-when denial codes (exact):
1. effect_params_mismatch  -- approved commit swapped for another (D1)
2. approval_params_mismatch -- approval covers branch X, proposal targets Y
3. claim_token_invalid     -- stolen claim token (issued to another agent)
4. claim_token_invalid     -- tampered claim token

TARGET STATUS (2026-10-05): the broker's effect/approval binding checks are
not present in this repo snapshot. The denial tests below are therefore
marked xfail(strict=True): they record the missing target as evidence and
become the live battery the moment the checks land (rewire
`_require_broker_effects()` to the real entry point and remove the marks).

The `test_attack_*` tests run NOW and prove each attack request is
genuinely malformed as described -- no broker needed to see that.
"""

import pytest

_NO_BROKER = (
    "T3.4: broker effect/approval binding checks not present in repo "
    "snapshot; retarget refusals unavailable"
)

INNOCENT = "aaaabbbbccccddddeeeeffff0000111122223333"
EVIL = "ffffeeeeddddccccbbbbaaaa9999888877776666"


def _good_proposal():
    return {
        "action": "push",
        "params": {"branch": "synthe/dogfood", "commit": INNOCENT},
        "approval": {
            "approver": "rishab",
            "action": "push",
            "params": {"branch": "synthe/dogfood", "commit": INNOCENT},
            "sig": "human-sig-ok",
        },
        "claim_token": {"token": "ct-agent-cy-001", "owner": "agent-cy",
                        "sig": "broker-sig-ok"},
        "submitter": "agent-cy",
    }


def _require_broker_effects():
    """Seam for the broker's effect/approval/claim binding checks.

    Rewire to the real entry point when it lands. Must return an object
    with:
        check(proposal) -> denial with .code exactly one of
        {"effect_params_mismatch", "approval_params_mismatch",
         "claim_token_invalid"}
    """
    raise RuntimeError(_NO_BROKER)


# --------------------------------------------------------------------------
# attack builders: each returns a proposal violating exactly one binding
# --------------------------------------------------------------------------

def build_commit_swapped_under_target_approval():
    """D1: approval pinned the target branch; the commit was swapped."""
    p = _good_proposal()
    p["params"] = {"branch": "synthe/dogfood", "commit": EVIL}
    # approval still names the innocent commit:
    assert p["approval"]["params"]["commit"] == INNOCENT
    return p


def build_branch_retargeted():
    """Approval covers synthe/dogfood; proposal targets main."""
    p = _good_proposal()
    p["params"] = {"branch": "main", "commit": INNOCENT}
    assert p["approval"]["params"]["branch"] == "synthe/dogfood"
    return p


def build_stolen_claim_token():
    """Claim token issued to agent-dee, presented by agent-cy."""
    p = _good_proposal()
    p["claim_token"] = {"token": "ct-agent-dee-007", "owner": "agent-dee",
                        "sig": "broker-sig-ok"}
    assert p["submitter"] == "agent-cy"
    return p


def build_tampered_claim_token():
    """Claim token string altered after issuance."""
    p = _good_proposal()
    tok = p["claim_token"]["token"]
    p["claim_token"] = {"token": tok[:-1] + ("0" if tok[-1] != "0" else "1"),
                        "owner": "agent-cy", "sig": "broker-sig-ok"}
    return p


# --------------------------------------------------------------------------
# Part 1 (runs NOW): each attack is genuinely malformed as described.
# --------------------------------------------------------------------------

def test_attack_commit_swapped_under_target_approval():
    p = build_commit_swapped_under_target_approval()
    assert p["params"]["commit"] != p["approval"]["params"]["commit"]
    assert p["params"]["branch"] == p["approval"]["params"]["branch"]


def test_attack_branch_retargeted():
    p = build_branch_retargeted()
    assert p["params"]["branch"] != p["approval"]["params"]["branch"]


def test_attack_stolen_claim_token():
    p = build_stolen_claim_token()
    assert p["claim_token"]["owner"] != p["submitter"]


def test_attack_tampered_claim_token():
    p = build_tampered_claim_token()
    assert p["claim_token"]["token"] != "ct-agent-cy-001"


# --------------------------------------------------------------------------
# Part 2 (xfail until the checks land): exact done-when codes.
# --------------------------------------------------------------------------

@pytest.mark.xfail(strict=True, reason=_NO_BROKER)
def test_broker_denies_effect_params_mismatch():
    denial = _require_broker_effects().check(
        build_commit_swapped_under_target_approval())
    assert denial.code == "effect_params_mismatch"


@pytest.mark.xfail(strict=True, reason=_NO_BROKER)
def test_broker_denies_approval_params_mismatch():
    denial = _require_broker_effects().check(build_branch_retargeted())
    assert denial.code == "approval_params_mismatch"


@pytest.mark.xfail(strict=True, reason=_NO_BROKER)
def test_broker_denies_stolen_claim_token():
    denial = _require_broker_effects().check(build_stolen_claim_token())
    assert denial.code == "claim_token_invalid"


@pytest.mark.xfail(strict=True, reason=_NO_BROKER)
def test_broker_denies_tampered_claim_token():
    denial = _require_broker_effects().check(build_tampered_claim_token())
    assert denial.code == "claim_token_invalid"
