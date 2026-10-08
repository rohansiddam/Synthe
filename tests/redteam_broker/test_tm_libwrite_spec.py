"""TM-LIBWRITE-SPEC: Spec tests for library_write (C5).

Intent key: loop-redteam. Playbook: C5 (library_write as a broker effect with
a signed receipt), P11 (every library write is a commit), G3 (a human
approves each new template), G4 (specifics never enter the library).

These are the attacks a future `library_write` effect must REFUSE once it
exists. Each attack is a write request that violates exactly one rule:

1. no human approval at all                          -> libwrite_no_approval
2. an approval for template A reused to write B      -> libwrite_approval_reuse
3. steps still holding specifics (names, SHAs, $)    -> libwrite_specifics_present
4. submitted by an agent directly, not via broker    -> libwrite_direct_submit
5. a replayed write (nonce already seen)              -> libwrite_replay
6. an edit to an approved template without new approval
                                                     -> libwrite_unapproved_edit

TARGET STATUS (2026-10-05): library_write (C5) does not exist yet. Every
denial test is therefore marked xfail(strict=True) with reason
"TASK: LB-C5 <refusal>", so the suite stays green today and the LB-C5 build
task has an exact definition of done: make each of these pass for real.

The `test_attack_write_*` tests run NOW and prove each attack request is
genuinely malformed in the way described -- no broker needed to see that.
"""

import re

import pytest

_NO_BROKER = "library_write (C5) not implemented; task LB-C5 will make these pass"

# A write request: what an agent submits when asking the broker to save a
# plan template to the library.
#
#   template   template name being written
#   version    template version (1 = new)
#   steps      plan/expect pairs; G4 requires named slots, never specifics
#   approvals  human approvals, each bound to (template, version)
#   via        "broker" or "agent-direct"
#   nonce      idempotency key; replays reuse it
#   sig        submitter signature (None = unsigned)


def _good_write():
    return {
        "template": "redteam-battery",
        "version": 1,
        "steps": [
            {"plan": "Claim handoff {handoff_id}", "expect": "ACCEPT with claim"},
            {"plan": "Push {file_scope} to {branch}", "expect": "commit lands"},
            {"plan": "Ship via broker", "expect": "signed receipt"},
        ],
        "approvals": [{"template": "redteam-battery", "version": 1,
                       "approver": "rishab", "sig": "human-sig-1"}],
        "via": "broker",
        "nonce": "nonce-001",
        "sig": "submitter-sig-1",
    }


def _require_library_write():
    """Seam for the library_write broker effect (C5, task LB-C5).

    Rewire to the real entry point when LB-C5 lands. Must return an object
    with:
        submit(write_request) -> denial with .code startswith "libwrite_"
    """
    raise RuntimeError(_NO_BROKER)


# --------------------------------------------------------------------------
# attack builders: each returns a write request violating exactly one rule
# --------------------------------------------------------------------------

def build_write_no_approval():
    """No human approval attached at all (G3)."""
    req = _good_write()
    req["approvals"] = []
    return req


def build_write_approval_reuse():
    """Approval bound to template A, used to write template B."""
    req = _good_write()
    req["template"] = "different-template"
    # approvals still name the old template:
    assert req["approvals"][0]["template"] == "redteam-battery"
    return req


def build_write_with_specifics():
    """Steps hold specifics: SHAs, branch names, dollar figures (G4)."""
    req = _good_write()
    req["steps"] = [
        {"plan": "Ship commit 3826db899b12a4ce23a0cc4fe5fbe7efe300e5b8",
         "expect": "receipt #12"},
        {"plan": "Push to sandbox/agent-cy/T3.1-b", "expect": "lands"},
        {"plan": "Charge $1,500 per parcel", "expect": "paid"},
    ]
    return req


def build_write_direct_agent():
    """Submitted by the agent directly, bypassing the broker (C5)."""
    req = _good_write()
    req["via"] = "agent-direct"
    return req


def build_write_replay():
    """Nonce already used by an earlier accepted write (replay)."""
    first = _good_write()  # accepted earlier under nonce-001...
    second = _good_write()
    second["steps"] = [{"plan": "Do something else entirely",
                        "expect": "different outcome"}]
    second["nonce"] = first["nonce"]  # ...replayed under the same nonce
    return first, second


def build_write_unapproved_edit():
    """Approved v1 exists; v2 changes steps but reuses the v1 approval."""
    req = _good_write()
    req["version"] = 2
    req["steps"] = [{"plan": "Completely rewritten step",
                     "expect": "new expectation"}]
    # approvals still bound to version 1:
    assert req["approvals"][0]["version"] == 1
    return req


_SPECIFICS = re.compile(r"\b[0-9a-f]{7,40}\b|#[0-9]+|\$[0-9,]+|sandbox/")


# --------------------------------------------------------------------------
# Part 1 (runs NOW): each attack request is genuinely malformed as described.
# --------------------------------------------------------------------------

def test_attack_write_no_approval():
    req = build_write_no_approval()
    assert req["approvals"] == []  # G3: no human approved anything


def test_attack_write_approval_reuse():
    req = build_write_approval_reuse()
    approved_for = {a["template"] for a in req["approvals"]}
    assert req["template"] not in approved_for  # approval is for another template


def test_attack_write_with_specifics():
    req = build_write_with_specifics()
    text = " ".join(s["plan"] + " " + s["expect"] for s in req["steps"])
    assert _SPECIFICS.search(text)  # G4: specifics present, not slots
    assert "{" not in text  # no named slots at all


def test_attack_write_direct_agent():
    req = build_write_direct_agent()
    assert req["via"] != "broker"  # C5: must go through the broker


def test_attack_write_replay():
    first, second = build_write_replay()
    assert first["nonce"] == second["nonce"]  # same idempotency key...
    assert first["steps"] != second["steps"]  # ...different content


def test_attack_write_unapproved_edit():
    req = build_write_unapproved_edit()
    approved_versions = {a["version"] for a in req["approvals"]}
    assert req["version"] not in approved_versions  # v2 has no approval


# --------------------------------------------------------------------------
# Part 2 (xfail until LB-C5): each attack must end in a libwrite_* refusal.
# --------------------------------------------------------------------------

@pytest.mark.xfail(strict=True,
                   reason="TASK: LB-C5 must refuse writes with no human approval")
def test_libwrite_refuses_no_approval():
    denial = _require_library_write().submit(build_write_no_approval())
    assert denial.code.startswith("libwrite_")


@pytest.mark.xfail(strict=True,
                   reason="TASK: LB-C5 must refuse approvals reused across templates")
def test_libwrite_refuses_approval_reuse():
    denial = _require_library_write().submit(build_write_approval_reuse())
    assert denial.code.startswith("libwrite_")


@pytest.mark.xfail(strict=True,
                   reason="TASK: LB-C5 must refuse steps that still hold specifics")
def test_libwrite_refuses_specifics():
    denial = _require_library_write().submit(build_write_with_specifics())
    assert denial.code.startswith("libwrite_")


@pytest.mark.xfail(strict=True,
                   reason="TASK: LB-C5 must refuse agent-direct writes bypassing the broker")
def test_libwrite_refuses_direct_agent():
    denial = _require_library_write().submit(build_write_direct_agent())
    assert denial.code.startswith("libwrite_")


@pytest.mark.xfail(strict=True,
                   reason="TASK: LB-C5 must refuse replayed writes")
def test_libwrite_refuses_replay():
    first, second = build_write_replay()
    _require_library_write().submit(first)  # accepted...
    denial = _require_library_write().submit(second)  # replay refused
    assert denial.code.startswith("libwrite_")


@pytest.mark.xfail(strict=True,
                   reason="TASK: LB-C5 must refuse unapproved edits to approved templates")
def test_libwrite_refuses_unapproved_edit():
    denial = _require_library_write().submit(build_write_unapproved_edit())
    assert denial.code.startswith("libwrite_")
