"""Commit-time invalidation suite: authority must be re-checked at commit time.

Research (arXiv 2607.10487, "Temporary Authority, Permanent Effects") shows
agents commit actions after their authority became invalid between planning
and commit. Synthe's commit broker re-validates the signed handoff, the
approvals, the receiver policy and the pinned inputs at commit time, inside
the claim fence, before it touches the remote.

Every test follows the same shape: build a packet, claim it (ACCEPT), do the
agent's commit, then INVALIDATE exactly one thing, then propose, and assert:

  * the receipt is "denied" and carries the specific reason code,
  * the remote branch did not move for the proposed push,
  * the ledger entry is still RESERVED (the denial did not consume the claim),
  * the receipt chain verifies and the denial is the newest receipt.

Where it makes sense, the test then repairs the invalidation and shows the
same claim still executes exactly once.

The control test (no invalidation) proves the denials mean something: without
it, a broker that denied everything would pass this suite.
"""

import copy
import datetime as dt
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import handoff_check as hc  # noqa: E402
import synthe_commit as cm  # noqa: E402
import synthe_sign as ss  # noqa: E402

from test_commit import World, codes, git, ts  # noqa: E402


@pytest.fixture
def w(tmp_path):
    """A fresh broker universe per test (registry, keys, git remote, ledger)."""
    return World(tmp_path)


def _rewrite_registry(w, mutate):
    """Apply `mutate` to the registry JSON the broker reads at commit time.

    `propose` loads the registry file fresh on every call, so edits here
    simulate policy or key changes that land after the claim was issued.
    """
    path = w.tmp / "registry.json"
    reg = json.loads(path.read_text())
    mutate(reg)
    path.write_text(json.dumps(reg, indent=2) + "\n")


def _assert_denied(w, receipt, code, branch="feature/x", remote_before=None):
    """The standard denial assertions shared by every invalidation test."""
    assert receipt["decision"] == "denied", receipt
    assert code in codes(receipt), receipt["reasons"]
    assert w.remote_ref(branch) == remote_before
    assert w.ledger_entry()["state"] == "RESERVED"
    chain = w.chain()
    assert chain["ok"]
    assert chain["receipts"][-1]["decision"] == "denied"


# ---------------------------------------------------------------------------
# 1. the human approval expires between claim and commit


def test_approval_expires_between_claim_and_commit(w, monkeypatch):
    p = w.packet(approval_exp=ts(dt.timedelta(seconds=10)))
    token = w.claim(p)  # the approval is valid at admission ...
    c = w.commit({"src/app.py": "x\n"})
    real_now = hc.now_utc
    # ... but expired by the time the effect would happen. (Simulated clock
    # advance instead of a real sleep: deterministic, same code path.)
    monkeypatch.setattr(hc, "now_utc", lambda: real_now() + dt.timedelta(seconds=600))
    r = w.propose(p, token, c)
    _assert_denied(w, r, "approval_expired")
    # recovery: the invalidation was the clock; with real time restored, the
    # same claim still executes exactly once (the denial did not consume it).
    monkeypatch.setattr(hc, "now_utc", real_now)
    ok = w.propose(p, token, c)
    assert ok["decision"] == "executed", ok
    assert w.remote_ref("feature/x") == c
    assert w.ledger_entry()["state"] == "COMPLETED"


# ---------------------------------------------------------------------------
# 2. the approver is removed from the receiver's trusted_approvers after claim


def test_approver_removed_from_trusted_approvers_after_claim(w):
    p = w.packet()
    token = w.claim(p)
    c = w.commit({"src/app.py": "x\n"})
    _rewrite_registry(
        w,
        lambda reg: reg["agents"]["builder"]["policy"]["trusted_approvers"].remove("rishab"),
    )
    r = w.propose(p, token, c)
    _assert_denied(w, r, "approver_not_trusted")
    # recovery: trust restored -> the same claim executes.
    _rewrite_registry(
        w,
        lambda reg: reg["agents"]["builder"]["policy"]["trusted_approvers"].append("rishab"),
    )
    ok = w.propose(p, token, c)
    assert ok["decision"] == "executed", ok
    assert w.remote_ref("feature/x") == c


# ---------------------------------------------------------------------------
# 3. the approver's signing key is removed from the registry after claim


def test_approver_key_removed_from_registry_after_claim(w):
    p = w.packet()
    token = w.claim(p)
    c = w.commit({"src/app.py": "x\n"})
    saved = copy.deepcopy(w.registry["agents"]["rishab"])
    _rewrite_registry(w, lambda reg: reg["agents"].pop("rishab"))
    r = w.propose(p, token, c)
    _assert_denied(w, r, "approval_signature_invalid")
    # recovery: key restored -> the same claim executes.
    _rewrite_registry(w, lambda reg: reg["agents"].update({"rishab": saved}))
    ok = w.propose(p, token, c)
    assert ok["decision"] == "executed", ok
    assert w.remote_ref("feature/x") == c


# ---------------------------------------------------------------------------
# 4. the packet's own acceptance window passes between claim and commit


def test_packet_acceptance_expires_between_claim_and_commit(w, monkeypatch):
    p = w.packet()
    p["handoff"]["acceptance"]["expires_at"] = ts(dt.timedelta(seconds=10))
    p = ss.sign_packet(p, w.keys["planner"])  # acceptance is signature-covered
    token = w.claim(p)
    c = w.commit({"src/app.py": "x\n"})
    real_now = hc.now_utc
    monkeypatch.setattr(hc, "now_utc", lambda: real_now() + dt.timedelta(seconds=600))
    r = w.propose(p, token, c)
    _assert_denied(w, r, "handoff_expired")
    # recovery: with real time restored the window is still open, so the same
    # claim executes.
    monkeypatch.setattr(hc, "now_utc", real_now)
    ok = w.propose(p, token, c)
    assert ok["decision"] == "executed", ok
    assert w.remote_ref("feature/x") == c


# ---------------------------------------------------------------------------
# 5. a pinned input artifact changes after claim


def test_pinned_artifact_changes_after_claim(w):
    p = w.packet()
    token = w.claim(p)
    c = w.commit({"src/app.py": "x\n"})
    task = w.tmp / "workspace" / "task.md"
    task.write_text("tampered task\n")
    r = w.propose(p, token, c)
    _assert_denied(w, r, "artifact_hash_mismatch")
    # recovery: restore the exact pinned bytes -> the same claim executes.
    task.write_text("add a flag\n")
    ok = w.propose(p, token, c)
    assert ok["decision"] == "executed", ok
    assert w.remote_ref("feature/x") == c


# ---------------------------------------------------------------------------
# 6a. receiver policy narrows after claim: git_push no longer allowed


def test_receiver_removes_tool_after_claim(w):
    p = w.packet()
    token = w.claim(p)
    c = w.commit({"src/app.py": "x\n"})
    _rewrite_registry(
        w,
        lambda reg: reg["agents"]["builder"]["policy"]["allowed_tools"].remove("git_push"),
    )
    r = w.propose(p, token, c)
    _assert_denied(w, r, "authority_exceeds_receiver_policy")
    # recovery: policy restored -> the same claim executes.
    _rewrite_registry(
        w,
        lambda reg: reg["agents"]["builder"]["policy"]["allowed_tools"].append("git_push"),
    )
    ok = w.propose(p, token, c)
    assert ok["decision"] == "executed", ok
    assert w.remote_ref("feature/x") == c


# ---------------------------------------------------------------------------
# 6b. receiver policy narrows after claim: allowed_paths shrinks


def test_receiver_narrows_allowed_paths_after_claim(w):
    p = w.packet()
    token = w.claim(p)
    c = w.commit({"src/app.py": "x\n"})
    _rewrite_registry(
        w,
        lambda reg: reg["agents"]["builder"]["policy"]["allowed_paths"].remove("src/**"),
    )
    r = w.propose(p, token, c)
    _assert_denied(w, r, "path_outside_receiver_policy")
    # recovery: policy restored -> the same claim executes.
    _rewrite_registry(
        w,
        lambda reg: reg["agents"]["builder"]["policy"]["allowed_paths"].append("src/**"),
    )
    ok = w.propose(p, token, c)
    assert ok["decision"] == "executed", ok
    assert w.remote_ref("feature/x") == c


# ---------------------------------------------------------------------------
# 7a. the remote branch moves after claim and before commit


def test_remote_moved_after_claim_before_commit(w):
    p = w.packet()
    token = w.claim(p)
    c = w.commit({"src/app.py": "x\n"})
    # someone else creates the branch on the remote after the claim
    racer = w.commit({"other.txt": "racer\n"})
    git(w.agent, "push", "-q", "origin", f"{racer}:refs/heads/feature/x")
    assert w.remote_ref("feature/x") == racer
    r = w.propose(p, token, c, params={"expected_old": "new"})
    _assert_denied(w, r, "remote_moved", remote_before=racer)
    # recovery: rebase onto the new tip and re-propose with the fresh
    # expectation; the same claim executes once.
    c2 = w.commit({"src/app.py": "y\n"})
    ok = w.propose(p, token, c2, params={"expected_old": racer})
    assert ok["decision"] == "executed", ok
    assert w.remote_ref("feature/x") == c2


# ---------------------------------------------------------------------------
# 7b. the remote branch moves *during* the commit (check-to-push race)


def test_remote_moved_during_commit_caught_by_cas(w, monkeypatch):
    p = w.packet()
    token = w.claim(p)
    c = w.commit({"src/app.py": "x\n"})
    racer = w.commit({"other.txt": "racer\n"})
    real = cm.GitPush._is_ancestor

    def checks_then_race(self, a, b):
        result = real(self, a, b)
        # someone else lands on the branch after the broker's checks
        git(w.agent, "push", "-q", "origin", f"{racer}:refs/heads/feature/x")
        return result

    monkeypatch.setattr(cm.GitPush, "_is_ancestor", checks_then_race)
    r = w.propose(p, token, c)
    assert r["decision"] == "denied", r
    assert "remote_moved_during_commit" in codes(r), r["reasons"]
    # the racer's own push landed; the broker's push did not.
    assert w.remote_ref("feature/x") == racer
    assert w.remote_ref("feature/x") != c
    assert w.ledger_entry()["state"] == "RESERVED"
    chain = w.chain()
    assert chain["ok"]
    assert chain["receipts"][-1]["decision"] == "denied"


# ---------------------------------------------------------------------------
# 8. claim released and re-dispatched: the old token must be refused


def test_released_claim_old_token_is_refused(w):
    p = w.packet()
    old = w.claim(p)
    c = w.commit({"src/app.py": "x\n"})
    assert hc.release(p, w.tmp / "ledger.json", force=True)["decision"] == "RELEASED"
    new = w.claim(p)
    assert new != old
    r = w.propose(p, old, c)
    _assert_denied(w, r, "claim_token_invalid")
    assert w.ledger_entry()["epoch"] == 2
    # recovery: the re-dispatched (epoch 2) claim executes.
    ok = w.propose(p, new, c)
    assert ok["decision"] == "executed", ok
    assert ok["claim"]["epoch"] == 2
    assert w.remote_ref("feature/x") == c


# ---------------------------------------------------------------------------
# 9. a stale holder tries to commit twice


def test_stale_holder_cannot_commit_twice(w):
    # Two broker-mediated actions keep the claim open after the first
    # executes, so replaying the executed action must be fenced. (With a
    # single mediated action the claim auto-completes and a replay is
    # `duplicate_idempotency_key` instead; see test_commit.py.)
    p = w.packet(
        extra_actions=[
            {
                "name": "push_docs",
                "tool": "git_push",
                "params": {"remote": "origin", "branch": "feature/x"},
                "est_tokens": 10,
                "est_usd": 0.01,
                "est_minutes": 1,
            }
        ]
    )
    ss.approve_packet(
        p,
        w.keys["rishab"],
        "push_docs",
        ts(dt.timedelta(days=7)),
        ss.planned_params(p["handoff"], "push_docs"),
    )
    p = ss.sign_packet(p, w.keys["planner"])
    token = w.claim(p)
    c = w.commit({"src/app.py": "x\n"})
    first = w.propose(p, token, c)
    assert first["decision"] == "executed", first
    assert w.ledger_entry()["state"] == "RESERVED"  # push_docs still pending
    second = w.propose(p, token, c)
    _assert_denied(w, second, "effect_already_executed", remote_before=c)
    # recovery: the same claim can still execute the *other* planned action once.
    d = w.commit({"src/other.py": "y\n"})
    third = w.propose(p, token, d, action="push_docs", params={"expected_old": c})
    assert third["decision"] == "executed", third
    assert w.remote_ref("feature/x") == d
    assert w.ledger_entry()["state"] == "COMPLETED"


# ---------------------------------------------------------------------------
# 10a. planned params changed after the approval (and re-signed)


def test_planned_params_changed_after_approval(w):
    p = w.packet()
    token = w.claim(p)
    c = w.commit({"src/app.py": "x\n"})
    main_before = w.remote_ref("main")
    # the sender edits its plan after the approval and re-signs; the approval
    # signature still verifies, but it pins feature/x, not main.
    p["handoff"]["planned_actions"][1]["params"]["branch"] = "main"
    p = ss.sign_packet(p, w.keys["planner"])
    r = w.propose(p, token, c, branch="main")
    _assert_denied(w, r, "approval_params_mismatch", branch="main", remote_before=main_before)


# ---------------------------------------------------------------------------
# 10b. the approval pins no params at all


def test_approval_without_pinned_params_refused_at_commit(w):
    p = w.packet(pin_params=False)
    token = w.claim(p)
    c = w.commit({"src/app.py": "x\n"})
    r = w.propose(p, token, c)
    _assert_denied(w, r, "approval_params_missing")


# ---------------------------------------------------------------------------
# 11. the packet is tampered with after signing


def test_packet_tampered_after_signing_refused_at_commit(w):
    p = w.packet()
    token = w.claim(p)
    c = w.commit({"src/app.py": "x\n"})
    p["handoff"]["purpose"] = "tampered purpose"
    r = w.propose(p, token, c)
    _assert_denied(w, r, "signature_invalid")


# ---------------------------------------------------------------------------
# 12. control: with no invalidation, the commit executes and the chain verifies


def test_control_no_invalidation_executes_and_chain_verifies(w):
    p = w.packet()
    token = w.claim(p)
    c = w.commit({"src/app.py": "x\n"})
    r = w.propose(p, token, c)
    assert r["decision"] == "executed", r
    assert w.remote_ref("feature/x") == c
    assert w.ledger_entry()["state"] == "COMPLETED"
    chain = w.chain()
    assert chain["ok"]
    assert chain["receipts"][-1]["decision"] == "executed"


# ---------------------------------------------------------------------------
# 13. depends_on is not implemented yet: document the expected behaviour


# v0.4 has no depends_on (expected failure); the sprint branch does, where this
# is a regular regression test. Detect it so one file serves both.
DEPENDS_ON_IMPLEMENTED = "depends_on" in Path(hc.__file__).read_text()


@pytest.mark.xfail(not DEPENDS_ON_IMPLEMENTED, strict=True, reason="depends_on not implemented")
def test_depends_on_blocks_commit_until_upstream_completes(w):
    upstream = w.packet(idem="up-1")
    w.claim(upstream)  # claimed but never executed: upstream is not COMPLETED
    down = w.packet(idem="down-1")
    down["handoff"]["depends_on"] = ["up-1"]
    down = ss.sign_packet(down, w.keys["planner"])
    down_token = w.claim(down)
    c = w.commit({"src/app.py": "x\n"})
    r = w.propose(down, down_token, c)
    # Expected once depends_on exists: the broker must deny the downstream
    # commit until up-1 is COMPLETED. Where depends_on is missing it executes, so this xfails.
    assert r["decision"] == "denied", r
