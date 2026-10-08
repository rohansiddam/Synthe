"""Grant delegates: a reviewing model approves each push in the human's place, inside a grant the human signed.

- The default is unchanged: no grant, or a grant with a delegate but no delegate approval, means a human
  approves the push. A human's approval always works and spends no grant use.
- The delegate is a registered "model_approver", named by the grant, never a party to the handoff, and
  signs (its own key, its own signing domain) the exact commit the broker staged, for at most an hour.
- An escalation ("send this to the human") sticks to the proposal: no later delegate approval counts.
- At dispatch, under the lane lock, the delegate's approval is read again before a use is reserved.

tests/test_delegate_mutations.py removes each guard in a copy and checks this file (or the lane tests) fail.
"""
import datetime as dt
import json

import pytest

from test_speculative import PUSH, detached, stage, staged_state
from world import World, cm, mkkey, ts, codes
import synthe_lane_templates as lanes

DELEGATE = "claude-reviewer"


@pytest.fixture
def w(tmp_path):
    w = World(tmp_path)
    w.cfg.raw["lane_templates"] = {"receivers": ["builder"]}
    for name in (DELEGATE, "other-reviewer"):
        w.keys[name], pub = mkkey(name)
        w.registry["agents"][name] = {"role": "reviewer", "kind": "model_approver", "keys": [pub]}
    w.save_registry()
    return w


def grant(w, delegate=DELEGATE, **updates):
    x = {"template_id": "review-1", "receiver": "builder", "tool": "git_push",
         "params": {"remote": "origin", "branch_pattern": "feature/*"}, "path_scope": ["src/**"],
         "max_uses": 3, "expires_at": ts(dt.timedelta(days=1)), "lineage": lanes.lineage(w.cfg, w.registry, "builder")}
    if delegate is not None:
        x["delegate"] = delegate
    x.update(updates)
    return lanes.sign(x, w.keys["rishab"])


def doc(w, sha, signer=DELEGATE, minutes=30, escalate=False, idem="k1", branch="feature/x", **updates):
    body = {"template_id": "review-1", "idempotency_key": idem, "from": "planner", "to": "builder", "action": PUSH,
            "params": {"remote": "origin", "branch": branch, "commit": sha}, "note": "matches the task; tests pass"}
    if escalate:
        body["recommendation"] = "reject"
    else:
        body["expires_at"] = ts(dt.timedelta(minutes=minutes))
    body.update(updates)
    return lanes.sign_delegate(body, w.keys[signer], escalate)


def submit(w, x, escalate=False):
    return cm.submit_delegate(w.cfg, x, escalate=escalate)


def rcodes(out):
    return codes(out["receipt"])


def uses_left(w):
    return lanes.view(w.cfg)["templates"][0]["uses_left"]


# ---- the happy path, and the default ------------------------------------------------------------

def test_delegate_approves_the_staged_commit_and_it_ships(w):
    lanes.submit(w.cfg, grant(w))
    p, tok, sha, r = stage(w)
    assert r["decision"] == "staged" and w.remote_ref("feature/x") is None
    assert cm.staged_view(w.cfg, "k1")[0]["waiting_for"] == ["approval", "review"]
    out = submit(w, doc(w, sha))
    assert out["receipt"]["decision"] == "delegate_approval_accepted", out["receipt"]
    [c] = out["commits"]
    assert c["decision"] == "executed", c
    assert w.remote_ref("feature/x") == sha
    a = c["approvals"][0]
    assert (a["approver"], a["delegate"], a["delegated_by"], a["template_id"]) == (DELEGATE, True, "rishab", "review-1")
    assert c["lane_template"]["use"] == 1 and uses_left(w) == 2
    assert w.chain()["ok"]


def test_without_any_grant_a_human_still_approves(w):
    p, tok, sha, r = stage(w)
    assert cm.staged_view(w.cfg, "k1")[0]["waiting_for"] == ["approval"]
    out = submit(w, doc(w, sha))
    assert out["receipt"]["decision"] == "delegate_approval_rejected" and "delegate_not_named" in rcodes(out)
    assert w.remote_ref("feature/x") is None and staged_state(w) == {PUSH: "STAGED"}


def test_a_human_approval_still_works_and_spends_no_use(w):
    lanes.submit(w.cfg, grant(w))
    p, tok, sha, _ = stage(w)
    out = cm.submit_approval(w.cfg, detached(w, p, params={"remote": "origin", "branch": "feature/x", "commit": sha}))
    assert [c["decision"] for c in out["commits"]] == ["executed"], out
    assert out["commits"][0]["approvals"][0]["approver"] == "rishab" and "lane_template" not in out["commits"][0]
    assert uses_left(w) == 3


def test_a_grant_without_a_delegate_is_unchanged(w):
    # Codex's lane: the grant itself stands in for the approval (no reviewer).
    lanes.submit(w.cfg, grant(w, delegate=None))
    p, tok, sha, r = stage(w)
    assert r["decision"] == "executed" and w.remote_ref("feature/x") == sha


# ---- who may be a delegate -------------------------------------------------------------------------

def test_the_delegate_must_be_a_registered_model_approver(w):
    for who in ("mallory", "builder", "nobody"):
        with pytest.raises(cm.Deny, match="delegate invalid"):
            lanes.submit(w.cfg, grant(w, delegate=who))


def test_only_the_named_delegate_counts(w):
    lanes.submit(w.cfg, grant(w))
    _, _, sha, _ = stage(w)
    out = submit(w, doc(w, sha, signer="other-reviewer"))
    assert "delegate_not_named" in rcodes(out) and w.remote_ref("feature/x") is None


def test_the_delegate_is_never_a_party_to_the_handoff(w):
    # The sender registered as a model approver and named as the delegate: it can't approve its own handoff.
    w.registry["agents"]["planner"]["kind"] = "model_approver"
    w.save_registry()
    lanes.submit(w.cfg, grant(w, delegate="planner", lineage=lanes.lineage(w.cfg, w.registry, "builder")))
    _, _, sha, _ = stage(w)
    out = submit(w, doc(w, sha, signer="planner"))
    assert "delegate_is_party" in rcodes(out) and w.remote_ref("feature/x") is None


def test_a_tampered_or_human_domain_signature_is_refused(w):
    lanes.submit(w.cfg, grant(w))
    _, _, sha, _ = stage(w)
    x = doc(w, sha)
    x["note"] = "edited after signing"
    assert "delegate_signature_invalid" in rcodes(submit(w, x))
    # A signature over the escalation domain never passes as an approval, nor back.
    y = doc(w, sha)
    y["sig"] = lanes.sign_delegate({k: v for k, v in y.items() if k not in ("approver", "kid", "sig")},
                                   w.keys[DELEGATE], escalate=True)["sig"]
    assert "delegate_signature_invalid" in rcodes(submit(w, y))
    assert w.remote_ref("feature/x") is None


# ---- what the delegate approves ------------------------------------------------------------------

def test_the_approval_pins_the_commit_the_broker_staged(w):
    lanes.submit(w.cfg, grant(w))
    other = "0" * 40
    assert "delegate_approval_stale" in rcodes(submit(w, doc(w, other)))  # nothing staged yet
    _, _, sha, _ = stage(w)
    assert "delegate_approval_stale" in rcodes(submit(w, doc(w, other)))  # not the staged commit
    assert "delegate_approval_stale" in rcodes(submit(w, doc(w, sha, **{"from": "mallory"})))
    assert w.remote_ref("feature/x") is None
    assert [c["decision"] for c in submit(w, doc(w, sha))["commits"]] == ["executed"]


def test_a_stored_approval_for_another_commit_never_ships_a_restaged_one(w):
    # The broker re-reads the approval at commit time: a proposal restaged on a new commit after the
    # delegate looked is not covered (the approval is written straight into the store here to model the race).
    lanes.submit(w.cfg, grant(w))
    p, tok, a, _ = stage(w)
    d = lanes.delegate_load(w.cfg)
    d["approvals"][f"k1/{PUSH}"] = doc(w, "1" * 40)
    lanes.save(w.cfg, d, lanes.delegate_path(w.cfg))
    assert cm.retry_staged(w.cfg, idempotency_key="k1") == []
    assert w.remote_ref("feature/x") is None and staged_state(w) == {PUSH: "STAGED"}


def test_the_approval_lifetime_is_bounded(w):
    lanes.submit(w.cfg, grant(w))
    _, _, sha, _ = stage(w)
    assert "delegate_approval_too_long" in rcodes(submit(w, doc(w, sha, minutes=61)))
    assert "delegate_approval_expired" in rcodes(submit(w, doc(w, sha, minutes=-1)))
    assert [c["decision"] for c in submit(w, doc(w, sha, minutes=59))["commits"]] == ["executed"]


def test_out_of_scope_branches_and_paths_are_never_covered(w):
    lanes.submit(w.cfg, grant(w, params={"remote": "origin", "branch_pattern": "feature/ok-*"}))
    _, _, sha, _ = stage(w)
    assert "template_scope" in rcodes(submit(w, doc(w, sha)))
    assert w.remote_ref("feature/x") is None


def test_paths_outside_the_grant_are_denied_at_dispatch_without_spending_a_use(w):
    lanes.submit(w.cfg, grant(w))
    p = w.packet(idem="k2", branch="feature/y", approve=False)
    from test_speculative import speculative_claim
    tok = speculative_claim(w, p)
    sha = w.commit({"tests/t.py": "x\n"}, msg="outside")
    assert w.propose(p, tok, sha, branch="feature/y", wait_for_approval=True)["decision"] == "staged"
    out = submit(w, doc(w, sha, idem="k2", branch="feature/y"))
    assert [c["decision"] for c in out["commits"]] == ["denied"] and "template_scope" in codes(out["commits"][0])
    assert w.remote_ref("feature/y") is None and uses_left(w) == 3


# ---- escalation ----------------------------------------------------------------------------------

def test_escalation_sends_it_to_the_human_for_good(w):
    lanes.submit(w.cfg, grant(w))
    p, tok, sha, _ = stage(w)
    out = submit(w, doc(w, sha, escalate=True), escalate=True)
    assert out["receipt"]["decision"] == "escalated" and out["recommendation"] == "reject"
    cm.retry_staged(w.cfg, idempotency_key="k1")
    assert "escalated" in cm.staged_view(w.cfg, "k1")[0]["waiting_for"]
    # the delegate can't change its mind: only a human approves it now
    assert "delegate_escalated" in rcodes(submit(w, doc(w, sha)))
    assert w.remote_ref("feature/x") is None
    out = cm.submit_approval(w.cfg, detached(w, p, params={"remote": "origin", "branch": "feature/x", "commit": sha}))
    assert [c["decision"] for c in out["commits"]] == ["executed"]


def test_an_escalation_during_dispatch_wins_and_spends_no_use(w, monkeypatch):
    lanes.submit(w.cfg, grant(w))
    _, _, sha, _ = stage(w)
    original = cm.GitPush.prepare

    def prepare(*a, **kw):  # the delegate escalates after the broker read its approval, before the push
        result = original(*a, **kw)
        lanes.escalate(w.cfg, w.registry, doc(w, sha, escalate=True))
        return result
    monkeypatch.setattr(cm.GitPush, "prepare", prepare)
    out = submit(w, doc(w, sha))
    assert [c["decision"] for c in out["commits"]] == ["denied"] and "delegate_escalated" in codes(out["commits"][0])
    assert w.remote_ref("feature/x") is None and uses_left(w) == 3


def test_escalation_must_be_signed_by_the_named_delegate(w):
    lanes.submit(w.cfg, grant(w))
    _, _, sha, _ = stage(w)
    assert "delegate_not_named" in rcodes(submit(w, doc(w, sha, signer="other-reviewer", escalate=True), escalate=True))
    x = doc(w, sha, escalate=True)
    x["recommendation"] = "approve"
    assert "delegate_malformed" in rcodes(submit(w, x, escalate=True))


# ---- the grant around it -------------------------------------------------------------------------

def test_a_revoked_or_exhausted_grant_takes_no_delegate_approval(w):
    lanes.submit(w.cfg, grant(w, max_uses=1))
    _, _, sha, _ = stage(w)
    assert [c["decision"] for c in submit(w, doc(w, sha))["commits"]] == ["executed"]
    _, _, sha2, _ = stage(w, idem="k2", branch="feature/y")
    assert "template_exhausted" in rcodes(submit(w, doc(w, sha2, idem="k2", branch="feature/y")))
    lanes.revoke(w.cfg, lanes.sign({"template_id": "review-1"}, w.keys["rishab"], True))
    assert "template_revoked" in rcodes(submit(w, doc(w, sha2, idem="k2", branch="feature/y")))
    assert w.remote_ref("feature/y") is None


def test_an_expired_grant_is_refused(w):
    with pytest.raises(cm.Deny, match="template expired"):
        lanes.submit(w.cfg, grant(w, expires_at=ts(dt.timedelta(seconds=-1))))


def test_only_a_trusted_human_revokes(w):
    lanes.submit(w.cfg, grant(w))
    with pytest.raises(cm.Deny, match="revocation invalid"):
        lanes.revoke(w.cfg, lanes.sign({"template_id": "review-1"}, w.keys["mallory"], True))
    with pytest.raises(cm.Deny, match="revocation invalid"):
        lanes.revoke(w.cfg, lanes.sign({"template_id": "review-1"}, w.keys[DELEGATE], True))
    assert lanes.view(w.cfg)["templates"][0]["status"] == "active"


def test_every_delegate_decision_is_receipted_and_the_chain_verifies(w):
    lanes.submit(w.cfg, grant(w))
    _, _, sha, _ = stage(w)
    submit(w, doc(w, sha, signer="other-reviewer"))
    submit(w, doc(w, sha))
    kinds = [(r.get("kind", "effect"), r["decision"]) for r in w.chain()["receipts"]]
    assert kinds == [("effect", "staged"), ("delegate_approval", "delegate_approval_rejected"),
                     ("delegate_approval", "delegate_approval_accepted"), ("effect", "executed")]
    assert w.chain()["ok"]
    assert "sig" not in json.dumps(w.chain()["receipts"][2]["delegate"])


def test_delegate_grant_tells_the_approver_which_grant_to_cite(w):
    lanes.submit(w.cfg, grant(w))
    stage(w)
    g = cm.delegate_grant(w.cfg, f"k1/{PUSH}")
    assert (g["template_id"], g["delegate"], g["granted_by"]) == ("review-1", DELEGATE, "rishab")
    with pytest.raises(cm.Deny):
        cm.delegate_grant(w.cfg, "nope/push_branch")
