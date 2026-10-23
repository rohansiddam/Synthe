"""synthe-notify: what it says, what it stays quiet about, and that it never speaks from a chain that does not
verify. Receipts here are the ones the real broker writes (tests/world.py); a few extra ones are appended
with the broker's own signer so every decision kind exists without re-creating each flow."""
import datetime as dt
import io
import json
import os
import re
import subprocess
import urllib.error
from pathlib import Path

import pytest
from world import ROOT, World, cm, hc, mkkey, ss, ts

import synthe_notify as sn
import synthe_verify as sv
from test_openclaw_flow import Mcp, _commit, _task, broker, world  # noqa: F401  (the dev flow's fixtures and helpers)

PUSH = "push_branch"
SOURCES = ("src/synthe_commit.py", "src/synthe_broker.py", "src/handoff_check.py", "src/synthe_lane_templates.py")
HOSTILE = '\x1b[2J\x1b]0;pwned\x07"; do shell script "rm -rf ~"; -- <!channel> <b>x</b> ‮ & \r\n'


@pytest.fixture
def w(tmp_path):
    return World(tmp_path)


# -- building chains -------------------------------------------------------------------------------------

def broker_key(w, tmp_path):
    entry = w.registry["agents"]["synthe-broker"]["keys"][0]
    path = tmp_path / "broker.pub.json"
    path.write_text(json.dumps({"broker": "synthe-broker", **{k: entry[k] for k in ("kid", "alg", "public_key")}}))
    return path


def speculative_claim(w, packet):
    v = w.check(packet, defer_approvals={PUSH}, extra_approvals=cm.load_approvals(w.cfg, packet["handoff"]))
    assert v["decision"] == "ACCEPT", v
    return v["claim"]["token"]


def detached(w, packet, approver="rishab"):
    policy = w.registry["agents"]["builder"]["policy"]
    return ss.detached_approval(packet, w.keys[approver], PUSH, ts(dt.timedelta(days=1)),
                                ss.planned_params(packet["handoff"], PUSH), policy=policy)


def stage(w, idem, branch="feature/x", files=None, msg="work"):
    p = w.packet(idem=idem, branch=branch, approve=False)
    tok = speculative_claim(w, p)
    sha = w.commit(files or {"src/app.py": f"print('{idem}')\n"}, msg=msg)
    return p, tok, sha, w.propose(p, tok, sha, branch=branch, wait_for_approval=True)


def append(w, **fields):
    """A receipt the broker signs and chains, for decisions that are tedious to provoke for real."""
    base = {"v": 1, "time": hc.now_utc().isoformat(), "decision": "denied", "reasons": [], "effect": None,
            "observed": None, "handoff": None, "claim": None, "approvals": []}
    return cm.append_receipt(w.cfg, w.keys["synthe-broker"], {**base, **fields})


def refusal(w, code, idem="z", branch="agent/z", message="", decision="denied", **fields):
    return append(w, decision=decision, reasons=[{"state": "blocked", "code": code, "message": message}],
                  handoff={"idempotency_key": idem}, effect={"action": PUSH, "branch": branch, "type": "git_push"},
                  **fields)


def receipts(w):
    return [json.loads(x) for x in w.cfg.receipts_path.read_text().splitlines() if x.strip()]


# -- every reason code has a plain-English message ------------------------------------------------------

_CODE = r'f?"([a-z][a-z0-9_]*)'
_PATTERNS = (
    r'Deny\(\s*"[a-z]+",\s*' + _CODE, r'_reject\(\s*"[a-z]+",\s*' + _CODE, r'\bfail\(\s*"[a-z]+",\s*' + _CODE,
    r'\bfail\(\s*"([a-z][a-z0-9_]*)"\s*\)', r'Refused\(\s*"([a-z][a-z0-9_]*)"', r'"code":\s*' + _CODE,
    r'_corrupt_marker\(\s*"([a-z][a-z0-9_]*)"', r'"(ledger_[a-z_]+)"',
    r'\(\s*"((?:approval|approver|delegate)_[a-z_]+)",\s*f?"',   # (code, message) pairs from the approval checks
    r'bad\.append\(\(\s*"([a-z_]+)"',                          # path_outside_scope and friends
)


def emitted_codes() -> dict:
    """Every reason code the broker, the checker and the grants can emit: found in the source, and in the
    reason-code tables of docs/COMMIT.md. A new code that is not in either place is a gap in this test."""
    found = {}
    for f in SOURCES:
        text = (ROOT / f).read_text()
        for pat in _PATTERNS:
            for m in re.finditer(pat, text):
                found.setdefault(m.group(1), set()).add(f)
    for line in (ROOT / "docs" / "COMMIT.md").read_text().splitlines():
        if line.startswith("|"):
            for code in re.findall(r"`([a-z][a-z0-9_]*)`", line.split("|")[1]):
                found.setdefault(code, set()).add("docs/COMMIT.md")
    return found


def test_the_code_scan_finds_the_codes_it_should():
    found = emitted_codes()
    for code in ("path_forbidden", "path_outside_scope", "non_fast_forward", "approval_missing", "template_exhausted",
                 "delegate_escalated", "remote_moved", "signature_invalid", "broker_not_isolated", "ledger_rollback"):
        assert code in found, code
    assert len(found) > 120


def test_every_reason_code_has_a_message():
    missing = sorted(c for c in emitted_codes() if not sn.lookup(c)[3])
    assert not missing, f"add these to synthe_notify.MESSAGES (category, what happened, why it matters): {missing}"


def test_messages_are_short_plain_and_do_not_overclaim():
    for code, (cat, tried, why) in sn.MESSAGES.items():
        assert cat in sn.SEVERITY, code
        assert tried and not tried.endswith("."), code            # the sentence is built around it
        assert why.endswith("."), code
        assert len(tried) + len(why) < 240, code
        text = f"{tried} {why}".lower()
        for word in ("guarantee", "safe", "secure", "malicious", "attack", "model"):
            assert not re.search(rf"\b{word}\b", text), (code, word)


def test_unknown_codes_fall_back_to_an_honest_generic_message():
    cat, tried, why, known = sn.lookup("brand_new_code")
    assert known is False and cat == "problem" and "does not know" in tried and "receipt" in why
    assert sn.lookup("malformed:purpose")[3] and sn.lookup("unknown_agent:to")[3]   # detail after a colon
    e = sn.describe({"seq": 3, "decision": "denied", "reasons": [{"code": "brand_new_code", "message": "x"}]})
    assert e["level"] == "problem" and e["known"] is False and "brand_new_code" not in e["body"]


def test_the_ci_example_reads_the_way_a_person_would_want(w):
    _, _, _, r = stage(w, "ci", files={".github/workflows/ci.yml": "on: push\n"})
    assert r["decision"] == "denied"
    e = sn.describe(receipts(w)[-1])
    assert e["level"] == "stop"
    assert e["body"].startswith("Blocked: the agent tried to change a CI workflow (.github/workflows/ci.yml) on 'feature/x'.")
    assert "what runs in CI" in e["body"] and e["body"].endswith("Nothing was pushed.")


# -- classification: quiet or notify --------------------------------------------------------------------

def test_a_real_flow_is_quiet_when_you_approve_and_loud_when_something_is_stopped(w):
    p, tok, sha, staged = stage(w, "k1")
    assert staged["decision"] == "staged"
    out = cm.submit_approval(w.cfg, detached(w, p))
    assert [c["decision"] for c in out["commits"]] == ["executed"]
    _, _, _, r2 = stage(w, "k2", branch="feature/y", files={"src/secrets/a.py": "x = 1\n"})   # a forbidden path
    assert r2["decision"] == "denied"
    got = [(r.get("kind"), r["decision"], sn.describe(r)["level"]) for r in receipts(w)]
    assert got == [(None, "staged", "waiting"), ("approval", "approval_accepted", "quiet"), (None, "executed", "quiet"),
                   (None, "denied", "stop")]
    stop = sn.describe(receipts(w)[-1])
    assert "'feature/y'" in stop["body"] and stop["body"].endswith("Nothing was pushed.")
    # what a person actually gets: the wait you settled yourself is dropped; only the stop remains
    assert [(e["level"], e["seq"]) for e in sn.select(receipts(w))] == [("stop", 4)]
    # told at the time (before you approved), the wait was worth a message
    assert [e["level"] for e in sn.select(receipts(w)[:1])] == ["waiting"]


def test_a_wait_still_open_is_notified_and_names_the_branch_and_size(w):
    stage(w, "k1", branch="feature/greet")
    [e] = sn.select(receipts(w))
    assert e["level"] == "waiting" and e["title"] == "Synthe is waiting for you"
    assert e["body"].startswith("The agent wants to make a push on 'feature/greet' (1 file).")
    assert "synthe-approve" in e["body"] and "your approval" in e["body"]


def risk_receipt(**over):
    """What the broker writes when a risk-aware lane sends a push to its human (docs/COMMIT.md, Risk-aware lanes)."""
    risk = {"tier": "high", "reasons": ["changes .github/workflows/ci.yml"], "paths": [".github/workflows/ci.yml"],
            "sensitive_paths": 1, "auto_approve": ["routine"], "template_id": "lane-1", "commit": "a" * 40,
            "base": "b" * 40, "rules_digest": "c" * 64, "escalated": True}
    return {"seq": 5, "decision": "staged", "effect": {"action": PUSH, "branch": "agent/feature-x"},
            "handoff": {"idempotency_key": "k"},
            "reasons": [{"state": "blocked", "code": "risk_escalated", "message": "needs a human"},
                        {"state": "blocked", "code": "approval_missing", "message": "m"}],
            "staged": {"id": f"k/{PUSH}", "waiting_for": ["approval", "risk"]}, "risk": risk, **over}


def scope_receipt(**over):
    scope = {"template_id": "lane-1", "path_scope": ["src/**", "tests/**"], "outside_paths": ["docs/a.md", "docs/b.md", "README.md"],
             "outside_count": 3, "commit": "a" * 40}
    return {"seq": 6, "decision": "staged", "effect": {"action": PUSH, "branch": "agent/feature-x"},
            "handoff": {"idempotency_key": "k2"},
            "reasons": [{"state": "blocked", "code": "outside_lane_paths", "message": "needs a human"}],
            "staged": {"id": f"k2/{PUSH}", "waiting_for": ["approval", "scope"]}, "lane_scope": scope, **over}


def test_a_high_risk_push_your_lane_sent_to_you_says_what_and_why():
    e = sn.describe(risk_receipt())
    assert e["level"] == "waiting" and e["lane"] == "risk" and e["title"] == "Synthe is waiting for you"
    assert e["body"] == ("Needs you: agent/feature-x changes a CI workflow (.github/workflows/ci.yml). "
                         "Your lane lets routine work through; this one is high-risk. Run synthe-approve to see the diff.")
    assert [x["seq"] for x in sn.select([risk_receipt()])] == [5]


def test_the_risk_wording_follows_the_receipt_not_a_fixed_script():
    def body(**risk):
        r = risk_receipt()
        r["risk"] = {**r["risk"], **risk}
        return sn.describe(r)["body"]
    assert body(auto_approve=["routine", "review"]).count("lets routine and review-level work through") == 1
    big = body(paths=[], reasons=["450 lines changed", "deletes 3 files"])
    assert big.startswith("Needs you: agent/feature-x: 450 lines changed; deletes 3 files. ")
    both = body(paths=["package.json", "Makefile"], reasons=["changes package.json and 1 more", "450 lines changed"], tier="review")
    assert both.startswith("Needs you: agent/feature-x changes a build or dependency file (package.json, …); 450 lines changed. ")
    assert "this one is review-level." in both
    assert "changes a file that looks like it holds secrets or keys (deploy/prod.pem)" in body(paths=["deploy/prod.pem"])
    assert body(paths=[], reasons=[]).startswith("Needs you: agent/feature-x is a high-risk push. ")
    assert "Your lane sends this kind of push to you." in body(auto_approve=[], tier="someday")


def test_a_push_outside_your_lane_says_how_many_files_and_what_the_lane_covers():
    e = sn.describe(scope_receipt())
    assert e["level"] == "waiting" and e["lane"] == "scope"
    assert e["body"] == ("Needs you: agent/feature-x changes 3 files outside your lane (docs/a.md, …). "
                         "Your lane covers src/** and tests/**; anything else asks you. Run synthe-approve to see the diff.")
    one = scope_receipt()
    one["lane_scope"] = {**one["lane_scope"], "outside_paths": ["docs/a.md"], "outside_count": 1}
    assert "changes 1 file outside your lane (docs/a.md)." in sn.describe(one)["body"]
    many = scope_receipt()
    many["lane_scope"] = {**many["lane_scope"], "path_scope": ["a/**", "b/**", "c/**", "d/**"]}
    assert "Your lane covers a/**, b/** and c/** …;" in sn.describe(many)["body"]


@pytest.mark.parametrize("make, field", [(risk_receipt, "risk"), (scope_receipt, "lane_scope")])
@pytest.mark.parametrize("junk", [None, "text", 7, [], {}, {"tier": ["high"], "paths": "x", "reasons": 3, "outside_paths": {"a": 1},
                                                           "outside_count": "many", "path_scope": 5, "auto_approve": "routine"}])
def test_a_receipt_with_odd_escalation_fields_is_still_a_wait_for_you(make, field, junk):
    e = sn.describe(make(**{field: junk}))
    assert e["level"] == "waiting" and e["body"].startswith("Needs you: agent/feature-x")


def test_hostile_text_in_an_escalation_reaches_no_notification_unescaped():
    r = risk_receipt()
    r["effect"] = {"action": PUSH, "branch": "agent/" + HOSTILE}
    r["risk"] = {**r["risk"], "paths": [".github/workflows/" + HOSTILE], "reasons": [HOSTILE, "450 lines changed " + HOSTILE]}
    s = scope_receipt()
    s["effect"] = r["effect"]
    s["lane_scope"] = {**s["lane_scope"], "outside_paths": ["docs/" + HOSTILE], "path_scope": ["src/" + HOSTILE]}
    for e in (sn.describe(r), sn.describe(s)):
        assert e["level"] == "waiting"
        for text in (e["body"], e["headline"], e["why"], e["branch"]):
            assert not re.search("[\x00-\x1f\x7f-\x9f\u202e]", text), repr(text)   # escaping for Slack and notify-send
                                                                          # happens at delivery, as for every message
        assert len(e["body"]) < 900


def test_malformed_risk_rules_are_a_problem_to_fix_not_a_push_to_approve():
    r = {"seq": 7, "decision": "staged", "effect": {"action": PUSH, "branch": "agent/x"}, "handoff": {"idempotency_key": "k3"},
         "reasons": [{"state": "blocked", "code": "risk_rules_invalid", "message": "risk rules invalid"}],
         "staged": {"id": f"k3/{PUSH}", "waiting_for": ["approval"]}}
    e = sn.describe(r)
    assert e["level"] == "problem" and e["body"].startswith("Needs a look: pushes under your lane are waiting for you on 'agent/x'")
    d = sn.describe({**r, "decision": "denied", "staged": None})
    assert d["level"] == "problem" and "risk rules are malformed" in d["body"] and d["body"].endswith("Nothing was pushed.")


def test_a_reviewer_blocked_from_approving_a_high_risk_push_is_not_a_second_alarm():
    r = {"seq": 8, "kind": "delegate_approval", "decision": "delegate_approval_rejected", "handoff": {"idempotency_key": "k"},
         "reasons": [{"state": "blocked", "code": "risk_escalated", "message": "m"}]}
    assert sn.describe(r)["level"] == "retry" and sn.select([r]) == []


def lane_shipped(seq, tier, reasons, paths=(), branch="agent/x", escalated=False, hours=1, **over):
    """A push that went out under a risk-aware lane: the receipt carries the lane's `risk` object, escalated false."""
    now = dt.datetime(2026, 10, 23, 12, tzinfo=dt.timezone.utc)
    risk = {"tier": tier, "reasons": reasons, "paths": list(paths), "sensitive_paths": len(paths),
            "auto_approve": ["routine", "review"], "template_id": "lane-1", "commit": "a" * 40, "base": "b" * 40,
            "rules_digest": "c" * 64, "escalated": escalated}
    return {"seq": seq, "decision": "executed", "time": (now - dt.timedelta(hours=hours)).isoformat(),
            "handoff": {"idempotency_key": f"s{seq}"}, "effect": {"action": PUSH, "branch": branch}, "risk": risk, **over}


def test_the_digest_lists_what_went_out_under_your_lane_at_the_review_level():
    now = dt.datetime(2026, 10, 23, 12, tzinfo=dt.timezone.utc)
    rs = [lane_shipped(1, "review", ["changes package.json"], ["package.json"], "agent/deps"),
          lane_shipped(2, "review", ["changes Dockerfile and 1 more"], ["Dockerfile", "docker/a.sh"], "agent/img"),
          lane_shipped(3, "review", ["changes requirements.txt"], ["requirements.txt"]),
          lane_shipped(4, "review", ["deletes 1 file"], []),
          lane_shipped(5, "review", ["changes scripts/build.sh"], ["scripts/build.sh"]),
          lane_shipped(6, "review", ["250 lines changed"], []),
          lane_shipped(7, "routine", []),                                       # routine: nothing to list
          lane_shipped(8, "review", ["changes package.json"], ["package.json"], hours=24 * 30),    # outside the week
          lane_shipped(9, "review", ["changes package.json"], ["package.json"], escalated=True)]   # you approved this one
    d = sn.build_digest(rs, now=now)
    assert d["lane_review"] == 6 and d["lane_review_kinds"] == {"build": 3, "delete": 1, "file": 1, "size": 1}
    text = sn.render_digest(d, {"count": 9, "signer": "synthe-broker", "head": "ab" * 32, "complete": True})
    assert ("3 dependency or build changes, 1 deletion, 1 change to a sensitive file and 1 larger change went out under "
            "your lane without asking you (review level, not high-risk):") in text
    assert "agent/deps: changes package.json" in text and "agent/img: changes Dockerfile and 1 more" in text
    assert "it reads paths and sizes, not code. synthe-task grant --auto-approve routine would make them ask you." in text
    one = sn.render_digest(sn.build_digest(rs[:1], now=now), {"count": 1, "signer": "s", "head": None, "complete": True})
    assert "1 dependency or build change went out under your lane" in one
    none = sn.render_digest(sn.build_digest(rs[6:7], now=now), {"count": 1, "signer": "s", "head": None, "complete": True})
    assert "under your lane" not in none


def test_a_long_review_list_is_capped_and_hostile_reasons_are_cleaned():
    now = dt.datetime(2026, 10, 23, 12, tzinfo=dt.timezone.utc)
    rs = [lane_shipped(i, "review", ["changes " + HOSTILE], [HOSTILE], "agent/" + HOSTILE) for i in range(1, 15)]
    text = sn.render_digest(sn.build_digest(rs, now=now), {"count": 14, "signer": "s", "head": None, "complete": True})
    assert "... and 4 more" in text and not re.search("[\x00-\x08\x0b-\x1f\x7f-\x9f\u202e]", text)
    odd = lane_shipped(1, "review", None)
    odd["risk"]["paths"] = 7
    assert sn.build_digest([odd], now=now)["lane_review_kinds"] == {"other": 1}


def test_the_digest_says_how_many_pushes_your_lane_sent_to_you_and_why():
    now = dt.datetime(2026, 10, 23, 12, tzinfo=dt.timezone.utc)
    stamp = {"time": (now - dt.timedelta(hours=1)).isoformat()}
    done = {"seq": 7, "decision": "executed", "handoff": {"idempotency_key": "k"}, "effect": {"action": PUSH, "branch": "agent/feature-x"},
            **stamp}
    d = sn.build_digest([{**risk_receipt(), **stamp}, {**scope_receipt(), **stamp}, done], now=now)
    assert (d["needed_you"], d["lane_high_risk"], d["lane_outside_paths"], d["needed_you_shipped"]) == (2, 1, 1, 1)
    text = sn.render_digest(d, {"count": 7, "signer": "synthe-broker", "head": "ab" * 32, "complete": True})
    assert ("Your lane sent 2 of them to you: 1 riskier than your lane lets through and 1 outside your lane's files. "
            "Everything else in the lane went out on its own.") in text
    quiet = sn.render_digest(sn.build_digest([done], now=now), {"count": 1, "signer": "s", "head": None, "complete": True})
    assert "Your lane sent" not in quiet


@pytest.mark.parametrize("waiting_for, level", [
    (["approval"], "waiting"), (["escalated"], "waiting"), (["approval", "escalated"], "waiting"),
    (["review"], "quiet"), (["dependency"], "quiet"), (["review", "dependency"], "quiet"),
    (["review", "approval"], "waiting"), ([], "waiting"), (["something_new"], "waiting"),
])
def test_staged_pushes_notify_only_when_a_person_is_the_one_they_wait_for(waiting_for, level):
    r = {"seq": 1, "decision": "staged", "staged": {"id": "k/push", "waiting_for": waiting_for}}
    assert sn.describe(r)["level"] == level


def test_an_escalation_to_a_human_is_notified_whatever_the_wording_of_the_new_lanes():
    for decision in ("escalated", "needs_human_review", "awaiting_approval", "approval_pending"):
        e = sn.describe({"seq": 1, "kind": "delegate_escalation", "decision": decision,
                         "handoff": {"idempotency_key": "k"}, "delegate": {"action": PUSH}})
        assert e["level"] == "waiting", decision
    e = sn.describe({"seq": 1, "kind": "delegate_escalation", "decision": "escalated",
                     "handoff": {"idempotency_key": "k"}, "delegate": {"action": PUSH}})
    assert e["id"] == f"k/{PUSH}" and "reviewer sent" in e["body"]


@pytest.mark.parametrize("decision, code, level", [
    ("executed", None, "quiet"), ("approval_accepted", None, "quiet"), ("approval_duplicate", "approval_duplicate", "quiet"),
    ("delegate_approval_accepted", None, "quiet"), ("lane_granted", None, "quiet"),
    ("denied", "path_forbidden", "stop"), ("denied", "non_fast_forward", "stop"), ("denied", "approval_missing", "stop"),
    ("denied", "remote_moved", "retry"), ("denied", "effect_already_executed", "quiet"), ("denied", "no_change", "quiet"),
    ("denied", "push_rejected", "problem"), ("denied", "template_exhausted", "problem"),
    ("errored", "push_failed", "retry"), ("errored", "broker_credentials_missing", "problem"),
    ("unconfirmed", "effect_unconfirmed", "problem"), ("denied", "effect_outcome_unknown", "problem"),
    ("approval_rejected", "approver_not_trusted", "stop"), ("approval_rejected", "approval_expired", "retry"),
    ("delegate_approval_rejected", "delegate_is_party", "stop"), ("escalation_rejected", "delegate_not_named", "stop"),
    ("denied", "a_code_from_the_future", "problem"), ("some_new_decision", None, "problem"),
])
def test_classification(decision, code, level):
    r = {"seq": 9, "decision": decision, "reasons": [{"code": code, "message": "m"}] if code else []}
    assert sn.describe(r)["level"] == level, (decision, code)


def test_a_refusal_the_agent_can_retry_is_quiet_unless_you_ask_for_everything():
    r = {"seq": 2, "decision": "denied", "reasons": [{"code": "remote_moved", "message": "m"}]}
    assert sn.select([r]) == []
    [e] = sn.select([r], all_refusals=True)
    assert e["level"] == "retry" and e["body"].startswith("Refused: the branch changed after the agent last looked")


def test_the_most_serious_reason_leads_and_the_rest_are_counted():
    r = {"seq": 2, "decision": "denied", "reasons": [{"code": "remote_moved", "message": ""},
                                                     {"code": "branch_not_allowed", "message": ""},
                                                     {"code": "no_change", "message": ""}]}
    e = sn.describe(r)
    assert e["level"] == "stop" and "branch it is not allowed" in e["body"] and "(+2 more reasons)" in e["body"]


def test_paths_are_named_for_what_they_are():
    def body(paths):
        msg = f"{len(paths)} path(s) not allowed: " + ", ".join(f"{p} (path_forbidden)" for p in paths)
        return sn.describe({"seq": 1, "decision": "denied", "effect": {"branch": "b"},
                            "reasons": [{"code": "path_forbidden", "message": msg}]})["body"]
    assert "CI workflow" in body([".github/workflows/release.yml"])
    assert "holds secrets or keys" in body(["deploy/prod.pem"])
    assert "build or dependency file" in body(["package.json"])
    assert "off-limits" in body(["src/internal/a.py"])
    assert sn.path_class([".GITHUB/workflows/x.yml", "package.json"]) == "ci"        # most serious wins
    assert "(+" not in body([".github/workflows/a.yml"]) and "..." in body(["package.json", "Makefile"])


def test_a_burst_becomes_one_summary_message():
    events = [sn.describe({"seq": i, "decision": "denied", "reasons": [{"code": "path_forbidden", "message": ""}]})
              for i in range(1, 8)]
    s = sn.summarize_batch(events)
    assert s["title"] == "Synthe: 7 things happened" and s["level"] == "stop" and "7 stopped" in s["body"]
    mixed = events[:2] + [sn.describe({"seq": 9, "decision": "staged", "staged": {"waiting_for": ["approval"]}})]
    assert "2 stopped, 1 waiting for you" in sn.summarize_batch(mixed)["body"]


# -- refusing to speak from a chain that does not verify ------------------------------------------------

class Opts:
    def __init__(self, receipts_path, state, **kw):
        self.receipts, self.state, self.broker, self.key, self.signer = str(receipts_path), str(state), None, None, None
        self.all_refusals, self.from_start, self.config_values = False, True, {}
        self.__dict__.update(kw)


def watcher(w, tmp_path, **kw):
    out, err = io.StringIO(), io.StringIO()
    sent = []
    n = sn.Notifier({"desktop": False}, stdout=True, out=out, err=err)
    n.send = lambda title, body, level="waiting": sent.append((level, title, body)) or ["fake"]
    opts = Opts(w.cfg.receipts_path, tmp_path / "state.json", **kw)
    trust = sn.load_trust(broker_key(w, tmp_path), None)
    return opts, trust, n, sent, err


def test_a_tampered_chain_is_never_notified_from_and_is_reported_once(w, tmp_path):
    refusal(w, "path_forbidden", message=f"1 path(s) not allowed: {HOSTILE} (path_forbidden)")
    refusal(w, "branch_not_allowed", idem="y")
    lines = w.cfg.receipts_path.read_text().splitlines()
    edited = json.loads(lines[1])
    edited["decision"] = "executed"
    edited["reasons"] = []
    w.cfg.receipts_path.write_text(lines[0] + "\n" + json.dumps(edited, sort_keys=True) + "\n")
    opts, trust, n, sent, err = watcher(w, tmp_path)
    state, code = sn.poll(opts, trust, n, {})
    assert code == 1 and state["alerted"] is True
    assert len(sent) == 1 and sent[0][0] == "stop" and "did not verify" in sent[0][1]
    assert "signature_invalid" in sent[0][2] and "NOT VERIFIED" in err.getvalue()
    assert "pwned" not in repr(sent) and "rm -rf" not in repr(sent)       # none of the chain's text leaked
    state, code = sn.poll(opts, trust, n, state)
    assert code == 1 and len(sent) == 1                                    # said once, not every poll
    # the same chain, repaired, speaks again
    w.cfg.receipts_path.write_text("\n".join(lines) + "\n")
    state, code = sn.poll(opts, trust, n, state)
    assert code == 0 and "alerted" not in state and len(sent) == 3          # the alert, then the two real stops


@pytest.mark.parametrize("attack", ["delete_first", "truncate_tail", "reorder", "wrong_signer", "append_garbage"])
def test_every_way_of_breaking_the_chain_stops_the_notifier(w, tmp_path, attack):
    for i in range(4):
        refusal(w, "path_forbidden", idem=f"k{i}")
    opts, trust, n, sent, err = watcher(w, tmp_path, from_start=False)
    state, code = sn.poll(opts, trust, n, {})
    assert code == 0 and state["seq"] == 4 and sent == []                   # baseline: starts from now
    lines = w.cfg.receipts_path.read_text().splitlines()
    if attack == "delete_first":
        lines = lines[1:]
    elif attack == "truncate_tail":
        lines = lines[:2]                                                  # rolls back behind what was verified
    elif attack == "reorder":
        lines[1], lines[2] = lines[2], lines[1]
    elif attack == "wrong_signer":
        forged = json.loads(lines[-1])
        forged["broker"] = "mallory"
        lines[-1] = json.dumps(forged, sort_keys=True)
    else:
        lines.append("{garbage")
    w.cfg.receipts_path.write_text("\n".join(lines) + "\n")
    sent.clear()
    state, code = sn.poll(opts, trust, n, state)
    assert code == 1 and len(sent) == 1 and "did not verify" in sent[0][1], attack


# -- watching a real chain end to end ------------------------------------------------------------------

def test_watch_starts_from_now_then_notifies_only_what_is_new(w, tmp_path):
    refusal(w, "path_forbidden", idem="old")                                # before you installed anything
    opts, trust, n, sent, err = watcher(w, tmp_path, from_start=False)
    state, code = sn.poll(opts, trust, n, {})
    assert (code, state["seq"], sent) == (0, 1, []) and "watching from receipt 1" in err.getvalue()
    p, tok, sha, _ = stage(w, "k1")
    cm.submit_approval(w.cfg, detached(w, p))                               # you approve it yourself
    refusal(w, "remote_moved", idem="r")                                    # routine
    refusal(w, "non_fast_forward", idem="ff", branch="agent/ff", message="rewrite")
    append(w, kind=None, decision="unconfirmed", reasons=[{"state": "unknown", "code": "effect_unconfirmed", "message": ""}],
           handoff={"idempotency_key": "u"}, effect={"action": PUSH, "branch": "agent/u"})
    state, code = sn.poll(opts, trust, n, state)
    assert code == 0 and state["seq"] == len(receipts(w))
    assert [(lvl, b.split(":")[0]) for lvl, _, b in sent] == [("stop", "Blocked"), ("problem", "Needs a look")]
    assert "rewrite branch history" in sent[0][2] and "does not show the commit" in sent[1][2]
    sent.clear()
    state, code = sn.poll(opts, trust, n, state)                            # nothing new: nothing said
    assert code == 0 and sent == []


def test_state_file_is_private_and_remembers_the_chain_head(w, tmp_path):
    refusal(w, "path_forbidden")
    opts, trust, n, sent, err = watcher(w, tmp_path)
    state, _ = sn.poll(opts, trust, n, {})
    sn.save_state(opts.state, state)
    st = Path(opts.state)
    assert st.stat().st_mode & 0o777 == 0o600
    again = sn.load_state(st)
    assert again["seq"] == 1 and again["head"] == sv.receipt_digest(receipts(w)[0])
    st.write_text("{not json")
    assert sn.load_state(st) == {}
    st.write_text(json.dumps({"seq": -4}))
    assert sn.load_state(st) == {}


def test_many_new_stops_arrive_as_one_summary_and_the_log_keeps_each(w, tmp_path):
    opts, trust, n, sent, err = watcher(w, tmp_path)
    state, _ = sn.poll(opts, trust, n, {})
    for i in range(6):
        refusal(w, "path_forbidden", idem=f"k{i}")
    state, _ = sn.poll(opts, trust, n, state)
    assert len(sent) == 1 and sent[0][1] == "Synthe: 6 things happened"
    assert err.getvalue().count("Blocked:") == 6


def test_the_cli_runs_against_a_receipt_file(w, tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(sn, "send_desktop", lambda *a, **k: False)
    key, state, cfg = broker_key(w, tmp_path), tmp_path / "state.json", tmp_path / "none.json"
    refusal(w, "path_forbidden")
    base = ["--receipts", str(w.cfg.receipts_path), "--key", str(key), "--state", str(state), "--config", str(cfg)]
    assert sn.main(["watch", "--once", "--from-start", "--stdout", *base]) == 0
    out = capsys.readouterr().out
    assert "Synthe stopped something" in out and "Blocked:" in out
    assert sn.main(["watch", "--once", *base]) == 0 and capsys.readouterr().out == ""
    assert sn.main(["watch", "--once", "--key", str(tmp_path / "missing.json"), "--state", str(state),
                    "--config", str(cfg)]) == 2


# -- the broker socket path, where receipts arrive as a window -----------------------------------------

class FakeClient:
    def __init__(self, w, limit_to=None):
        self.w, self.limit_to = w, limit_to

    def call(self, op, **args):
        assert op == "receipts" and args == {"limit": sn.WINDOW}
        chain = cm.verify_receipts(self.w.cfg.receipts_path, self.w.registry, self.w.cfg.broker_id)
        rs = chain["receipts"][-self.limit_to:] if self.limit_to else chain["receipts"]
        return {"ok": chain["ok"], "count": chain["count"], "head": chain["head"], "errors": [], "receipts": rs}


def test_receipts_from_the_broker_socket_verify_with_the_published_key(w, tmp_path):
    for i in range(3):
        refusal(w, "path_forbidden", idem=f"k{i}")
    trust = sn.load_trust(broker_key(w, tmp_path), None)
    got = sn.read_broker(None, client=FakeClient(w))
    assert all("verified" not in r for r in got["receipts"])               # the broker's display flag is not signed
    rep = sn.verify_chain(trust, receipts=got["receipts"])
    assert rep["ok"] and rep["count"] == 3 and rep["complete"]
    got["receipts"][1]["decision"] = "executed"
    assert sn.verify_chain(trust, receipts=got["receipts"])["ok"] is False


def test_a_window_is_accepted_only_when_it_ties_back_to_what_was_verified(w, tmp_path):
    for i in range(6):
        refusal(w, "path_forbidden", idem=f"k{i}")
    trust = sn.load_trust(broker_key(w, tmp_path), None)
    rs = receipts(w)
    anchor = {"seq": 3, "head": sv.receipt_digest(rs[2])}
    ok = sn.verify_chain(trust, receipts=rs[3:], anchor=anchor)             # continues right after the anchor
    assert ok["ok"] and ok["count"] == 6 and ok["complete"] is False
    assert sn.verify_chain(trust, receipts=rs[2:], anchor=anchor)["ok"]      # overlaps it
    none = sn.verify_chain(trust, receipts=rs[3:], anchor=None)
    assert none["ok"] is False and none["errors"][0]["code"] == "window_unanchored"
    gap = sn.verify_chain(trust, receipts=rs[4:], anchor=anchor)
    assert gap["ok"] is False and gap["errors"][0]["code"] == "window_unanchored"
    wrong = sn.verify_chain(trust, receipts=rs[3:], anchor={"seq": 3, "head": "0" * 64})
    assert wrong["ok"] is False and wrong["errors"][0]["code"] == "checkpoint_mismatch"
    forged = [dict(r) for r in rs[3:]]
    forged[1]["decision"] = "executed"
    assert sn.verify_chain(trust, receipts=forged, anchor=anchor)["ok"] is False
    other = [dict(r, broker="mallory") for r in rs[3:]]
    assert sn.verify_chain(trust, receipts=other, anchor=anchor)["ok"] is False


def test_a_broker_with_no_receipts_yet_is_fine_but_an_emptied_chain_is_not(w, tmp_path):
    trust = sn.load_trust(broker_key(w, tmp_path), None)
    for kw in ({"data": b""}, {"data": b"\n"}, {"receipts": []}):
        rep = sn.verify_chain(trust, **kw)
        assert rep["ok"] and rep["count"] == 0 and rep["receipts"] == [], kw
    refusal(w, "path_forbidden")
    anchor = {"seq": 1, "head": sv.receipt_digest(receipts(w)[0])}
    for kw in ({"data": b""}, {"receipts": []}):
        assert sn.verify_chain(trust, anchor=anchor, **kw)["ok"] is False, kw   # receipts were seen, now none


def test_an_unreachable_broker_is_not_a_failed_chain(w, tmp_path):
    class Down:
        def call(self, *a, **k):
            raise ConnectionRefusedError("nope")
    with pytest.raises(sn.SourceError, match="cannot read receipts"):
        sn.read_broker(None, client=Down())


# -- hostile text --------------------------------------------------------------------------------------

def test_clean_strips_terminal_escapes_and_control_characters():
    out = sn.clean(HOSTILE, 500)
    for bad in ("\x1b", "\x07", "\r", "\n", "‮"):
        assert bad not in out
    assert "pwned" not in out                                              # an OSC title sequence goes whole
    assert sn.clean("a" * 500, 50).endswith("…") and len(sn.clean("a" * 500, 50)) == 50
    assert sn.clean(None) == "" and sn.clean("x\ty\nz") == "x y z"


def test_hostile_receipt_text_reaches_no_notification_unescaped(w):
    r = {"seq": 4, "decision": "denied", "effect": {"branch": HOSTILE, "action": PUSH},
         "observed": {"paths": [HOSTILE]}, "handoff": {"idempotency_key": HOSTILE},
         "reasons": [{"code": "path_forbidden", "message": f"1 path(s) not allowed: {HOSTILE} (path_forbidden)"},
                     {"code": HOSTILE, "message": HOSTILE}]}
    e = sn.describe(r)
    for text in (e["title"], e["body"], e["headline"], e["why"], *e["codes"]):
        assert "\x1b" not in text and "\x07" not in text and "\r" not in text and "\n" not in text
    assert len(e["body"]) < 400


def test_hostile_commit_message_never_leaves_the_broker(w):
    p, tok, sha, r = stage(w, "m", msg='evil\x1b[31m"; osascript -e "beep" <!channel>')
    assert "evil" not in json.dumps(receipts(w))                            # receipts hold no commit messages
    assert all("evil" not in e["body"] for e in sn.select(receipts(w)))


def test_the_applescript_is_fixed_and_the_text_is_only_ever_an_argument():
    cmd = sn.desktop_command("T\x1b[0m", HOSTILE, "stop", platform="darwin", which=lambda x: "/usr/bin/" + x)
    assert cmd[0] == "osascript" and isinstance(cmd, list)
    script = [cmd[i + 1] for i, a in enumerate(cmd) if a == "-e"]
    assert script == list(sn.APPLESCRIPT)                                  # nothing from the receipt is in the program
    body, title = cmd[-2:]
    assert cmd.count("-e") == len(sn.APPLESCRIPT) and cmd[1 + 2 * len(script):] == [body, title]
    assert "\x1b" not in body + title and "\n" not in body + title and len(body) <= sn.BODY_LIMIT
    assert "shell script" in body                                          # present, but only as inert data
    assert sn.desktop_command("-t", "--version", platform="darwin", which=lambda x: "x")[-2:] == ["version", "t"]
    assert sn.desktop_command("t", "", platform="darwin", which=lambda x: "x")[-2] == "(no text)"


def test_the_notification_command_is_run_without_a_shell():
    calls = []

    def fake_run(cmd, **kw):
        calls.append((cmd, kw))
        return subprocess.CompletedProcess(cmd, 0)
    assert sn.send_desktop("t", HOSTILE, "stop", run=fake_run, platform="darwin", which=lambda x: "x") is True
    cmd, kw = calls[0]
    assert isinstance(cmd, list) and kw["shell"] is False and kw["stdin"] == subprocess.DEVNULL
    assert sn.send_desktop("t", "b", run=fake_run, platform="freebsd", which=lambda x: None) is False


def test_notify_send_gets_no_markup_and_no_options():
    env = {"DISPLAY": ":0"}
    cmd = sn.desktop_command("t", '<b>x</b> & <a href="http://evil">y</a>', "stop", platform="linux",
                             which=lambda x: "/usr/bin/" + x, environ=env)
    assert cmd[0] == "notify-send" and "--" in cmd and cmd.index("--") < len(cmd) - 2
    body = cmd[-1]
    assert "<b>" not in body and "<a " not in body and "&lt;b&gt;" in body and "&amp;" in body
    assert "--urgency=critical" in cmd
    assert sn.desktop_command("t", "b", platform="linux", which=lambda x: "x", environ={}) is None   # no desktop session
    assert sn.desktop_command("t", "b", platform="linux", which=lambda x: None, environ=env) is None


def test_slack_text_cannot_ping_anyone_or_inject_links():
    p = sn.slack_payload("Synthe <!here>", "branch <!channel> <@U123|admin> <https://evil|click> & \x1b[0m\n*bold*")
    assert "<" not in p["text"].replace("&lt;", "").replace("&gt;", "")
    assert "&lt;!channel&gt;" in p["text"] and "&amp;" in p["text"] and "\x1b" not in p["text"]
    assert p["unfurl_links"] is False and p["unfurl_media"] is False
    assert sn.slack_escape("<&>") == "&lt;&amp;&gt;"


URL = "https://hooks.slack.com/services/T000/B000/SECRETSECRET"


def test_slack_url_is_checked_and_never_printed():
    assert sn.slack_url_ok(URL)
    for bad in ("http://hooks.slack.com/x", "https://evil.example/hooks.slack.com", "https://slack.com.evil.example/x",
                "https://user:pw@hooks.slack.com/x", "ftp://hooks.slack.com/x", "", None, 5):
        assert not sn.slack_url_ok(bad), bad
    out, err = io.StringIO(), io.StringIO()

    def failing(req, timeout):
        raise urllib.error.HTTPError(req.full_url, 404, "gone " + URL, {}, None)
    n = sn.Notifier({"slack_webhook": URL, "desktop": False}, out=out, err=err, opener=failing)
    for _ in range(3):
        n.send("t", "b", "stop")
    seen = out.getvalue() + err.getvalue()
    assert "SECRETSECRET" not in seen and "hooks.slack.com" not in seen
    assert err.getvalue().count("Slack delivery failed") == 1 and "404" in err.getvalue()
    assert "stdout" in n.send("t", "b")                                       # nothing else worked: still visible


def test_slack_posts_json_over_https_and_reports_success():
    sent = {}

    class Resp:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def opener(req, timeout):
        sent.update(url=req.full_url, data=json.loads(req.data), method=req.get_method(), timeout=timeout)
        return Resp()
    assert sn.send_slack(URL, "Synthe stopped something", "Blocked: <!channel>", opener) is None
    assert sent["method"] == "POST" and sent["url"] == URL and sent["timeout"] <= 15
    assert "&lt;!channel&gt;" in sent["data"]["text"]
    assert sn.send_slack("http://hooks.slack.com/x", "t", "b", opener) == "the Slack webhook URL must be https on slack.com"


def test_config_only_trusts_a_slack_url_in_a_private_file(tmp_path):
    p = tmp_path / "notify.json"
    p.write_text(json.dumps({"slack_webhook": URL, "all_refusals": True, "desktop": "yes", "key": "/k"}))
    os.chmod(p, 0o644)
    cfg, warnings = sn.load_config(p)
    assert "slack_webhook" not in cfg and any("chmod 600" in x for x in warnings)
    assert URL not in " ".join(warnings)
    os.chmod(p, 0o600)
    cfg, warnings = sn.load_config(p)
    assert cfg == {"slack_webhook": URL, "all_refusals": True, "key": "/k"} and warnings == []
    p.write_text(json.dumps({"slack_webhook": "https://evil.example/x"}))
    assert sn.load_config(p)[0] == {} and "slack.com" in sn.load_config(p)[1][0]
    assert sn.load_config(tmp_path / "absent.json") == ({}, [])
    p.write_text("[1]")
    assert sn.load_config(p)[0] == {}


def test_notifier_falls_back_to_the_terminal_and_stays_short():
    out = io.StringIO()
    n = sn.Notifier({"desktop": False}, out=out, clock=lambda: 0)
    assert n.send("Synthe stopped something", "x" * 2000, "stop") == ["stdout"]
    line = out.getvalue()
    assert line.startswith("[19")                                          # the stamp from the fake clock
    assert len(line) < 600 and "…" in line


# -- finding the key -----------------------------------------------------------------------------------

def test_find_key_prefers_what_you_name_and_distrusts_a_key_others_can_write(w, tmp_path):
    key = broker_key(w, tmp_path)
    assert sn.find_key(str(key), {}) == key
    assert sn.find_key(None, {"key": str(key)}) == key
    with pytest.raises(sn.SourceError, match="no key file"):
        sn.find_key(str(tmp_path / "nope.json"), {})
    cand = tmp_path / "cand.json"
    cand.write_text(key.read_text())
    os.chmod(cand, 0o644)
    assert sn.find_key(None, {}, candidates=(cand,), home=tmp_path) == cand
    os.chmod(cand, 0o666)                                                    # anyone could swap who is trusted
    with pytest.raises(sn.SourceError, match="no broker public key found"):
        sn.find_key(None, {}, candidates=(cand,), home=tmp_path)


def test_a_dev_registry_serves_as_the_key(w, tmp_path):
    home = tmp_path / "home"
    (home / ".synthe" / "broker").mkdir(parents=True)
    (home / ".synthe" / "broker" / "registry.json").write_text(json.dumps(w.registry))
    found = sn.find_key(None, {}, candidates=(), home=home)
    assert sn.load_trust(found, None)["signer"] == "synthe-broker"
    with pytest.raises(sn.SourceError, match="cannot use the key file"):
        sn.load_trust(found, "no-such-signer")


# -- the digest ----------------------------------------------------------------------------------------

def week(w):
    """4 pushes under a standing task, 3 that needed you (2 approved, 1 still waiting), 2 risky attempts stopped
    (one tried twice), a routine stale-branch refusal, and one problem."""
    for i in range(4):
        append(w, decision="executed", handoff={"idempotency_key": f"auto{i}"},
               effect={"action": PUSH, "branch": f"agent/a{i}", "type": "git_push"})
    for i in range(3):
        append(w, decision="staged", handoff={"idempotency_key": f"need{i}"}, staged={"id": f"need{i}/{PUSH}", "waiting_for": ["approval"]},
               effect={"action": PUSH, "branch": f"agent/n{i}"}, observed={"paths": ["src/a.py"]})
    for i in range(2):
        append(w, kind="approval", decision="approval_accepted", approval={"action": PUSH},
               handoff={"idempotency_key": f"need{i}"})
        append(w, decision="executed", handoff={"idempotency_key": f"need{i}"}, staged={"id": f"need{i}/{PUSH}"},
               effect={"action": PUSH, "branch": f"agent/n{i}", "type": "git_push"})
    ci = ".github/workflows/ci.yml (path_outside_scope)"
    for _ in range(2):
        refusal(w, "path_outside_scope", idem="ci", branch="agent/ci", message=f"1 path(s) not allowed: {ci}")
    refusal(w, "non_fast_forward", idem="ff", branch="agent/ff")
    refusal(w, "remote_moved", idem="stale")
    refusal(w, "broker_credentials_missing", idem="cred", decision="errored")
    refusal(w, "effect_already_executed", idem="auto0")


def test_digest_counts_and_tells_what_each_stop_prevented(w, tmp_path):
    week(w)
    d = sn.build_digest(receipts(w), 7)
    assert (d["pushes_shipped"], d["shipped_without_asking"], d["needed_you"]) == (6, 4, 3)
    assert (d["needed_you_shipped"], d["needed_you_still_waiting"]) == (2, 1)
    assert (d["stopped"], d["problems"], d["routine_refusals"]) == (2, 1, 1)     # the repeated CI attempt counts once
    chain = {"count": len(receipts(w)), "head": "ab" * 32, "signer": "synthe-broker", "complete": True}
    text = sn.render_digest(d, chain)
    assert text.startswith("Last 7 days: 4 pushes shipped without asking you, 3 needed you, 2 risky attempts stopped, "
                           "1 problem needing a look.")
    assert "Of the 3 that needed you: 2 shipped after you approved, 1 still waiting." in text
    assert "Also 1 routine refusal (a stale branch" in text
    assert "Blocked: the agent tried to change a CI workflow (.github/workflows/ci.yml) on 'agent/ci'." in text
    assert "That file controls what runs in CI" in text and "rewrite branch history" in text
    assert "Needs a look: Synthe has no GitHub credentials (branch 'agent/z'). It cannot push anything" in text
    assert "which key acted, not which model" in text and "does not judge whether pushed code is good" in text
    assert "ababababab" in text


def test_digest_only_counts_the_period_and_handles_a_quiet_week(w):
    old = (hc.now_utc() - dt.timedelta(days=30)).isoformat()
    append(w, decision="executed", time=old, handoff={"idempotency_key": "o"}, effect={"action": PUSH})
    refusal(w, "non_fast_forward", time=old)
    d = sn.build_digest(receipts(w), 7)
    assert (d["pushes_shipped"], d["stopped"]) == (0, 0)
    assert sn.build_digest(receipts(w), 90)["stopped"] == 1
    text = sn.render_digest(d, {"count": 2, "head": "cd" * 32, "signer": "synthe-broker", "complete": True})
    assert text.startswith("Last 7 days: nothing to report.")
    assert sn.render_digest(sn.build_digest([], 1), {"count": 0, "head": None, "signer": "s", "complete": False}) \
        .startswith("Today: nothing to report.")


def test_digest_cli_text_and_json_from_a_verified_chain(w, tmp_path, capsys):
    week(w)
    base = ["--receipts", str(w.cfg.receipts_path), "--key", str(broker_key(w, tmp_path)),
            "--state", str(tmp_path / "s.json"), "--config", str(tmp_path / "c.json")]
    assert sn.main(["digest", *base]) == 0
    text = capsys.readouterr().out
    assert "4 pushes shipped without asking you, 3 needed you, 2 risky attempts stopped" in text
    assert re.search(r"Verified: \d+ receipts signed by synthe-broker, head [0-9a-f]{12}\.", text)
    assert sn.main(["digest", "--json", "--days", "30", *base]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["days"] == 30 and data["shipped_without_asking"] == 4 and data["stopped"] == 2
    assert data["chain"]["ok"] is True and data["chain"]["count"] == len(receipts(w))
    assert {s["codes"][0] for s in data["stops"]} == {"path_outside_scope", "non_fast_forward"}
    with pytest.raises(SystemExit):
        sn.main(["digest", "--days", "0", *base])


def test_digest_refuses_an_unverified_chain(w, tmp_path, capsys):
    week(w)
    lines = w.cfg.receipts_path.read_text().splitlines()
    forged = json.loads(lines[-1])
    forged["decision"] = "executed"
    w.cfg.receipts_path.write_text("\n".join(lines[:-1] + [json.dumps(forged, sort_keys=True)]) + "\n")
    base = ["--receipts", str(w.cfg.receipts_path), "--key", str(broker_key(w, tmp_path)),
            "--state", str(tmp_path / "s.json"), "--config", str(tmp_path / "c.json")]
    assert sn.main(["digest", *base]) == 1
    cap = capsys.readouterr()
    assert cap.out == "" and "NOT VERIFIED" in cap.err and "No digest" in cap.err


# -- the test command ----------------------------------------------------------------------------------

def test_the_test_command_sends_a_labelled_sample(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(sn, "send_desktop", lambda *a, **k: False)
    assert sn.main(["test", "--config", str(tmp_path / "none.json")]) == 1      # only the terminal: say so
    cap = capsys.readouterr()
    assert "Synthe test:" in cap.out and "CI workflow" in cap.out and "This is a test" in cap.out
    assert "no desktop notifier" in cap.err
    monkeypatch.setattr(sn, "send_desktop", lambda *a, **k: True)
    assert sn.main(["test", "--config", str(tmp_path / "none.json")]) == 0
    assert "delivered to desktop" in capsys.readouterr().err


def test_main_has_the_three_commands_and_is_installed_as_a_console_script():
    with pytest.raises(SystemExit):
        sn.main([])
    toml = (ROOT / "pyproject.toml").read_text()
    assert 'synthe-notify = "synthe_notify:main"' in toml and '"synthe_notify"' in toml


# -- against the real broker daemon (the OpenClaw flow's dev setup) --------------------------------------

def test_watch_reads_a_real_broker_over_its_socket_and_hears_about_the_blocked_ci_change(world, tmp_path, capsys,
                                                                                         monkeypatch):
    monkeypatch.setattr(sn, "send_desktop", lambda *a, **k: False)
    clone, home = world["clone"], world["home"]
    packet = _task(world, "Change the CI workflow", "agent/ci")
    registry = home / "broker" / "registry.json"                # the dev layout: the broker's key is in the registry
    base = ["--key", str(registry), "--state", str(tmp_path / "s.json"), "--config", str(tmp_path / "none.json")]
    with broker(home) as url:
        assert sn.main(["watch", "--once", "--broker", url, *base]) == 0     # nothing yet: starts from now
        assert "watching from receipt 0" in capsys.readouterr().err
        mcp = Mcp(url)
        try:
            v = mcp.tool("synthe_validate_handoff", packet=packet, wait_for_approval=True)
            sha = _commit(clone, "agent/ci", {".github/workflows/ci.yml": "on: push\n"})
            r = mcp.tool("synthe_propose_effect", packet=packet, claim_token=v["claim"]["token"], action="push_branch",
                         params={"remote": "origin", "branch": "agent/ci", "commit": sha}, source=str(clone),
                         wait_for_approval=True)
        finally:
            mcp.close()
        assert r["decision"] == "denied"
        assert sn.main(["watch", "--once", "--stdout", "--broker", url, *base]) == 0
        out = capsys.readouterr().out
        assert "Blocked: the agent tried to change a CI workflow (.github/workflows/ci.yml) on 'agent/ci'" in out
        assert sn.main(["watch", "--once", "--stdout", "--broker", url, *base]) == 0
        assert capsys.readouterr().out == ""                                 # already told
        assert sn.main(["digest", "--broker", url, *base]) == 0
        digest = capsys.readouterr().out
        assert "1 risky attempt stopped" in digest and "Verified: " in digest
        # some other key is not the broker's: the same receipts do not verify, and nothing is said from them
        _, pub = mkkey("synthe-broker")
        wrong = tmp_path / "wrong.pub.json"
        wrong.write_text(json.dumps({"broker": "synthe-broker", **pub, "kid": "synthe-broker-1"}))
        assert sn.main(["digest", "--broker", url, "--key", str(wrong), "--state", str(tmp_path / "s2.json"),
                        "--config", str(tmp_path / "none.json")]) == 1
        cap = capsys.readouterr()
        assert cap.out == "" and "signature_invalid" in cap.err


# -- running at login: install-agent / uninstall-agent, and the offer at the end of setup ------------------

class Runs:
    def __init__(self, code=0):
        self.calls, self.code = [], code

    def __call__(self, argv, **kw):
        self.calls.append(list(argv))
        return subprocess.CompletedProcess(argv, self.code, "", "boom" if self.code else "")


def test_install_agent_on_macos_writes_a_launch_agent_in_your_account_and_starts_it(tmp_path):
    import plistlib
    run = Runs()
    r = sn.install_agent(tmp_path, platform="darwin", run=run, uid=501, user="rohan",
                         program=["/opt/synthe/bin/synthe-notify"], out=lambda *_: None)
    plist = tmp_path / "Library" / "LaunchAgents" / "com.synthe.notify.plist"
    assert r == {"installed": str(plist), "started": True, "kind": "launchd"}
    body = plistlib.loads(plist.read_bytes())
    assert body["ProgramArguments"] == ["/opt/synthe/bin/synthe-notify", "watch", "--stdout", "--interval", "15"]
    assert body["RunAtLoad"] and body["KeepAlive"] and body["StandardOutPath"] == str(tmp_path / ".synthe/notify.log")
    assert run.calls[-1] == ["launchctl", "bootstrap", "gui/501", str(plist)]
    sn.install_agent(tmp_path, platform="darwin", run=run, uid=501, user="rohan", program=["/x"], out=lambda *_: None)
    assert run.calls[-2][:2] == ["launchctl", "bootout"]          # a second install replaces the first
    assert sn.uninstall_agent(tmp_path, platform="darwin", run=run, uid=501, out=lambda *_: None) == {"removed": True}
    assert not plist.exists() and run.calls[-1][:2] == ["launchctl", "bootout"]


def test_install_agent_on_linux_writes_a_user_unit_and_quotes_its_command(tmp_path):
    run = Runs()
    r = sn.install_agent(tmp_path, platform="linux", run=run, uid=1000, user="rohan",
                         program=["/home/rohan/synthe venv/bin/synthe-notify"], interval=30, out=lambda *_: None)
    unit = tmp_path / ".config/systemd/user/synthe-notify.service"
    assert r["started"] and r["kind"] == "systemd"
    assert 'ExecStart="/home/rohan/synthe venv/bin/synthe-notify" "watch" "--stdout" "--interval" "30"' in unit.read_text()
    assert ["systemctl", "--user", "enable", "--now", "synthe-notify.service"] in run.calls
    with pytest.raises(sn.SourceError, match="systemd unit"):
        sn.install_agent(tmp_path, platform="linux", run=run, uid=1000, user="rohan", program=["/a\nExecStart=/evil"])
    assert sn.uninstall_agent(tmp_path, platform="linux", run=run, uid=1000, out=lambda *_: None)["removed"]
    assert not unit.exists()


def test_a_failed_start_is_said_not_hidden(tmp_path):
    said = []
    r = sn.install_agent(tmp_path, platform="darwin", run=Runs(code=5), uid=501, user="rohan", program=["/x"],
                         out=said.append)
    assert r["started"] is False and "starting it failed" in said[0]


@pytest.mark.parametrize("user,uid,role", [("root", 0, None), ("_synthe", 250, None), ("synthe", 990, None),
                                           ("openclaw", 502, "agent")])
def test_install_agent_refuses_root_the_broker_and_the_agents_account(tmp_path, user, uid, role):
    if role:
        (tmp_path / ".synthe").mkdir()
        (tmp_path / ".synthe" / "setup.json").write_text(json.dumps({"role": role}))
    run = Runs()
    with pytest.raises(sn.SourceError, match="not turning notifications on here"):
        sn.install_agent(tmp_path, platform="darwin", run=run, uid=uid, user=user, program=["/x"])
    assert run.calls == [] and not (tmp_path / "Library").exists()


def test_install_agent_cli_exists():
    out = subprocess.run([os.environ.get("PYTHON", "python3"), str(ROOT / "src/synthe_notify.py"), "--help"],
                         capture_output=True, text=True)
    assert "install-agent" in out.stdout and "uninstall-agent" in out.stdout


def test_setup_offers_notifications_once_and_never_installs_without_a_person(tmp_path):
    import synthe_init as si
    said, installs = [], []
    install = lambda **kw: installs.append(kw) or {"started": True}  # noqa: E731
    assert si.offer_notifications(tmp_path, interactive=False, out=said.append, install=install) == "off"
    assert installs == [] and "synthe-notify install-agent" in said[-1]
    assert si.offer_notifications(tmp_path, interactive=True, ask=lambda q: "", out=said.append, install=install) == "on"
    assert len(installs) == 1                                   # Return alone: yes
    assert si.offer_notifications(tmp_path, interactive=True, ask=lambda q: "n", out=said.append, install=install) == "off"
    si.write_setup(tmp_path, {"role": "agent"})
    assert si.offer_notifications(tmp_path, interactive=True, ask=lambda q: "y", out=said.append, install=install) == "off"
    assert len(installs) == 1 and "agent's" in said[-1]


def test_finish_setup_offers_notifications_after_the_lane(tmp_path, monkeypatch):
    import synthe_init as si
    monkeypatch.setattr(si.sys, "platform", "darwin")
    monkeypatch.setattr(si.os, "geteuid", lambda: 501)
    monkeypatch.setattr(si.shutil, "which", lambda x: "/usr/bin/" + x)
    monkeypatch.setattr(si, "source_root", lambda: ROOT)
    text = si.prepare(tmp_path / "setup", repo_url="https://github.com/example/repo.git", branches=["agent/*"],
                      allowed_paths=["src/**"], agent_account="worker", approver="human", python="/usr/bin/python3",
                      script_path=ROOT / "src/synthe_init.py", node=tmp_path / "absent", agent_kind="none").read_text()
    assert text.index("lane-offer") < text.index("notify-offer")
    assert "sudo" not in text.split("lane-offer")[1]            # in the person's account, after the admin step
