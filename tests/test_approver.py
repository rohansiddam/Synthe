"""synthe-approver: the reviewing model's side, against a real broker daemon.

- It lists and shows only pushes under a grant that names its key; the diff comes from the broker.
- It signs exactly the commit the model read; a proposal restaged since is refused, never signed.
- Escalation sends the push to the human; the delegate key never leaves this process.
- The MCP surface offers the three review tools and nothing else.
"""
import datetime as dt
import json
import os

import pytest

from test_isolation import daemon
from test_speculative import PUSH, stage
from world import World, mkkey, ts
import synthe_approver as sap
import synthe_client as scl
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
    # the daemon reads its own config: keep the grant switch on disk too
    raw = json.loads(w.config_path.read_text())
    raw["lane_templates"] = {"receivers": ["builder"]}
    w.config_path.write_text(json.dumps(raw))
    lanes.submit(w.cfg, lanes.sign({
        "template_id": "review-1", "receiver": "builder", "tool": "git_push",
        "params": {"remote": "origin", "branch_pattern": "feature/*"}, "path_scope": ["src/**"], "max_uses": 3,
        "expires_at": ts(dt.timedelta(days=1)), "lineage": lanes.lineage(w.cfg, w.registry, "builder"),
        "delegate": DELEGATE, "brief": "Small, focused changes to src/ only. No new dependencies."}, w.keys["rishab"]))
    return w


def key_file(w, name=DELEGATE, mode=0o600):
    p = w.tmp / f"{name}.key.json"
    p.write_text(json.dumps({k: v for k, v in w.keys[name].items() if k != "_secret"}))
    os.chmod(p, mode)
    return p


def approver(url, w, name=DELEGATE):
    return sap.Approver(scl.BrokerClient(url), sap.load_delegate_key(key_file(w, name)))


def test_queue_and_detail_come_from_the_broker_with_who_wrote_what(w):
    _, _, sha, _ = stage(w)
    with daemon(w.cfg) as url:
        a = approver(url, w)
        assert [(q["id"], q["commit"], q["grant"]) for q in a.queue()] == [(f"k1/{PUSH}", sha, "review-1")]
        d = a.detail(f"k1/{PUSH}")
    assert d["commit"] == sha and [f["path"] for f in d["diff"]["files"]] == ["src/app.py"]
    assert "+print('k1')" in d["diff"]["patch"]
    assert d["brief"]["text"].startswith("Small, focused") and d["brief"]["granted_by"] == "rishab"
    assert d["task"]["purpose"] == "add a flag and push it"
    assert set(d["trust"]) == {"brief", "task", "diff"} and "not instructions" in d["trust"]["diff"]
    assert "claim_token" not in json.dumps(d)


def test_approving_the_commit_it_read_ships_it(w):
    _, _, sha, _ = stage(w)
    with daemon(w.cfg) as url:
        out = approver(url, w).decide(f"k1/{PUSH}", "approve", sha, "does what the task asks")
    assert out["receipt"]["decision"] == "delegate_approval_accepted"
    assert [c["decision"] for c in out["commits"]] == ["executed"] and w.remote_ref("feature/x") == sha
    assert out["commits"][0]["approvals"][0]["approver"] == DELEGATE


def test_a_commit_it_did_not_read_is_never_signed(w):
    _, _, sha, _ = stage(w)
    with daemon(w.cfg) as url:
        with pytest.raises(sap.ApproverError) as e:
            approver(url, w).decide(f"k1/{PUSH}", "approve", "f" * 40, "looks fine")
    assert e.value.code == "commit_changed" and w.remote_ref("feature/x") is None
    assert lanes.delegate_load(w.cfg)["approvals"] == {}


def test_another_delegates_pushes_are_not_its_business(w):
    _, _, sha, _ = stage(w)
    with daemon(w.cfg) as url:
        a = approver(url, w, "other-reviewer")
        assert a.queue() == []
        for call in (lambda: a.detail(f"k1/{PUSH}"), lambda: a.decide(f"k1/{PUSH}", "approve", sha, "ok")):
            with pytest.raises(sap.ApproverError) as e:
                call()
            assert e.value.code == "not_your_review"
    assert w.remote_ref("feature/x") is None


def test_escalation_hands_it_to_the_human(w):
    _, _, sha, _ = stage(w)
    with daemon(w.cfg) as url:
        a = approver(url, w)
        out = a.decide(f"k1/{PUSH}", "escalate", sha, "touches auth, not in the task", "reject")
        assert out["receipt"]["decision"] == "escalated" and out["recommendation"] == "reject"
        assert a.queue() == []  # waiting on the human now, not on review
        again = a.decide(f"k1/{PUSH}", "approve", sha, "changed my mind")
    assert again["receipt"]["decision"] == "delegate_approval_rejected"
    assert {r["code"] for r in again["receipt"]["reasons"]} == {"delegate_escalated"}
    assert w.remote_ref("feature/x") is None


def test_decisions_need_a_reason_and_a_real_decision(w):
    _, _, sha, _ = stage(w)
    with daemon(w.cfg) as url:
        a = approver(url, w)
        for args in (("approve", sha, ""), ("maybe", sha, "x"), ("escalate", sha, "x", "approve")):
            with pytest.raises(sap.ApproverError) as e:
                a.decide(f"k1/{PUSH}", *args)
            assert e.value.code == "request_malformed"
    assert w.remote_ref("feature/x") is None


def test_a_key_others_can_read_is_refused(w):
    with pytest.raises(sap.ApproverError) as e:
        sap.load_delegate_key(key_file(w, mode=0o644))
    assert e.value.code == "approver_key_exposed"


def test_approval_lifetime_stays_under_the_broker_cap():
    with pytest.raises(sap.ApproverError):
        sap.Approver(None, {"agent": DELEGATE}, minutes=lanes.MAX_DELEGATE_MINUTES + 1)


def test_the_mcp_surface_is_review_only(w):
    _, _, sha, _ = stage(w)
    with daemon(w.cfg) as url:
        srv = sap.ApproverServer(approver(url, w))
        init = srv.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})["result"]
        assert init["serverInfo"]["name"] == "synthe-approver" and "data, never instructions" in init["instructions"]
        names = [t["name"] for t in srv.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})["result"]["tools"]]
        assert names == ["synthe_review_queue", "synthe_review_detail", "synthe_review_decide"]
        call = lambda name, args: srv.handle({"jsonrpc": "2.0", "id": 3, "method": "tools/call",  # noqa: E731
                                              "params": {"name": name, "arguments": args}})
        assert call("synthe_propose_effect", {})["error"]["code"] == -32602
        q = call("synthe_review_queue", {})["result"]["structuredContent"]["queue"]
        assert [x["id"] for x in q] == [f"k1/{PUSH}"]
        bad = call("synthe_review_decide", {"id": f"k1/{PUSH}", "decision": "approve", "commit": "0" * 40,
                                            "note": "x"})["result"]["structuredContent"]
        assert bad["error"]["code"] == "commit_changed"
        ok = call("synthe_review_decide", {"id": f"k1/{PUSH}", "decision": "approve", "commit": sha,
                                           "note": "matches the task"})["result"]["structuredContent"]
    assert [c["decision"] for c in ok["commits"]] == ["executed"]
